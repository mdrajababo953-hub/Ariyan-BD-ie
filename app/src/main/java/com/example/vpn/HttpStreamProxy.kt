package com.example.vpn

import com.example.decoder.HexUtils
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.Locale
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

data class CapturedHttpRequestMeta(
    val startedAt: Long,
    val method: String,
    val url: String,
    val host: String,
    val path: String,
    val port: Int,
    val protocol: String,
    val requestHeadersJson: String,
    val requestBodyHex: String,
    val bytesTx: Int,
    val packetIdHolder: PacketIdHolder
)

class PacketIdHolder {
    @Volatile
    var packetId: Long = 0L
}

interface HttpCaptureCallbacks {
    fun onHttpRequest(meta: CapturedHttpRequestMeta)
    fun onHttpResponse(
        meta: CapturedHttpRequestMeta,
        statusCode: Int?,
        responseHeadersJson: String,
        responseBodyHex: String,
        bytesRx: Int,
        durationMs: Long
    )
    fun onRawTunnelBytes(
        isHttps: Boolean,
        host: String,
        port: Int,
        reqBytes: ByteArray?,
        respBytes: ByteArray?
    )
    fun onBytesTransferred(bytes: Int)
}

object HttpStreamProxy {

    const val MAX_CAPTURE_BYTES = 131_072
    private const val MAX_COMPRESSED_CAPTURE_BYTES = 524_288

    private val HTTP_METHODS = setOf(
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"
    )

    suspend fun relayStream(
        scope: CoroutineScope,
        clientIn: InputStream,
        clientOut: OutputStream,
        serverIn: InputStream,
        serverOut: OutputStream,
        initialClientBytes: ByteArray,
        isHttps: Boolean,
        defaultHost: String,
        port: Int,
        callbacks: HttpCaptureCallbacks,
        skipHttpPeek: Boolean = false,
        ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
        onClientEof: (() -> Unit)? = null,
        onServerEof: (() -> Unit)? = null
    ) {
        val scheme = if (isHttps) "https" else "http"
        val protocolLabel = if (isHttps) "HTTPS" else "HTTP"

        val prefixedClientIn = if (initialClientBytes.isNotEmpty()) {
            java.io.SequenceInputStream(ByteArrayInputStream(initialClientBytes), clientIn)
        } else {
            clientIn
        }

        if (skipHttpPeek) {
            relayRawBinary(
                scope = scope,
                clientIn = prefixedClientIn,
                clientOut = clientOut,
                serverIn = serverIn,
                serverOut = serverOut,
                isHttps = isHttps,
                host = defaultHost,
                port = port,
                callbacks = callbacks,
                ioDispatcher = ioDispatcher,
                onClientEof = onClientEof,
                onServerEof = onServerEof
            )
            return
        }

        // Peek first line bytes up to 16 bytes to decide HTTP/1.x vs Raw Binary TCP/TLS
        val peekBuf = ByteArray(16)
        val bufferedClient = java.io.BufferedInputStream(prefixedClientIn, 16384)
        bufferedClient.mark(16)
        val peeked = readUpTo(bufferedClient, peekBuf)
        if (peeked <= 0) return
        bufferedClient.reset()

        val peekText = String(peekBuf, 0, peeked, Charsets.ISO_8859_1)
        val looksHttp = HTTP_METHODS.any { m -> peekText.startsWith("$m ") }

        if (!looksHttp) {
            relayRawBinary(
                scope = scope,
                clientIn = bufferedClient,
                clientOut = clientOut,
                serverIn = serverIn,
                serverOut = serverOut,
                isHttps = isHttps,
                host = defaultHost,
                port = port,
                callbacks = callbacks,
                ioDispatcher = ioDispatcher,
                onClientEof = onClientEof,
                onServerEof = onServerEof
            )
            return
        }

        val pendingQueue = Channel<CapturedHttpRequestMeta>(capacity = 64)
        val bufferedServer = java.io.BufferedInputStream(serverIn, 16384)
        val upgradedToRaw = java.util.concurrent.atomic.AtomicBoolean(false)

        val responseJob: Job = scope.launch(ioDispatcher) {
            try {
                while (isActive) {
                    val headerBytes = readHeaderBlock(bufferedServer) ?: break
                    clientOut.write(headerBytes)
                    clientOut.flush()
                    callbacks.onBytesTransferred(headerBytes.size)

                    val parsed = parseResponseHeader(headerBytes)
                    if (parsed == null) {
                        // Unexpected non-HTTP response framing: drain remaining bytes raw
                        drainRaw(bufferedServer, clientOut, callbacks)
                        break
                    }

                    // 100 Continue / 1xx informational responses (except 101 WebSocket upgrade) precede the final response
                    if (parsed.statusCode in 100..199 && parsed.statusCode != 101) {
                        continue
                    }

                    val pendingReq = pendingQueue.receiveCatching().getOrNull()
                    if (parsed.statusCode == 101) {
                        if (pendingReq != null) {
                            callbacks.onHttpResponse(
                                meta = pendingReq,
                                statusCode = 101,
                                responseHeadersJson = parsed.headersJson,
                                responseBodyHex = "",
                                bytesRx = headerBytes.size,
                                durationMs = (System.currentTimeMillis() - pendingReq.startedAt).coerceAtLeast(1L)
                            )
                        }
                        upgradedToRaw.set(true)
                        val hostForWs = pendingReq?.host ?: defaultHost
                        val wsBuf = ByteArray(8192)
                        while (isActive) {
                            val n = bufferedServer.read(wsBuf)
                            if (n <= 0) break
                            val slice = wsBuf.copyOfRange(0, n)
                            clientOut.write(slice)
                            clientOut.flush()
                            callbacks.onBytesTransferred(n)
                            callbacks.onRawTunnelBytes(isHttps, hostForWs, port, reqBytes = null, respBytes = slice)
                        }
                        break
                    }

                    val isRespCompressed = !parsed.contentEncoding.isNullOrBlank() &&
                        (parsed.contentEncoding.contains("gzip", true) || parsed.contentEncoding.contains("deflate", true))
                    val bodyCollector = BoundedByteCollector(
                        if (isRespCompressed) MAX_COMPRESSED_CAPTURE_BYTES else MAX_CAPTURE_BYTES
                    )
                    var rawBodyCount = 0

                    val noBody = parsed.statusCode == 204 ||
                        parsed.statusCode == 304 ||
                        pendingReq?.method.equals("HEAD", ignoreCase = true)

                    if (!noBody) {
                        if (parsed.isChunked) {
                            rawBodyCount = forwardChunkedBody(bufferedServer, clientOut, bodyCollector, callbacks)
                        } else if (parsed.contentLength >= 0L) {
                            rawBodyCount = forwardFixedBody(bufferedServer, clientOut, parsed.contentLength, bodyCollector, callbacks)
                        } else {
                            rawBodyCount = forwardUntilEof(bufferedServer, clientOut, bodyCollector, callbacks)
                        }
                    }

                    val totalRx = headerBytes.size + rawBodyCount
                    val rawBody = bodyCollector.toByteArray()
                    val decodedBody = decompressIfNeeded(rawBody, parsed.contentEncoding)
                    val cappedBody = if (decodedBody.size > MAX_CAPTURE_BYTES) {
                        decodedBody.copyOf(MAX_CAPTURE_BYTES)
                    } else {
                        decodedBody
                    }

                    if (pendingReq != null) {
                        callbacks.onHttpResponse(
                            meta = pendingReq,
                            statusCode = parsed.statusCode,
                            responseHeadersJson = parsed.headersJson,
                            responseBodyHex = HexUtils.bytesToHex(cappedBody),
                            bytesRx = totalRx,
                            durationMs = (System.currentTimeMillis() - pendingReq.startedAt).coerceAtLeast(1L)
                        )
                    }
                }
            } catch (_: Exception) {
            } finally {
                runCatching { clientOut.flush() }
                runCatching { onServerEof?.invoke() }
            }
        }

        try {
            while (scope.isActive) {
                if (upgradedToRaw.get()) {
                    val wsBuf = ByteArray(8192)
                    while (scope.isActive) {
                        val n = bufferedClient.read(wsBuf)
                        if (n <= 0) break
                        val slice = wsBuf.copyOfRange(0, n)
                        serverOut.write(slice)
                        serverOut.flush()
                        callbacks.onBytesTransferred(n)
                        callbacks.onRawTunnelBytes(isHttps, defaultHost, port, reqBytes = slice, respBytes = null)
                    }
                    break
                }
                val headerBytes = readHeaderBlock(bufferedClient) ?: break
                val reqHeader = parseRequestHeader(headerBytes, defaultHost)
                if (reqHeader == null) {
                    serverOut.write(headerBytes)
                    serverOut.flush()
                    callbacks.onBytesTransferred(headerBytes.size)
                    if (upgradedToRaw.get()) {
                        callbacks.onRawTunnelBytes(isHttps, defaultHost, port, reqBytes = headerBytes, respBytes = null)
                        val wsBuf = ByteArray(8192)
                        while (scope.isActive) {
                            val n = bufferedClient.read(wsBuf)
                            if (n <= 0) break
                            val slice = wsBuf.copyOfRange(0, n)
                            serverOut.write(slice)
                            serverOut.flush()
                            callbacks.onBytesTransferred(n)
                            callbacks.onRawTunnelBytes(isHttps, defaultHost, port, reqBytes = slice, respBytes = null)
                        }
                    } else {
                        drainRaw(bufferedClient, serverOut, callbacks)
                    }
                    break
                }

                serverOut.write(headerBytes)
                serverOut.flush()
                callbacks.onBytesTransferred(headerBytes.size)

                val isReqCompressed = !reqHeader.contentEncoding.isNullOrBlank() &&
                    (reqHeader.contentEncoding.contains("gzip", true) || reqHeader.contentEncoding.contains("deflate", true))
                val reqBodyCollector = BoundedByteCollector(
                    if (isReqCompressed) MAX_COMPRESSED_CAPTURE_BYTES else MAX_CAPTURE_BYTES
                )
                val reqBodyCount = when {
                    reqHeader.isChunked -> forwardChunkedBody(bufferedClient, serverOut, reqBodyCollector, callbacks)
                    reqHeader.contentLength > 0L -> forwardFixedBody(bufferedClient, serverOut, reqHeader.contentLength, reqBodyCollector, callbacks)
                    else -> 0
                }

                val rawReqBody = reqBodyCollector.toByteArray()
                val decodedReqBody = decompressIfNeeded(rawReqBody, reqHeader.contentEncoding)
                val cappedReqBody = if (decodedReqBody.size > MAX_CAPTURE_BYTES) {
                    decodedReqBody.copyOf(MAX_CAPTURE_BYTES)
                } else {
                    decodedReqBody
                }

                val cleanPath = normalizePath(reqHeader.rawTarget)
                val fullUrl = "$scheme://${reqHeader.host}$cleanPath"
                val meta = CapturedHttpRequestMeta(
                    startedAt = System.currentTimeMillis(),
                    method = reqHeader.method,
                    url = fullUrl,
                    host = reqHeader.host,
                    path = cleanPath,
                    port = port,
                    protocol = protocolLabel,
                    requestHeadersJson = reqHeader.headersJson,
                    requestBodyHex = HexUtils.bytesToHex(cappedReqBody),
                    bytesTx = headerBytes.size + reqBodyCount,
                    packetIdHolder = PacketIdHolder()
                )
                callbacks.onHttpRequest(meta)
                pendingQueue.trySend(meta)
            }
        } catch (_: Exception) {
        } finally {
            pendingQueue.close()
            runCatching { serverOut.flush() }
            runCatching { onClientEof?.invoke() }
            responseJob.join()
        }
    }

    private suspend fun relayRawBinary(
        scope: CoroutineScope,
        clientIn: InputStream,
        clientOut: OutputStream,
        serverIn: InputStream,
        serverOut: OutputStream,
        isHttps: Boolean,
        host: String,
        port: Int,
        callbacks: HttpCaptureCallbacks,
        ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
        onClientEof: (() -> Unit)? = null,
        onServerEof: (() -> Unit)? = null
    ) {
        val respJob = scope.launch(ioDispatcher) {
            val buf = ByteArray(8192)
            try {
                while (isActive) {
                    val n = serverIn.read(buf)
                    if (n <= 0) break
                    val slice = buf.copyOfRange(0, n)
                    clientOut.write(slice)
                    clientOut.flush()
                    callbacks.onBytesTransferred(n)
                    callbacks.onRawTunnelBytes(isHttps, host, port, reqBytes = null, respBytes = slice)
                }
            } catch (_: Exception) {
            } finally {
                runCatching { clientOut.flush() }
                runCatching { onServerEof?.invoke() }
            }
        }
        val buf = ByteArray(8192)
        try {
            while (scope.isActive) {
                val n = clientIn.read(buf)
                if (n <= 0) break
                val slice = buf.copyOfRange(0, n)
                serverOut.write(slice)
                serverOut.flush()
                callbacks.onBytesTransferred(n)
                callbacks.onRawTunnelBytes(isHttps, host, port, reqBytes = slice, respBytes = null)
            }
        } catch (_: Exception) {
        } finally {
            runCatching { serverOut.flush() }
            runCatching { onClientEof?.invoke() }
            respJob.join()
        }
    }

    private fun drainRaw(input: InputStream, output: OutputStream, callbacks: HttpCaptureCallbacks) {
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n <= 0) break
            output.write(buf, 0, n)
            output.flush()
            callbacks.onBytesTransferred(n)
        }
    }

    private fun readUpTo(input: InputStream, buf: ByteArray): Int {
        var total = 0
        while (total < buf.size) {
            val n = input.read(buf, total, buf.size - total)
            if (n <= 0) break
            total += n
            // Wait until we have at least 8 bytes (covers "OPTIONS ") if client hasn't paused
            if (total >= 8 && input.available() == 0) break
            val hasSpace = (0 until total).any { buf[it] == ' '.code.toByte() }
            if (hasSpace && input.available() == 0) break
        }
        return total
    }

    private fun readHeaderBlock(input: InputStream): ByteArray? {
        val out = ByteArrayOutputStream(1024)
        var state = 0 // 0->none, 1->\r, 2->\r\n, 3->\r\n\r
        while (out.size() < 65536) {
            val b = input.read()
            if (b == -1) {
                return if (out.size() > 0) out.toByteArray() else null
            }
            out.write(b)
            when (state) {
                0 -> if (b == 13) state = 1 else if (b == 10 && endsWithDoubleLf(out)) return out.toByteArray()
                1 -> state = if (b == 10) 2 else if (b == 13) 1 else 0
                2 -> state = if (b == 13) 3 else if (b == 10) return out.toByteArray() else 0
                3 -> if (b == 10) return out.toByteArray() else state = if (b == 13) 1 else 0
            }
        }
        return out.toByteArray()
    }

    private fun endsWithDoubleLf(out: ByteArrayOutputStream): Boolean {
        val arr = out.toByteArray()
        return arr.size >= 2 && arr[arr.size - 1] == 10.toByte() && arr[arr.size - 2] == 10.toByte()
    }

    private data class ParsedReqHeader(
        val method: String,
        val rawTarget: String,
        val host: String,
        val headersJson: String,
        val contentLength: Long,
        val isChunked: Boolean,
        val contentEncoding: String?
    )

    private data class ParsedRespHeader(
        val statusCode: Int,
        val headersJson: String,
        val contentLength: Long,
        val isChunked: Boolean,
        val contentEncoding: String?
    )

    private fun parseRequestHeader(headerBytes: ByteArray, defaultHost: String): ParsedReqHeader? {
        val text = String(headerBytes, Charsets.ISO_8859_1)
        val lines = text.split(Regex("\r?\n"))
        val firstParts = lines.firstOrNull()?.trim()?.split(Regex("\\s+")) ?: return null
        if (firstParts.size < 3 || !firstParts[2].startsWith("HTTP/")) return null
        val method = firstParts[0].uppercase(Locale.US)
        if (method !in HTTP_METHODS) return null

        val headersObj = JSONObject()
        var host = defaultHost
        var contentLength = -1L
        var isChunked = false
        var contentEncoding: String? = null

        for (i in 1 until lines.size) {
            val line = lines[i]
            if (line.isBlank()) continue
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val k = line.substring(0, colon).trim()
            val v = line.substring(colon + 1).trim()
            headersObj.put(k, v)
            when {
                k.equals("Host", true) -> host = v.substringBefore(':')
                k.equals("Content-Length", true) -> contentLength = v.toLongOrNull() ?: contentLength
                k.equals("Transfer-Encoding", true) -> if (v.contains("chunked", true)) isChunked = true
                k.equals("Content-Encoding", true) -> contentEncoding = v
            }
        }

        return ParsedReqHeader(
            method = method,
            rawTarget = firstParts[1],
            host = host.ifBlank { defaultHost },
            headersJson = headersObj.toString(),
            contentLength = contentLength,
            isChunked = isChunked,
            contentEncoding = contentEncoding
        )
    }

    private fun parseResponseHeader(headerBytes: ByteArray): ParsedRespHeader? {
        val text = String(headerBytes, Charsets.ISO_8859_1)
        val lines = text.split(Regex("\r?\n"))
        val firstLine = lines.firstOrNull()?.trim() ?: return null
        if (!firstLine.startsWith("HTTP/")) return null
        val statusCode = firstLine.split(Regex("\\s+")).getOrNull(1)?.toIntOrNull() ?: return null

        val headersObj = JSONObject()
        var contentLength = -1L
        var isChunked = false
        var contentEncoding: String? = null

        for (i in 1 until lines.size) {
            val line = lines[i]
            if (line.isBlank()) continue
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val k = line.substring(0, colon).trim()
            val v = line.substring(colon + 1).trim()
            headersObj.put(k, v)
            when {
                k.equals("Content-Length", true) -> contentLength = v.toLongOrNull() ?: contentLength
                k.equals("Transfer-Encoding", true) -> if (v.contains("chunked", true)) isChunked = true
                k.equals("Content-Encoding", true) -> contentEncoding = v
            }
        }

        return ParsedRespHeader(
            statusCode = statusCode,
            headersJson = headersObj.toString(),
            contentLength = contentLength,
            isChunked = isChunked,
            contentEncoding = contentEncoding
        )
    }

    private fun normalizePath(rawTarget: String): String {
        if (rawTarget.startsWith("http://", true) || rawTarget.startsWith("https://", true)) {
            val afterScheme = rawTarget.substringAfter("://")
            val slashIdx = afterScheme.indexOf('/')
            return if (slashIdx >= 0) afterScheme.substring(slashIdx) else "/"
        }
        return if (rawTarget.startsWith("/")) rawTarget else "/$rawTarget"
    }

    private fun forwardFixedBody(
        input: InputStream,
        output: OutputStream,
        length: Long,
        collector: BoundedByteCollector,
        callbacks: HttpCaptureCallbacks
    ): Int {
        var remaining = length
        var total = 0
        val buf = ByteArray(8192)
        while (remaining > 0) {
            val toRead = minOf(buf.size.toLong(), remaining).toInt()
            val n = input.read(buf, 0, toRead)
            if (n <= 0) break
            output.write(buf, 0, n)
            output.flush()
            collector.append(buf, 0, n)
            callbacks.onBytesTransferred(n)
            remaining -= n
            total += n
        }
        return total
    }

    private fun forwardUntilEof(
        input: InputStream,
        output: OutputStream,
        collector: BoundedByteCollector,
        callbacks: HttpCaptureCallbacks
    ): Int {
        var total = 0
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n <= 0) break
            output.write(buf, 0, n)
            output.flush()
            collector.append(buf, 0, n)
            callbacks.onBytesTransferred(n)
            total += n
        }
        return total
    }

    private fun forwardChunkedBody(
        input: InputStream,
        output: OutputStream,
        collector: BoundedByteCollector,
        callbacks: HttpCaptureCallbacks
    ): Int {
        var totalWireBytes = 0
        val buf = ByteArray(8192)
        while (true) {
            val sizeLineBytes = readLineWithCrlf(input) ?: break
            output.write(sizeLineBytes)
            totalWireBytes += sizeLineBytes.size
            callbacks.onBytesTransferred(sizeLineBytes.size)

            val sizeText = String(sizeLineBytes, Charsets.ISO_8859_1).trim().substringBefore(';').trim()
            val chunkSize = sizeText.toIntOrNull(16) ?: break
            if (chunkSize == 0) {
                // Forward trailing headers until blank CRLF line
                while (true) {
                    val trailer = readLineWithCrlf(input) ?: break
                    output.write(trailer)
                    totalWireBytes += trailer.size
                    callbacks.onBytesTransferred(trailer.size)
                    val s = String(trailer, Charsets.ISO_8859_1)
                    if (s == "\r\n" || s == "\n") break
                }
                output.flush()
                break
            }

            var remaining = chunkSize
            while (remaining > 0) {
                val n = input.read(buf, 0, minOf(buf.size, remaining))
                if (n <= 0) break
                output.write(buf, 0, n)
                collector.append(buf, 0, n)
                callbacks.onBytesTransferred(n)
                remaining -= n
                totalWireBytes += n
            }

            // Forward chunk-terminating CRLF
            val crlf = readLineWithCrlf(input)
            if (crlf != null) {
                output.write(crlf)
                totalWireBytes += crlf.size
                callbacks.onBytesTransferred(crlf.size)
            }
            output.flush()
        }
        return totalWireBytes
    }

    private fun readLineWithCrlf(input: InputStream): ByteArray? {
        val out = ByteArrayOutputStream(64)
        while (out.size() < 4096) {
            val b = input.read()
            if (b == -1) return if (out.size() > 0) out.toByteArray() else null
            out.write(b)
            if (b == 10) break
        }
        return out.toByteArray()
    }

    private fun decompressIfNeeded(bytes: ByteArray, encoding: String?): ByteArray {
        if (bytes.isEmpty() || encoding.isNullOrBlank()) return bytes
        val enc = encoding.lowercase(Locale.US)
        return when {
            enc.contains("gzip") -> runCatching {
                GZIPInputStream(ByteArrayInputStream(bytes)).use { readBounded(it, MAX_CAPTURE_BYTES) }
            }.getOrDefault(bytes)
            enc.contains("deflate") -> runCatching {
                InflaterInputStream(ByteArrayInputStream(bytes)).use { readBounded(it, MAX_CAPTURE_BYTES) }
            }.recoverCatching {
                InflaterInputStream(ByteArrayInputStream(bytes), Inflater(true)).use { readBounded(it, MAX_CAPTURE_BYTES) }
            }.getOrDefault(bytes)
            else -> bytes
        }
    }

    private fun readBounded(input: InputStream, maxBytes: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (out.size() < maxBytes) {
            val toRead = minOf(buf.size, maxBytes - out.size())
            val n = runCatching { input.read(buf, 0, toRead) }.getOrDefault(-1)
            if (n <= 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private class BoundedByteCollector(private val maxBytes: Int) {
        private val out = ByteArrayOutputStream()
        fun append(src: ByteArray, offset: Int, len: Int) {
            val room = maxBytes - out.size()
            if (room > 0) {
                out.write(src, offset, minOf(len, room))
            }
        }
        fun toByteArray(): ByteArray = out.toByteArray()
    }
}
