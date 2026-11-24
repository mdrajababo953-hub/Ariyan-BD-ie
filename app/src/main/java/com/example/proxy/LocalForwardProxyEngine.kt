package com.example.proxy

import com.example.decoder.HexUtils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExecutorCoroutineDispatcher
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.Headers
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

data class CapturedProxyTransaction(
    val timestamp: Long,
    val method: String,
    val url: String,
    val host: String,
    val path: String,
    val port: Int,
    val protocol: String,
    val statusCode: Int,
    val requestHeadersJson: String,
    val requestBodyHex: String,
    val responseHeadersJson: String,
    val responseBodyHex: String,
    val bytesTx: Int,
    val bytesRx: Int,
    val durationMs: Long
)

class LocalForwardProxyEngine(
    private val port: Int,
    private val forwardBaseUrl: String,
    private val bindAddress: String = "0.0.0.0",
    private val client: OkHttpClient = defaultClient(),
    private val onTransaction: (CapturedProxyTransaction) -> Unit
) {
    companion object {
        const val MAX_CAPTURE_BYTES = 131_072
        private const val MAX_COMPRESSED_CAPTURE_BYTES = 524_288
        private val HOP_BY_HOP_REQUEST_HEADERS = setOf(
            "host",
            "connection",
            "proxy-connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "content-length",
            "expect"
        )
        private val HOP_BY_HOP_RESPONSE_HEADERS = setOf(
            "connection",
            "proxy-connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "content-length"
        )
        private val METHODS_WITH_BODY = setOf("POST", "PUT", "PATCH", "DELETE")

        fun defaultClient(): OkHttpClient {
            return OkHttpClient.Builder()
                .followRedirects(false)
                .followSslRedirects(false)
                .retryOnConnectionFailure(true)
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build()
        }

        fun sanitizeBaseUrl(rawUrl: String): String {
            val trimmed = rawUrl.trim().trimEnd('/')
            if (trimmed.isEmpty()) return "https://client.ind.freefiremobile.com"
            return if (trimmed.startsWith("http://", true) || trimmed.startsWith("https://", true)) {
                trimmed
            } else {
                "https://$trimmed"
            }
        }
    }

    private val normalizedBaseUrl = sanitizeBaseUrl(forwardBaseUrl)
    private val baseUri = URI.create(normalizedBaseUrl)
    private val targetHost = baseUri.host ?: "client.ind.freefiremobile.com"
    private val targetScheme = (baseUri.scheme ?: "https").lowercase(Locale.US)
    private val targetPort = when {
        baseUri.port > 0 -> baseUri.port
        targetScheme == "https" -> 443
        else -> 80
    }
    private val hostHeaderValue = if (baseUri.port > 0) "$targetHost:${baseUri.port}" else targetHost
    private val basePathPrefix = baseUri.rawPath.orEmpty().trimEnd('/')

    @Volatile
    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null
    private val workerCounter = AtomicInteger(0)

    @Volatile
    private var workerExecutor: ExecutorService? = null

    @Volatile
    private var workerDispatcher: ExecutorCoroutineDispatcher? = null

    val boundPort: Int
        get() = serverSocket?.localPort ?: port

    fun start(scope: CoroutineScope): Int {
        val exec = Executors.newCachedThreadPool { r ->
            Thread(r, "nettrace-proxy-io-${workerCounter.incrementAndGet()}").apply {
                isDaemon = true
            }
        }
        val disp = exec.asCoroutineDispatcher()
        workerExecutor = exec
        workerDispatcher = disp

        val sock = ServerSocket().apply {
            reuseAddress = true
            bind(InetSocketAddress(InetAddress.getByName(bindAddress), port), 64)
        }
        serverSocket = sock
        acceptJob = scope.launch(disp) {
            while (isActive && !sock.isClosed) {
                val clientSock = try {
                    sock.accept()
                } catch (_: Exception) {
                    break
                }
                launch(disp) {
                    handleClientConnection(clientSock, scope)
                }
            }
        }
        return sock.localPort
    }

    fun stop() {
        acceptJob?.cancel()
        acceptJob = null
        runCatching { serverSocket?.close() }
        serverSocket = null
        runCatching { workerDispatcher?.close() }
        workerDispatcher = null
        runCatching { workerExecutor?.shutdownNow() }
        workerExecutor = null
    }

    private fun handleClientConnection(socket: Socket, scope: CoroutineScope) {
        socket.use { sock ->
            runCatching {
                sock.tcpNoDelay = true
                sock.soTimeout = 30_000
                val input = BufferedInputStream(sock.getInputStream(), 16384)
                val output = BufferedOutputStream(sock.getOutputStream(), 16384)

                while (scope.isActive && !sock.isClosed) {
                    val headerBytes = readHeaderBlock(input) ?: break
                    val parsedReq = parseRequestHeader(headerBytes) ?: break

                    if (parsedReq.expectContinue) {
                        output.write("HTTP/1.1 100 Continue\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
                        output.flush()
                    }

                    val reqBodyBytes = when {
                        parsedReq.isChunked -> readChunkedBody(input)
                        parsedReq.contentLength > 0L -> readFixedBody(input, parsedReq.contentLength)
                        else -> ByteArray(0)
                    }

                    val normalizedPath = normalizeTargetPath(parsedReq.rawTarget)
                    val combinedPath = if (basePathPrefix.isNotEmpty() && !normalizedPath.startsWith(basePathPrefix)) {
                        "$basePathPrefix$normalizedPath"
                    } else {
                        normalizedPath
                    }
                    val fullTargetUrl = "$targetScheme://$hostHeaderValue$combinedPath"

                    val reqHeadersBuilder = Headers.Builder()
                    val reqHeadersJson = JSONObject()
                    var contentTypeHeader: String? = null
                    var reqEncoding: String? = null

                    parsedReq.headers.forEach { (k, v) ->
                        reqHeadersJson.put(k, v)
                        val lower = k.lowercase(Locale.US)
                        if (lower == "content-type") contentTypeHeader = v
                        if (lower == "content-encoding") reqEncoding = v
                        if (lower !in HOP_BY_HOP_REQUEST_HEADERS) {
                            reqHeadersBuilder.add(k, v)
                        }
                    }
                    reqHeadersJson.put("Host", hostHeaderValue)
                    reqHeadersBuilder.set("Host", hostHeaderValue)

                    val okBody = when {
                        parsedReq.method in METHODS_WITH_BODY -> {
                            val mediaType = contentTypeHeader?.toMediaTypeOrNull()
                            reqBodyBytes.toRequestBody(mediaType)
                        }
                        reqBodyBytes.isNotEmpty() -> {
                            val mediaType = contentTypeHeader?.toMediaTypeOrNull()
                            reqBodyBytes.toRequestBody(mediaType)
                        }
                        else -> null
                    }

                    val okRequest = Request.Builder()
                        .url(fullTargetUrl)
                        .headers(reqHeadersBuilder.build())
                        .method(parsedReq.method, okBody)
                        .build()

                    val startMs = System.currentTimeMillis()
                    try {
                        client.newCall(okRequest).execute().use { resp ->
                            val respBody = resp.body
                            val upstreamContentLength = respBody?.contentLength() ?: -1L

                            val respHeadersJson = JSONObject()
                            var respEncoding: String? = null
                            val respHeaderLines = StringBuilder()
                            val statusMsg = resp.message.ifBlank { defaultReasonPhrase(resp.code) }
                            respHeaderLines.append("HTTP/1.1 ${resp.code} $statusMsg\r\n")

                            for (i in 0 until resp.headers.size) {
                                val k = resp.headers.name(i)
                                val v = resp.headers.value(i)
                                respHeadersJson.put(k, v)
                                if (k.equals("Content-Encoding", ignoreCase = true)) {
                                    respEncoding = v
                                }
                                if (k.lowercase(Locale.US) !in HOP_BY_HOP_RESPONSE_HEADERS) {
                                    respHeaderLines.append("$k: $v\r\n")
                                }
                            }

                            val hasBodyStream = respBody != null
                            val useChunkedEncoding = hasBodyStream && upstreamContentLength < 0L
                            if (!hasBodyStream) {
                                respHeaderLines.append("Content-Length: 0\r\n")
                            } else if (upstreamContentLength >= 0L) {
                                respHeaderLines.append("Content-Length: $upstreamContentLength\r\n")
                            } else {
                                respHeaderLines.append("Transfer-Encoding: chunked\r\n")
                            }

                            val shouldClose = parsedReq.connectionClose
                            respHeaderLines.append(
                                if (shouldClose) "Connection: close\r\n\r\n" else "Connection: keep-alive\r\n\r\n"
                            )

                            val respHeaderBytes = respHeaderLines.toString().toByteArray(Charsets.ISO_8859_1)
                            output.write(respHeaderBytes)
                            output.flush()

                            val isCompressed = !respEncoding.isNullOrBlank() &&
                                (respEncoding.contains("gzip", true) || respEncoding.contains("deflate", true))
                            val captureCap = if (isCompressed) MAX_COMPRESSED_CAPTURE_BYTES else MAX_CAPTURE_BYTES
                            val capturedRespBuf = ByteArrayOutputStream(minOf(4096, captureCap))
                            var totalBodyBytesRx = 0L

                            if (respBody != null) {
                                val streamBuf = ByteArray(16384)
                                respBody.byteStream().use { bodyIn ->
                                    while (true) {
                                        val n = bodyIn.read(streamBuf)
                                        if (n <= 0) break
                                        totalBodyBytesRx += n
                                        if (useChunkedEncoding) {
                                            output.write(
                                                "${n.toString(16)}\r\n".toByteArray(Charsets.ISO_8859_1)
                                            )
                                            output.write(streamBuf, 0, n)
                                            output.write("\r\n".toByteArray(Charsets.ISO_8859_1))
                                        } else {
                                            output.write(streamBuf, 0, n)
                                        }
                                        val room = captureCap - capturedRespBuf.size()
                                        if (room > 0) {
                                            capturedRespBuf.write(streamBuf, 0, minOf(n, room))
                                        }
                                    }
                                }
                                if (useChunkedEncoding) {
                                    output.write("0\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
                                }
                                output.flush()
                            }

                            val durationMs = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)
                            val rawRespSample = capturedRespBuf.toByteArray()
                            val decodedReq = decompressIfNeeded(reqBodyBytes, reqEncoding)
                            val decodedResp = decompressIfNeeded(rawRespSample, respEncoding)

                            onTransaction(
                                CapturedProxyTransaction(
                                    timestamp = startMs,
                                    method = parsedReq.method,
                                    url = fullTargetUrl,
                                    host = targetHost,
                                    path = combinedPath,
                                    port = targetPort,
                                    protocol = if (targetScheme == "https") "HTTPS" else "HTTP",
                                    statusCode = resp.code,
                                    requestHeadersJson = reqHeadersJson.toString(),
                                    requestBodyHex = cappedHex(decodedReq),
                                    responseHeadersJson = respHeadersJson.toString(),
                                    responseBodyHex = cappedHex(decodedResp),
                                    bytesTx = headerBytes.size + reqBodyBytes.size,
                                    bytesRx = (respHeaderBytes.size + totalBodyBytesRx)
                                        .coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
                                    durationMs = durationMs
                                )
                            )

                            if (shouldClose) break
                        }
                    } catch (e: Exception) {
                        val errBytes = "Proxy upstream error: ${e.message ?: "connection failed"}"
                            .toByteArray(Charsets.UTF_8)
                        val errHeader = (
                            "HTTP/1.1 502 Bad Gateway\r\n" +
                                "Content-Type: text/plain; charset=utf-8\r\n" +
                                "Content-Length: ${errBytes.size}\r\n" +
                                "Connection: close\r\n\r\n"
                            ).toByteArray(Charsets.ISO_8859_1)
                        output.write(errHeader)
                        output.write(errBytes)
                        output.flush()
                        break
                    }
                }
            }
        }
    }

    private data class ParsedHttpRequest(
        val method: String,
        val rawTarget: String,
        val headers: List<Pair<String, String>>,
        val contentLength: Long,
        val isChunked: Boolean,
        val expectContinue: Boolean,
        val connectionClose: Boolean
    )

    private fun parseRequestHeader(headerBytes: ByteArray): ParsedHttpRequest? {
        val text = String(headerBytes, Charsets.ISO_8859_1)
        val lines = text.split(Regex("\r?\n"))
        val requestLine = lines.firstOrNull()?.trim() ?: return null
        val parts = requestLine.split(Regex("\\s+"))
        if (parts.size < 2) return null
        val method = parts[0].uppercase(Locale.US)
        val rawTarget = parts[1]

        val headers = mutableListOf<Pair<String, String>>()
        var contentLength = -1L
        var isChunked = false
        var expectContinue = false
        var connectionClose = false

        for (i in 1 until lines.size) {
            val line = lines[i]
            if (line.isBlank()) continue
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val k = line.substring(0, colon).trim()
            val v = line.substring(colon + 1).trim()
            headers.add(k to v)
            when {
                k.equals("Content-Length", true) -> contentLength = v.toLongOrNull() ?: contentLength
                k.equals("Transfer-Encoding", true) && v.contains("chunked", true) -> isChunked = true
                k.equals("Expect", true) && v.contains("100-continue", true) -> expectContinue = true
                k.equals("Connection", true) && v.contains("close", true) -> connectionClose = true
            }
        }
        return ParsedHttpRequest(
            method = method,
            rawTarget = rawTarget,
            headers = headers,
            contentLength = contentLength,
            isChunked = isChunked,
            expectContinue = expectContinue,
            connectionClose = connectionClose
        )
    }

    private fun normalizeTargetPath(rawTarget: String): String {
        if (rawTarget.startsWith("http://", true) || rawTarget.startsWith("https://", true)) {
            val afterScheme = rawTarget.substringAfter("://")
            val slashIdx = afterScheme.indexOf('/')
            return if (slashIdx >= 0) afterScheme.substring(slashIdx) else "/"
        }
        return if (rawTarget.startsWith("/")) rawTarget else "/$rawTarget"
    }

    private fun readHeaderBlock(input: InputStream): ByteArray? {
        val out = ByteArrayOutputStream(1024)
        var state = 0
        while (out.size() < 65536) {
            val b = input.read()
            if (b == -1) return if (out.size() > 0) out.toByteArray() else null
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

    private fun readFixedBody(input: InputStream, length: Long): ByteArray {
        val target = length.coerceAtMost(8L * 1024L * 1024L).toInt()
        val buf = ByteArray(target)
        var readTotal = 0
        while (readTotal < target) {
            val n = input.read(buf, readTotal, target - readTotal)
            if (n <= 0) break
            readTotal += n
        }
        return if (readTotal == target) buf else buf.copyOf(readTotal)
    }

    private fun readChunkedBody(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (true) {
            val sizeLine = readLine(input) ?: break
            val sizeHex = String(sizeLine, Charsets.ISO_8859_1).trim().substringBefore(';').trim()
            val chunkSize = sizeHex.toIntOrNull(16) ?: break
            if (chunkSize == 0) {
                while (true) {
                    val trailer = readLine(input) ?: break
                    val str = String(trailer, Charsets.ISO_8859_1)
                    if (str == "\r\n" || str == "\n") break
                }
                break
            }
            var remaining = chunkSize
            while (remaining > 0) {
                val n = input.read(buf, 0, minOf(buf.size, remaining))
                if (n <= 0) break
                out.write(buf, 0, n)
                remaining -= n
            }
            readLine(input)
        }
        return out.toByteArray()
    }

    private fun readLine(input: InputStream): ByteArray? {
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

    private fun cappedHex(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val sliced = if (bytes.size > MAX_CAPTURE_BYTES) bytes.copyOf(MAX_CAPTURE_BYTES) else bytes
        return HexUtils.bytesToHex(sliced)
    }

    private fun defaultReasonPhrase(code: Int): String = when (code) {
        200 -> "OK"
        201 -> "Created"
        204 -> "No Content"
        301 -> "Moved Permanently"
        302 -> "Found"
        304 -> "Not Modified"
        400 -> "Bad Request"
        401 -> "Unauthorized"
        403 -> "Forbidden"
        404 -> "Not Found"
        500 -> "Internal Server Error"
        502 -> "Bad Gateway"
        else -> "OK"
    }
}
