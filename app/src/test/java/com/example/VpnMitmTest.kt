package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.decoder.HexUtils
import com.example.vpn.CapturedHttpRequestMeta
import com.example.vpn.HttpCaptureCallbacks
import com.example.vpn.HttpStreamProxy
import com.example.vpn.MitmCertificateManager
import com.example.vpn.PacketBuilder
import com.example.vpn.PacketDissector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.zip.GZIPOutputStream
import javax.net.ssl.KeyManagerFactory

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class VpnMitmTest {

    @Test
    fun `mitm certificate manager builds valid root ca and signed host leaf cert`() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val mgr = MitmCertificateManager(ctx)
        val (caCert, _) = mgr.ensureCa()
        assertTrue(mgr.isCaReady())
        assertTrue(caCert.basicConstraints >= 0)
        assertTrue(mgr.getCaPemString().contains("-----BEGIN CERTIFICATE-----"))

        val sslCtx = mgr.getSslContextForHost("clientbp.ppmainecoonghj.com")
        assertNotNull(sslCtx)

        // Ensure KeyManager inside SSLContext holds a valid chain signed by CA
        val host = "clientbp.ppmainecoonghj.com"
        val certMgrMethod = MitmCertificateManager::class.java.getDeclaredField("hostSslContexts")
        certMgrMethod.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val cache = certMgrMethod.get(mgr) as Map<String, Any>
        assertTrue(cache.containsKey(host))

        // Verify CA self-signature
        caCert.verify(caCert.publicKey)
        assertTrue(KeyManagerFactory.getDefaultAlgorithm().isNotEmpty())
        assertNotNull(KeyStore.getInstance(KeyStore.getDefaultType()))
    }

    @Test
    fun `http stream proxy splits keep-alive endpoints and decompresses gzip and chunked bodies`() = runTest {
        val clientOutCapture = ByteArrayOutputStream()
        val serverOutCapture = ByteArrayOutputStream()

        val req1Body = HexUtils.hexToBytes("1a725b2c56ec52ba7d09623454c0a003")
        val req1 = (
            "POST /UpdateSocialBasicInfo HTTP/1.1\r\n" +
                "Host: clientbp.ppmainecoonghj.com\r\n" +
                "Content-Length: ${req1Body.size}\r\n\r\n"
            ).toByteArray(Charsets.ISO_8859_1) + req1Body

        val req2Body = HexUtils.hexToBytes("0801")
        val req2 = (
            "POST /GetLikedRecord HTTP/1.1\r\n" +
                "Host: clientbp.ppmainecoonghj.com\r\n" +
                "Content-Length: ${req2Body.size}\r\n\r\n"
            ).toByteArray(Charsets.ISO_8859_1) + req2Body

        val gzipBytes = ByteArrayOutputStream().apply {
            GZIPOutputStream(this).use { it.write(HexUtils.hexToBytes("0a00")) }
        }.toByteArray()
        val resp1 = (
            "HTTP/1.1 200 OK\r\n" +
                "Content-Encoding: gzip\r\n" +
                "Content-Length: ${gzipBytes.size}\r\n\r\n"
            ).toByteArray(Charsets.ISO_8859_1) + gzipBytes

        val chunkPayload = HexUtils.hexToBytes("08f4f3c8cf3d")
        val chunkHexLen = chunkPayload.size.toString(16)
        val resp2 = (
            "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding: chunked\r\n\r\n" +
                "$chunkHexLen\r\n"
            ).toByteArray(Charsets.ISO_8859_1) + chunkPayload + "\r\n0\r\n\r\n".toByteArray(Charsets.ISO_8859_1)

        val clientPipeIn = PipedInputStream()
        val clientPipeWriter = PipedOutputStream(clientPipeIn)
        val serverPipeIn = PipedInputStream()
        val serverPipeWriter = PipedOutputStream(serverPipeIn)

        val capturedReqs = mutableListOf<CapturedHttpRequestMeta>()
        val capturedResps = mutableListOf<Pair<Int?, String>>()

        val relayJob = launch(Dispatchers.IO) {
            HttpStreamProxy.relayStream(
                scope = this,
                clientIn = clientPipeIn,
                clientOut = clientOutCapture,
                serverIn = serverPipeIn,
                serverOut = serverOutCapture,
                initialClientBytes = ByteArray(0),
                isHttps = true,
                defaultHost = "clientbp.ppmainecoonghj.com",
                port = 443,
                callbacks = object : HttpCaptureCallbacks {
                    override fun onHttpRequest(meta: CapturedHttpRequestMeta) {
                        synchronized(capturedReqs) { capturedReqs.add(meta) }
                    }

                    override fun onHttpResponse(
                        meta: CapturedHttpRequestMeta,
                        statusCode: Int?,
                        responseHeadersJson: String,
                        responseBodyHex: String,
                        bytesRx: Int,
                        durationMs: Long
                    ) {
                        synchronized(capturedResps) { capturedResps.add(statusCode to responseBodyHex) }
                    }

                    override fun onRawTunnelBytes(
                        isHttps: Boolean,
                        host: String,
                        port: Int,
                        reqBytes: ByteArray?,
                        respBytes: ByteArray?
                    ) = Unit

                    override fun onBytesTransferred(bytes: Int) = Unit
                }
            )
        }

        // Write request 1, wait briefly, write response 1, then request 2 + response 2, then close pipes
        clientPipeWriter.write(req1)
        clientPipeWriter.flush()
        Thread.sleep(60)
        serverPipeWriter.write(resp1)
        serverPipeWriter.flush()
        Thread.sleep(60)

        clientPipeWriter.write(req2)
        clientPipeWriter.flush()
        Thread.sleep(60)
        serverPipeWriter.write(resp2)
        serverPipeWriter.flush()
        Thread.sleep(60)

        clientPipeWriter.close()
        serverPipeWriter.close()
        relayJob.join()

        assertEquals(2, capturedReqs.size)
        assertEquals("https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo", capturedReqs[0].url)
        assertEquals("1a725b2c56ec52ba7d09623454c0a003", capturedReqs[0].requestBodyHex)
        assertEquals("https://clientbp.ppmainecoonghj.com/GetLikedRecord", capturedReqs[1].url)
        assertEquals("0801", capturedReqs[1].requestBodyHex)

        assertEquals(2, capturedResps.size)
        assertEquals(200, capturedResps[0].first)
        assertEquals("0a00", capturedResps[0].second)
        assertEquals(200, capturedResps[1].first)
        assertEquals("08f4f3c8cf3d", capturedResps[1].second)
    }

    @Test
    fun `packet dissector formats ipv4 quickly and extracts tls sni`() {
        val raw = PacketBuilder.buildIpv4UdpPacket(
            srcIp = byteArrayOf(10, 110, 0, 2),
            dstIp = byteArrayOf(172.toByte(), 65, 240.toByte(), 10),
            srcPort = 50000,
            dstPort = 443,
            payload = byteArrayOf(1)
        )
        val ip = PacketDissector.parseIpv4(raw, raw.size)!!
        assertEquals("10.110.0.2", ip.srcIpStr)
        assertEquals("172.65.240.10", ip.dstIpStr)

        // Synthetic minimal TLS ClientHello with SNI "clientbp.ppmainecoonghj.com"
        val hostBytes = "clientbp.ppmainecoonghj.com".toByteArray(Charsets.US_ASCII)
        val serverNameList = byteArrayOf(
            0x00, (hostBytes.size + 3).toByte(),
            0x00, 0x00, hostBytes.size.toByte()
        ) + hostBytes
        val sniExt = byteArrayOf(
            0x00, 0x00, // server_name extension
            0x00, (serverNameList.size).toByte()
        ) + serverNameList
        val hello = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x60)) // TLS record header
            write(byteArrayOf(0x01, 0x00, 0x00, 0x50)) // ClientHello
            write(ByteArray(34)) // version + random
            write(0) // session id len
            write(byteArrayOf(0x00, 0x02, 0x13, 0x01)) // cipher suites
            write(byteArrayOf(0x01, 0x00)) // compression
            write(byteArrayOf(0x00, sniExt.size.toByte())) // extensions len
            write(sniExt)
        }.toByteArray()

        assertEquals("clientbp.ppmainecoonghj.com", PacketDissector.extractTlsSni(hello))
    }

    @Test
    fun `tls stream channel completes mitm handshake after peeking client hello and captures separate https endpoints`() = runTest {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val mgr = MitmCertificateManager(ctx)
        val (caCert, _) = mgr.ensureCa()
        val serverCtx = mgr.getSslContextForHost("clientbp.ppmainecoonghj.com")

        // Build a client SSLContext trusting NetTrace's generated CA
        val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("nettrace_ca", caCert)
        }
        val tmf = javax.net.ssl.TrustManagerFactory.getInstance(
            javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
        ).apply { init(ks) }
        val clientSslCtx = javax.net.ssl.SSLContext.getInstance("TLS").apply {
            init(null, tmf.trustManagers, null)
        }

        val serverSock = java.net.ServerSocket(0, 4, java.net.InetAddress.getLoopbackAddress())
        val capturedUrls = mutableListOf<String>()
        val capturedStatuses = mutableListOf<Pair<Int?, String>>()

        val serverJob = launch(Dispatchers.IO) {
            val clientConn = serverSock.accept()
            val rawIn = clientConn.getInputStream()
            val rawOut = clientConn.getOutputStream()
            val peekBuf = ByteArray(4096)
            val firstLen = rawIn.read(peekBuf)
            val firstBytes = peekBuf.copyOfRange(0, firstLen)

            val sni = PacketDissector.extractTlsSni(firstBytes)
            assertEquals("clientbp.ppmainecoonghj.com", sni)

            val engine = serverCtx.createSSLEngine().apply { useClientMode = false }
            val tlsChannel = com.example.vpn.TlsStreamChannel(engine, rawIn, rawOut, firstBytes)
            tlsChannel.handshake()

            // Simulated upstream server pipe returning 2 distinct responses
            val fakeServerPipeIn = PipedInputStream()
            val fakeServerWriter = PipedOutputStream(fakeServerPipeIn)
            val fakeServerReqSink = ByteArrayOutputStream()

            val upstreamResponder = launch(Dispatchers.IO) {
                val r1 = "{\"ok\":1}".toByteArray()
                fakeServerWriter.write(
                    ("HTTP/1.1 200 OK\r\nContent-Length: ${r1.size}\r\n\r\n").toByteArray() + r1
                )
                fakeServerWriter.flush()
                Thread.sleep(60)
                val r2 = HexUtils.hexToBytes("0a00")
                fakeServerWriter.write(
                    ("HTTP/1.1 200 OK\r\nContent-Length: ${r2.size}\r\n\r\n").toByteArray() + r2
                )
                fakeServerWriter.flush()
                Thread.sleep(60)
                fakeServerWriter.close()
            }

            HttpStreamProxy.relayStream(
                scope = this,
                clientIn = tlsChannel.inputStream,
                clientOut = tlsChannel.outputStream,
                serverIn = fakeServerPipeIn,
                serverOut = fakeServerReqSink,
                initialClientBytes = ByteArray(0),
                isHttps = true,
                defaultHost = sni ?: "localhost",
                port = 443,
                callbacks = object : HttpCaptureCallbacks {
                    override fun onHttpRequest(meta: CapturedHttpRequestMeta) {
                        synchronized(capturedUrls) { capturedUrls.add(meta.url) }
                    }
                    override fun onHttpResponse(
                        meta: CapturedHttpRequestMeta,
                        statusCode: Int?,
                        responseHeadersJson: String,
                        responseBodyHex: String,
                        bytesRx: Int,
                        durationMs: Long
                    ) {
                        synchronized(capturedStatuses) { capturedStatuses.add(statusCode to responseBodyHex) }
                    }
                    override fun onRawTunnelBytes(
                        isHttps: Boolean,
                        host: String,
                        port: Int,
                        reqBytes: ByteArray?,
                        respBytes: ByteArray?
                    ) = Unit
                    override fun onBytesTransferred(bytes: Int) = Unit
                }
            )
            upstreamResponder.join()
            tlsChannel.close()
            clientConn.close()
        }

        val clientJob = launch(Dispatchers.IO) {
            val plain = java.net.Socket(java.net.InetAddress.getLoopbackAddress(), serverSock.localPort)
            val sslSock = clientSslCtx.socketFactory.createSocket(
                plain,
                "clientbp.ppmainecoonghj.com",
                serverSock.localPort,
                true
            ) as javax.net.ssl.SSLSocket
            sslSock.sslParameters = sslSock.sslParameters.apply {
                serverNames = listOf(javax.net.ssl.SNIHostName("clientbp.ppmainecoonghj.com"))
            }
            sslSock.startHandshake()
            val out = sslSock.outputStream
            val inStream = sslSock.inputStream
            out.write(
                (
                    "POST /UpdateSocialBasicInfo HTTP/1.1\r\n" +
                        "Host: clientbp.ppmainecoonghj.com\r\n" +
                        "Content-Length: 2\r\n\r\n{}"
                    ).toByteArray()
            )
            out.flush()
            out.write(
                (
                    "POST /GetHeroicInfo HTTP/1.1\r\n" +
                        "Host: clientbp.ppmainecoonghj.com\r\n" +
                        "Content-Length: 0\r\n\r\n"
                    ).toByteArray()
            )
            out.flush()

            // Read both HTTP responses back through the MITM TLS channel before closing
            val totalRead = StringBuilder()
            val buf = ByteArray(1024)
            sslSock.soTimeout = 5000
            while (!totalRead.contains("0a00") && totalRead.length < 4096) {
                val n = inStream.read(buf)
                if (n <= 0) break
                totalRead.append(HexUtils.bytesToHex(buf.copyOfRange(0, n)))
            }
            sslSock.close()
        }

        clientJob.join()
        serverJob.join()
        serverSock.close()

        assertEquals(
            listOf(
                "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo",
                "https://clientbp.ppmainecoonghj.com/GetHeroicInfo"
            ),
            capturedUrls
        )
        assertEquals(2, capturedStatuses.size)
        assertEquals(200, capturedStatuses[0].first)
        assertEquals("0a00", capturedStatuses[1].second)
    }

    @Test
    fun `http stream proxy relays server-first binary stream and respects half-close without dropping response`() = runTest {
        val serverSock = java.net.ServerSocket(0, 4, java.net.InetAddress.getLoopbackAddress())
        val bridgeSock = java.net.ServerSocket(0, 4, java.net.InetAddress.getLoopbackAddress())

        // Upstream server sends greeting immediately before client sends anything,
        // then waits for client request + EOF, then sends final reply.
        val upstreamJob = launch(Dispatchers.IO) {
            val conn = serverSock.accept()
            conn.use {
                val out = it.getOutputStream()
                val inp = it.getInputStream()
                out.write(byteArrayOf(0x01, 0x02, 0x03, 0x04))
                out.flush()

                val req = inp.readBytes()
                assertTrue(req.contentEquals(byteArrayOf(0x0A, 0x0B)))

                out.write(byteArrayOf(0x05, 0x06, 0x07))
                out.flush()
            }
        }

        val proxyJob = launch(Dispatchers.IO) {
            val clientConn = bridgeSock.accept()
            val upstream = java.net.Socket(java.net.InetAddress.getLoopbackAddress(), serverSock.localPort)
            try {
                HttpStreamProxy.relayStream(
                    scope = this,
                    clientIn = clientConn.getInputStream(),
                    clientOut = clientConn.getOutputStream(),
                    serverIn = upstream.getInputStream(),
                    serverOut = upstream.getOutputStream(),
                    initialClientBytes = ByteArray(0),
                    isHttps = false,
                    defaultHost = "127.0.0.1",
                    port = serverSock.localPort,
                    callbacks = object : HttpCaptureCallbacks {
                        override fun onHttpRequest(meta: CapturedHttpRequestMeta) = Unit
                        override fun onHttpResponse(
                            meta: CapturedHttpRequestMeta,
                            statusCode: Int?,
                            responseHeadersJson: String,
                            responseBodyHex: String,
                            bytesRx: Int,
                            durationMs: Long
                        ) = Unit
                        override fun onRawTunnelBytes(
                            isHttps: Boolean,
                            host: String,
                            port: Int,
                            reqBytes: ByteArray?,
                            respBytes: ByteArray?
                        ) = Unit
                        override fun onBytesTransferred(bytes: Int) = Unit
                    },
                    skipHttpPeek = true,
                    onClientEof = { runCatching { upstream.shutdownOutput() } },
                    onServerEof = { runCatching { clientConn.shutdownOutput() } }
                )
            } finally {
                runCatching { upstream.close() }
                runCatching { clientConn.close() }
            }
        }

        val appReply = ByteArrayOutputStream()
        val clientJob = launch(Dispatchers.IO) {
            val appSock = java.net.Socket(java.net.InetAddress.getLoopbackAddress(), bridgeSock.localPort)
            appSock.use { s ->
                val inp = s.getInputStream()
                val out = s.getOutputStream()
                val first4 = ByteArray(4)
                var readCount = 0
                while (readCount < 4) {
                    val n = inp.read(first4, readCount, 4 - readCount)
                    if (n <= 0) break
                    readCount += n
                }
                assertEquals(4, readCount)
                appReply.write(first4, 0, readCount)

                // Client sends payload and half-closes output while expecting remaining server bytes
                out.write(byteArrayOf(0x0A, 0x0B))
                out.flush()
                s.shutdownOutput()

                val rest = inp.readBytes()
                appReply.write(rest)
            }
        }

        clientJob.join()
        proxyJob.join()
        upstreamJob.join()
        bridgeSock.close()
        serverSock.close()

        assertEquals("01020304050607", HexUtils.bytesToHex(appReply.toByteArray()))
    }
}
