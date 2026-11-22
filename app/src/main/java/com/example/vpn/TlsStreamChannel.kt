package com.example.vpn

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException

/**
 * Pure-standard-library server-side TLS stream wrapper backed by [SSLEngine].
 * Avoids Android/JDK differences in SSLSocketFactory.createSocket(Socket, InputStream, Boolean)
 * by accepting already-peeked initial ClientHello bytes directly before delegating to [rawIn]/[rawOut].
 */
class TlsStreamChannel(
    private val engine: SSLEngine,
    private val rawIn: InputStream,
    private val rawOut: OutputStream,
    initialBytes: ByteArray
) {
    private val writeLock = Any()
    private val readLock = Any()
    @Volatile
    private var closed = false

    private var inNetBuf: ByteBuffer
    private var outNetBuf: ByteBuffer
    private var inAppBuf: ByteBuffer

    init {
        val pktSize = maxOf(engine.session.packetBufferSize, 32768)
        val appSize = maxOf(engine.session.applicationBufferSize, 32768)
        inNetBuf = ByteBuffer.allocate(maxOf(pktSize, initialBytes.size + 4096))
        outNetBuf = ByteBuffer.allocate(pktSize)
        inAppBuf = ByteBuffer.allocate(appSize)

        if (initialBytes.isNotEmpty()) {
            inNetBuf.put(initialBytes)
        }
        inNetBuf.flip()
        inAppBuf.flip() // empty ready-to-read state
    }

    fun handshake() {
        engine.beginHandshake()
        val emptyApp = ByteBuffer.allocate(0)
        var status = engine.handshakeStatus

        while (status != SSLEngineResult.HandshakeStatus.FINISHED &&
            status != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
        ) {
            when (status) {
                SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                    while (true) {
                        val task = engine.delegatedTask ?: break
                        task.run()
                    }
                    status = engine.handshakeStatus
                }
                SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    synchronized(writeLock) {
                        outNetBuf.clear()
                        val res = engine.wrap(emptyApp, outNetBuf)
                        if (res.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                            outNetBuf = ByteBuffer.allocate(maxOf(outNetBuf.capacity() * 2, engine.session.packetBufferSize))
                            status = engine.handshakeStatus
                        } else {
                            flushOutNetBufLocked()
                            status = res.handshakeStatus
                        }
                    }
                }
                SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                    if (!inNetBuf.hasRemaining()) {
                        readMoreNetBytes()
                    }
                    inAppBuf.clear()
                    val res = engine.unwrap(inNetBuf, inAppBuf)
                    inAppBuf.flip()
                    when (res.status) {
                        SSLEngineResult.Status.OK -> {
                            status = res.handshakeStatus
                        }
                        SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                            readMoreNetBytes()
                            status = engine.handshakeStatus
                        }
                        SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                            val newCap = maxOf(inAppBuf.capacity() * 2, engine.session.applicationBufferSize)
                            inAppBuf = ByteBuffer.allocate(newCap).apply { flip() }
                            status = engine.handshakeStatus
                        }
                        SSLEngineResult.Status.CLOSED -> {
                            throw SSLHandshakeException("TLS connection closed during handshake")
                        }
                    }
                }
                else -> {
                    status = engine.handshakeStatus
                }
            }
        }
    }

    val inputStream: InputStream = object : InputStream() {
        private val single = ByteArray(1)

        override fun read(): Int {
            val n = read(single, 0, 1)
            return if (n == -1) -1 else single[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            synchronized(readLock) {
                while (!inAppBuf.hasRemaining()) {
                    if (closed || engine.isInboundDone) return -1
                    if (!unwrapNextRecord()) return -1
                }
                val toCopy = minOf(len, inAppBuf.remaining())
                inAppBuf.get(b, off, toCopy)
                return toCopy
            }
        }

        override fun available(): Int = synchronized(readLock) { inAppBuf.remaining() }

        override fun close() {
            this@TlsStreamChannel.close()
        }
    }

    val outputStream: OutputStream = object : OutputStream() {
        private val single = ByteArray(1)

        override fun write(b: Int) {
            single[0] = b.toByte()
            write(single, 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (len <= 0) return
            if (closed) throw IOException("TLS channel closed")
            synchronized(writeLock) {
                val src = ByteBuffer.wrap(b, off, len)
                while (src.hasRemaining()) {
                    outNetBuf.clear()
                    val res = engine.wrap(src, outNetBuf)
                    when (res.status) {
                        SSLEngineResult.Status.OK -> {
                            flushOutNetBufLocked()
                            if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                                runDelegatedTasks()
                            }
                        }
                        SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                            outNetBuf = ByteBuffer.allocate(maxOf(outNetBuf.capacity() * 2, engine.session.packetBufferSize))
                        }
                        SSLEngineResult.Status.CLOSED -> {
                            throw IOException("TLS outbound closed")
                        }
                        SSLEngineResult.Status.BUFFER_UNDERFLOW -> break
                    }
                }
            }
        }

        override fun flush() {
            synchronized(writeLock) {
                rawOut.flush()
            }
        }

        override fun close() {
            this@TlsStreamChannel.close()
        }
    }

    private fun readMoreNetBytes() {
        inNetBuf.compact()
        if (inNetBuf.remaining() < 4096) {
            val grown = ByteBuffer.allocate(inNetBuf.capacity() * 2)
            inNetBuf.flip()
            grown.put(inNetBuf)
            inNetBuf = grown
        }
        val arr = ByteArray(minOf(inNetBuf.remaining(), 16384))
        val n = rawIn.read(arr)
        if (n < 0) {
            inNetBuf.flip()
            throw SSLHandshakeException("EOF while reading TLS record")
        }
        inNetBuf.put(arr, 0, n)
        inNetBuf.flip()
    }

    private fun unwrapNextRecord(): Boolean {
        while (true) {
            if (!inNetBuf.hasRemaining()) {
                inNetBuf.compact()
                if (inNetBuf.remaining() < 4096) {
                    val grown = ByteBuffer.allocate(inNetBuf.capacity() * 2)
                    inNetBuf.flip()
                    grown.put(inNetBuf)
                    inNetBuf = grown
                }
                val tmp = ByteArray(minOf(inNetBuf.remaining(), 16384))
                val n = rawIn.read(tmp)
                if (n < 0) {
                    inNetBuf.flip()
                    return false
                }
                inNetBuf.put(tmp, 0, n)
                inNetBuf.flip()
            }

            inAppBuf.clear()
            val res = try {
                engine.unwrap(inNetBuf, inAppBuf)
            } catch (e: SSLException) {
                inAppBuf.flip()
                throw e
            }
            inAppBuf.flip()

            if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                runDelegatedTasks()
            } else if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                wrapEmptyControlFrame()
            }

            when (res.status) {
                SSLEngineResult.Status.OK -> {
                    if (inAppBuf.hasRemaining()) return true
                }
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                    inNetBuf.compact()
                    if (inNetBuf.remaining() < 4096) {
                        val grown = ByteBuffer.allocate(inNetBuf.capacity() * 2)
                        inNetBuf.flip()
                        grown.put(inNetBuf)
                        inNetBuf = grown
                    }
                    val tmp = ByteArray(minOf(inNetBuf.remaining(), 16384))
                    val n = rawIn.read(tmp)
                    if (n < 0) {
                        inNetBuf.flip()
                        return false
                    }
                    inNetBuf.put(tmp, 0, n)
                    inNetBuf.flip()
                }
                SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                    val newCap = maxOf(inAppBuf.capacity() * 2, engine.session.applicationBufferSize)
                    inAppBuf = ByteBuffer.allocate(newCap).apply { flip() }
                }
                SSLEngineResult.Status.CLOSED -> {
                    return inAppBuf.hasRemaining()
                }
            }
        }
    }

    private fun runDelegatedTasks() {
        while (true) {
            val task = engine.delegatedTask ?: break
            task.run()
        }
    }

    private fun wrapEmptyControlFrame() {
        synchronized(writeLock) {
            val empty = ByteBuffer.allocate(0)
            outNetBuf.clear()
            val res = engine.wrap(empty, outNetBuf)
            if (res.status == SSLEngineResult.Status.OK) {
                flushOutNetBufLocked()
            }
        }
    }

    private fun flushOutNetBufLocked() {
        outNetBuf.flip()
        val count = outNetBuf.remaining()
        if (count > 0) {
            val bytes = ByteArray(count)
            outNetBuf.get(bytes)
            rawOut.write(bytes)
            rawOut.flush()
        }
        outNetBuf.clear()
    }

    fun close() {
        if (closed) return
        closed = true
        runCatching {
            synchronized(writeLock) {
                engine.closeOutbound()
                val empty = ByteBuffer.allocate(0)
                while (!engine.isOutboundDone) {
                    outNetBuf.clear()
                    val res = engine.wrap(empty, outNetBuf)
                    if (outNetBuf.position() > 0) {
                        flushOutNetBufLocked()
                    } else if (res.bytesProduced() == 0) {
                        break
                    }
                }
            }
        }
        runCatching { rawOut.close() }
        runCatching { rawIn.close() }
    }
}
