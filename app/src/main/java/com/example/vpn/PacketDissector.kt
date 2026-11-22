package com.example.vpn

import org.json.JSONObject
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger

data class Ipv4Header(
    val ihlBytes: Int,
    val totalLength: Int,
    val protocol: Int,
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcIpStr: String,
    val dstIpStr: String
)

data class TcpSegment(
    val srcPort: Int,
    val dstPort: Int,
    val seqNum: Long,
    val ackNum: Long,
    val headerBytes: Int,
    val flags: Int,
    val window: Int,
    val payload: ByteArray
) {
    val isFin: Boolean get() = (flags and FLAG_FIN) != 0
    val isSyn: Boolean get() = (flags and FLAG_SYN) != 0
    val isRst: Boolean get() = (flags and FLAG_RST) != 0
    val isAck: Boolean get() = (flags and FLAG_ACK) != 0

    companion object {
        const val FLAG_FIN = 0x01
        const val FLAG_SYN = 0x02
        const val FLAG_RST = 0x04
        const val FLAG_PSH = 0x08
        const val FLAG_ACK = 0x10
    }
}

data class UdpDatagram(
    val srcPort: Int,
    val dstPort: Int,
    val payload: ByteArray
)

data class HttpParsedRequest(
    val method: String,
    val path: String,
    val host: String?,
    val headersJson: String,
    val body: ByteArray
)

data class HttpParsedResponse(
    val statusCode: Int,
    val headersJson: String,
    val body: ByteArray
)

object PacketDissector {

    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    fun parseIpv4(raw: ByteArray, len: Int): Ipv4Header? {
        if (len < 20) return null
        val version = (raw[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null
        val ihlBytes = (raw[0].toInt() and 0x0F) * 4
        if (ihlBytes < 20 || len < ihlBytes) return null
        val totalLength = ((raw[2].toInt() and 0xFF) shl 8) or (raw[3].toInt() and 0xFF)
        val effectiveLen = minOf(len, totalLength)
        if (effectiveLen < ihlBytes) return null
        val protocol = raw[9].toInt() and 0xFF
        val srcIp = raw.copyOfRange(12, 16)
        val dstIp = raw.copyOfRange(16, 20)
        return Ipv4Header(
            ihlBytes = ihlBytes,
            totalLength = effectiveLen,
            protocol = protocol,
            srcIp = srcIp,
            dstIp = dstIp,
            srcIpStr = InetAddress.getByAddress(srcIp).hostAddress ?: "0.0.0.0",
            dstIpStr = InetAddress.getByAddress(dstIp).hostAddress ?: "0.0.0.0"
        )
    }

    fun parseTcp(raw: ByteArray, ip: Ipv4Header): TcpSegment? {
        val start = ip.ihlBytes
        if (ip.totalLength < start + 20) return null
        val srcPort = ((raw[start].toInt() and 0xFF) shl 8) or (raw[start + 1].toInt() and 0xFF)
        val dstPort = ((raw[start + 2].toInt() and 0xFF) shl 8) or (raw[start + 3].toInt() and 0xFF)
        val seq = readUInt32(raw, start + 4)
        val ack = readUInt32(raw, start + 8)
        val dataOffsetBytes = ((raw[start + 12].toInt() ushr 4) and 0x0F) * 4
        if (dataOffsetBytes < 20 || ip.totalLength < start + dataOffsetBytes) return null
        val flags = raw[start + 13].toInt() and 0x3F
        val window = ((raw[start + 14].toInt() and 0xFF) shl 8) or (raw[start + 15].toInt() and 0xFF)
        val payloadStart = start + dataOffsetBytes
        val payload = if (payloadStart < ip.totalLength) {
            raw.copyOfRange(payloadStart, ip.totalLength)
        } else {
            ByteArray(0)
        }
        return TcpSegment(
            srcPort = srcPort,
            dstPort = dstPort,
            seqNum = seq,
            ackNum = ack,
            headerBytes = dataOffsetBytes,
            flags = flags,
            window = window,
            payload = payload
        )
    }

    fun parseUdp(raw: ByteArray, ip: Ipv4Header): UdpDatagram? {
        val start = ip.ihlBytes
        if (ip.totalLength < start + 8) return null
        val srcPort = ((raw[start].toInt() and 0xFF) shl 8) or (raw[start + 1].toInt() and 0xFF)
        val dstPort = ((raw[start + 2].toInt() and 0xFF) shl 8) or (raw[start + 3].toInt() and 0xFF)
        val udpLen = ((raw[start + 4].toInt() and 0xFF) shl 8) or (raw[start + 5].toInt() and 0xFF)
        val payloadStart = start + 8
        val payloadEnd = minOf(ip.totalLength, start + udpLen)
        val payload = if (payloadEnd > payloadStart) {
            raw.copyOfRange(payloadStart, payloadEnd)
        } else {
            ByteArray(0)
        }
        return UdpDatagram(srcPort, dstPort, payload)
    }

    fun extractDnsQueryName(payload: ByteArray): String? {
        if (payload.size < 13) return null
        val qdCount = ((payload[4].toInt() and 0xFF) shl 8) or (payload[5].toInt() and 0xFF)
        if (qdCount <= 0) return null
        return readDnsName(payload, 12)?.first
    }

    fun extractDnsAnswers(payload: ByteArray): Pair<String, List<String>>? {
        if (payload.size < 12) return null
        val qdCount = ((payload[4].toInt() and 0xFF) shl 8) or (payload[5].toInt() and 0xFF)
        val anCount = ((payload[6].toInt() and 0xFF) shl 8) or (payload[7].toInt() and 0xFF)
        if (qdCount <= 0 || anCount <= 0) return null

        var offset = 12
        var queryName = ""
        repeat(qdCount) { idx ->
            val res = readDnsName(payload, offset) ?: return null
            if (idx == 0) queryName = res.first
            offset = res.second + 4 // QTYPE + QCLASS
            if (offset > payload.size) return null
        }

        val ips = mutableListOf<String>()
        repeat(anCount) {
            if (offset >= payload.size) return@repeat
            val nameRes = readDnsName(payload, offset) ?: return@repeat
            offset = nameRes.second
            if (offset + 10 > payload.size) return@repeat
            val type = ((payload[offset].toInt() and 0xFF) shl 8) or (payload[offset + 1].toInt() and 0xFF)
            val rdLen = ((payload[offset + 8].toInt() and 0xFF) shl 8) or (payload[offset + 9].toInt() and 0xFF)
            offset += 10
            if (offset + rdLen > payload.size) return@repeat
            if (type == 1 && rdLen == 4) {
                val ip = InetAddress.getByAddress(payload.copyOfRange(offset, offset + 4)).hostAddress
                if (ip != null) ips.add(ip)
            }
            offset += rdLen
        }
        return if (queryName.isNotEmpty() && ips.isNotEmpty()) queryName to ips else null
    }

    private fun readDnsName(buf: ByteArray, startOffset: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var offset = startOffset
        var jumped = false
        var endOffset = startOffset
        var guard = 0
        while (offset < buf.size && guard++ < 64) {
            val len = buf[offset].toInt() and 0xFF
            if (len == 0) {
                if (!jumped) endOffset = offset + 1
                break
            }
            if ((len and 0xC0) == 0xC0) {
                if (offset + 1 >= buf.size) return null
                val ptr = ((len and 0x3F) shl 8) or (buf[offset + 1].toInt() and 0xFF)
                if (!jumped) endOffset = offset + 2
                offset = ptr
                jumped = true
            } else {
                offset++
                if (offset + len > buf.size) return null
                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(buf, offset, len, Charsets.US_ASCII))
                offset += len
                if (!jumped) endOffset = offset
            }
        }
        return sb.toString() to endOffset
    }

    fun extractTlsSni(payload: ByteArray): String? {
        if (payload.size < 43) return null
        if ((payload[0].toInt() and 0xFF) != 0x16) return null // TLS Handshake
        if ((payload[5].toInt() and 0xFF) != 0x01) return null // ClientHello

        var pos = 43
        if (pos >= payload.size) return null
        val sessionIdLen = payload[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen
        if (pos + 2 > payload.size) return null
        val cipherSuitesLen = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
        pos += 2 + cipherSuitesLen
        if (pos >= payload.size) return null
        val compMethodsLen = payload[pos].toInt() and 0xFF
        pos += 1 + compMethodsLen
        if (pos + 2 > payload.size) return null
        val extensionsLen = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
        pos += 2
        val end = minOf(payload.size, pos + extensionsLen)

        while (pos + 4 <= end) {
            val extType = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
            val extLen = ((payload[pos + 2].toInt() and 0xFF) shl 8) or (payload[pos + 3].toInt() and 0xFF)
            pos += 4
            if (pos + extLen > end) break
            if (extType == 0x0000 && extLen >= 5) { // server_name
                val nameType = payload[pos + 2].toInt() and 0xFF
                val nameLen = ((payload[pos + 3].toInt() and 0xFF) shl 8) or (payload[pos + 4].toInt() and 0xFF)
                if (nameType == 0 && pos + 5 + nameLen <= end) {
                    return String(payload, pos + 5, nameLen, Charsets.US_ASCII)
                }
            }
            pos += extLen
        }
        return null
    }

    fun tryParseHttpRequest(payload: ByteArray): HttpParsedRequest? {
        if (payload.size < 12) return null
        val headerEnd = findHeaderEnd(payload) ?: minOf(payload.size, 4096)
        val headerStr = String(payload, 0, headerEnd, Charsets.ISO_8859_1)
        val lines = headerStr.split("\r\n")
        if (lines.isEmpty()) return null
        val firstParts = lines[0].split(" ")
        if (firstParts.size < 3 || !firstParts[2].startsWith("HTTP/")) return null
        val method = firstParts[0].uppercase()
        if (method !in listOf("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")) return null

        val headersObj = JSONObject()
        var host: String? = null
        for (i in 1 until lines.size) {
            val line = lines[i]
            val colon = line.indexOf(':')
            if (colon > 0) {
                val k = line.substring(0, colon).trim()
                val v = line.substring(colon + 1).trim()
                headersObj.put(k, v)
                if (k.equals("Host", ignoreCase = true)) host = v
            }
        }
        val bodyStart = findHeaderEnd(payload)?.let { it + 4 } ?: payload.size
        val body = if (bodyStart < payload.size) payload.copyOfRange(bodyStart, payload.size) else ByteArray(0)

        return HttpParsedRequest(
            method = method,
            path = firstParts[1],
            host = host,
            headersJson = headersObj.toString(),
            body = body
        )
    }

    fun tryParseHttpResponse(payload: ByteArray): HttpParsedResponse? {
        if (payload.size < 12) return null
        val peek = String(payload, 0, minOf(payload.size, 12), Charsets.ISO_8859_1)
        if (!peek.startsWith("HTTP/")) return null
        val headerEnd = findHeaderEnd(payload) ?: minOf(payload.size, 4096)
        val headerStr = String(payload, 0, headerEnd, Charsets.ISO_8859_1)
        val lines = headerStr.split("\r\n")
        val statusParts = lines.firstOrNull()?.split(" ") ?: return null
        val statusCode = statusParts.getOrNull(1)?.toIntOrNull() ?: return null

        val headersObj = JSONObject()
        for (i in 1 until lines.size) {
            val line = lines[i]
            val colon = line.indexOf(':')
            if (colon > 0) {
                headersObj.put(line.substring(0, colon).trim(), line.substring(colon + 1).trim())
            }
        }
        val bodyStart = findHeaderEnd(payload)?.let { it + 4 } ?: payload.size
        val body = if (bodyStart < payload.size) payload.copyOfRange(bodyStart, payload.size) else ByteArray(0)

        return HttpParsedResponse(
            statusCode = statusCode,
            headersJson = headersObj.toString(),
            body = body
        )
    }

    private fun findHeaderEnd(data: ByteArray): Int? {
        for (i in 0 until data.size - 3) {
            if (data[i] == 13.toByte() && data[i + 1] == 10.toByte() &&
                data[i + 2] == 13.toByte() && data[i + 3] == 10.toByte()
            ) {
                return i
            }
        }
        return null
    }

    private fun readUInt32(buf: ByteArray, offset: Int): Long {
        return ((buf[offset].toLong() and 0xFF) shl 24) or
            ((buf[offset + 1].toLong() and 0xFF) shl 16) or
            ((buf[offset + 2].toLong() and 0xFF) shl 8) or
            (buf[offset + 3].toLong() and 0xFF)
    }
}

object PacketBuilder {
    private val ipIdCounter = AtomicInteger(1000)

    fun buildIpv4UdpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val packet = ByteArray(totalLen)
        writeIpv4Header(packet, totalLen, PacketDissector.PROTO_UDP, srcIp, dstIp)

        packet[20] = ((srcPort ushr 8) and 0xFF).toByte()
        packet[21] = (srcPort and 0xFF).toByte()
        packet[22] = ((dstPort ushr 8) and 0xFF).toByte()
        packet[23] = (dstPort and 0xFF).toByte()
        packet[24] = ((udpLen ushr 8) and 0xFF).toByte()
        packet[25] = (udpLen and 0xFF).toByte()
        System.arraycopy(payload, 0, packet, 28, payload.size)

        val udpChecksum = computeTransportChecksum(srcIp, dstIp, PacketDissector.PROTO_UDP, packet, 20, udpLen)
        packet[26] = ((udpChecksum ushr 8) and 0xFF).toByte()
        packet[27] = (udpChecksum and 0xFF).toByte()
        return packet
    }

    fun buildIpv4TcpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long,
        flags: Int,
        payload: ByteArray = ByteArray(0),
        windowSize: Int = 65535
    ): ByteArray {
        val tcpLen = 20 + payload.size
        val totalLen = 20 + tcpLen
        val packet = ByteArray(totalLen)
        writeIpv4Header(packet, totalLen, PacketDissector.PROTO_TCP, srcIp, dstIp)

        val buf = ByteBuffer.wrap(packet, 20, 20)
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putInt(seqNum.toInt())
        buf.putInt(ackNum.toInt())
        buf.put(((5 shl 4) and 0xF0).toByte()) // 20-byte TCP header
        buf.put((flags and 0x3F).toByte())
        buf.putShort(windowSize.toShort())
        buf.putShort(0) // checksum placeholder
        buf.putShort(0) // urgent pointer

        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, packet, 40, payload.size)
        }

        val tcpChecksum = computeTransportChecksum(srcIp, dstIp, PacketDissector.PROTO_TCP, packet, 20, tcpLen)
        packet[36] = ((tcpChecksum ushr 8) and 0xFF).toByte()
        packet[37] = (tcpChecksum and 0xFF).toByte()
        return packet
    }

    private fun writeIpv4Header(
        packet: ByteArray,
        totalLen: Int,
        protocol: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ) {
        val ipId = ipIdCounter.incrementAndGet() and 0xFFFF
        packet[0] = 0x45.toByte()
        packet[1] = 0
        packet[2] = ((totalLen ushr 8) and 0xFF).toByte()
        packet[3] = (totalLen and 0xFF).toByte()
        packet[4] = ((ipId ushr 8) and 0xFF).toByte()
        packet[5] = (ipId and 0xFF).toByte()
        packet[6] = 0x40.toByte() // Don't fragment
        packet[7] = 0
        packet[8] = 64.toByte() // TTL
        packet[9] = protocol.toByte()
        System.arraycopy(srcIp, 0, packet, 12, 4)
        System.arraycopy(dstIp, 0, packet, 16, 4)

        val checksum = computeChecksum(packet, 0, 20)
        packet[10] = ((checksum ushr 8) and 0xFF).toByte()
        packet[11] = (checksum and 0xFF).toByte()
    }

    private fun computeTransportChecksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        protocol: Int,
        segment: ByteArray,
        offset: Int,
        length: Int
    ): Int {
        var sum = 0L
        sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
        sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
        sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
        sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
        sum += protocol.toLong()
        sum += length.toLong()

        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((segment[i].toInt() and 0xFF) shl 8) or (segment[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (segment[i].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        val result = (sum.inv() and 0xFFFFL).toInt()
        return if (protocol == PacketDissector.PROTO_UDP && result == 0) 0xFFFF else result
    }

    private fun computeChecksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }
}
