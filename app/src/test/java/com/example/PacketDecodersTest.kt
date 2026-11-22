package com.example

import com.example.decoder.HexUtils
import com.example.decoder.JwtDecoder
import com.example.decoder.PayloadAnalyzer
import com.example.decoder.PayloadClassification
import com.example.decoder.ProtobufWireDecoder
import com.example.decoder.RawPacketImporter
import com.example.vpn.PacketBuilder
import com.example.vpn.PacketDissector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class PacketDecodersTest {

    @Test
    fun `protobuf decoder decodes CS ranking response accurately`() {
        val hex = "08f4f3c8cf3d102618ad0220ad02300170807d8001ad028801cc08a80101b001019a0200"
        val bytes = HexUtils.hexToBytes(hex)
        val result = ProtobufWireDecoder.decode(bytes)
        assertNotNull(result)
        val field1 = result!!.fields.first { it.fieldNumber == 1 }
        assertEquals("16541432308", field1.displayValue)
        val field2 = result.fields.first { it.fieldNumber == 2 }
        assertEquals("38", field2.displayValue)
        val field3 = result.fields.first { it.fieldNumber == 3 }
        assertEquals("301", field3.displayValue)
    }

    @Test
    fun `protobuf decoder decodes nested repeated level rewards`() {
        val hex =
            "0a0f081e100118a288a38703200528e7070a0f082810011888b9e0be01200528e707" +
                "0a0f0832100118a288a38703200a28e7070a0f083c10011888b9e0be01200a28e707" +
                "0a0f0846100118dd9ed3ad03200128e7070a0f08501001189aa390ae03200128e707" +
                "0a0f085a100118d49fc5b003200128e7070a0f0864100118d7c2bbb103200128e707"
        val analysis = PayloadAnalyzer.analyze(hex)
        assertEquals(PayloadClassification.PROTOBUF, analysis.classification)
        val proto = analysis.protobuf
        assertNotNull(proto)
        assertEquals(8, proto!!.fields.size)
        val firstLevel = proto.fields.first().children.first { it.fieldNumber == 1 }
        assertEquals("30", firstLevel.displayValue)
        assertTrue(proto.fieldsDictFormatted.contains("fields = {"))
        assertTrue(proto.fieldsDictFormatted.contains("1: ["))
    }

    @Test
    fun `protobuf fields formatter renders empty message as {} and builds async def snippet`() {
        val likedRes = PayloadAnalyzer.analyze("0a00")
        assertEquals(PayloadClassification.PROTOBUF, likedRes.classification)
        val proto = likedRes.protobuf!!
        assertTrue(proto.fieldsDictFormatted.contains("1: {}"))

        val snippet = com.example.decoder.ProtobufFieldsFormatter.formatAsyncSnippet(
            nodes = proto.fields,
            endpointOrPath = "/GetLikedRecord",
            packetHeaderHex = "0E15"
        )
        assertTrue(snippet.contains("async def SendGetLikedRecord(key, iv):"))
        assertTrue(snippet.contains("CrEaTe_ProTo(fields)"))
        assertTrue(snippet.contains("'0E15'"))
    }

    @Test
    fun `payload analyzer detects 16-byte encrypted block`() {
        val hex = "9b886fb750efb187097dbbb281be7bae"
        val analysis = PayloadAnalyzer.analyze(hex)
        assertEquals(PayloadClassification.ENCRYPTED_BLOCK, analysis.classification)
        assertEquals(16, analysis.byteCount)
    }

    @Test
    fun `jwt decoder extracts account id and release version`() {
        val jwt =
            "Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ." +
                "eyJhY2NvdW50X2lkIjoxNjU0MTQzMjMwOCwibmlja25hbWUiOiJZUXhCVEFGeVdqbGFHMUE4IiwibG9ja19yZWdpb24iOiJCRCIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNTQiLCJleHAiOjE3ODUwMjU1NDd9." +
                "KHCBeyZRj66JhndGm7qtxu6drBV7U01egja0oYKdJaI"
        val decoded = JwtDecoder.decode(jwt)
        assertNotNull(decoded)
        assertEquals("16541432308", decoded!!.claims["account_id"])
        assertEquals("OB54", decoded.claims["release_version"])
        assertEquals("BD", decoded.claims["lock_region"])
    }

    @Test
    fun `raw packet importer parses multiple HTTP hex blocks`() {
        val raw = """
            Method & URL : POST https://clientbp.ggpolarbear.com/GetHeroicInfo

            Headers :
            User-Agent: UnityPlayer/2022.3.47f1
            Releaseversion: OB54

            Request body Hex:
            9b886fb750efb187097dbbb281be7bae

            Response body Hex:
            <Empty Body>

            Method & URL : POST https://clientbp.ggpolarbear.com/GetLikedRecord

            Headers :
            User-Agent: UnityPlayer/2022.3.47f1

            Request body Hex:
            1a725b2c56ec52ba7d09623454c0a003

            Response body Hex:
            0a00
        """.trimIndent()
        val packets = RawPacketImporter.parseRawText(raw, sessionId = 1L)
        assertEquals(2, packets.size)
        assertEquals("/GetHeroicInfo", packets[0].path)
        assertEquals("9b886fb750efb187097dbbb281be7bae", packets[0].requestBodyHex)
        assertEquals("", packets[0].responseBodyHex)
        assertEquals("/GetLikedRecord", packets[1].path)
        assertEquals("0a00", packets[1].responseBodyHex)
    }

    @Test
    fun `packet builder and dissector round trip ipv4 tcp and udp`() {
        val src = byteArrayOf(10, 110, 0, 2)
        val dst = byteArrayOf(8, 8, 8, 8)
        val udpRaw = PacketBuilder.buildIpv4UdpPacket(src, dst, 55123, 53, byteArrayOf(1, 2, 3, 4))
        val ipUdp = PacketDissector.parseIpv4(udpRaw, udpRaw.size)!!
        val udp = PacketDissector.parseUdp(udpRaw, ipUdp)!!
        assertEquals(55123, udp.srcPort)
        assertEquals(53, udp.dstPort)
        assertTrue(udp.payload.contentEquals(byteArrayOf(1, 2, 3, 4)))

        val tcpRaw = PacketBuilder.buildIpv4TcpPacket(src, dst, 40001, 443, 100L, 200L, 0x18, byteArrayOf(9, 8, 7))
        val ipTcp = PacketDissector.parseIpv4(tcpRaw, tcpRaw.size)!!
        val tcp = PacketDissector.parseTcp(tcpRaw, ipTcp)!!
        assertEquals(40001, tcp.srcPort)
        assertEquals(443, tcp.dstPort)
        assertEquals(100L, tcp.seqNum)
        assertEquals(200L, tcp.ackNum)
        assertTrue(tcp.payload.contentEquals(byteArrayOf(9, 8, 7)))
    }

    @Test
    fun `quickClassify matches analyze classification for protobuf json encrypted and empty`() {
        assertEquals(PayloadClassification.EMPTY, PayloadAnalyzer.quickClassify(""))
        assertEquals(
            PayloadClassification.PROTOBUF,
            PayloadAnalyzer.quickClassify("08f4f3c8cf3d102618ad0220ad02300170807d8001ad028801cc08a80101b001019a0200")
        )
        assertEquals(
            PayloadClassification.ENCRYPTED_BLOCK,
            PayloadAnalyzer.quickClassify("9b886fb750efb187097dbbb281be7bae")
        )
        val jsonHex = HexUtils.bytesToHex("{\"ok\":true}".toByteArray())
        assertEquals(PayloadClassification.JSON, PayloadAnalyzer.quickClassify(jsonHex))
    }

    @Test
    fun `batch decode exporter filters protocols and builds combined aryan json`() = kotlinx.coroutines.test.runTest {
        val ctx = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
        val httpsPkt = com.example.data.db.CapturedPacketEntity(
            id = 1,
            sessionId = 1,
            timestamp = 1000L,
            method = "POST",
            url = "https://clientbp.ggpolarbear.com/GetLikedRecord",
            host = "clientbp.ggpolarbear.com",
            path = "/GetLikedRecord",
            port = 443,
            protocol = "HTTPS",
            statusCode = 200,
            requestHeadersJson = "{}",
            requestBodyHex = "1a725b2c56ec52ba7d09623454c0a003",
            responseHeadersJson = "{}",
            responseBodyHex = "0a00",
            durationMs = 10,
            bytesTx = 16,
            bytesRx = 2,
            isBlocked = false,
            blockReason = null
        )
        val udpPkt = httpsPkt.copy(
            id = 2,
            method = "UDP",
            url = "udp://1.1.1.1:443",
            host = "1.1.1.1",
            path = "/",
            protocol = "UDP",
            requestBodyHex = "08f4f3c8cf3d",
            responseBodyHex = ""
        )
        val tlsHandshakePkt = httpsPkt.copy(
            id = 3,
            method = "TLS",
            url = "https://clientbp.ggpolarbear.com/Passthrough",
            path = "/Passthrough",
            requestBodyHex = "160303007a02000076",
            responseBodyHex = ""
        )
        val all = listOf(httpsPkt, udpPkt, tlsHandshakePkt)

        assertEquals(1, com.example.decoder.BatchDecodeExporter.filterPacketsByScope(all, com.example.decoder.FullDecodeScope.HTTP_HTTPS).size)
        assertEquals(1, com.example.decoder.BatchDecodeExporter.filterPacketsByScope(all, com.example.decoder.FullDecodeScope.UDP_DNS).size)
        assertEquals(2, com.example.decoder.BatchDecodeExporter.filterPacketsByScope(all, com.example.decoder.FullDecodeScope.TCP).size)
        assertEquals(3, com.example.decoder.BatchDecodeExporter.filterPacketsByScope(all, com.example.decoder.FullDecodeScope.ALL).size)

        val result = com.example.decoder.BatchDecodeExporter.decodeAndSaveToAryanFolder(
            context = ctx,
            session = null,
            packets = all,
            scope = com.example.decoder.FullDecodeScope.HTTP_HTTPS,
            onProgress = { _, _ -> }
        )
        assertTrue(result.isSuccess)
        val res = result.getOrThrow()
        assertEquals(1, res.decodedCount)
        assertTrue(res.displayPath.contains("Aryan"))

        val arr = org.json.JSONArray(res.jsonContent)
        assertEquals(1, arr.length())
        val item = arr.getJSONObject(0)
        assertEquals(setOf("request", "response"), item.keys().asSequence().toSet())
        val reqObj = item.getJSONObject("request")
        val respObj = item.getJSONObject("response")
        assertEquals(setOf("hex", "decoded"), reqObj.keys().asSequence().toSet())
        assertEquals(setOf("hex", "decoded"), respObj.keys().asSequence().toSet())
        assertEquals("1a725b2c56ec52ba7d09623454c0a003", reqObj.getString("hex"))
        assertEquals("0a00", respObj.getString("hex"))
        assertTrue(!res.jsonContent.contains("0000  "))
        assertTrue(!res.jsonContent.contains("sourceLink"))
        assertTrue(!res.jsonContent.contains("requestHeaders"))
    }

    @Test
    fun `formatHexDump and packetToFormattedJson emit clean hex and strictly request response json`() {
        val hexDump = HexUtils.formatHexDump(HexUtils.hexToBytes("160303007a"))
        assertEquals("160303007a", hexDump)
        assertTrue(!hexDump.contains("|"))
        assertTrue(!hexDump.contains("0000"))

        val pkt = com.example.data.db.CapturedPacketEntity(
            id = 10,
            sessionId = 1,
            timestamp = 2000L,
            method = "POST",
            url = "https://clientbp.ggpolarbear.com/GetLikedRecord",
            host = "clientbp.ggpolarbear.com",
            path = "/GetLikedRecord",
            port = 443,
            protocol = "HTTPS",
            statusCode = 200,
            requestHeadersJson = "{\"Authorization\":\"Bearer abc\"}",
            requestBodyHex = "1a725b2c56ec52ba7d09623454c0a003",
            responseHeadersJson = "{\"Server\":\"nginx\"}",
            responseBodyHex = "0a00",
            durationMs = 12,
            bytesTx = 16,
            bytesRx = 2,
            isBlocked = false,
            blockReason = null
        )
        val obj = org.json.JSONObject(com.example.decoder.PacketJsonSerializer.packetToFormattedJson(pkt))
        assertEquals(setOf("request", "response"), obj.keys().asSequence().toSet())
        assertEquals("1a725b2c56ec52ba7d09623454c0a003", obj.getJSONObject("request").getString("hex"))
        assertTrue(obj.getJSONObject("request").isNull("decoded"))
        assertEquals("0a00", obj.getJSONObject("response").getString("hex"))
        assertTrue(obj.getJSONObject("response").getJSONObject("decoded").has("field_1"))

        val protoReqPkt = pkt.copy(requestBodyHex = "08f4f3c8cf3d1026")
        val protoObj = org.json.JSONObject(com.example.decoder.PacketJsonSerializer.packetToFormattedJson(protoReqPkt))
        assertEquals(16541432308L, protoObj.getJSONObject("request").getJSONObject("decoded").getLong("field_1"))
        assertEquals(38L, protoObj.getJSONObject("request").getJSONObject("decoded").getLong("field_2"))
    }
}
