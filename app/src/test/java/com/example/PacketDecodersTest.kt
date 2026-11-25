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
    fun `batch decode exporter filters protocols and builds combined aryan json without hex`() = kotlinx.coroutines.test.runTest {
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
        val tcpProtoPkt = httpsPkt.copy(
            id = 3,
            method = "TCP",
            url = "tcp://10.0.0.5:9000",
            host = "10.0.0.5",
            path = ":9000",
            port = 9000,
            protocol = "TCP",
            requestBodyHex = "0801",
            responseBodyHex = ""
        )
        val tlsHandshakePkt = httpsPkt.copy(
            id = 4,
            method = "TLS",
            url = "https://clientbp.ggpolarbear.com:443",
            path = ":443",
            protocol = "TCP",
            requestBodyHex = "160303007a02000076",
            responseBodyHex = ""
        )
        val all = listOf(httpsPkt, udpPkt, tcpProtoPkt, tlsHandshakePkt)

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
        assertTrue(res.fileName.startsWith("ARIYAN_A9X_HTTPS_"))
        assertTrue(res.fileName.endsWith(".txt"))
        assertTrue(res.packageContent.contains("https://clientbp.ggpolarbear.com/GetLikedRecord"))
        assertTrue(res.packageContent.contains("Request Hex:\n1a725b2c56ec52ba7d09623454c0a003"))
        assertTrue(res.packageContent.contains("Response Hex:\n0a00"))
        assertTrue(res.packageContent.contains("def get_liked_record_response(K, V):"))
        assertTrue(res.packageContent.contains("    fields = {}"))
        assertTrue(res.packageContent.contains("    fields[1] = {}"))
        assertTrue(res.packageContent.contains("    return iZ(str(gZ(fields).hex()), packet_id, K, V)"))

        val arr = org.json.JSONArray(res.jsonContent)
        assertEquals(1, arr.length())
        val item = arr.getJSONObject(0)
        assertEquals(listOf("api", "request", "response"), item.keys().asSequence().toList())
        assertEquals("POST https://clientbp.ggpolarbear.com/GetLikedRecord", item.getString("api"))
        assertTrue(item.isNull("request"))
        val respObj = item.getJSONObject("response")
        assertTrue(respObj.has("1"))
        assertTrue(!res.jsonContent.contains("\"hex\""))
        assertTrue(!res.jsonContent.contains("0000  "))
        assertTrue(!res.jsonContent.contains("sourceLink"))
        assertTrue(!res.jsonContent.contains("requestHeaders"))
    }

    @Test
    fun `formatHexDump and packetToFormattedJson emit clean hex and api request response without hex`() {
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
        assertEquals(listOf("api", "request", "response"), obj.keys().asSequence().toList())
        assertEquals("POST https://clientbp.ggpolarbear.com/GetLikedRecord", obj.getString("api"))
        assertTrue(obj.isNull("request"))
        assertTrue(obj.getJSONObject("response").has("1"))

        val protoReqPkt = pkt.copy(requestBodyHex = "08f4f3c8cf3d1026")
        val protoObj = org.json.JSONObject(com.example.decoder.PacketJsonSerializer.packetToFormattedJson(protoReqPkt))
        assertEquals(16541432308L, protoObj.getJSONObject("request").getLong("1"))
        assertEquals(38L, protoObj.getJSONObject("request").getLong("2"))
    }

    @Test
    fun `protobuf decoder preserves ascii dates and versions as strings and rejects pure bytes noise`() {
        // Field 1 (varint 1) + Field 2 (length-delimited ASCII date "2026-11-25 00:01:39") + Field 3 ("1.134.21")
        val ts = "2026-11-25 00:01:39".toByteArray(Charsets.UTF_8)
        val ver = "1.134.21".toByteArray(Charsets.UTF_8)
        val protoPayload = byteArrayOf(0x08, 0x01, 0x12, ts.size.toByte()) + ts + byteArrayOf(0x1A, ver.size.toByte()) + ver
        val analysis = PayloadAnalyzer.analyze(HexUtils.bytesToHex(protoPayload))
        assertEquals(PayloadClassification.PROTOBUF, analysis.classification)
        val jsonObj = org.json.JSONObject(analysis.protobuf!!.jsonFormatted)
        assertEquals("2026-11-25 00:01:39", jsonObj.getString("2"))
        assertEquals("1.134.21", jsonObj.getString("3"))

        // Opaque non-ASCII length-delimited blob (all fields BYTES) should not falsely classify as PROTOBUF
        val noiseBytes = byteArrayOf(0x1A, 0x06, 0xFE.toByte(), 0x80.toByte(), 0xFF.toByte(), 0xAA.toByte(), 0x99.toByte(), 0xBB.toByte())
        assertEquals(null, ProtobufWireDecoder.decode(noiseBytes))
        assertEquals(PayloadClassification.RAW_BINARY, PayloadAnalyzer.quickClassify(HexUtils.bytesToHex(noiseBytes)))
    }

    @Test
    fun `formatSpacedHex produces uppercase spaced hex without offsets`() {
        val spaced = HexUtils.formatSpacedHex("12cf1d0a020801")
        assertEquals("12 CF 1D 0A 02 08 01", spaced)
        assertTrue(!spaced.contains("|"))
        assertTrue(!spaced.contains("0000"))
    }

    @Test
    fun `hasDecodablePayload accepts when either request or response decodes to protobuf or json`() {
        val enc16 = "9b886fb750efb187097dbbb281be7bae"
        val proto = "08f4f3c8cf3d1026"
        val jsonHex = HexUtils.bytesToHex("{\"uid\":123}".toByteArray())

        // Both undecodable -> false
        assertTrue(!PayloadAnalyzer.hasDecodablePayload(enc16, enc16))
        assertTrue(!PayloadAnalyzer.hasDecodablePayload("", ""))

        // Either request OR response decodable -> true
        assertTrue(PayloadAnalyzer.hasDecodablePayload(enc16, proto))
        assertTrue(PayloadAnalyzer.hasDecodablePayload(proto, enc16))
        assertTrue(PayloadAnalyzer.hasDecodablePayload(jsonHex, ""))
    }

    @Test
    fun `app starts clean with zero pre-seeded sample sessions`() = kotlinx.coroutines.test.runTest {
        val ctx = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
        val db = androidx.room.Room.inMemoryDatabaseBuilder(
            ctx,
            com.example.data.db.NetTraceDatabase::class.java
        ).allowMainThreadQueries().build()
        try {
            val seeded = com.example.data.SampleDataSeeder.seedIfEmpty(
                db.sessionDao(),
                db.packetDao(),
                db.ruleDao()
            )
            assertEquals(null, seeded)
            assertEquals(0, db.sessionDao().getSessionCount())
        } finally {
            db.close()
        }
    }

    @Test
    fun `payload analyzer caches quickClassify and bounds oversized hex inputs cleanly`() {
        val sampleProto = "08f4f3c8cf3d102618ad02"
        assertEquals(PayloadClassification.PROTOBUF, PayloadAnalyzer.quickClassify(sampleProto))
        assertEquals(PayloadClassification.PROTOBUF, PayloadAnalyzer.quickClassify(sampleProto))

        val hugeHex = "aa".repeat(200_000)
        val hugeClass = PayloadAnalyzer.quickClassify(hugeHex)
        assertEquals(PayloadClassification.ENCRYPTED_BLOCK, hugeClass)
        val analysis = PayloadAnalyzer.analyze(hugeHex)
        assertEquals(131_072, analysis.byteCount)
    }

    @Test
    fun `smart python package formats login payload, nested endpoint package, and multi-entry report separation`() {
        fun pbString(fieldNum: Int, value: String): ByteArray {
            val tag = (fieldNum shl 3) or 2
            val bytes = value.toByteArray(Charsets.UTF_8)
            val out = java.io.ByteArrayOutputStream()
            fun writeVarint(v: Int) {
                var x = v
                while ((x and 0x7F.inv()) != 0) {
                    out.write((x and 0x7F) or 0x80)
                    x = x ushr 7
                }
                out.write(x)
            }
            writeVarint(tag)
            writeVarint(bytes.size)
            out.write(bytes)
            return out.toByteArray()
        }

        // Login payload: field 3 timestamp, field 4 "free fire", field 22 token, field 26 "IND", field 29 open_id
        val loginBytes = pbString(3, "2026-11-25 00:01:39") +
            pbString(4, "free fire") +
            pbString(22, "tok_abc123") +
            pbString(26, "IND") +
            pbString(29, "oid_999")
        val loginHex = HexUtils.bytesToHex(loginBytes)
        val loginAnalysis = PayloadAnalyzer.analyze(loginHex)
        assertEquals(PayloadClassification.PROTOBUF, loginAnalysis.classification)
        val loginPy = com.example.decoder.ProtobufFieldsFormatter.formatSmartPythonPackage(
            nodes = loginAnalysis.protobuf!!.fields,
            endpointOrPath = "/GetLoginData",
            isResponse = false
        )
        assertTrue(loginPy.contains("def build_login_payload(access_token, open_id, region=\"IND\", server_time_str=None):"))
        assertTrue(loginPy.contains("P = {}"))
        assertTrue(loginPy.contains("P[3]  = server_time_str"))
        assertTrue(loginPy.contains("P[4]  = \"free fire\""))
        assertTrue(loginPy.contains("P[22] = access_token"))
        assertTrue(loginPy.contains("P[26] = region"))
        assertTrue(loginPy.contains("P[29] = open_id"))
        assertTrue(loginPy.contains("raw = pb(P)"))
        assertTrue(loginPy.contains("return enc(xK, xV, raw)"))

        // General nested endpoint payload: /UpdateSocialBasicInfo
        // field 1 = 13 (08 0D), field 2 = { 1: 1 (08 01), 2: "bio" (12 03 62 69 6f) } -> 12 07 08 01 12 03 62 69 6f
        val nestedHex = "080d12070801120362696f"
        val nestedAnalysis = PayloadAnalyzer.analyze(nestedHex)
        assertEquals(PayloadClassification.PROTOBUF, nestedAnalysis.classification)
        val endpointPy = com.example.decoder.ProtobufFieldsFormatter.formatSmartPythonPackage(
            nodes = nestedAnalysis.protobuf!!.fields,
            endpointOrPath = "/UpdateSocialBasicInfo",
            isResponse = false
        )
        assertTrue(endpointPy.contains("def update_social_basic_info(K, V):"))
        assertTrue(endpointPy.contains("packet_id = '0E15'"))
        assertTrue(endpointPy.contains("fields = {}"))
        assertTrue(endpointPy.contains("fields[1] = 13"))
        assertTrue(endpointPy.contains("fields[2] = {}"))
        assertTrue(endpointPy.contains("fields[2][1] = 1"))
        assertTrue(endpointPy.contains("fields[2][2] = \"bio\""))
        assertTrue(endpointPy.contains("return iZ(str(gZ(fields).hex()), packet_id, K, V)"))

        // Multi-entry batch package report checks 6-newline separation between APIs
        val p1 = com.example.data.db.CapturedPacketEntity(
            id = 1, sessionId = 1, timestamp = 1000L, method = "POST",
            url = "https://client.ind.freefiremobile.com/GetLoginData",
            host = "client.ind.freefiremobile.com", path = "/GetLoginData", port = 443,
            protocol = "HTTPS", statusCode = 200, requestHeadersJson = "{}",
            requestBodyHex = loginHex, responseHeadersJson = "{}", responseBodyHex = "0801",
            durationMs = 5, bytesTx = 10, bytesRx = 2, isBlocked = false, blockReason = null
        )
        val p2 = p1.copy(
            id = 2,
            url = "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo",
            path = "/UpdateSocialBasicInfo",
            requestBodyHex = nestedHex,
            responseBodyHex = ""
        )
        val (report, arr) = com.example.decoder.BatchDecodeExporter.buildPremiumPackageReport(
            session = null,
            packets = listOf(p1, p2),
            scope = com.example.decoder.FullDecodeScope.HTTP_HTTPS
        )
        assertEquals(2, arr.length())
        assertTrue(report.contains("https://client.ind.freefiremobile.com/GetLoginData\n\nRequest Hex:\n$loginHex\n\nResponse Hex:\n0801"))
        assertTrue(report.contains("\n\n\n\n\n\nhttps://client.ind.freefiremobile.com/UpdateSocialBasicInfo"))
        assertTrue(report.contains("Response Hex:\n<Empty>"))

        // Bulk catalog repeated-message responses like [{1: 1001, ...}, {1: 1001, ...}] MUST be skipped
        val bulkCatalogHex =
            "0a0f081e100118a288a38703200528e7070a0f082810011888b9e0be01200528e707" +
                "0a0f0832100118a288a38703200a28e7070a0f083c10011888b9e0be01200a28e707"
        val catalogPkt = p1.copy(
            id = 3,
            url = "https://client.ind.freefiremobile.com/GetCatalog",
            path = "/GetCatalog",
            requestBodyHex = "9b886fb750efb187097dbbb281be7bae",
            responseBodyHex = bulkCatalogHex
        )
        val (filteredReport, filteredArr) = com.example.decoder.BatchDecodeExporter.buildPremiumPackageReport(
            session = null,
            packets = listOf(p2, catalogPkt),
            scope = com.example.decoder.FullDecodeScope.HTTP_HTTPS
        )
        assertEquals(1, filteredArr.length())
        assertTrue(filteredReport.contains("UpdateSocialBasicInfo"))
        assertTrue(!filteredReport.contains("GetCatalog"))
        assertTrue(!filteredReport.contains("response_fields["))
    }

    @Test
    fun `ca certificate save succeeds without throwing No such file or directory`() {
        val ctx = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
        val mgr = com.example.vpn.MitmCertificateManager(ctx)
        val savedPath = mgr.saveCaCertToAryanFolder()
        assertTrue(savedPath.contains("ARIYAN_A9X_CA.crt"))
        assertTrue(mgr.isCaReady())
        assertTrue(mgr.getCaPemString().contains("BEGIN CERTIFICATE"))
    }
}
