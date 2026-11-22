package com.example.data

import com.example.data.db.CaptureSessionDao
import com.example.data.db.CaptureSessionEntity
import com.example.data.db.CapturedPacketDao
import com.example.data.db.CapturedPacketEntity
import com.example.data.db.TrafficRuleDao
import com.example.data.db.TrafficRuleEntity
import org.json.JSONObject

object SampleDataSeeder {

    private const val SAMPLE_JWT =
        "eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ." +
            "eyJhY2NvdW50X2lkIjoxNjU0MTQzMjMwOCwibmlja25hbWUiOiJZUXhCVEFGeVdqbGFHMUE4Iiwibm90aV9yZWdpb24iOiJCRCIsImxvY2tfcmVnaW9uIjoiQkQiLCJleHRlcm5hbF9pZCI6IjQ3YjczMGQ3ZDQxNmYxZmRmZGFkOTBjMmY0ZDk3OWYyIiwiZXh0ZXJuYWxfdHlwZSI6NCwicGxhdF9pZCI6MSwiY2xpZW50X3ZlcnNpb24iOiIxLjEyNi4xNSIsImVtdWxhdG9yX3Njb3JlIjowLCJpc19lbXVsYXRvciI6ZmFsc2UsImNvdW50cnlfY29kZSI6Ik5QIiwiZXh0ZXJuYWxfdWlkIjo1Njk0OTgwMjc1LCJyZWdfYXZhdGFyIjoxMDIwMDAwMDcsInNvdXJjZSI6NCwibG9ja19yZWdpb25fdGltZSI6MTc4NDc4ODIwMCwiY2xpZW50X3R5cGUiOjIsInNpZ25hdHVyZV9tZDUiOiIxYWM0YjgwZWNmMDQ3OGE0NDIwM2JmOGZhYzYxMjBmNSIsInVzaW5nX3ZlcnNpb24iOjEsInJlbGVhc2VfY2hhbm5lbCI6IjNyZF9wYXJ0eSIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNTQiLCJleHAiOjE3ODUwMjU1NDd9." +
            "KHCBeyZRj66JhndGm7qtxu6drBV7U01egja0oYKdJaI"

    suspend fun seedIfEmpty(
        sessionDao: CaptureSessionDao,
        packetDao: CapturedPacketDao,
        ruleDao: TrafficRuleDao
    ): Long? {
        if (sessionDao.getSessionCount() > 0) return null

        val now = System.currentTimeMillis()
        val reqHeadersJson = JSONObject().apply {
            put("User-Agent", "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)")
            put("Accept", "*/*")
            put("Accept-Encoding", "deflate, gzip")
            put("Authorization", "Bearer $SAMPLE_JWT")
            put("X-Ga", "v1 1")
            put("Releaseversion", "OB54")
            put("Content-Type", "application/x-www-form-urlencoded")
            put("X-Unity-Version", "2022.3.47f1")
        }.toString()

        val respHeadersJson = JSONObject().apply {
            put("Content-Type", "application/x-protobuf")
            put("Server", "UnityGateway/OB54")
            put("Cache-Control", "no-store")
        }.toString()

        val samplePackets = listOf(
            CapturedPacketEntity(
                sessionId = 0L,
                timestamp = now - 48_000,
                method = "POST",
                url = "https://clientbp.ggpolarbear.com/GetHeroicInfo",
                host = "clientbp.ggpolarbear.com",
                path = "/GetHeroicInfo",
                port = 443,
                protocol = "HTTPS",
                statusCode = 200,
                requestHeadersJson = reqHeadersJson,
                requestBodyHex = "9b886fb750efb187097dbbb281be7bae",
                responseHeadersJson = respHeadersJson,
                responseBodyHex = "",
                durationMs = 64,
                bytesTx = 16,
                bytesRx = 0
            ),
            CapturedPacketEntity(
                sessionId = 0L,
                timestamp = now - 36_000,
                method = "POST",
                url = "https://clientbp.ggpolarbear.com/GetPlayerCSRankingInfoByAccountID",
                host = "clientbp.ggpolarbear.com",
                path = "/GetPlayerCSRankingInfoByAccountID",
                port = 443,
                protocol = "HTTPS",
                statusCode = 200,
                requestHeadersJson = reqHeadersJson,
                requestBodyHex = "14712cba0eac504d9ddd0070d3e9ed4f",
                responseHeadersJson = respHeadersJson,
                responseBodyHex = "08f4f3c8cf3d102618ad0220ad02300170807d8001ad028801cc08a80101b001019a0200",
                durationMs = 83,
                bytesTx = 16,
                bytesRx = 36
            ),
            CapturedPacketEntity(
                sessionId = 0L,
                timestamp = now - 24_000,
                method = "POST",
                url = "https://clientbp.ggpolarbear.com/GetLikedRecord",
                host = "clientbp.ggpolarbear.com",
                path = "/GetLikedRecord",
                port = 443,
                protocol = "HTTPS",
                statusCode = 200,
                requestHeadersJson = reqHeadersJson,
                requestBodyHex = "1a725b2c56ec52ba7d09623454c0a003",
                responseHeadersJson = respHeadersJson,
                responseBodyHex = "0a00",
                durationMs = 51,
                bytesTx = 16,
                bytesRx = 2
            ),
            CapturedPacketEntity(
                sessionId = 0L,
                timestamp = now - 12_000,
                method = "POST",
                url = "https://clientbp.ggpolarbear.com/GetLevelRewardsDisplayConfig",
                host = "clientbp.ggpolarbear.com",
                path = "/GetLevelRewardsDisplayConfig",
                port = 443,
                protocol = "HTTPS",
                statusCode = 200,
                requestHeadersJson = reqHeadersJson,
                requestBodyHex = "1a725b2c56ec52ba7d09623454c0a003",
                responseHeadersJson = respHeadersJson,
                responseBodyHex = "0a0f081e100118a288a38703200528e7070a0f082810011888b9e0be01200528e7070a0f0832100118a288a38703200a28e7070a0f083c10011888b9e0be01200a28e7070a0f0846100118dd9ed3ad03200128e7070a0f08501001189aa390ae03200128e7070a0f085a100118d49fc5b003200128e7070a0f0864100118d7c2bbb103200128e707",
                durationMs = 112,
                bytesTx = 16,
                bytesRx = 136
            ),
            CapturedPacketEntity(
                sessionId = 0L,
                timestamp = now - 4_000,
                method = "POST",
                url = "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
                host = "clientbp.ggpolarbear.com",
                path = "/UpdateSocialBasicInfo",
                port = 443,
                protocol = "HTTPS",
                statusCode = 200,
                requestHeadersJson = reqHeadersJson,
                requestBodyHex = "",
                responseHeadersJson = respHeadersJson,
                responseBodyHex = "",
                durationMs = 47,
                bytesTx = 0,
                bytesRx = 0
            )
        )

        val totalBytes = samplePackets.sumOf { (it.bytesTx + it.bytesRx).toLong() }
        val sessionId = sessionDao.insertSession(
            CaptureSessionEntity(
                title = "Example: Game API Capture (OB54)",
                targetAppName = "Target Game (Example)",
                targetPackageName = "com.example.targetgame",
                startedAt = now - 50_000,
                endedAt = now,
                isLive = false,
                isSample = true,
                packetCount = samplePackets.size,
                blockedCount = 0,
                totalBytes = totalBytes
            )
        )

        packetDao.insertPackets(samplePackets.map { it.copy(sessionId = sessionId) })

        if (ruleDao.getRuleCount() == 0) {
            ruleDao.insertRule(
                TrafficRuleEntity(
                    name = "Block Analytics Telemetry",
                    pattern = "analytics",
                    matchType = "HOST",
                    action = "BLOCK",
                    isEnabled = false
                )
            )
            ruleDao.insertRule(
                TrafficRuleEntity(
                    name = "Highlight Polarbear Game API",
                    pattern = "ggpolarbear.com",
                    matchType = "HOST",
                    action = "HIGHLIGHT",
                    isEnabled = true
                )
            )
        }

        return sessionId
    }
}
