package com.example.data

import com.example.data.db.CaptureSessionEntity
import com.example.data.db.CapturedPacketEntity
import com.example.data.db.NetTraceDatabase
import com.example.data.db.TrafficRuleEntity
import com.example.decoder.PacketJsonSerializer
import com.example.decoder.RawPacketImporter
import kotlinx.coroutines.flow.Flow

class CaptureRepository(private val db: NetTraceDatabase) {
    private val sessionDao = db.sessionDao()
    private val packetDao = db.packetDao()
    private val ruleDao = db.ruleDao()

    fun observeAllSessions(): Flow<List<CaptureSessionEntity>> = sessionDao.observeAllSessions()

    fun observeSessionById(id: Long): Flow<CaptureSessionEntity?> = sessionDao.observeSessionById(id)

    fun observePacketsForSession(sessionId: Long): Flow<List<CapturedPacketEntity>> =
        packetDao.observePacketsForSession(sessionId)

    fun observePacketById(packetId: Long): Flow<CapturedPacketEntity?> =
        packetDao.observePacketById(packetId)

    fun observeAllRules(): Flow<List<TrafficRuleEntity>> = ruleDao.observeAllRules()

    suspend fun ensureSeeded(): Long? {
        return SampleDataSeeder.seedIfEmpty(sessionDao, packetDao, ruleDao)
    }

    suspend fun startLiveSession(targetAppName: String, targetPackageName: String): Long {
        sessionDao.finishAllLiveSessions(System.currentTimeMillis())
        return sessionDao.insertSession(
            CaptureSessionEntity(
                title = "Live: $targetAppName",
                targetAppName = targetAppName,
                targetPackageName = targetPackageName,
                startedAt = System.currentTimeMillis(),
                isLive = true,
                isSample = false
            )
        )
    }

    suspend fun finishSession(sessionId: Long) {
        sessionDao.finishSession(sessionId, System.currentTimeMillis())
    }

    suspend fun finishAllLiveSessions() {
        sessionDao.finishAllLiveSessions(System.currentTimeMillis())
    }

    suspend fun deleteSession(sessionId: Long) {
        sessionDao.deleteSession(sessionId)
    }

    suspend fun recordCapturedPacket(packet: CapturedPacketEntity): Long {
        val id = packetDao.insertPacket(packet)
        val deltaBytes = (packet.bytesTx + packet.bytesRx).toLong()
        sessionDao.incrementSessionStats(
            sessionId = packet.sessionId,
            blockedInc = if (packet.isBlocked) 1 else 0,
            bytesDelta = deltaBytes
        )
        return id
    }

    suspend fun updateCapturedPacketResponse(
        sessionId: Long,
        packetId: Long,
        statusCode: Int?,
        responseHeadersJson: String,
        responseBodyHex: String,
        totalBytesRx: Int,
        addedBytesRx: Int,
        durationMs: Long
    ) {
        packetDao.updatePacketResponse(
            packetId = packetId,
            statusCode = statusCode,
            responseHeadersJson = responseHeadersJson,
            responseBodyHex = responseBodyHex,
            bytesRx = totalBytesRx,
            durationMs = durationMs
        )
        if (addedBytesRx > 0) {
            sessionDao.addSessionBytes(sessionId, addedBytesRx.toLong())
        }
    }

    suspend fun getEnabledRulesSync(): List<TrafficRuleEntity> = ruleDao.getEnabledRulesSync()

    suspend fun incrementRuleHit(ruleId: Long) = ruleDao.incrementHitCount(ruleId)

    suspend fun addRule(
        name: String,
        pattern: String,
        matchType: String,
        action: String,
        targetPackage: String = "*"
    ): Long {
        return ruleDao.insertRule(
            TrafficRuleEntity(
                name = name.trim(),
                pattern = pattern.trim(),
                matchType = matchType,
                action = action,
                targetPackage = targetPackage
            )
        )
    }

    suspend fun toggleRule(ruleId: Long, enabled: Boolean) = ruleDao.setRuleEnabled(ruleId, enabled)

    suspend fun deleteRule(ruleId: Long) = ruleDao.deleteRule(ruleId)

    suspend fun importRawTextAsSession(
        title: String,
        targetAppName: String,
        targetPackageName: String,
        rawText: String
    ): Long? {
        val tempPackets = RawPacketImporter.parseRawText(rawText, sessionId = 0L)
        if (tempPackets.isEmpty()) return null

        val totalBytes = tempPackets.sumOf { (it.bytesTx + it.bytesRx).toLong() }
        val now = System.currentTimeMillis()
        val sessionId = sessionDao.insertSession(
            CaptureSessionEntity(
                title = title.ifBlank { "Imported Capture" },
                targetAppName = targetAppName.ifBlank { "Imported Target" },
                targetPackageName = targetPackageName.ifBlank { "com.imported.capture" },
                startedAt = now,
                endedAt = now,
                isLive = false,
                isSample = false,
                packetCount = tempPackets.size,
                blockedCount = 0,
                totalBytes = totalBytes
            )
        )
        packetDao.insertPackets(tempPackets.map { it.copy(sessionId = sessionId) })
        return sessionId
    }

    suspend fun exportSessionAsJson(sessionId: Long): String? {
        val session = sessionDao.getSessionById(sessionId) ?: return null
        val packets = packetDao.getPacketsForSessionOnce(sessionId)
        return PacketJsonSerializer.sessionToFormattedJson(session, packets)
    }
}
