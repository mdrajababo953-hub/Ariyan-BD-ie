package com.example.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface CaptureSessionDao {
    @Query("SELECT * FROM capture_sessions ORDER BY isLive DESC, startedAt DESC")
    fun observeAllSessions(): Flow<List<CaptureSessionEntity>>

    @Query("SELECT * FROM capture_sessions WHERE id = :id")
    fun observeSessionById(id: Long): Flow<CaptureSessionEntity?>

    @Query("SELECT * FROM capture_sessions WHERE id = :id")
    suspend fun getSessionById(id: Long): CaptureSessionEntity?

    @Query("SELECT COUNT(*) FROM capture_sessions")
    suspend fun getSessionCount(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSession(session: CaptureSessionEntity): Long

    @Query(
        "UPDATE capture_sessions SET packetCount = packetCount + 1, " +
            "blockedCount = blockedCount + :blockedInc, " +
            "totalBytes = totalBytes + :bytesDelta WHERE id = :sessionId"
    )
    suspend fun incrementSessionStats(sessionId: Long, blockedInc: Int, bytesDelta: Long)

    @Query("UPDATE capture_sessions SET totalBytes = totalBytes + :bytesDelta WHERE id = :sessionId")
    suspend fun addSessionBytes(sessionId: Long, bytesDelta: Long)

    @Query("UPDATE capture_sessions SET isLive = 0, endedAt = :endedAt WHERE id = :sessionId")
    suspend fun finishSession(sessionId: Long, endedAt: Long)

    @Query("UPDATE capture_sessions SET isLive = 0, endedAt = :endedAt WHERE isLive = 1")
    suspend fun finishAllLiveSessions(endedAt: Long)

    @Query("DELETE FROM capture_sessions WHERE id = :sessionId")
    suspend fun deleteSession(sessionId: Long)
}

@Dao
interface CapturedPacketDao {
    @Query("SELECT * FROM captured_packets WHERE sessionId = :sessionId ORDER BY timestamp DESC, id DESC")
    fun observePacketsForSession(sessionId: Long): Flow<List<CapturedPacketEntity>>

    @Query("SELECT * FROM captured_packets WHERE id = :packetId")
    fun observePacketById(packetId: Long): Flow<CapturedPacketEntity?>

    @Query("SELECT * FROM captured_packets WHERE id = :packetId")
    suspend fun getPacketById(packetId: Long): CapturedPacketEntity?

    @Query("SELECT * FROM captured_packets WHERE sessionId = :sessionId ORDER BY timestamp ASC, id ASC")
    suspend fun getPacketsForSessionOnce(sessionId: Long): List<CapturedPacketEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPacket(packet: CapturedPacketEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPackets(packets: List<CapturedPacketEntity>)

    @Query(
        "UPDATE captured_packets SET statusCode = :statusCode, " +
            "responseHeadersJson = :responseHeadersJson, " +
            "responseBodyHex = :responseBodyHex, " +
            "bytesRx = :bytesRx, " +
            "durationMs = :durationMs WHERE id = :packetId"
    )
    suspend fun updatePacketResponse(
        packetId: Long,
        statusCode: Int?,
        responseHeadersJson: String,
        responseBodyHex: String,
        bytesRx: Int,
        durationMs: Long
    )

    @Query("DELETE FROM captured_packets WHERE sessionId = :sessionId")
    suspend fun clearSessionPackets(sessionId: Long)
}

@Dao
interface TrafficRuleDao {
    @Query("SELECT * FROM traffic_rules ORDER BY createdAt DESC")
    fun observeAllRules(): Flow<List<TrafficRuleEntity>>

    @Query("SELECT * FROM traffic_rules WHERE isEnabled = 1")
    suspend fun getEnabledRulesSync(): List<TrafficRuleEntity>

    @Query("SELECT COUNT(*) FROM traffic_rules")
    suspend fun getRuleCount(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertRule(rule: TrafficRuleEntity): Long

    @Query("UPDATE traffic_rules SET isEnabled = :enabled WHERE id = :ruleId")
    suspend fun setRuleEnabled(ruleId: Long, enabled: Boolean)

    @Query("UPDATE traffic_rules SET hitCount = hitCount + 1 WHERE id = :ruleId")
    suspend fun incrementHitCount(ruleId: Long)

    @Query("DELETE FROM traffic_rules WHERE id = :ruleId")
    suspend fun deleteRule(ruleId: Long)
}
