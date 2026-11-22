package com.example.data.db

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(tableName = "capture_sessions")
data class CaptureSessionEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val title: String,
    val targetAppName: String,
    val targetPackageName: String,
    val startedAt: Long = System.currentTimeMillis(),
    val endedAt: Long? = null,
    val isLive: Boolean = false,
    val isSample: Boolean = false,
    val packetCount: Int = 0,
    val blockedCount: Int = 0,
    val totalBytes: Long = 0
)

@Entity(
    tableName = "captured_packets",
    foreignKeys = [
        ForeignKey(
            entity = CaptureSessionEntity::class,
            parentColumns = ["id"],
            childColumns = ["sessionId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [Index("sessionId"), Index("timestamp")]
)
data class CapturedPacketEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sessionId: Long,
    val timestamp: Long = System.currentTimeMillis(),
    val method: String,
    val url: String,
    val host: String,
    val path: String,
    val port: Int,
    val protocol: String,
    val statusCode: Int? = null,
    val requestHeadersJson: String = "{}",
    val requestBodyHex: String = "",
    val responseHeadersJson: String = "{}",
    val responseBodyHex: String = "",
    val durationMs: Long = 0,
    val bytesTx: Int = 0,
    val bytesRx: Int = 0,
    val isBlocked: Boolean = false,
    val blockReason: String? = null
)

@Entity(tableName = "traffic_rules")
data class TrafficRuleEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val pattern: String,
    val matchType: String = "HOST", // HOST, PATH, PORT, PROTOCOL
    val action: String = "BLOCK",   // BLOCK, ALLOW, HIGHLIGHT
    val targetPackage: String = "*",
    val isEnabled: Boolean = true,
    val hitCount: Int = 0,
    val createdAt: Long = System.currentTimeMillis()
)
