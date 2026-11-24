package com.example.data

import com.example.data.db.CaptureSessionDao
import com.example.data.db.CapturedPacketDao
import com.example.data.db.TrafficRuleDao

object SampleDataSeeder {
    /**
     * Purges any legacy pre-seeded example/fake sessions so NetTrace always starts clean
     * with only real captured or user-imported traffic.
     */
    suspend fun seedIfEmpty(
        sessionDao: CaptureSessionDao,
        @Suppress("UNUSED_PARAMETER") packetDao: CapturedPacketDao,
        @Suppress("UNUSED_PARAMETER") ruleDao: TrafficRuleDao
    ): Long? {
        sessionDao.deleteSampleSessions()
        return null
    }
}
