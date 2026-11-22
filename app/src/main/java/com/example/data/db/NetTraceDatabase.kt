package com.example.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        CaptureSessionEntity::class,
        CapturedPacketEntity::class,
        TrafficRuleEntity::class
    ],
    version = 1,
    exportSchema = false
)
abstract class NetTraceDatabase : RoomDatabase() {
    abstract fun sessionDao(): CaptureSessionDao
    abstract fun packetDao(): CapturedPacketDao
    abstract fun ruleDao(): TrafficRuleDao

    companion object {
        @Volatile
        private var INSTANCE: NetTraceDatabase? = null

        fun getInstance(context: Context): NetTraceDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    NetTraceDatabase::class.java,
                    "nettrace_captures.db"
                ).build().also { INSTANCE = it }
            }
        }
    }
}
