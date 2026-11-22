package com.example

import android.app.Application
import com.example.apps.InstalledAppsRepository
import com.example.data.CaptureRepository
import com.example.data.db.NetTraceDatabase
import com.example.data.prefs.UserPreferencesRepository

class NetTraceApp : Application() {
    val database: NetTraceDatabase by lazy { NetTraceDatabase.getInstance(this) }
    val captureRepository: CaptureRepository by lazy { CaptureRepository(database) }
    val preferencesRepository: UserPreferencesRepository by lazy { UserPreferencesRepository(this) }
    val installedAppsRepository: InstalledAppsRepository by lazy { InstalledAppsRepository(this) }
}
