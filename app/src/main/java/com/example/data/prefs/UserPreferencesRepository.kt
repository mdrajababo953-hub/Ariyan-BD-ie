package com.example.data.prefs

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "nettrace_prefs")

data class TargetAppSelection(
    val packageName: String = "",
    val appName: String = "",
    val uid: Int = -1
)

data class AppSettings(
    val targetApp: TargetAppSelection = TargetAppSelection(),
    val activeSessionId: Long = 0L,
    val darkTheme: Boolean = true,
    val autoDecodeOnOpen: Boolean = true
)

class UserPreferencesRepository(private val context: Context) {
    private object Keys {
        val TARGET_PACKAGE = stringPreferencesKey("target_package")
        val TARGET_APP_NAME = stringPreferencesKey("target_app_name")
        val TARGET_UID = stringPreferencesKey("target_uid")
        val ACTIVE_SESSION_ID = longPreferencesKey("active_session_id")
        val DARK_THEME = booleanPreferencesKey("dark_theme")
        val AUTO_DECODE = booleanPreferencesKey("auto_decode")
    }

    val settingsFlow: Flow<AppSettings> = context.dataStore.data.map { prefs ->
        AppSettings(
            targetApp = TargetAppSelection(
                packageName = prefs[Keys.TARGET_PACKAGE].orEmpty(),
                appName = prefs[Keys.TARGET_APP_NAME].orEmpty(),
                uid = prefs[Keys.TARGET_UID]?.toIntOrNull() ?: -1
            ),
            activeSessionId = prefs[Keys.ACTIVE_SESSION_ID] ?: 0L,
            darkTheme = prefs[Keys.DARK_THEME] ?: true,
            autoDecodeOnOpen = prefs[Keys.AUTO_DECODE] ?: true
        )
    }

    suspend fun setTargetApp(packageName: String, appName: String, uid: Int) {
        context.dataStore.edit { prefs ->
            prefs[Keys.TARGET_PACKAGE] = packageName
            prefs[Keys.TARGET_APP_NAME] = appName
            prefs[Keys.TARGET_UID] = uid.toString()
        }
    }

    suspend fun setActiveSessionId(sessionId: Long) {
        context.dataStore.edit { prefs ->
            prefs[Keys.ACTIVE_SESSION_ID] = sessionId
        }
    }

    suspend fun setDarkTheme(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.DARK_THEME] = enabled
        }
    }
}
