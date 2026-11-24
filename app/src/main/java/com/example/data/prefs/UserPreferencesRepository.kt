package com.example.data.prefs

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.ui.theme.AppAccentTheme
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "nettrace_prefs")

enum class CaptureEngineMode {
    LOCAL_PROXY,
    APP_VPN;

    companion object {
        fun fromName(raw: String?): CaptureEngineMode {
            return entries.firstOrNull { it.name == raw } ?: LOCAL_PROXY
        }
    }
}

data class TargetAppSelection(
    val packageName: String = "",
    val appName: String = "",
    val uid: Int = -1
)

data class AppSettings(
    val targetApp: TargetAppSelection = TargetAppSelection(),
    val activeSessionId: Long = 0L,
    val darkTheme: Boolean = true,
    val autoDecodeOnOpen: Boolean = true,
    val accentTheme: AppAccentTheme = AppAccentTheme.CYAN,
    val httpsMitmEnabled: Boolean = true,
    val captureMode: CaptureEngineMode = CaptureEngineMode.LOCAL_PROXY,
    val proxyPort: Int = 8080,
    val forwardBaseUrl: String = "https://client.ind.freefiremobile.com",
    val onlyDecodableHttp: Boolean = true
)

class UserPreferencesRepository(private val context: Context) {
    private object Keys {
        val TARGET_PACKAGE = stringPreferencesKey("target_package")
        val TARGET_APP_NAME = stringPreferencesKey("target_app_name")
        val TARGET_UID = stringPreferencesKey("target_uid")
        val ACTIVE_SESSION_ID = longPreferencesKey("active_session_id")
        val DARK_THEME = booleanPreferencesKey("dark_theme")
        val AUTO_DECODE = booleanPreferencesKey("auto_decode")
        val ACCENT_THEME = stringPreferencesKey("accent_theme")
        val HTTPS_MITM_ENABLED = booleanPreferencesKey("https_mitm_enabled")
        val CAPTURE_MODE = stringPreferencesKey("capture_mode")
        val PROXY_PORT = intPreferencesKey("proxy_port")
        val FORWARD_BASE_URL = stringPreferencesKey("forward_base_url")
        val ONLY_DECODABLE_HTTP = booleanPreferencesKey("only_decodable_http")
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
            autoDecodeOnOpen = prefs[Keys.AUTO_DECODE] ?: true,
            accentTheme = AppAccentTheme.fromName(prefs[Keys.ACCENT_THEME]),
            httpsMitmEnabled = prefs[Keys.HTTPS_MITM_ENABLED] ?: true,
            captureMode = CaptureEngineMode.fromName(prefs[Keys.CAPTURE_MODE]),
            proxyPort = (prefs[Keys.PROXY_PORT] ?: 8080).coerceIn(1024, 65535),
            forwardBaseUrl = prefs[Keys.FORWARD_BASE_URL]
                ?.takeIf { it.isNotBlank() }
                ?: "https://client.ind.freefiremobile.com",
            onlyDecodableHttp = prefs[Keys.ONLY_DECODABLE_HTTP] ?: true
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

    suspend fun setAccentTheme(theme: AppAccentTheme) {
        context.dataStore.edit { prefs ->
            prefs[Keys.ACCENT_THEME] = theme.name
        }
    }

    suspend fun setHttpsMitmEnabled(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.HTTPS_MITM_ENABLED] = enabled
        }
    }

    suspend fun setCaptureMode(mode: CaptureEngineMode) {
        context.dataStore.edit { prefs ->
            prefs[Keys.CAPTURE_MODE] = mode.name
        }
    }

    suspend fun setProxyPort(port: Int) {
        context.dataStore.edit { prefs ->
            prefs[Keys.PROXY_PORT] = port.coerceIn(1024, 65535)
        }
    }

    suspend fun setForwardBaseUrl(url: String) {
        context.dataStore.edit { prefs ->
            prefs[Keys.FORWARD_BASE_URL] = url.trim()
        }
    }

    suspend fun setOnlyDecodableHttp(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.ONLY_DECODABLE_HTTP] = enabled
        }
    }
}
