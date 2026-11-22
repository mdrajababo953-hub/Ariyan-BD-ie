package com.example.ui.theme

import androidx.compose.ui.graphics.Color

// Tactical Telemetry Dark Palette
val CyberObsidian = Color(0xFF080D14)
val CyberSurface = Color(0xFF0F1722)
val CyberSurfaceVariant = Color(0xFF172233)
val CyberSurfaceHigh = Color(0xFF1E2C42)
val CyberOutline = Color(0xFF283A54)

val ElectricCyan = Color(0xFF00E5FF)
val DeepCyanContainer = Color(0xFF003B47)
val LightCyanTint = Color(0xFFA6F7FF)

val EmeraldPulse = Color(0xFF10B981)
val EmeraldContainer = Color(0xFF063A2A)
val AmberSignal = Color(0xFFF59E0B)
val AmberContainer = Color(0xFF422904)
val CoralAlert = Color(0xFFEF4444)
val CoralContainer = Color(0xFF450E12)
val VioletProto = Color(0xFFA78BFA)
val VioletContainer = Color(0xFF2B1E52)

val TextPrimaryDark = Color(0xFFF1F5F9)
val TextSecondaryDark = Color(0xFF94A3B8)

// Crisp Light Palette
val LightCanvas = Color(0xFFF3F6FA)
val LightSurface = Color(0xFFFFFFFF)
val LightSurfaceVariant = Color(0xFFE6ECF5)
val LightOutline = Color(0xFFCBD5E1)
val PrimaryOcean = Color(0xFF007EA7)
val PrimaryOceanContainer = Color(0xFFD0F0FF)
val TextPrimaryLight = Color(0xFF0F172A)
val TextSecondaryLight = Color(0xFF475569)

enum class AppAccentTheme(
    val displayName: String,
    val darkPrimary: Color,
    val darkOnPrimary: Color,
    val darkContainer: Color,
    val darkOnContainer: Color,
    val lightPrimary: Color,
    val lightContainer: Color,
    val lightOnContainer: Color
) {
    CYAN(
        displayName = "Cyan",
        darkPrimary = Color(0xFF00E5FF),
        darkOnPrimary = Color(0xFF002026),
        darkContainer = Color(0xFF003B47),
        darkOnContainer = Color(0xFFA6F7FF),
        lightPrimary = Color(0xFF007EA7),
        lightContainer = Color(0xFFD0F0FF),
        lightOnContainer = Color(0xFF002635)
    ),
    EMERALD(
        displayName = "Emerald",
        darkPrimary = Color(0xFF10B981),
        darkOnPrimary = Color(0xFF002116),
        darkContainer = Color(0xFF063A2A),
        darkOnContainer = Color(0xFFA7F3D0),
        lightPrimary = Color(0xFF059669),
        lightContainer = Color(0xFFD1FAE5),
        lightOnContainer = Color(0xFF064E3B)
    ),
    VIOLET(
        displayName = "Violet",
        darkPrimary = Color(0xFFA78BFA),
        darkOnPrimary = Color(0xFF1E1042),
        darkContainer = Color(0xFF2B1E52),
        darkOnContainer = Color(0xFFEDE9FE),
        lightPrimary = Color(0xFF7C3AED),
        lightContainer = Color(0xFFEDE9FE),
        lightOnContainer = Color(0xFF2E1065)
    ),
    AMBER(
        displayName = "Amber",
        darkPrimary = Color(0xFFF59E0B),
        darkOnPrimary = Color(0xFF281800),
        darkContainer = Color(0xFF422904),
        darkOnContainer = Color(0xFFFDE68A),
        lightPrimary = Color(0xFFD97706),
        lightContainer = Color(0xFFFEF3C7),
        lightOnContainer = Color(0xFF78350F)
    ),
    CRIMSON(
        displayName = "Crimson",
        darkPrimary = Color(0xFFF43F5E),
        darkOnPrimary = Color.White,
        darkContainer = Color(0xFF4C0519),
        darkOnContainer = Color(0xFFFFE4E6),
        lightPrimary = Color(0xFFE11D48),
        lightContainer = Color(0xFFFFE4E6),
        lightOnContainer = Color(0xFF881337)
    ),
    COBALT(
        displayName = "Cobalt",
        darkPrimary = Color(0xFF3B82F6),
        darkOnPrimary = Color.White,
        darkContainer = Color(0xFF172554),
        darkOnContainer = Color(0xFFDBEAFE),
        lightPrimary = Color(0xFF2563EB),
        lightContainer = Color(0xFFDBEAFE),
        lightOnContainer = Color(0xFF1E3A8A)
    );

    companion object {
        fun fromName(name: String?): AppAccentTheme {
            return entries.firstOrNull { it.name.equals(name, ignoreCase = true) } ?: CYAN
        }
    }
}
