package com.example.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

private val NetTraceDarkScheme = darkColorScheme(
    primary = ElectricCyan,
    onPrimary = Color(0xFF002026),
    primaryContainer = DeepCyanContainer,
    onPrimaryContainer = LightCyanTint,
    secondary = EmeraldPulse,
    onSecondary = Color(0xFF002116),
    secondaryContainer = EmeraldContainer,
    onSecondaryContainer = Color(0xFFA7F3D0),
    tertiary = AmberSignal,
    onTertiary = Color(0xFF281800),
    tertiaryContainer = AmberContainer,
    onTertiaryContainer = Color(0xFFFDE68A),
    error = CoralAlert,
    onError = Color.White,
    errorContainer = CoralContainer,
    onErrorContainer = Color(0xFFFECACA),
    background = CyberObsidian,
    onBackground = TextPrimaryDark,
    surface = CyberSurface,
    onSurface = TextPrimaryDark,
    surfaceVariant = CyberSurfaceVariant,
    onSurfaceVariant = TextSecondaryDark,
    surfaceContainerHigh = CyberSurfaceHigh,
    outline = CyberOutline
)

private val NetTraceLightScheme = lightColorScheme(
    primary = PrimaryOcean,
    onPrimary = Color.White,
    primaryContainer = PrimaryOceanContainer,
    onPrimaryContainer = Color(0xFF002635),
    secondary = Color(0xFF059669),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFD1FAE5),
    onSecondaryContainer = Color(0xFF064E3B),
    tertiary = Color(0xFFD97706),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFFEF3C7),
    onTertiaryContainer = Color(0xFF78350F),
    error = Color(0xFFDC2626),
    onError = Color.White,
    errorContainer = Color(0xFFFEE2E2),
    onErrorContainer = Color(0xFF7F1D1D),
    background = LightCanvas,
    onBackground = TextPrimaryLight,
    surface = LightSurface,
    onSurface = TextPrimaryLight,
    surfaceVariant = LightSurfaceVariant,
    onSurfaceVariant = TextSecondaryLight,
    surfaceContainerHigh = Color(0xFFEDF2F7),
    outline = LightOutline
)

val NetTraceShapes = Shapes(
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(28.dp)
)

@Composable
fun NetTraceTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) NetTraceDarkScheme else NetTraceLightScheme
    MaterialTheme(
        colorScheme = colorScheme,
        typography = NetTraceTypography,
        shapes = NetTraceShapes,
        content = content
    )
}
