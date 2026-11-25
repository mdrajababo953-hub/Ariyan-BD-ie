package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.components.AppIcons
import com.example.ui.theme.CyberObsidian
import com.example.ui.theme.ElectricCyan
import com.example.ui.theme.EmeraldPulse
import com.example.ui.theme.JetBrainsMonoFamily
import com.example.ui.theme.SpaceGroteskFamily
import com.example.ui.theme.VioletProto
import kotlinx.coroutines.delay
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun PremiumIntroScreen(
    onEnterClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    var showBadge by remember { mutableStateOf(false) }
    var showTitle by remember { mutableStateOf(false) }
    var showFeatures by remember { mutableStateOf(false) }
    var showButton by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        showBadge = true
        delay(120)
        showTitle = true
        delay(140)
        showFeatures = true
        delay(140)
        showButton = true
    }

    val infiniteTransition = rememberInfiniteTransition(label = "intro_orbit")
    val outerAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 14000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "outer_orbit"
    )
    val innerAngle by infiniteTransition.animateFloat(
        initialValue = 360f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 9000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "inner_orbit"
    )
    val sweepAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 4200, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "radar_sweep"
    )
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.72f,
        targetValue = 1.22f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "sonar_pulse"
    )
    val buttonGlow by infiniteTransition.animateFloat(
        initialValue = 0.45f,
        targetValue = 0.95f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1600, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "cta_glow"
    )

    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val pressScale by animateFloatAsState(
        targetValue = if (isPressed) 0.96f else 1f,
        animationSpec = spring(dampingRatio = 0.55f, stiffness = 500f),
        label = "press_scale"
    )

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF040810),
                        CyberObsidian,
                        Color(0xFF0A1220),
                        Color(0xFF050911)
                    )
                )
            )
    ) {
        // Cyber telemetry grid + ambient glow backdrop
        Canvas(modifier = Modifier.fillMaxSize()) {
            val step = 36.dp.toPx()
            val gridColor = ElectricCyan.copy(alpha = 0.045f)
            var x = 0f
            while (x <= size.width) {
                drawLine(gridColor, Offset(x, 0f), Offset(x, size.height), strokeWidth = 1f)
                x += step
            }
            var y = 0f
            while (y <= size.height) {
                drawLine(gridColor, Offset(0f, y), Offset(size.width, y), strokeWidth = 1f)
                y += step
            }

            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(
                        ElectricCyan.copy(alpha = 0.16f),
                        VioletProto.copy(alpha = 0.06f),
                        Color.Transparent
                    ),
                    center = Offset(size.width * 0.5f, size.height * 0.34f),
                    radius = size.minDimension * 0.65f
                ),
                radius = size.minDimension * 0.65f,
                center = Offset(size.width * 0.5f, size.height * 0.34f)
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing)
                .padding(horizontal = 24.dp, vertical = 22.dp)
        ) {
            // Top live status pill
            AnimatedVisibility(
                visible = showBadge,
                enter = fadeIn(tween(450)) + slideInVertically(tween(450)) { -24 }
            ) {
                Surface(
                    shape = CircleShape,
                    color = Color(0xFF0E1B2B).copy(alpha = 0.9f),
                    border = BorderStroke(1.dp, EmeraldPulse.copy(alpha = 0.45f))
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 7.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .background(EmeraldPulse, CircleShape)
                        )
                        Text(
                            text = "A9X ENGINE ONLINE • PRO SUITE",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = JetBrainsMonoFamily,
                                letterSpacing = 1.2.sp,
                                fontWeight = FontWeight.SemiBold
                            ),
                            color = EmeraldPulse
                        )
                    }
                }
            }

            // Centerpiece animated orbital radar + title
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.widthIn(max = 520.dp)
            ) {
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier.size(210.dp)
                ) {
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        val center = Offset(size.width / 2f, size.height / 2f)
                        val maxR = size.minDimension * 0.46f

                        // Expanding sonar wave
                        val pulseAlpha = (1f - (pulseScale - 0.72f) / 0.50f).coerceIn(0f, 0.38f)
                        drawCircle(
                            color = ElectricCyan.copy(alpha = pulseAlpha),
                            radius = maxR * 0.84f * pulseScale,
                            center = center,
                            style = Stroke(width = 1.8.dp.toPx())
                        )

                        // Radar sweep sector
                        rotate(degrees = sweepAngle, pivot = center) {
                            drawArc(
                                brush = Brush.sweepGradient(
                                    0.0f to Color.Transparent,
                                    0.72f to Color.Transparent,
                                    0.94f to ElectricCyan.copy(alpha = 0.22f),
                                    1.0f to ElectricCyan.copy(alpha = 0.48f),
                                    center = center
                                ),
                                startAngle = -75f,
                                sweepAngle = 75f,
                                useCenter = true,
                                topLeft = Offset(center.x - maxR * 0.88f, center.y - maxR * 0.88f),
                                size = Size(maxR * 1.76f, maxR * 1.76f)
                            )
                        }

                        // Outer segmented ring
                        rotate(degrees = outerAngle, pivot = center) {
                            val r = maxR
                            val rectTopLeft = Offset(center.x - r, center.y - r)
                            val arcSize = Size(r * 2f, r * 2f)
                            for (i in 0 until 4) {
                                drawArc(
                                    color = if (i % 2 == 0) ElectricCyan.copy(alpha = 0.85f) else VioletProto.copy(alpha = 0.75f),
                                    startAngle = i * 90f + 10f,
                                    sweepAngle = 56f,
                                    useCenter = false,
                                    topLeft = rectTopLeft,
                                    size = arcSize,
                                    style = Stroke(width = 2.6.dp.toPx(), cap = StrokeCap.Round)
                                )
                            }
                        }

                        // Inner counter-rotating ring
                        rotate(degrees = innerAngle, pivot = center) {
                            val r = maxR * 0.72f
                            val rectTopLeft = Offset(center.x - r, center.y - r)
                            val arcSize = Size(r * 2f, r * 2f)
                            for (i in 0 until 3) {
                                drawArc(
                                    color = if (i == 0) EmeraldPulse.copy(alpha = 0.85f) else ElectricCyan.copy(alpha = 0.45f),
                                    startAngle = i * 120f + 16f,
                                    sweepAngle = 78f,
                                    useCenter = false,
                                    topLeft = rectTopLeft,
                                    size = arcSize,
                                    style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
                                )
                            }
                        }

                        // Center hexagon shield
                        val hexR = maxR * 0.46f
                        val hexPath = Path().apply {
                            for (i in 0 until 6) {
                                val rad = (60.0 * i - 30.0) * PI / 180.0
                                val px = center.x + (hexR * cos(rad)).toFloat()
                                val py = center.y + (hexR * sin(rad)).toFloat()
                                if (i == 0) moveTo(px, py) else lineTo(px, py)
                            }
                            close()
                        }
                        drawPath(
                            path = hexPath,
                            brush = Brush.linearGradient(
                                colors = listOf(Color(0xFF0E2239), Color(0xFF1A1438))
                            )
                        )
                        drawPath(
                            path = hexPath,
                            brush = Brush.linearGradient(
                                colors = listOf(ElectricCyan, VioletProto)
                            ),
                            style = Stroke(width = 2.2.dp.toPx())
                        )
                    }

                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "A9X",
                            style = MaterialTheme.typography.headlineSmall.copy(
                                fontFamily = SpaceGroteskFamily,
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 24.sp,
                                letterSpacing = 2.sp
                            ),
                            color = ElectricCyan
                        )
                        Text(
                            text = "BD",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = JetBrainsMonoFamily,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 2.5.sp
                            ),
                            color = VioletProto
                        )
                    }
                }

                Spacer(modifier = Modifier.height(18.dp))

                AnimatedVisibility(
                    visible = showTitle,
                    enter = fadeIn(tween(520)) + slideInVertically(tween(520)) { 30 }
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "ARIYAN A9X",
                            style = MaterialTheme.typography.displaySmall.copy(
                                fontFamily = SpaceGroteskFamily,
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 34.sp,
                                letterSpacing = 1.6.sp
                            ),
                            color = Color(0xFFF8FAFC),
                            textAlign = TextAlign.Center
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = ElectricCyan.copy(alpha = 0.13f),
                            border = BorderStroke(1.dp, ElectricCyan.copy(alpha = 0.45f))
                        ) {
                            Text(
                                text = "BD CAPTURE • PRO EDITION",
                                style = MaterialTheme.typography.labelMedium.copy(
                                    fontFamily = JetBrainsMonoFamily,
                                    fontWeight = FontWeight.Bold,
                                    letterSpacing = 1.8.sp
                                ),
                                color = ElectricCyan,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)
                            )
                        }
                        Spacer(modifier = Modifier.height(14.dp))
                        Text(
                            text = "Real-time Per-App VPN & Local Proxy Interceptor with Automatic Protobuf-to-Python Package Builder",
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color(0xFF94A3B8),
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(horizontal = 8.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(22.dp))

                AnimatedVisibility(
                    visible = showFeatures,
                    enter = fadeIn(tween(520)) + slideInVertically(tween(520)) { 28 }
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        IntroFeaturePill(
                            icon = AppIcons.Shield,
                            label = "VPN + PROXY",
                            accent = ElectricCyan,
                            modifier = Modifier.weight(1f)
                        )
                        IntroFeaturePill(
                            icon = AppIcons.Code,
                            label = "AUTO PY PKG",
                            accent = VioletProto,
                            modifier = Modifier.weight(1f)
                        )
                        IntroFeaturePill(
                            icon = AppIcons.AutoFixHigh,
                            label = "PRO DECODE",
                            accent = EmeraldPulse,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }

            // Bottom glowing ENTER CTA
            AnimatedVisibility(
                visible = showButton,
                enter = fadeIn(tween(520)) + slideInVertically(tween(520)) { 40 }
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Surface(
                        shape = RoundedCornerShape(18.dp),
                        color = Color.Transparent,
                        border = BorderStroke(
                            width = 1.5.dp,
                            brush = Brush.horizontalGradient(
                                listOf(
                                    ElectricCyan.copy(alpha = buttonGlow),
                                    VioletProto.copy(alpha = buttonGlow),
                                    EmeraldPulse.copy(alpha = buttonGlow)
                                )
                            )
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .widthIn(max = 380.dp)
                            .scale(pressScale)
                    ) {
                        Button(
                            onClick = onEnterClick,
                            interactionSource = interactionSource,
                            shape = RoundedCornerShape(17.dp),
                            contentPadding = PaddingValues(vertical = 16.dp, horizontal = 24.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = ElectricCyan,
                                contentColor = Color(0xFF001F26)
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .minimumInteractiveComponentSize()
                                .testTag("enter_app_button")
                        ) {
                            Text(
                                text = "ENTER",
                                style = MaterialTheme.typography.titleMedium.copy(
                                    fontFamily = SpaceGroteskFamily,
                                    fontWeight = FontWeight.ExtraBold,
                                    letterSpacing = 2.4.sp
                                )
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                                contentDescription = "Enter ARIYAN A9X BD CAPTURE",
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = "Tap ENTER to launch Traffic & Package Capture",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = JetBrainsMonoFamily
                        ),
                        color = Color(0xFF64748B)
                    )
                }
            }
        }
    }
}

@Composable
private fun IntroFeaturePill(
    icon: ImageVector,
    label: String,
    accent: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = Color(0xFF0F1826).copy(alpha = 0.85f),
        border = BorderStroke(1.dp, accent.copy(alpha = 0.35f)),
        modifier = modifier
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(5.dp),
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 10.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = accent,
                modifier = Modifier.size(18.dp)
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = JetBrainsMonoFamily,
                    fontWeight = FontWeight.Bold,
                    fontSize = 9.5.sp
                ),
                color = Color(0xFFE2E8F0),
                maxLines = 1
            )
        }
    }
}
