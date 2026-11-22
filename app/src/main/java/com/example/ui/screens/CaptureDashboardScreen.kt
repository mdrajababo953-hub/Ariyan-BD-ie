package com.example.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.apps.InstalledAppInfo
import com.example.data.db.CaptureSessionEntity
import com.example.data.db.CapturedPacketEntity
import com.example.data.prefs.TargetAppSelection
import com.example.ui.components.AppIconAvatar
import com.example.ui.components.AppIcons
import com.example.ui.components.Formatters
import com.example.ui.components.PacketRowCard
import com.example.ui.components.TagChip
import com.example.ui.theme.CoralAlert
import com.example.ui.theme.EmeraldPulse
import com.example.ui.theme.JetBrainsMonoFamily
import com.example.ui.viewmodel.PacketFilterChip
import com.example.vpn.VpnRuntimeState

@Composable
fun CaptureDashboardScreen(
    targetApp: TargetAppSelection,
    targetAppInfo: InstalledAppInfo?,
    vpnState: VpnRuntimeState,
    activeSession: CaptureSessionEntity?,
    packets: List<CapturedPacketEntity>,
    selectedPacket: CapturedPacketEntity?,
    searchQuery: String,
    activeFilter: PacketFilterChip,
    httpsMitmEnabled: Boolean,
    caReady: Boolean,
    onToggleHttpsMitm: (Boolean) -> Unit,
    onInstallCaCert: () -> Unit,
    onSaveCaCert: () -> Unit,
    onSearchChange: (String) -> Unit,
    onFilterChange: (PacketFilterChip) -> Unit,
    onOpenTargetPicker: () -> Unit,
    onStartCapture: () -> Unit,
    onStopCapture: () -> Unit,
    onOpenImportDialog: () -> Unit,
    onExportSessionJson: () -> Unit,
    onOpenFullDecode: () -> Unit,
    onSelectPacket: (CapturedPacketEntity) -> Unit,
    onDeletePacket: (CapturedPacketEntity) -> Unit,
    onShareJson: (String) -> Unit,
    onSendToDecoderLab: (String) -> Unit,
    onCopyToast: (String) -> Unit
) {
    var packetPendingDelete by remember { mutableStateOf<CapturedPacketEntity?>(null) }

    packetPendingDelete?.let { pkt ->
        AlertDialog(
            onDismissRequest = { packetPendingDelete = null },
            icon = {
                Icon(
                    imageVector = Icons.Default.Delete,
                    contentDescription = null,
                    tint = CoralAlert
                )
            },
            title = { Text("Delete Captured Request?") },
            text = {
                Text(
                    text = "Remove ${pkt.method} ${pkt.path.ifBlank { pkt.host }} from this capture session?",
                    style = MaterialTheme.typography.bodyMedium
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        onDeletePacket(pkt)
                        packetPendingDelete = null
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = CoralAlert),
                    modifier = Modifier.testTag("confirm_delete_packet_button")
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { packetPendingDelete = null }) {
                    Text("Cancel")
                }
            }
        )
    }
    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val isExpanded = maxWidth >= 840.dp

        if (isExpanded) {
            Row(modifier = Modifier.fillMaxSize()) {
                CaptureListPane(
                    targetApp = targetApp,
                    targetAppInfo = targetAppInfo,
                    vpnState = vpnState,
                    activeSession = activeSession,
                    packets = packets,
                    selectedPacketId = selectedPacket?.id,
                    searchQuery = searchQuery,
                    activeFilter = activeFilter,
                    httpsMitmEnabled = httpsMitmEnabled,
                    caReady = caReady,
                    onToggleHttpsMitm = onToggleHttpsMitm,
                    onInstallCaCert = onInstallCaCert,
                    onSaveCaCert = onSaveCaCert,
                    onSearchChange = onSearchChange,
                    onFilterChange = onFilterChange,
                    onOpenTargetPicker = onOpenTargetPicker,
                    onStartCapture = onStartCapture,
                    onStopCapture = onStopCapture,
                    onOpenImportDialog = onOpenImportDialog,
                    onExportSessionJson = onExportSessionJson,
                    onOpenFullDecode = onOpenFullDecode,
                    onSelectPacket = onSelectPacket,
                    onLongClickPacket = { packetPendingDelete = it },
                    modifier = Modifier
                        .weight(0.46f)
                        .fillMaxHeight()
                )
                VerticalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
                Box(
                    modifier = Modifier
                        .weight(0.54f)
                        .fillMaxHeight()
                ) {
                    if (selectedPacket != null) {
                        PacketDetailScreen(
                            packet = selectedPacket,
                            isPaneMode = true,
                            onBack = {},
                            onShareJson = onShareJson,
                            onSendToDecoderLab = onSendToDecoderLab,
                            onCopyToast = onCopyToast
                        )
                    } else {
                        EmptyDetailPlaceholder()
                    }
                }
            }
        } else {
            CaptureListPane(
                targetApp = targetApp,
                targetAppInfo = targetAppInfo,
                vpnState = vpnState,
                activeSession = activeSession,
                packets = packets,
                selectedPacketId = selectedPacket?.id,
                searchQuery = searchQuery,
                activeFilter = activeFilter,
                httpsMitmEnabled = httpsMitmEnabled,
                caReady = caReady,
                onToggleHttpsMitm = onToggleHttpsMitm,
                onInstallCaCert = onInstallCaCert,
                onSaveCaCert = onSaveCaCert,
                onSearchChange = onSearchChange,
                onFilterChange = onFilterChange,
                onOpenTargetPicker = onOpenTargetPicker,
                onStartCapture = onStartCapture,
                onStopCapture = onStopCapture,
                onOpenImportDialog = onOpenImportDialog,
                onExportSessionJson = onExportSessionJson,
                onOpenFullDecode = onOpenFullDecode,
                onSelectPacket = onSelectPacket,
                onLongClickPacket = { packetPendingDelete = it },
                modifier = Modifier.fillMaxSize()
            )
        }
    }
}

@Composable
private fun CaptureListPane(
    targetApp: TargetAppSelection,
    targetAppInfo: InstalledAppInfo?,
    vpnState: VpnRuntimeState,
    activeSession: CaptureSessionEntity?,
    packets: List<CapturedPacketEntity>,
    selectedPacketId: Long?,
    searchQuery: String,
    activeFilter: PacketFilterChip,
    httpsMitmEnabled: Boolean,
    caReady: Boolean,
    onToggleHttpsMitm: (Boolean) -> Unit,
    onInstallCaCert: () -> Unit,
    onSaveCaCert: () -> Unit,
    onSearchChange: (String) -> Unit,
    onFilterChange: (PacketFilterChip) -> Unit,
    onOpenTargetPicker: () -> Unit,
    onStartCapture: () -> Unit,
    onStopCapture: () -> Unit,
    onOpenImportDialog: () -> Unit,
    onExportSessionJson: () -> Unit,
    onOpenFullDecode: () -> Unit,
    onSelectPacket: (CapturedPacketEntity) -> Unit,
    onLongClickPacket: (CapturedPacketEntity) -> Unit,
    modifier: Modifier = Modifier
) {
    LazyColumn(
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = modifier
    ) {
        item {
            TargetIsolationHeroCard(
                targetApp = targetApp,
                targetAppInfo = targetAppInfo,
                vpnState = vpnState,
                httpsMitmEnabled = httpsMitmEnabled,
                caReady = caReady,
                onToggleHttpsMitm = onToggleHttpsMitm,
                onInstallCaCert = onInstallCaCert,
                onSaveCaCert = onSaveCaCert,
                onOpenTargetPicker = onOpenTargetPicker,
                onStartCapture = onStartCapture,
                onStopCapture = onStopCapture
            )
        }

        if (vpnState.errorMessage != null) {
            item {
                Surface(
                    color = CoralAlert.copy(alpha = 0.14f),
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, CoralAlert.copy(alpha = 0.5f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = vpnState.errorMessage,
                        style = MaterialTheme.typography.bodySmall,
                        color = CoralAlert,
                        modifier = Modifier.padding(12.dp)
                    )
                }
            }
        }

        item {
            SessionTelemetryBar(
                activeSession = activeSession,
                vpnState = vpnState,
                onOpenImportDialog = onOpenImportDialog,
                onExportSessionJson = onExportSessionJson,
                onOpenFullDecode = onOpenFullDecode
            )
        }

        item {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = onSearchChange,
                placeholder = { Text("Filter by endpoint, host, method, hex...") },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                trailingIcon = {
                    if (searchQuery.isNotEmpty()) {
                        IconButton(onClick = { onSearchChange("") }) {
                            Icon(Icons.Default.Close, contentDescription = stringResource(R.string.cd_clear_search))
                        }
                    }
                },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("packet_search_input")
            )
        }

        item {
            LazyRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                items(PacketFilterChip.entries) { chip ->
                    FilterChip(
                        selected = activeFilter == chip,
                        onClick = { onFilterChange(chip) },
                        label = { Text(chip.label) },
                        modifier = Modifier.testTag("filter_chip_${chip.name.lowercase()}")
                    )
                }
            }
        }

        if (packets.isEmpty()) {
            item {
                EmptyPacketsState(
                    isRunning = vpnState.isRunning,
                    onOpenImportDialog = onOpenImportDialog
                )
            }
        } else {
            items(packets, key = { it.id }) { packet ->
                PacketRowCard(
                    packet = packet,
                    isSelected = packet.id == selectedPacketId,
                    onClick = { onSelectPacket(packet) },
                    onLongClick = { onLongClickPacket(packet) },
                    modifier = Modifier.testTag("packet_card_${packet.id}")
                )
            }
        }
    }
}

@Composable
private fun TargetIsolationHeroCard(
    targetApp: TargetAppSelection,
    targetAppInfo: InstalledAppInfo?,
    vpnState: VpnRuntimeState,
    httpsMitmEnabled: Boolean,
    caReady: Boolean,
    onToggleHttpsMitm: (Boolean) -> Unit,
    onInstallCaCert: () -> Unit,
    onSaveCaCert: () -> Unit,
    onOpenTargetPicker: () -> Unit,
    onStartCapture: () -> Unit,
    onStopCapture: () -> Unit
) {
    val isLive = vpnState.isRunning
    val accentColor by animateColorAsState(
        targetValue = if (isLive) EmeraldPulse else MaterialTheme.colorScheme.primary,
        label = "vpn_accent"
    )
    val pulseTransition = rememberInfiniteTransition(label = "pulse")
    val pulseRadius by pulseTransition.animateFloat(
        initialValue = 0.6f,
        targetValue = 1.15f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_radius"
    )

    Surface(
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.5.dp, accentColor.copy(alpha = if (isLive) 0.7f else 0.45f)),
        tonalElevation = 4.dp,
        modifier = Modifier.fillMaxWidth()
    ) {
        Box {
            Canvas(
                modifier = Modifier
                    .matchParentSize()
                    .clip(RoundedCornerShape(20.dp))
            ) {
                drawRect(
                    brush = Brush.linearGradient(
                        colors = listOf(
                            accentColor.copy(alpha = 0.14f),
                            Color.Transparent
                        ),
                        start = Offset(0f, 0f),
                        end = Offset(size.width, size.height)
                    )
                )
                val center = Offset(size.width * 0.88f, size.height * 0.25f)
                if (isLive) {
                    drawCircle(
                        color = accentColor.copy(alpha = (1.2f - pulseRadius).coerceIn(0f, 0.35f)),
                        radius = 52.dp.toPx() * pulseRadius,
                        center = center,
                        style = Stroke(width = 2.dp.toPx())
                    )
                }
                drawCircle(
                    color = accentColor.copy(alpha = 0.09f),
                    radius = 68.dp.toPx(),
                    center = center,
                    style = Stroke(width = 1.dp.toPx())
                )
            }

            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    TagChip(
                        text = if (isLive) "LIVE CAPTURE" else "PER-APP ISOLATED",
                        color = accentColor,
                        icon = if (isLive) AppIcons.Radar else AppIcons.Shield
                    )
                    Spacer(modifier = Modifier.weight(1f))
                    Text(
                        text = "VPN TUN • NO ROOT",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Spacer(modifier = Modifier.height(14.dp))

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    AppIconAvatar(
                        drawable = targetAppInfo?.icon,
                        fallbackLetter = targetApp.appName.ifBlank { "NT" },
                        size = 50.dp
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = targetApp.appName.ifBlank { "No Target Selected" },
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = targetApp.packageName.ifBlank { "Tap Select Target to pick a game/app" },
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        if (targetApp.uid > 0) {
                            Text(
                                text = "UID ${targetApp.uid} • Other apps bypassed",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Row(
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    OutlinedButton(
                        onClick = onOpenTargetPicker,
                        enabled = !isLive,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp)
                            .testTag("select_target_button")
                    ) {
                        Icon(AppIcons.Apps, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Target App")
                    }

                    Button(
                        onClick = if (isLive) onStopCapture else onStartCapture,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isLive) CoralAlert else MaterialTheme.colorScheme.primary,
                            contentColor = if (isLive) Color.White else MaterialTheme.colorScheme.onPrimary
                        ),
                        modifier = Modifier
                            .weight(1.15f)
                            .height(48.dp)
                            .testTag("toggle_vpn_capture_button")
                    ) {
                        Icon(
                            imageVector = if (isLive) AppIcons.Stop else Icons.Default.PlayArrow,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = stringResource(
                                if (isLive) R.string.action_stop_capture else R.string.action_start_capture
                            ),
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                    border = BorderStroke(
                        1.dp,
                        if (httpsMitmEnabled) MaterialTheme.colorScheme.primary.copy(alpha = 0.35f)
                        else MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            FilterChip(
                                selected = httpsMitmEnabled,
                                onClick = { onToggleHttpsMitm(!httpsMitmEnabled) },
                                enabled = !isLive,
                                leadingIcon = {
                                    Icon(
                                        imageVector = if (httpsMitmEnabled) AppIcons.LockOpen else AppIcons.Key,
                                        contentDescription = null,
                                        modifier = Modifier.size(16.dp)
                                    )
                                },
                                label = {
                                    Text(
                                        text = if (httpsMitmEnabled) "HTTPS Decrypt ON" else "HTTPS Decrypt OFF",
                                        maxLines = 1
                                    )
                                },
                                modifier = Modifier.testTag("https_mitm_toggle")
                            )

                            Spacer(modifier = Modifier.weight(1f))

                            FilledTonalButton(
                                onClick = onInstallCaCert,
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                                modifier = Modifier
                                    .height(36.dp)
                                    .testTag("install_ca_button")
                            ) {
                                Icon(
                                    imageVector = AppIcons.Key,
                                    contentDescription = null,
                                    modifier = Modifier.size(15.dp)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text(
                                    text = if (caReady) "Trust CA" else "Install CA",
                                    style = MaterialTheme.typography.labelMedium
                                )
                            }

                            IconButton(
                                onClick = onSaveCaCert,
                                modifier = Modifier
                                    .size(36.dp)
                                    .testTag("save_ca_button")
                            ) {
                                Icon(
                                    imageVector = AppIcons.FileDownload,
                                    contentDescription = "Save NetTrace CA to Aryan folder",
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }

                        Text(
                            text = when {
                                !httpsMitmEnabled -> "Passthrough mode: TLS SNI captured without decrypting HTTPS URLs."
                                vpnState.isRunning && !vpnState.caTrusted ->
                                    "CA not trusted yet — passthrough active so game stays online. Install & trust NetTrace CA to decrypt HTTPS URLs."
                                vpnState.pinningBypassCount > 0 ->
                                    "${vpnState.pinningBypassCount} host(s) enforced SSL Pinning & auto-bypassed to keep traffic alive."
                                else ->
                                    "Install & trust NetTrace CA (User Cert) to decrypt HTTPS endpoints like /UpdateSocialBasicInfo."
                            },
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SessionTelemetryBar(
    activeSession: CaptureSessionEntity?,
    vpnState: VpnRuntimeState,
    onOpenImportDialog: () -> Unit,
    onExportSessionJson: () -> Unit,
    onOpenFullDecode: () -> Unit
) {
    val pktCount = if (vpnState.isRunning) vpnState.packetCount else activeSession?.packetCount ?: 0
    val blkCount = if (vpnState.isRunning) vpnState.blockedCount else activeSession?.blockedCount ?: 0
    val totalBytes = if (vpnState.isRunning) vpnState.totalBytes else activeSession?.totalBytes ?: 0L

    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.45f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = activeSession?.title ?: "No Active Session",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "$pktCount packets • $blkCount blocked • ${Formatters.formatBytes(totalBytes)}",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFamily),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                IconButton(
                    onClick = onOpenImportDialog,
                    modifier = Modifier.testTag("import_raw_button")
                ) {
                    Icon(
                        AppIcons.UploadFile,
                        contentDescription = stringResource(R.string.action_import_raw),
                        tint = MaterialTheme.colorScheme.primary
                    )
                }

                IconButton(
                    onClick = onExportSessionJson,
                    enabled = activeSession != null,
                    modifier = Modifier.testTag("export_session_json_button")
                ) {
                    Icon(
                        AppIcons.FileDownload,
                        contentDescription = stringResource(R.string.action_export_json),
                        tint = if (activeSession != null) EmeraldPulse else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            if (activeSession != null) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    FilledTonalButton(
                        onClick = onOpenFullDecode,
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(38.dp)
                            .testTag("full_decode_button")
                    ) {
                        Icon(
                            AppIcons.AutoFixHigh,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Full Decode (Save to Aryan)",
                            style = MaterialTheme.typography.labelMedium
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun EmptyPacketsState(
    isRunning: Boolean,
    onOpenImportDialog: () -> Unit
) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(24.dp)
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(56.dp)
                    .background(MaterialTheme.colorScheme.primaryContainer, CircleShape)
            ) {
                Icon(
                    imageVector = if (isRunning) AppIcons.Radar else AppIcons.DataObject,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp)
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = if (isRunning) "Listening for Target App Packets..." else "No Matching Requests",
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = if (isRunning) {
                    "Launch or interact with your target game/app. All HTTP, TLS, DNS & UDP traffic will stream here."
                } else {
                    "Clear your search filter, switch filter to All, start VPN capture, or import a raw HTTP/Hex dump."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (!isRunning) {
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedButton(onClick = onOpenImportDialog) {
                    Icon(AppIcons.UploadFile, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Import Raw Capture")
                }
            }
        }
    }
}

@Composable
private fun EmptyDetailPlaceholder() {
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier.fillMaxSize()
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(24.dp)
        ) {
            Icon(
                imageVector = AppIcons.Code,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.7f),
                modifier = Modifier.size(48.dp)
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = "Select a Captured Request",
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Tap any packet to inspect JSON, JWT & Protobuf. Hold a packet to delete it.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
