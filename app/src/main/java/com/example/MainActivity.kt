package com.example

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.components.AppIcons
import com.example.ui.components.TagChip
import com.example.ui.screens.CaptureDashboardScreen
import com.example.ui.screens.DecoderLabScreen
import com.example.ui.screens.FullDecodeDialog
import com.example.ui.screens.ImportRawDialog
import com.example.ui.screens.PacketDetailScreen
import com.example.ui.screens.SessionsScreen
import com.example.ui.screens.TargetAppPickerSheet
import com.example.ui.screens.TrafficRulesScreen
import com.example.ui.theme.AppAccentTheme
import com.example.ui.theme.EmeraldPulse
import com.example.ui.theme.NetTraceTheme
import com.example.ui.viewmodel.NetTraceViewModel
import kotlinx.coroutines.launch

enum class MainTab(
    val labelRes: Int,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
    val testTag: String
) {
    CAPTURE(R.string.nav_capture, AppIcons.Radar, AppIcons.Radar, "nav_capture"),
    SESSIONS(R.string.nav_sessions, AppIcons.Folder, AppIcons.FolderOpen, "nav_sessions"),
    RULES(R.string.nav_rules, AppIcons.Shield, AppIcons.ShieldOutlined, "nav_rules"),
    DECODER(R.string.nav_decoder, AppIcons.Code, AppIcons.Code, "nav_decoder")
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            NetTraceRoot()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NetTraceRoot(vm: NetTraceViewModel = viewModel()) {
    val context = LocalContext.current
    val settings by vm.settings.collectAsStateWithLifecycle()
    val vpnState by vm.vpnState.collectAsStateWithLifecycle()
    val sessions by vm.sessions.collectAsStateWithLifecycle()
    val activeSession by vm.activeSession.collectAsStateWithLifecycle()
    val packets by vm.filteredPackets.collectAsStateWithLifecycle()
    val selectedPacket by vm.selectedPacket.collectAsStateWithLifecycle()
    val searchQuery by vm.searchQuery.collectAsStateWithLifecycle()
    val filterChip by vm.filterChip.collectAsStateWithLifecycle()
    val installedApps by vm.installedApps.collectAsStateWithLifecycle()
    val isLoadingApps by vm.isLoadingApps.collectAsStateWithLifecycle()
    val trafficRules by vm.trafficRules.collectAsStateWithLifecycle()
    val decoderLabState by vm.decoderLab.collectAsStateWithLifecycle()
    val fullDecodeState by vm.fullDecodeState.collectAsStateWithLifecycle()
    val caReady by vm.caReady.collectAsStateWithLifecycle()
    val snackbarMsg by vm.snackbarMessage.collectAsStateWithLifecycle()

    var currentTab by remember { mutableStateOf(MainTab.CAPTURE) }
    var showTargetPicker by remember { mutableStateOf(false) }
    var showImportDialog by remember { mutableStateOf(false) }
    var showColorMenu by remember { mutableStateOf(false) }

    val snackbarHostState = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()

    LaunchedEffect(snackbarMsg) {
        snackbarMsg?.let { msg ->
            snackbarHostState.showSnackbar(msg)
            vm.consumeSnackbar()
        }
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            vm.startVpnCapture()
        } else {
            coroutineScope.launch {
                snackbarHostState.showSnackbar("VPN permission is required for per-app traffic capture.")
            }
        }
    }

    val launchVpnCapture: () -> Unit = {
        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            vm.startVpnCapture()
        }
    }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) {
        // Start VPN regardless; notification permission only affects status bar visibility
        launchVpnCapture()
    }

    val caInstallLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            coroutineScope.launch {
                snackbarHostState.showSnackbar("NetTrace Proxy CA installed — HTTPS decryption ready.")
            }
        } else {
            coroutineScope.launch {
                snackbarHostState.showSnackbar("Tip: Use Save CA button and install via Settings → Security → CA certificate.")
            }
        }
    }

    val launchCaInstall: () -> Unit = {
        vm.prepareCaInstallIntent { intent ->
            runCatching { caInstallLauncher.launch(intent) }
                .onFailure { vm.saveCaCertToAryan() }
        }
    }

    val startCaptureWithPermissions: () -> Unit = {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            launchVpnCapture()
        }
    }

    val shareJsonText: (String) -> Unit = { jsonText ->
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_SUBJECT, "NetTrace Capture JSON")
            putExtra(Intent.EXTRA_TEXT, jsonText)
        }
        context.startActivity(Intent.createChooser(intent, "Share Captured JSON"))
    }

    val targetAppInfo = remember(installedApps, settings.targetApp.packageName) {
        installedApps.firstOrNull { it.packageName == settings.targetApp.packageName }
    }

    NetTraceTheme(
        darkTheme = settings.darkTheme,
        accentTheme = settings.accentTheme
    ) {
        BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
            val useRail = maxWidth >= 600.dp
            val isExpanded = maxWidth >= 840.dp

            // Compact phones open full-screen PacketDetailScreen when a packet is selected
            if (!isExpanded && currentTab == MainTab.CAPTURE && selectedPacket != null) {
                PacketDetailScreen(
                    packet = selectedPacket!!,
                    isPaneMode = false,
                    onBack = { vm.selectPacket(null) },
                    onShareJson = shareJsonText,
                    onSendToDecoderLab = { hex ->
                        vm.sendHexToDecoderLab(hex)
                        vm.selectPacket(null)
                        currentTab = MainTab.DECODER
                    },
                    onCopyToast = { msg ->
                        coroutineScope.launch { snackbarHostState.showSnackbar(msg) }
                    }
                )
            } else {
                Scaffold(
                    contentWindowInsets = WindowInsets.safeDrawing,
                    snackbarHost = { SnackbarHost(snackbarHostState) },
                    topBar = {
                        TopAppBar(
                            title = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = stringResource(R.string.app_name),
                                        style = MaterialTheme.typography.titleLarge
                                    )
                                    if (vpnState.isRunning) {
                                        Spacer(modifier = Modifier.width(10.dp))
                                        TagChip(text = "VPN ACTIVE", color = EmeraldPulse)
                                    }
                                }
                            },
                            actions = {
                                Box {
                                    IconButton(
                                        onClick = { showColorMenu = true },
                                        modifier = Modifier.testTag("accent_color_picker_button")
                                    ) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Icon(
                                                imageVector = AppIcons.Palette,
                                                contentDescription = "Choose accent color",
                                                tint = MaterialTheme.colorScheme.primary,
                                                modifier = Modifier.size(21.dp)
                                            )
                                        }
                                    }

                                    DropdownMenu(
                                        expanded = showColorMenu,
                                        onDismissRequest = { showColorMenu = false }
                                    ) {
                                        Column(
                                            verticalArrangement = Arrangement.spacedBy(8.dp),
                                            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)
                                        ) {
                                            Text(
                                                text = "Theme Color",
                                                style = MaterialTheme.typography.labelMedium,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                            Row(
                                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                AppAccentTheme.entries.forEach { option ->
                                                    val swatchColor = if (settings.darkTheme) option.darkPrimary else option.lightPrimary
                                                    val selected = settings.accentTheme == option
                                                    Box(
                                                        contentAlignment = Alignment.Center,
                                                        modifier = Modifier
                                                            .size(32.dp)
                                                            .clip(CircleShape)
                                                            .background(swatchColor)
                                                            .then(
                                                                if (selected) {
                                                                    Modifier.border(
                                                                        2.dp,
                                                                        MaterialTheme.colorScheme.onSurface,
                                                                        CircleShape
                                                                    )
                                                                } else Modifier
                                                            )
                                                            .clickable {
                                                                vm.setAccentTheme(option)
                                                                showColorMenu = false
                                                            }
                                                            .testTag("accent_swatch_${option.name.lowercase()}")
                                                    ) {
                                                        if (selected) {
                                                            Icon(
                                                                imageVector = Icons.Default.Check,
                                                                contentDescription = option.displayName,
                                                                tint = if (settings.darkTheme) option.darkOnPrimary else MaterialTheme.colorScheme.onPrimary,
                                                                modifier = Modifier.size(16.dp)
                                                            )
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                IconButton(
                                    onClick = { vm.toggleTheme() },
                                    modifier = Modifier.testTag("theme_toggle_button")
                                ) {
                                    Icon(
                                        imageVector = if (settings.darkTheme) AppIcons.LightMode else AppIcons.DarkMode,
                                        contentDescription = "Toggle theme",
                                        modifier = Modifier.size(22.dp)
                                    )
                                }
                            },
                            colors = TopAppBarDefaults.topAppBarColors(
                                containerColor = MaterialTheme.colorScheme.background
                            )
                        )
                    },
                    bottomBar = {
                        if (!useRail) {
                            NavigationBar(
                                containerColor = MaterialTheme.colorScheme.surface
                            ) {
                                MainTab.entries.forEach { tab ->
                                    val selected = currentTab == tab
                                    NavigationBarItem(
                                        selected = selected,
                                        onClick = { currentTab = tab },
                                        icon = {
                                            Icon(
                                                imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                                                contentDescription = stringResource(tab.labelRes)
                                            )
                                        },
                                        label = { Text(stringResource(tab.labelRes)) },
                                        modifier = Modifier.testTag(tab.testTag)
                                    )
                                }
                            }
                        }
                    }
                ) { innerPadding ->
                    Row(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding)
                    ) {
                        if (useRail) {
                            NavigationRail(
                                containerColor = MaterialTheme.colorScheme.surface,
                                modifier = Modifier.fillMaxHeight()
                            ) {
                                MainTab.entries.forEach { tab ->
                                    val selected = currentTab == tab
                                    NavigationRailItem(
                                        selected = selected,
                                        onClick = { currentTab = tab },
                                        icon = {
                                            Icon(
                                                imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                                                contentDescription = stringResource(tab.labelRes)
                                            )
                                        },
                                        label = { Text(stringResource(tab.labelRes)) },
                                        modifier = Modifier.testTag(tab.testTag)
                                    )
                                }
                            }
                        }

                        Box(modifier = Modifier.weight(1f).fillMaxHeight()) {
                            when (currentTab) {
                                MainTab.CAPTURE -> CaptureDashboardScreen(
                                    targetApp = settings.targetApp,
                                    targetAppInfo = targetAppInfo,
                                    vpnState = vpnState,
                                    activeSession = activeSession,
                                    packets = packets,
                                    selectedPacket = selectedPacket,
                                    searchQuery = searchQuery,
                                    activeFilter = filterChip,
                                    httpsMitmEnabled = settings.httpsMitmEnabled,
                                    caReady = caReady,
                                    onToggleHttpsMitm = vm::toggleHttpsMitm,
                                    onInstallCaCert = launchCaInstall,
                                    onSaveCaCert = vm::saveCaCertToAryan,
                                    onSearchChange = vm::setSearchQuery,
                                    onFilterChange = vm::setFilterChip,
                                    onOpenTargetPicker = { showTargetPicker = true },
                                    onStartCapture = startCaptureWithPermissions,
                                    onStopCapture = vm::stopVpnCapture,
                                    onOpenImportDialog = { showImportDialog = true },
                                    onExportSessionJson = {
                                        vm.exportActiveSessionJson(shareJsonText)
                                    },
                                    onOpenFullDecode = {
                                        vm.openFullDecodeDialog()
                                    },
                                    onSelectPacket = { pkt -> vm.selectPacket(pkt.id) },
                                    onDeletePacket = vm::deletePacket,
                                    onShareJson = shareJsonText,
                                    onSendToDecoderLab = { hex ->
                                        vm.sendHexToDecoderLab(hex)
                                        currentTab = MainTab.DECODER
                                    },
                                    onCopyToast = { msg ->
                                        coroutineScope.launch { snackbarHostState.showSnackbar(msg) }
                                    }
                                )
                                MainTab.SESSIONS -> SessionsScreen(
                                    sessions = sessions,
                                    activeSessionId = activeSession?.id ?: 0L,
                                    onSelectSession = { sid ->
                                        vm.selectSession(sid)
                                        currentTab = MainTab.CAPTURE
                                    },
                                    onExportSessionJson = { sid ->
                                        vm.exportSessionJson(sid, shareJsonText)
                                    },
                                    onFullDecodeSession = { sid ->
                                        vm.openFullDecodeDialog(sid)
                                    },
                                    onDeleteSession = vm::deleteSession,
                                    onOpenImportDialog = { showImportDialog = true }
                                )
                                MainTab.RULES -> TrafficRulesScreen(
                                    rules = trafficRules,
                                    targetApp = settings.targetApp,
                                    onAddRule = vm::addRule,
                                    onToggleRule = vm::toggleRule,
                                    onDeleteRule = vm::deleteRule
                                )
                                MainTab.DECODER -> DecoderLabScreen(
                                    state = decoderLabState,
                                    onInputChange = vm::updateDecoderLabInput,
                                    onHeaderSkipChange = vm::updateDecoderLabHeaderSkip,
                                    onUpdateCrypto = vm::updateDecoderLabCrypto,
                                    onRunDecrypt = vm::runDecoderLabDecrypt,
                                    onCopyToast = { msg ->
                                        coroutineScope.launch { snackbarHostState.showSnackbar(msg) }
                                    }
                                )
                            }
                        }
                    }
                }
            }
        }

        if (showTargetPicker) {
            TargetAppPickerSheet(
                apps = installedApps,
                isLoading = isLoadingApps,
                selectedPackage = settings.targetApp.packageName,
                onSelectApp = vm::selectTargetApp,
                onRefresh = vm::refreshInstalledApps,
                onDismiss = { showTargetPicker = false }
            )
        }

        if (showImportDialog) {
            ImportRawDialog(
                onDismiss = { showImportDialog = false },
                onImport = { title, rawText ->
                    vm.importRawCapture(title, rawText) {
                        currentTab = MainTab.CAPTURE
                    }
                }
            )
        }

        if (fullDecodeState.isDialogOpen) {
            FullDecodeDialog(
                state = fullDecodeState,
                onSelectAndRun = vm::runFullDecode,
                onShareJson = shareJsonText,
                onDismiss = vm::dismissFullDecodeDialog
            )
        }
    }
}
