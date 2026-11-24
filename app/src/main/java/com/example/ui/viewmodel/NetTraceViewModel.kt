package com.example.ui.viewmodel

import android.app.Application
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.NetTraceApp
import com.example.apps.InstalledAppInfo
import com.example.data.db.CaptureSessionEntity
import com.example.data.db.CapturedPacketEntity
import com.example.data.db.TrafficRuleEntity
import com.example.data.prefs.AppSettings
import com.example.decoder.BatchDecodeExporter
import com.example.decoder.DecryptMode
import com.example.decoder.FullDecodeResult
import com.example.decoder.FullDecodeScope
import com.example.decoder.HexUtils
import com.example.decoder.JwtDecodeResult
import com.example.decoder.JwtDecoder
import com.example.decoder.PacketJsonSerializer
import com.example.decoder.PayloadAnalysis
import com.example.decoder.PayloadAnalyzer
import com.example.decoder.PayloadClassification
import com.example.decoder.PayloadDecryptor
import com.example.data.prefs.CaptureEngineMode
import com.example.proxy.LocalForwardProxyEngine
import com.example.proxy.LocalForwardProxyService
import com.example.proxy.LocalProxyRuntimeState
import com.example.ui.theme.AppAccentTheme
import com.example.vpn.NetTraceVpnService
import com.example.vpn.VpnRuntimeState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class PacketFilterChip(val label: String) {
    HTTP_HTTPS("HTTP/S"),
    ALL("All"),
    PROTOBUF("Protobuf"),
    BLOCKED("Blocked"),
    DNS_UDP("DNS/UDP")
}

data class FullDecodeUiState(
    val isDialogOpen: Boolean = false,
    val isRunning: Boolean = false,
    val processed: Int = 0,
    val total: Int = 0,
    val selectedScope: FullDecodeScope = FullDecodeScope.HTTP_HTTPS,
    val targetSessionId: Long? = null,
    val result: FullDecodeResult? = null,
    val error: String? = null
)

data class DecoderLabState(
    val inputText: String = "",
    val headerSkipBytes: Int = 0,
    val headerHexPreview: String = "",
    val effectivePayloadHex: String = "",
    val jwtResult: JwtDecodeResult? = null,
    val payloadAnalysis: PayloadAnalysis? = null,
    val keyInput: String = "",
    val ivInput: String = "",
    val keyIsHex: Boolean = false,
    val decryptMode: DecryptMode = DecryptMode.AES_CBC_PKCS5,
    val decryptedAnalysis: PayloadAnalysis? = null,
    val decryptError: String? = null
)

@OptIn(ExperimentalCoroutinesApi::class)
class NetTraceViewModel(application: Application) : AndroidViewModel(application) {

    private val app = application as NetTraceApp
    private val repo = app.captureRepository
    private val prefs = app.preferencesRepository
    private val appsRepo = app.installedAppsRepository
    private val certManager = app.mitmCertificateManager

    val settings: StateFlow<AppSettings> = prefs.settingsFlow.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = AppSettings()
    )

    val vpnState: StateFlow<VpnRuntimeState> = NetTraceVpnService.runtimeState
    val proxyState: StateFlow<LocalProxyRuntimeState> = LocalForwardProxyService.runtimeState

    val sessions: StateFlow<List<CaptureSessionEntity>> = repo.observeAllSessions().stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptyList()
    )

    val trafficRules: StateFlow<List<TrafficRuleEntity>> = repo.observeAllRules().stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptyList()
    )

    private val _selectedSessionId = MutableStateFlow(0L)
    val selectedSessionId: StateFlow<Long> = _selectedSessionId.asStateFlow()

    private val _selectedPacketId = MutableStateFlow<Long?>(null)
    val selectedPacketId: StateFlow<Long?> = _selectedPacketId.asStateFlow()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    private val _filterChip = MutableStateFlow(PacketFilterChip.HTTP_HTTPS)
    val filterChip: StateFlow<PacketFilterChip> = _filterChip.asStateFlow()

    private val _installedApps = MutableStateFlow<List<InstalledAppInfo>>(emptyList())
    val installedApps: StateFlow<List<InstalledAppInfo>> = _installedApps.asStateFlow()

    private val _isLoadingApps = MutableStateFlow(false)
    val isLoadingApps: StateFlow<Boolean> = _isLoadingApps.asStateFlow()

    private val _snackbarMessage = MutableStateFlow<String?>(null)
    val snackbarMessage: StateFlow<String?> = _snackbarMessage.asStateFlow()

    private val _fullDecodeState = MutableStateFlow(FullDecodeUiState())
    val fullDecodeState: StateFlow<FullDecodeUiState> = _fullDecodeState.asStateFlow()

    private val _caReady = MutableStateFlow(certManager.isCaReady())
    val caReady: StateFlow<Boolean> = _caReady.asStateFlow()

    private val _decoderLab = MutableStateFlow(
        DecoderLabState(
            inputText = "08f4f3c8cf3d102618ad0220ad02300170807d8001ad028801cc08a80101b001019a0200"
        ).let {
            it.copy(
                jwtResult = JwtDecoder.decode(it.inputText),
                payloadAnalysis = PayloadAnalyzer.analyze(it.inputText)
            )
        }
    )
    val decoderLab: StateFlow<DecoderLabState> = _decoderLab.asStateFlow()

    val activeSession: StateFlow<CaptureSessionEntity?> = combine(
        _selectedSessionId,
        sessions,
        vpnState,
        proxyState
    ) { chosenId, allSessions, vpn, proxy ->
        val effectiveId = when {
            proxy.isRunning && proxy.sessionId != 0L -> proxy.sessionId
            vpn.isRunning && vpn.sessionId != 0L -> vpn.sessionId
            chosenId != 0L -> chosenId
            else -> allSessions.firstOrNull()?.id ?: 0L
        }
        allSessions.firstOrNull { it.id == effectiveId }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    val sessionPackets: StateFlow<List<CapturedPacketEntity>> = activeSession.flatMapLatest { session ->
        if (session == null) flowOf(emptyList())
        else repo.observePacketsForSession(session.id)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val filteredPackets: StateFlow<List<CapturedPacketEntity>> = combine(
        sessionPackets,
        _searchQuery,
        _filterChip
    ) { packets, query, chip ->
        packets.filter { pkt ->
            val matchesQuery = query.isBlank() ||
                pkt.url.contains(query, ignoreCase = true) ||
                pkt.host.contains(query, ignoreCase = true) ||
                pkt.method.contains(query, ignoreCase = true) ||
                pkt.requestBodyHex.contains(query, ignoreCase = true) ||
                pkt.responseBodyHex.contains(query, ignoreCase = true)

            val matchesChip = when (chip) {
                PacketFilterChip.ALL -> true
                PacketFilterChip.HTTP_HTTPS -> pkt.protocol.equals("HTTP", true) || pkt.protocol.equals("HTTPS", true)
                PacketFilterChip.PROTOBUF -> {
                    val reqProto = pkt.requestBodyHex.isNotEmpty() &&
                        PayloadAnalyzer.quickClassify(pkt.requestBodyHex) == PayloadClassification.PROTOBUF
                    val respProto = pkt.responseBodyHex.isNotEmpty() &&
                        PayloadAnalyzer.quickClassify(pkt.responseBodyHex) == PayloadClassification.PROTOBUF
                    reqProto || respProto
                }
                PacketFilterChip.BLOCKED -> pkt.isBlocked
                PacketFilterChip.DNS_UDP -> pkt.protocol.equals("DNS", true) || pkt.protocol.equals("UDP", true)
            }

            matchesQuery && matchesChip
        }
    }.flowOn(Dispatchers.Default).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val selectedPacket: StateFlow<CapturedPacketEntity?> = _selectedPacketId.flatMapLatest { id ->
        if (id == null) flowOf(null) else repo.observePacketById(id)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    init {
        viewModelScope.launch {
            val seededId = repo.ensureSeeded()
            if (seededId != null) {
                _selectedSessionId.value = seededId
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { certManager.ensureCa() }
            _caReady.value = certManager.isCaReady()
        }
        refreshInstalledApps()
    }

    fun refreshInstalledApps() {
        viewModelScope.launch {
            _isLoadingApps.value = true
            val list = appsRepo.getLaunchableApps()
            _installedApps.value = list
            _isLoadingApps.value = false

            // Pre-select first game or user app if none chosen yet
            if (settings.value.targetApp.packageName.isBlank() && list.isNotEmpty()) {
                val firstPreferred = list.firstOrNull { it.isGame } ?: list.first()
                prefs.setTargetApp(firstPreferred.packageName, firstPreferred.appName, firstPreferred.uid)
            }
        }
    }

    fun selectTargetApp(appInfo: InstalledAppInfo) {
        viewModelScope.launch {
            prefs.setTargetApp(appInfo.packageName, appInfo.appName, appInfo.uid)
            _snackbarMessage.value = "Target locked to ${appInfo.appName} (${appInfo.packageName})"
        }
    }

    fun selectSession(sessionId: Long) {
        _selectedSessionId.value = sessionId
        _selectedPacketId.value = null
    }

    fun selectPacket(packetId: Long?) {
        _selectedPacketId.value = packetId
    }

    fun setSearchQuery(query: String) {
        _searchQuery.value = query
    }

    fun setFilterChip(chip: PacketFilterChip) {
        _filterChip.value = chip
    }

    fun toggleTheme() {
        viewModelScope.launch {
            prefs.setDarkTheme(!settings.value.darkTheme)
        }
    }

    fun setAccentTheme(theme: AppAccentTheme) {
        viewModelScope.launch {
            prefs.setAccentTheme(theme)
        }
    }

    fun toggleHttpsMitm(enabled: Boolean) {
        NetTraceVpnService.clearPinningBypassCache()
        viewModelScope.launch {
            prefs.setHttpsMitmEnabled(enabled)
            _snackbarMessage.value = if (vpnState.value.isRunning) {
                "HTTPS Decrypt ${if (enabled) "enabled" else "disabled"} — stop & restart capture to apply."
            } else {
                "HTTPS Decrypt ${if (enabled) "enabled" else "disabled"}."
            }
        }
    }

    fun prepareCaInstallIntent(onReady: (Intent) -> Unit) {
        NetTraceVpnService.clearPinningBypassCache()
        viewModelScope.launch {
            val intent = withContext(Dispatchers.IO) {
                certManager.createInstallCaIntent()
            }
            _caReady.value = certManager.isCaReady()
            onReady(intent)
        }
    }

    fun saveCaCertToAryan() {
        viewModelScope.launch {
            val savedPath = withContext(Dispatchers.IO) {
                runCatching { certManager.saveCaCertToAryanFolder() }
            }
            _caReady.value = certManager.isCaReady()
            savedPath.fold(
                onSuccess = { path ->
                    _snackbarMessage.value = "CA Cert saved: $path (Settings → Security → CA certificate)"
                },
                onFailure = { err ->
                    _snackbarMessage.value = "Failed to export CA cert: ${err.message}"
                }
            )
        }
    }

    fun setCaptureMode(mode: CaptureEngineMode) {
        viewModelScope.launch {
            prefs.setCaptureMode(mode)
        }
    }

    fun setForwardBaseUrl(url: String) {
        viewModelScope.launch {
            prefs.setForwardBaseUrl(url)
        }
    }

    fun setProxyPort(portText: String) {
        val parsed = portText.filter { it.isDigit() }.toIntOrNull() ?: return
        if (parsed in 1024..65535) {
            viewModelScope.launch {
                prefs.setProxyPort(parsed)
            }
        }
    }

    fun toggleOnlyDecodableHttp(enabled: Boolean) {
        viewModelScope.launch {
            prefs.setOnlyDecodableHttp(enabled)
        }
    }

    fun startLocalProxy(portOverride: Int? = null, urlOverride: String? = null) {
        val current = settings.value
        val port = (portOverride ?: current.proxyPort).coerceIn(1024, 65535)
        val rawUrl = urlOverride ?: current.forwardBaseUrl
        val cleanUrl = LocalForwardProxyEngine.sanitizeBaseUrl(rawUrl)
        viewModelScope.launch {
            prefs.setProxyPort(port)
            prefs.setForwardBaseUrl(cleanUrl)
        }
        LocalForwardProxyService.startProxy(
            context = app,
            port = port,
            forwardUrl = cleanUrl,
            onlyDecodable = current.onlyDecodableHttp
        )
    }

    fun stopLocalProxy() {
        LocalForwardProxyService.stopProxy(app)
        _snackbarMessage.value = "Local proxy stopped."
    }

    fun clearActiveSessionPackets() {
        val session = activeSession.value ?: return
        viewModelScope.launch {
            repo.clearSessionPackets(session.id)
            _selectedPacketId.value = null
            _snackbarMessage.value = "Captured traffic cleared."
        }
    }

    fun startVpnCapture() {
        val target = settings.value.targetApp
        if (target.packageName.isBlank()) {
            _snackbarMessage.value = "Please select a target app first."
            return
        }
        NetTraceVpnService.startCapture(
            context = app,
            packageName = target.packageName,
            appName = target.appName,
            mitmEnabled = settings.value.httpsMitmEnabled,
            onlyDecodableHttp = settings.value.onlyDecodableHttp
        )
    }

    fun stopVpnCapture() {
        NetTraceVpnService.stopCapture(app)
        _snackbarMessage.value = "Capture session saved."
    }

    fun deleteSession(sessionId: Long) {
        viewModelScope.launch {
            repo.deleteSession(sessionId)
            if (_selectedSessionId.value == sessionId) {
                _selectedSessionId.value = 0L
                _selectedPacketId.value = null
            }
            _snackbarMessage.value = "Session deleted."
        }
    }

    fun deletePacket(packet: CapturedPacketEntity) {
        viewModelScope.launch {
            repo.deletePacket(packet)
            if (_selectedPacketId.value == packet.id) {
                _selectedPacketId.value = null
            }
            _snackbarMessage.value = "Deleted ${packet.method} ${packet.path.ifBlank { packet.host }}"
        }
    }

    fun openFullDecodeDialog(sessionId: Long? = null) {
        _fullDecodeState.value = FullDecodeUiState(
            isDialogOpen = true,
            targetSessionId = sessionId ?: activeSession.value?.id,
            selectedScope = FullDecodeScope.HTTP_HTTPS
        )
    }

    fun dismissFullDecodeDialog() {
        if (!_fullDecodeState.value.isRunning) {
            _fullDecodeState.value = FullDecodeUiState(isDialogOpen = false)
        }
    }

    fun runFullDecode(scope: FullDecodeScope) {
        val targetSid = _fullDecodeState.value.targetSessionId ?: activeSession.value?.id
        if (targetSid == null || targetSid == 0L) {
            _fullDecodeState.value = _fullDecodeState.value.copy(
                error = "No active capture session found."
            )
            return
        }
        viewModelScope.launch {
            _fullDecodeState.value = _fullDecodeState.value.copy(
                isRunning = true,
                selectedScope = scope,
                processed = 0,
                total = 0,
                result = null,
                error = null
            )
            val sessionEntity = sessions.value.firstOrNull { it.id == targetSid }
            val packets = repo.getPacketsForSessionOnce(targetSid)
            val outcome = BatchDecodeExporter.decodeAndSaveToAryanFolder(
                context = app,
                session = sessionEntity,
                packets = packets,
                scope = scope,
                onProgress = { done, total ->
                    _fullDecodeState.value = _fullDecodeState.value.copy(
                        processed = done,
                        total = total
                    )
                }
            )
            outcome.fold(
                onSuccess = { res ->
                    _fullDecodeState.value = _fullDecodeState.value.copy(
                        isRunning = false,
                        result = res,
                        error = null
                    )
                    _snackbarMessage.value = "Saved ${res.decodedCount} decoded requests to ${res.displayPath}"
                },
                onFailure = { err ->
                    _fullDecodeState.value = _fullDecodeState.value.copy(
                        isRunning = false,
                        error = err.message ?: "Full decode export failed."
                    )
                }
            )
        }
    }

    fun importRawCapture(title: String, rawText: String, onImported: (Long) -> Unit = {}) {
        viewModelScope.launch {
            val target = settings.value.targetApp
            val newId = repo.importRawTextAsSession(
                title = title,
                targetAppName = target.appName.ifBlank { "Imported Target" },
                targetPackageName = target.packageName.ifBlank { "com.imported.app" },
                rawText = rawText
            )
            if (newId != null) {
                _selectedSessionId.value = newId
                _snackbarMessage.value = "Imported capture session successfully."
                onImported(newId)
            } else {
                _snackbarMessage.value = "Could not find valid HTTP/Hex requests in pasted text."
            }
        }
    }

    fun addRule(name: String, pattern: String, matchType: String, action: String, targetOnly: Boolean) {
        if (pattern.isBlank()) return
        viewModelScope.launch {
            val targetPkg = if (targetOnly && settings.value.targetApp.packageName.isNotBlank()) {
                settings.value.targetApp.packageName
            } else {
                "*"
            }
            repo.addRule(
                name = name.ifBlank { "$action $pattern" },
                pattern = pattern,
                matchType = matchType,
                action = action,
                targetPackage = targetPkg
            )
            _snackbarMessage.value = "Traffic rule added: $action $pattern"
        }
    }

    fun toggleRule(ruleId: Long, enabled: Boolean) {
        viewModelScope.launch { repo.toggleRule(ruleId, enabled) }
    }

    fun deleteRule(ruleId: Long) {
        viewModelScope.launch { repo.deleteRule(ruleId) }
    }

    fun buildPacketJson(packet: CapturedPacketEntity): String {
        return PacketJsonSerializer.packetToFormattedJson(packet)
    }

    fun exportActiveSessionJson(onReady: (String) -> Unit) {
        val session = activeSession.value ?: return
        viewModelScope.launch {
            val json = repo.exportSessionAsJson(session.id)
            if (json != null) onReady(json)
        }
    }

    fun exportSessionJson(sessionId: Long, onReady: (String) -> Unit) {
        viewModelScope.launch {
            val json = repo.exportSessionAsJson(sessionId)
            if (json != null) onReady(json)
        }
    }

    fun updateDecoderLabInput(input: String) {
        recomputeDecoderLab(input = input, headerSkipBytes = _decoderLab.value.headerSkipBytes)
    }

    fun updateDecoderLabHeaderSkip(skipBytes: Int) {
        recomputeDecoderLab(input = _decoderLab.value.inputText, headerSkipBytes = skipBytes)
    }

    private fun recomputeDecoderLab(input: String, headerSkipBytes: Int) {
        val jwt = JwtDecoder.decode(input)
        val cleanHex = HexUtils.sanitizeHex(input)
        val skipChars = (headerSkipBytes * 2).coerceAtMost(cleanHex.length)
        val headerHex = if (skipChars > 0) cleanHex.substring(0, skipChars).uppercase() else ""
        val effectiveHex = if (skipChars > 0) cleanHex.substring(skipChars) else input
        val analysis = if (jwt == null) PayloadAnalyzer.analyze(effectiveHex) else null

        _decoderLab.value = _decoderLab.value.copy(
            inputText = input,
            headerSkipBytes = headerSkipBytes,
            headerHexPreview = headerHex,
            effectivePayloadHex = effectiveHex,
            jwtResult = jwt,
            payloadAnalysis = analysis,
            decryptedAnalysis = null,
            decryptError = null
        )
    }

    fun updateDecoderLabCrypto(
        key: String = _decoderLab.value.keyInput,
        iv: String = _decoderLab.value.ivInput,
        keyIsHex: Boolean = _decoderLab.value.keyIsHex,
        mode: DecryptMode = _decoderLab.value.decryptMode
    ) {
        _decoderLab.value = _decoderLab.value.copy(
            keyInput = key,
            ivInput = iv,
            keyIsHex = keyIsHex,
            decryptMode = mode
        )
    }

    fun runDecoderLabDecrypt() {
        val st = _decoderLab.value
        val targetHex = st.effectivePayloadHex.ifBlank { st.inputText }
        val result = PayloadDecryptor.decrypt(
            payloadHex = targetHex,
            keyInput = st.keyInput,
            ivInput = st.ivInput,
            keyIsHex = st.keyIsHex,
            mode = st.decryptMode
        )
        result.fold(
            onSuccess = {
                _decoderLab.value = st.copy(decryptedAnalysis = it, decryptError = null)
            },
            onFailure = {
                _decoderLab.value = st.copy(decryptedAnalysis = null, decryptError = it.message ?: "Decryption failed")
            }
        )
    }

    fun sendHexToDecoderLab(hex: String) {
        updateDecoderLabInput(hex)
    }

    fun consumeSnackbar() {
        _snackbarMessage.value = null
    }
}
