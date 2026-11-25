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
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class PacketFilterChip(val label: String) {
    HTTP_HTTPS("HTTP/S"),
    ALL("All Packets"),
    TCP("TCP"),
    DNS_UDP("UDP/DNS"),
    PROTOBUF("Protobuf"),
    BLOCKED("Blocked")
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

    private val _caReady = MutableStateFlow(false)
    val caReady: StateFlow<Boolean> = _caReady.asStateFlow()

    private val _caTrusted = MutableStateFlow(false)
    val caTrusted: StateFlow<Boolean> = _caTrusted.asStateFlow()

    private val _decoderLab = MutableStateFlow(DecoderLabState())
    val decoderLab: StateFlow<DecoderLabState> = _decoderLab.asStateFlow()
    private var decoderLabJob: Job? = null
    private var decryptLabJob: Job? = null

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

    val totalSessionPacketCount: StateFlow<Int> = sessionPackets
        .map { it.size }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

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
                pkt.protocol.contains(query, ignoreCase = true) ||
                pkt.requestBodyHex.contains(query, ignoreCase = true) ||
                pkt.responseBodyHex.contains(query, ignoreCase = true)

            val matchesChip = when (chip) {
                PacketFilterChip.ALL -> true
                PacketFilterChip.HTTP_HTTPS ->
                    (pkt.protocol.equals("HTTP", true) || pkt.protocol.equals("HTTPS", true)) &&
                        !pkt.method.equals("TLS", true) &&
                        !pkt.method.equals("SYN", true)
                PacketFilterChip.TCP ->
                    pkt.protocol.equals("TCP", true) ||
                        pkt.method.equals("TLS", true) ||
                        pkt.method.equals("SYN", true)
                PacketFilterChip.PROTOBUF -> {
                    pkt.requestBodyHex.isNotEmpty() &&
                        PayloadAnalyzer.quickClassify(pkt.requestBodyHex) == PayloadClassification.PROTOBUF
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
        refreshCaTrustStatus()
        refreshInstalledApps()
    }

    fun refreshCaTrustStatus() {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { certManager.ensureCa() }
            val ready = certManager.isCaReady()
            val trusted = runCatching { certManager.isCaTrustedByAndroid() }.getOrDefault(false)
            _caReady.value = ready
            _caTrusted.value = trusted
            NetTraceVpnService.updateCaTrusted(trusted)
        }
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

    fun toggleVpnFullPacket(enabled: Boolean) {
        NetTraceVpnService.updateFilter(!enabled)
        _filterChip.value = if (enabled) PacketFilterChip.ALL else PacketFilterChip.HTTP_HTTPS
        viewModelScope.launch {
            prefs.setVpnFullPacketMode(enabled)
            _snackbarMessage.value = if (enabled) {
                "Full Packet Capture ON — capturing HTTP/HTTPS, TCP, UDP & in-game actions"
            } else {
                "Decodable Only ON — filtering for decodable HTTP/Protobuf/JSON"
            }
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

    fun prepareDirectCaInstall(onReady: (intents: List<Intent>, savedPath: String?) -> Unit) {
        NetTraceVpnService.clearPinningBypassCache()
        viewModelScope.launch {
            val (intents, savedPath) = withContext(Dispatchers.IO) {
                val path = runCatching { certManager.saveCaCertToAryanFolder() }.getOrNull()
                val candidates = certManager.prepareDirectCaInstallIntents()
                candidates to path
            }
            _caReady.value = certManager.isCaReady()
            onReady(intents, savedPath)
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
        val cur = settings.value
        _filterChip.value = when (mode) {
            CaptureEngineMode.APP_VPN -> if (cur.vpnFullPacketMode) PacketFilterChip.ALL else PacketFilterChip.HTTP_HTTPS
            CaptureEngineMode.LOCAL_PROXY -> if (cur.onlyDecodableHttp) PacketFilterChip.HTTP_HTTPS else PacketFilterChip.ALL
        }
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
        LocalForwardProxyService.updateFilter(enabled)
        _filterChip.value = if (enabled) PacketFilterChip.HTTP_HTTPS else PacketFilterChip.ALL
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
        val current = settings.value
        val target = current.targetApp
        if (target.packageName.isBlank()) {
            _snackbarMessage.value = "Select a Target App before starting capture."
            return
        }
        val onlyDecodable = !current.vpnFullPacketMode
        NetTraceVpnService.updateFilter(onlyDecodable)
        _filterChip.value = if (current.vpnFullPacketMode) PacketFilterChip.ALL else PacketFilterChip.HTTP_HTTPS
        NetTraceVpnService.startCapture(
            context = app,
            packageName = target.packageName,
            appName = target.appName,
            mitmEnabled = current.httpsMitmEnabled,
            onlyDecodableHttp = onlyDecodable
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
                    _snackbarMessage.value = "Saved ${res.decodedCount} Pro Packages to ${res.displayPath}"
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
            val current = settings.value
            val targetPkg = if (targetOnly && current.targetApp.packageName.isNotBlank()) {
                current.targetApp.packageName
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
        decoderLabJob?.cancel()
        _decoderLab.update {
            it.copy(
                inputText = input,
                headerHexPreview = "",
                effectivePayloadHex = "",
                jwtResult = null,
                payloadAnalysis = null,
                decryptedAnalysis = null,
                decryptError = null
            )
        }
    }

    fun updateDecoderLabHeaderSkip(skipBytes: Int) {
        val current = _decoderLab.value
        val alreadyDecoded = current.payloadAnalysis != null || current.jwtResult != null
        _decoderLab.update { it.copy(headerSkipBytes = skipBytes) }
        if (alreadyDecoded && current.inputText.isNotBlank()) {
            recomputeDecoderLab(input = current.inputText, headerSkipBytes = skipBytes)
        }
    }

    fun runDecoderLabDecode() {
        val st = _decoderLab.value
        if (st.inputText.isBlank()) {
            _snackbarMessage.value = "Paste Hex, JWT Token, or JSON first."
            return
        }
        recomputeDecoderLab(input = st.inputText, headerSkipBytes = st.headerSkipBytes)
    }

    fun applyDecoderLabPreset(preset: String) {
        _decoderLab.update { it.copy(inputText = preset) }
        recomputeDecoderLab(input = preset, headerSkipBytes = _decoderLab.value.headerSkipBytes)
    }

    private fun recomputeDecoderLab(input: String, headerSkipBytes: Int) {
        _decoderLab.update {
            it.copy(
                inputText = input,
                headerSkipBytes = headerSkipBytes,
                decryptedAnalysis = null,
                decryptError = null
            )
        }
        decoderLabJob?.cancel()
        decoderLabJob = viewModelScope.launch(Dispatchers.Default) {
            val jwt = JwtDecoder.decode(input)
            val cleanHex = HexUtils.sanitizeHex(input)
            val skipChars = (headerSkipBytes * 2).coerceAtMost(cleanHex.length)
            val headerHex = if (skipChars > 0) cleanHex.substring(0, skipChars).uppercase() else ""
            val effectiveHex = if (skipChars > 0) cleanHex.substring(skipChars) else input
            val analysis = if (jwt == null) PayloadAnalyzer.analyze(effectiveHex) else null

            _decoderLab.update { cur ->
                if (cur.inputText == input && cur.headerSkipBytes == headerSkipBytes) {
                    cur.copy(
                        headerHexPreview = headerHex,
                        effectivePayloadHex = effectiveHex,
                        jwtResult = jwt,
                        payloadAnalysis = analysis
                    )
                } else cur
            }
        }
    }

    fun updateDecoderLabCrypto(
        key: String = _decoderLab.value.keyInput,
        iv: String = _decoderLab.value.ivInput,
        keyIsHex: Boolean = _decoderLab.value.keyIsHex,
        mode: DecryptMode = _decoderLab.value.decryptMode
    ) {
        _decoderLab.update {
            it.copy(
                keyInput = key,
                ivInput = iv,
                keyIsHex = keyIsHex,
                decryptMode = mode
            )
        }
    }

    fun runDecoderLabDecrypt() {
        val st = _decoderLab.value
        val targetHex = st.effectivePayloadHex.ifBlank { st.inputText }
        decryptLabJob?.cancel()
        decryptLabJob = viewModelScope.launch(Dispatchers.Default) {
            val result = PayloadDecryptor.decrypt(
                payloadHex = targetHex,
                keyInput = st.keyInput,
                ivInput = st.ivInput,
                keyIsHex = st.keyIsHex,
                mode = st.decryptMode
            )
            _decoderLab.update { cur ->
                result.fold(
                    onSuccess = { cur.copy(decryptedAnalysis = it, decryptError = null) },
                    onFailure = { cur.copy(decryptedAnalysis = null, decryptError = it.message ?: "Decryption failed") }
                )
            }
        }
    }

    fun sendHexToDecoderLab(hex: String) {
        _decoderLab.update { it.copy(inputText = hex) }
        recomputeDecoderLab(input = hex, headerSkipBytes = _decoderLab.value.headerSkipBytes)
    }

    fun consumeSnackbar() {
        _snackbarMessage.value = null
    }
}
