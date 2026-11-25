package com.example.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SecondaryTabRow
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.example.R
import com.example.data.db.CapturedPacketEntity
import com.example.decoder.AutoDecryptMatch
import com.example.decoder.BatchDecodeExporter
import com.example.decoder.DecryptMode
import com.example.decoder.HexUtils
import com.example.decoder.JwtDecodeResult
import com.example.decoder.JwtDecoder
import com.example.decoder.PacketJsonSerializer
import com.example.decoder.PayloadAnalysis
import com.example.decoder.PayloadAnalyzer
import com.example.decoder.PayloadClassification
import com.example.decoder.PayloadDecryptor
import com.example.decoder.ProtobufFieldsFormatter
import com.example.decoder.SessionCryptoResolver
import com.example.decoder.SessionKeyIv
import com.example.ui.components.AppIcons
import com.example.ui.components.Formatters
import com.example.ui.components.MethodBadge
import com.example.ui.components.ProtobufTreeView
import com.example.ui.components.PythonFieldsCodeBlock
import com.example.ui.components.SyntaxHighlightedJsonBlock
import com.example.ui.components.TagChip
import com.example.ui.theme.AmberSignal
import com.example.ui.theme.CoralAlert
import com.example.ui.theme.EmeraldPulse
import com.example.ui.theme.JetBrainsMonoFamily
import com.example.ui.theme.VioletProto
import com.example.ui.viewmodel.SessionCryptoUiState

private data class PacketDetailComputed(
    val packetJson: String,
    val requestPackageText: String,
    val fullPackageText: String,
    val reqDecodedText: String?,
    val respDecodedText: String?,
    val reqHeaders: Map<String, String>,
    val respHeaders: Map<String, String>,
    val jwtDecoded: JwtDecodeResult?,
    val reqAnalysis: PayloadAnalysis,
    val autoDecryptMatch: AutoDecryptMatch?,
    val respAnalysis: PayloadAnalysis
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PacketDetailScreen(
    packet: CapturedPacketEntity,
    isPaneMode: Boolean,
    sessionKeyIvCandidates: List<SessionKeyIv> = emptyList(),
    sessionCryptoState: SessionCryptoUiState = SessionCryptoUiState(),
    onSaveSessionKey: (key: String, iv: String, isHex: Boolean) -> Unit = { _, _, _ -> },
    onBack: () -> Unit,
    onShareJson: (String) -> Unit,
    onSendToDecoderLab: (String) -> Unit,
    onCopyToast: (String) -> Unit
) {
    if (!isPaneMode) {
        BackHandler(onBack = onBack)
    }

    val clipboard = LocalClipboardManager.current
    var selectedTab by remember(packet.id) { mutableIntStateOf(0) }

    val computed by produceState<PacketDetailComputed?>(
        initialValue = null,
        key1 = packet,
        key2 = sessionKeyIvCandidates
    ) {
        value = withContext(Dispatchers.Default) {
            val (effectiveReqAnalysis, autoMatch) = SessionCryptoResolver.analyzeWithAutoDecrypt(
                hexInput = packet.requestBodyHex,
                candidates = sessionKeyIvCandidates
            )
            PacketDetailComputed(
                packetJson = PacketJsonSerializer.packetToFormattedJson(packet, sessionKeyIvCandidates),
                requestPackageText = BatchDecodeExporter.formatRequestPackageOnly(packet, sessionKeyIvCandidates),
                fullPackageText = BatchDecodeExporter.formatSinglePackageEntry(packet, sessionKeyIvCandidates),
                reqDecodedText = PacketJsonSerializer.decodePayloadFormattedText(packet.requestBodyHex, sessionKeyIvCandidates),
                respDecodedText = PacketJsonSerializer.decodePayloadFormattedText(packet.responseBodyHex),
                reqHeaders = PacketJsonSerializer.parseHeadersMap(packet.requestHeadersJson),
                respHeaders = PacketJsonSerializer.parseHeadersMap(packet.responseHeadersJson),
                jwtDecoded = JwtDecoder.extractFromHeaders(packet.requestHeadersJson),
                reqAnalysis = effectiveReqAnalysis,
                autoDecryptMatch = autoMatch,
                respAnalysis = PayloadAnalyzer.analyze(packet.responseBodyHex)
            )
        }
    }

    val content: @Composable (PaddingValues) -> Unit = { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            // Compact endpoint summary header
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        MethodBadge(packet.method, packet.isBlocked)
                        if (packet.isBlocked) {
                            TagChip("BLOCKED", CoralAlert)
                        } else if (packet.statusCode != null) {
                            TagChip("${packet.statusCode} OK", EmeraldPulse)
                        }
                        TagChip(packet.protocol, MaterialTheme.colorScheme.primary)
                        Spacer(modifier = Modifier.weight(1f))
                        Text(
                            text = Formatters.formatDateTime(packet.timestamp),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    SelectionContainer {
                        Text(
                            text = packet.url,
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = JetBrainsMonoFamily,
                                fontWeight = FontWeight.Medium
                            ),
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }

            SecondaryTabRow(selectedTabIndex = selectedTab) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("BODY") },
                    modifier = Modifier.testTag("packet_tab_decode")
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("JSON") },
                    modifier = Modifier.testTag("packet_tab_json")
                )
                Tab(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    text = { Text("Headers & Hex") },
                    modifier = Modifier.testTag("packet_tab_raw")
                )
            }

            val ready = computed
            if (ready == null) {
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier.fillMaxSize()
                ) {
                    CircularProgressIndicator()
                }
            } else {
                when (selectedTab) {
                    0 -> DecodeTabContent(
                        packet = packet,
                        requestPackageText = ready.requestPackageText,
                        fullPackageText = ready.fullPackageText,
                        jwtDecoded = ready.jwtDecoded,
                        reqAnalysis = ready.reqAnalysis,
                        autoDecryptMatch = ready.autoDecryptMatch,
                        respAnalysis = ready.respAnalysis,
                        sessionCryptoState = sessionCryptoState,
                        onSaveSessionKey = onSaveSessionKey,
                        onSharePackage = { onShareJson(ready.requestPackageText) },
                        onCopyToast = onCopyToast,
                        onSendToDecoderLab = onSendToDecoderLab
                    )
                    1 -> JsonTabContent(
                        packet = packet,
                        reqDecodedText = ready.reqDecodedText,
                        respDecodedText = ready.respDecodedText,
                        reqAnalysis = ready.reqAnalysis,
                        respAnalysis = ready.respAnalysis,
                        onCopyAll = {
                            clipboard.setText(AnnotatedString(ready.packetJson))
                            onCopyToast("Combined Request + Response JSON copied")
                        },
                        onShare = { onShareJson(ready.packetJson) },
                        onCopyToast = onCopyToast
                    )
                    2 -> HeadersAndHexTabContent(
                        packet = packet,
                        reqHeaders = ready.reqHeaders,
                        respHeaders = ready.respHeaders,
                        reqAnalysis = ready.reqAnalysis,
                        respAnalysis = ready.respAnalysis,
                        onCopyToast = onCopyToast
                    )
                }
            }
        }
    }

    if (isPaneMode) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            text = packet.path.ifBlank { packet.host },
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            style = MaterialTheme.typography.titleMedium.copy(fontFamily = JetBrainsMonoFamily)
                        )
                    },
                    actions = {
                        IconButton(
                            enabled = computed != null,
                            onClick = {
                                computed?.packetJson?.let { json ->
                                    clipboard.setText(AnnotatedString(json))
                                    onCopyToast("Packet JSON copied")
                                }
                            },
                            modifier = Modifier.testTag("detail_copy_json_button")
                        ) {
                            Icon(AppIcons.ContentCopy, contentDescription = stringResource(R.string.cd_copy))
                        }
                        IconButton(
                            enabled = computed != null,
                            onClick = { computed?.packetJson?.let(onShareJson) },
                            modifier = Modifier.testTag("detail_share_json_button")
                        ) {
                            Icon(Icons.Default.Share, contentDescription = stringResource(R.string.cd_share))
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    )
                )
            },
            content = content
        )
    } else {
        Scaffold(
            topBar = {
                TopAppBar(
                    navigationIcon = {
                        IconButton(
                            onClick = onBack,
                            modifier = Modifier.testTag("detail_back_button")
                        ) {
                            Icon(
                                Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = stringResource(R.string.cd_back)
                            )
                        }
                    },
                    title = {
                        Text(
                            text = packet.path.ifBlank { packet.host },
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            style = MaterialTheme.typography.titleMedium.copy(fontFamily = JetBrainsMonoFamily)
                        )
                    },
                    actions = {
                        IconButton(
                            enabled = computed != null,
                            onClick = {
                                computed?.packetJson?.let { json ->
                                    clipboard.setText(AnnotatedString(json))
                                    onCopyToast("Packet JSON copied")
                                }
                            },
                            modifier = Modifier.testTag("detail_copy_json_button")
                        ) {
                            Icon(AppIcons.ContentCopy, contentDescription = stringResource(R.string.cd_copy))
                        }
                        IconButton(
                            enabled = computed != null,
                            onClick = { computed?.packetJson?.let(onShareJson) },
                            modifier = Modifier.testTag("detail_share_json_button")
                        ) {
                            Icon(Icons.Default.Share, contentDescription = stringResource(R.string.cd_share))
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    )
                )
            },
            content = content
        )
    }
}

@Composable
private fun DecodeTabContent(
    packet: CapturedPacketEntity,
    requestPackageText: String,
    fullPackageText: String,
    jwtDecoded: JwtDecodeResult?,
    reqAnalysis: PayloadAnalysis,
    autoDecryptMatch: AutoDecryptMatch?,
    respAnalysis: PayloadAnalysis,
    sessionCryptoState: SessionCryptoUiState,
    onSaveSessionKey: (key: String, iv: String, isHex: Boolean) -> Unit,
    onSharePackage: () -> Unit,
    onCopyToast: (String) -> Unit,
    onSendToDecoderLab: (String) -> Unit
) {
    val clipboard = LocalClipboardManager.current
    var showManualResponseDecode by remember(packet.id) { mutableStateOf(false) }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        modifier = Modifier
            .fillMaxSize()
            .testTag("decode_request_response_switch")
    ) {
        // 1. First & foremost: Request Body decoded into its Python Package
        item {
            PayloadDecodedSection(
                title = "Request Package",
                endpointPath = packet.path,
                isResponse = false,
                analysis = reqAnalysis,
                autoDecryptMatch = autoDecryptMatch,
                rawHex = packet.requestBodyHex,
                sessionCryptoState = sessionCryptoState,
                onSaveSessionKey = onSaveSessionKey,
                onCopyToast = onCopyToast,
                onSendToDecoderLab = onSendToDecoderLab
            )
        }

        // 2. Quick copy & share Request / Full Package
        item {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Button(
                    onClick = {
                        clipboard.setText(AnnotatedString(requestPackageText))
                        onCopyToast("Request Package copied")
                    },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("decode_copy_request_package_button")
                ) {
                    Icon(AppIcons.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Copy Request", maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                OutlinedButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(fullPackageText))
                        onCopyToast("Full URL + Hex + Package copied")
                    },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("decode_copy_full_package_button")
                ) {
                    Icon(AppIcons.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Full Package", maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                OutlinedButton(
                    onClick = onSharePackage,
                    modifier = Modifier.testTag("decode_share_full_package_button")
                ) {
                    Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                }
            }
        }

        // 3. Raw Body Hex overview (Request & Response Hex)
        item {
            DualBodyHexOverviewCard(
                requestHex = packet.requestBodyHex,
                responseHex = packet.responseBodyHex,
                showRequest = true,
                showResponse = true,
                onCopyToast = onCopyToast
            )
        }

        // 4. Response Body: Manual Decode Only (never auto-decoded upfront)
        item {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.45f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Response Body (Manual Decode)",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "${respAnalysis.byteCount}B • ${respAnalysis.classification.name} — tap to decode manually",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        TagChip(
                            text = if (showManualResponseDecode) "SHOWN" else "MANUAL",
                            color = if (showManualResponseDecode) EmeraldPulse else MaterialTheme.colorScheme.primary
                        )
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        OutlinedButton(
                            onClick = { showManualResponseDecode = !showManualResponseDecode },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("decode_manual_response_button")
                        ) {
                            Icon(AppIcons.DataObject, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(if (showManualResponseDecode) "Hide Response" else "Decode Response")
                        }
                        OutlinedButton(
                            onClick = { onSendToDecoderLab(packet.responseBodyHex) },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("decode_response_lab_button")
                        ) {
                            Icon(AppIcons.Code, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Open in Lab")
                        }
                    }

                    AnimatedVisibility(visible = showManualResponseDecode) {
                        Column(modifier = Modifier.padding(top = 12.dp)) {
                            PayloadDecodedSection(
                                title = "Response Package",
                                endpointPath = packet.path,
                                isResponse = true,
                                analysis = respAnalysis,
                                rawHex = packet.responseBodyHex,
                                sessionCryptoState = sessionCryptoState,
                                onSaveSessionKey = onSaveSessionKey,
                                onCopyToast = onCopyToast,
                                onSendToDecoderLab = onSendToDecoderLab
                            )
                        }
                    }
                }
            }
        }

        // 5. JWT Claims (if Authorization Bearer JWT is present)
        if (jwtDecoded != null) {
            item {
                JwtDecodedCard(jwt = jwtDecoded, onCopyToast = onCopyToast)
            }
        }
    }
}

@Composable
private fun DualBodyHexOverviewCard(
    requestHex: String,
    responseHex: String,
    showRequest: Boolean,
    showResponse: Boolean,
    onCopyToast: (String) -> Unit
) {
    val clipboard = LocalClipboardManager.current
    var expanded by remember(requestHex, responseHex) { mutableStateOf(true) }
    val cleanReq = remember(requestHex) { HexUtils.sanitizeHex(requestHex) }
    val cleanResp = remember(responseHex) { HexUtils.sanitizeHex(responseHex) }

    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.32f),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.45f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded }
            ) {
                Text(
                    text = "Body Hex (Request & Response)",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f)
                )
                Icon(
                    imageVector = if (expanded) AppIcons.ExpandLess else AppIcons.ExpandMore,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(18.dp)
                )
            }
            AnimatedVisibility(visible = expanded) {
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.padding(top = 8.dp)
                ) {
                    if (showRequest) {
                        CompactHexStrip(
                            label = "Request Hex (${cleanReq.length / 2}B)",
                            hex = cleanReq,
                            onCopy = {
                                clipboard.setText(AnnotatedString(cleanReq))
                                onCopyToast("Request Hex copied")
                            }
                        )
                    }
                    if (showResponse) {
                        CompactHexStrip(
                            label = "Response Hex (${cleanResp.length / 2}B)",
                            hex = cleanResp,
                            onCopy = {
                                clipboard.setText(AnnotatedString(cleanResp))
                                onCopyToast("Response Hex copied")
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CompactHexStrip(
    label: String,
    hex: String,
    onCopy: () -> Unit
) {
    Surface(
        shape = RoundedCornerShape(10.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f)
                )
                if (hex.isNotBlank()) {
                    IconButton(onClick = onCopy, modifier = Modifier.size(30.dp)) {
                        Icon(
                            AppIcons.ContentCopy,
                            contentDescription = stringResource(R.string.cd_copy),
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(15.dp)
                        )
                    }
                }
            }
            SelectionContainer {
                Text(
                    text = if (hex.isBlank()) "<Empty>" else if (hex.length > 1200) "${hex.take(1200)}..." else hex,
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFamily),
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
    }
}

@Composable
fun JwtDecodedCard(
    jwt: JwtDecodeResult,
    onCopyToast: (String) -> Unit
) {
    var showRawJson by remember { mutableStateOf(false) }

    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, EmeraldPulse.copy(alpha = 0.45f)),
        tonalElevation = 2.dp,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = AppIcons.Key,
                    contentDescription = null,
                    tint = EmeraldPulse,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Authorization JWT Decoded",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.weight(1f))
                if (jwt.isExpired != null) {
                    TagChip(
                        text = if (jwt.isExpired) "EXPIRED" else "ACTIVE",
                        color = if (jwt.isExpired) CoralAlert else EmeraldPulse
                    )
                }
            }

            if (jwt.expirationText != null) {
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Expires: ${jwt.expirationText}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            val priorityKeys = listOf(
                "account_id", "nickname", "lock_region", "noti_region",
                "country_code", "client_version", "release_version", "release_channel", "external_uid"
            )
            val orderedClaims = buildList {
                priorityKeys.forEach { k -> jwt.claims[k]?.let { add(k to it) } }
                jwt.claims.forEach { (k, v) -> if (k !in priorityKeys) add(k to v) }
            }

            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                orderedClaims.take(if (showRawJson) orderedClaims.size else 8).forEach { (k, v) ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = k,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        SelectionContainer {
                            Text(
                                text = v,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .clickable { showRawJson = !showRawJson }
                    .padding(vertical = 4.dp)
            ) {
                Text(
                    text = if (showRawJson) "Hide Raw JWT JSON" else "Show Full JWT Header & Payload JSON",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                Icon(
                    imageVector = if (showRawJson) AppIcons.ExpandLess else AppIcons.ExpandMore,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
            }

            AnimatedVisibility(visible = showRawJson) {
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.padding(top = 8.dp)
                ) {
                    SyntaxHighlightedJsonBlock(
                        json = jwt.headerJson,
                        title = "JWT Header",
                        onCopy = { onCopyToast("JWT Header copied") }
                    )
                    SyntaxHighlightedJsonBlock(
                        json = jwt.payloadJson,
                        title = "JWT Payload",
                        onCopy = { onCopyToast("JWT Payload copied") }
                    )
                }
            }
        }
    }
}

@Composable
fun PayloadDecodedSection(
    title: String,
    endpointPath: String = "/Packet",
    isResponse: Boolean = false,
    analysis: PayloadAnalysis,
    autoDecryptMatch: AutoDecryptMatch? = null,
    rawHex: String,
    sessionCryptoState: SessionCryptoUiState = SessionCryptoUiState(),
    onSaveSessionKey: (key: String, iv: String, isHex: Boolean) -> Unit = { _, _, _ -> },
    onCopyToast: (String) -> Unit,
    onSendToDecoderLab: (String) -> Unit
) {
    val decryptScope = rememberCoroutineScope()
    var protoViewMode by remember(rawHex) { mutableIntStateOf(0) }
    var decryptedProtoViewMode by remember(rawHex) { mutableIntStateOf(0) }
    var showDecryptor by remember(rawHex, autoDecryptMatch) {
        mutableStateOf(!isResponse && autoDecryptMatch == null && analysis.classification == PayloadClassification.ENCRYPTED_BLOCK)
    }
    var keyInput by remember(rawHex, sessionCryptoState.manualKey) {
        mutableStateOf(sessionCryptoState.manualKey)
    }
    var ivInput by remember(rawHex, sessionCryptoState.manualIv) {
        mutableStateOf(sessionCryptoState.manualIv)
    }
    var keyIsHex by remember(rawHex, sessionCryptoState.manualKeyIsHex) {
        mutableStateOf(sessionCryptoState.manualKeyIsHex)
    }
    var saveForSession by remember(rawHex) { mutableStateOf(true) }
    var mode by remember { mutableStateOf(DecryptMode.AES_CBC_PKCS5) }
    var isDecrypting by remember(rawHex) { mutableStateOf(false) }
    var decryptResult by remember(rawHex) { mutableStateOf<PayloadAnalysis?>(null) }
    var decryptError by remember(rawHex) { mutableStateOf<String?>(null) }

    val badgeColor = when (analysis.classification) {
        PayloadClassification.PROTOBUF -> VioletProto
        PayloadClassification.JSON -> EmeraldPulse
        PayloadClassification.ENCRYPTED_BLOCK -> AmberSignal
        PayloadClassification.TEXT -> MaterialTheme.colorScheme.primary
        PayloadClassification.EMPTY -> MaterialTheme.colorScheme.onSurfaceVariant
        PayloadClassification.RAW_BINARY -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.55f)),
        tonalElevation = 1.dp,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = AppIcons.DataObject,
                    contentDescription = null,
                    tint = badgeColor,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f)
                )
                if (autoDecryptMatch != null) {
                    TagChip(text = "AES AUTO", color = EmeraldPulse)
                    Spacer(modifier = Modifier.width(6.dp))
                }
                TagChip(text = analysis.classification.name, color = badgeColor)
            }

            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = if (autoDecryptMatch != null) {
                    "${autoDecryptMatch.sourceLabel} (${autoDecryptMatch.mode.label}) • ${analysis.summary}"
                } else {
                    analysis.summary
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            if (analysis.classification != PayloadClassification.EMPTY) {
                Spacer(modifier = Modifier.height(10.dp))

                analysis.protobuf?.let { proto ->
                    val packagePySnippet by produceState(
                        initialValue = "",
                        key1 = proto,
                        key2 = endpointPath,
                        key3 = isResponse
                    ) {
                        value = withContext(Dispatchers.Default) {
                            ProtobufFieldsFormatter.formatSmartPythonPackage(
                                nodes = proto.fields,
                                endpointOrPath = endpointPath,
                                isResponse = isResponse
                            )
                        }
                    }
                    val asyncSnippet by produceState(
                        initialValue = "",
                        key1 = proto,
                        key2 = endpointPath
                    ) {
                        value = withContext(Dispatchers.Default) {
                            ProtobufFieldsFormatter.formatAsyncSnippet(proto.fields, endpointPath)
                        }
                    }
                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        val labels = listOf("Package PY", "JSON", "Fields {}", "async def", "Tree")
                        items(labels.size) { idx ->
                            FilterChip(
                                selected = protoViewMode == idx,
                                onClick = { protoViewMode = idx },
                                label = { Text(labels[idx], style = MaterialTheme.typography.labelSmall) }
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    when (protoViewMode) {
                        0 -> PythonFieldsCodeBlock(
                            code = packagePySnippet,
                            title = if (isResponse) "Decoded Response Package (PY)" else "Pro Python Package Builder",
                            onCopy = { onCopyToast("Python package copied") }
                        )
                        1 -> SyntaxHighlightedJsonBlock(
                            json = proto.jsonFormatted,
                            title = "Decoded Protobuf JSON",
                            onCopy = { onCopyToast("Protobuf JSON copied") }
                        )
                        2 -> PythonFieldsCodeBlock(
                            code = proto.fieldsDictFormatted,
                            title = "Protobuf Fields Dict",
                            onCopy = { onCopyToast("Protobuf fields copied") }
                        )
                        3 -> PythonFieldsCodeBlock(
                            code = asyncSnippet,
                            title = "Async Packet Builder Snippet",
                            onCopy = { onCopyToast("Async snippet copied") }
                        )
                        else -> ProtobufTreeView(fields = proto.fields)
                    }
                }

                if (analysis.protobuf == null && analysis.formattedJson != null) {
                    SyntaxHighlightedJsonBlock(
                        json = analysis.formattedJson,
                        title = "Decoded JSON",
                        onCopy = { onCopyToast("JSON copied") }
                    )
                } else if (analysis.protobuf == null && analysis.utf8Text != null) {
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        SelectionContainer {
                            Text(
                                text = analysis.utf8Text,
                                style = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                                modifier = Modifier.padding(12.dp)
                            )
                        }
                    }
                }

                if (analysis.classification == PayloadClassification.ENCRYPTED_BLOCK ||
                    analysis.classification == PayloadClassification.RAW_BINARY
                ) {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "Encrypted AES payload (${analysis.byteCount}B). Enter your Session Key & IV below to decode into Python Package, or auto-capture /MajorLogin first.",
                        style = MaterialTheme.typography.labelSmall,
                        color = AmberSignal
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    OutlinedButton(
                        onClick = { showDecryptor = !showDecryptor },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(AppIcons.LockOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(if (showDecryptor) "Hide Key Tool" else "AES / XOR Key")
                    }
                    OutlinedButton(
                        onClick = { onSendToDecoderLab(rawHex) },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(AppIcons.Code, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Open in Lab")
                    }
                }

                AnimatedVisibility(visible = showDecryptor) {
                    Column(
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.padding(top = 12.dp)
                    ) {
                        HorizontalDivider()
                        Text(
                            text = "AES / Session Key Decryptor",
                            style = MaterialTheme.typography.labelLarge,
                            color = AmberSignal
                        )
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            DecryptMode.entries.take(2).forEach { m ->
                                FilterChip(
                                    selected = mode == m,
                                    onClick = { mode = m },
                                    label = { Text(m.label, style = MaterialTheme.typography.labelSmall) }
                                )
                            }
                        }
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            DecryptMode.entries.drop(2).forEach { m ->
                                FilterChip(
                                    selected = mode == m,
                                    onClick = { mode = m },
                                    label = { Text(m.label, style = MaterialTheme.typography.labelSmall) }
                                )
                            }
                        }
                        OutlinedTextField(
                            value = keyInput,
                            onValueChange = { keyInput = it },
                            label = { Text(if (keyIsHex) "Key (Hex)" else "Key (UTF-8 / 32-Hex)") },
                            singleLine = true,
                            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                            modifier = Modifier.fillMaxWidth()
                        )
                        if (mode == DecryptMode.AES_CBC_PKCS5 || mode == DecryptMode.AES_CBC_NOPAD) {
                            OutlinedTextField(
                                value = ivInput,
                                onValueChange = { ivInput = it },
                                label = { Text("IV (16B, blank = zero IV)") },
                                singleLine = true,
                                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Key/IV is Hex", style = MaterialTheme.typography.bodySmall)
                            Spacer(modifier = Modifier.width(6.dp))
                            Switch(checked = keyIsHex, onCheckedChange = { keyIsHex = it })
                            Spacer(modifier = Modifier.width(12.dp))
                            Text("Save Session", style = MaterialTheme.typography.bodySmall)
                            Spacer(modifier = Modifier.width(6.dp))
                            Switch(checked = saveForSession, onCheckedChange = { saveForSession = it })
                        }
                        Button(
                            enabled = !isDecrypting && keyInput.isNotBlank(),
                            onClick = {
                                isDecrypting = true
                                decryptScope.launch {
                                    val res = withContext(Dispatchers.Default) {
                                        PayloadDecryptor.decrypt(
                                            payloadHex = rawHex,
                                            keyInput = keyInput,
                                            ivInput = ivInput,
                                            keyIsHex = keyIsHex,
                                            mode = mode
                                        )
                                    }
                                    res.fold(
                                        onSuccess = {
                                            decryptResult = it
                                            decryptError = null
                                            if (saveForSession) {
                                                onSaveSessionKey(keyInput, ivInput, keyIsHex)
                                            }
                                        },
                                        onFailure = {
                                            decryptResult = null
                                            decryptError = it.message
                                        }
                                    )
                                    isDecrypting = false
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(if (isDecrypting) "Decrypting..." else "Decrypt & Build Package")
                        }

                        decryptError?.let { err ->
                            Text(err, style = MaterialTheme.typography.bodySmall, color = CoralAlert)
                        }

                        decryptResult?.let { dec ->
                            Surface(
                                color = EmeraldPulse.copy(alpha = 0.08f),
                                shape = RoundedCornerShape(10.dp),
                                border = BorderStroke(1.dp, EmeraldPulse.copy(alpha = 0.4f)),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    Text(
                                        text = "Decrypted Output: ${dec.summary}",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = EmeraldPulse
                                    )
                                    Spacer(modifier = Modifier.height(6.dp))
                                    dec.protobuf?.let { p ->
                                        val decPackagePy by produceState(
                                            initialValue = "",
                                            key1 = p,
                                            key2 = endpointPath,
                                            key3 = isResponse
                                        ) {
                                            value = withContext(Dispatchers.Default) {
                                                ProtobufFieldsFormatter.formatSmartPythonPackage(
                                                    nodes = p.fields,
                                                    endpointOrPath = endpointPath,
                                                    isResponse = isResponse
                                                )
                                            }
                                        }
                                        val decAsyncSnippet by produceState(
                                            initialValue = "",
                                            key1 = p,
                                            key2 = endpointPath
                                        ) {
                                            value = withContext(Dispatchers.Default) {
                                                ProtobufFieldsFormatter.formatAsyncSnippet(p.fields, endpointPath)
                                            }
                                        }
                                        LazyRow(
                                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                                            modifier = Modifier.fillMaxWidth()
                                        ) {
                                            val labels = listOf("Package PY", "JSON", "Fields {}", "async def", "Tree")
                                            items(labels.size) { idx ->
                                                FilterChip(
                                                    selected = decryptedProtoViewMode == idx,
                                                    onClick = { decryptedProtoViewMode = idx },
                                                    label = { Text(labels[idx], style = MaterialTheme.typography.labelSmall) }
                                                )
                                            }
                                        }
                                        Spacer(modifier = Modifier.height(6.dp))
                                        when (decryptedProtoViewMode) {
                                            0 -> PythonFieldsCodeBlock(
                                                code = decPackagePy,
                                                title = "Decrypted Package (PY)",
                                                onCopy = { onCopyToast("Decrypted Python package copied") }
                                            )
                                            1 -> SyntaxHighlightedJsonBlock(
                                                json = p.jsonFormatted,
                                                title = "Decrypted Protobuf JSON",
                                                onCopy = { onCopyToast("Decrypted JSON copied") }
                                            )
                                            2 -> PythonFieldsCodeBlock(
                                                code = p.fieldsDictFormatted,
                                                title = "Decrypted Fields {}",
                                                onCopy = { onCopyToast("Decrypted fields copied") }
                                            )
                                            3 -> PythonFieldsCodeBlock(
                                                code = decAsyncSnippet,
                                                title = "Async Packet Builder Snippet",
                                                onCopy = { onCopyToast("Async snippet copied") }
                                            )
                                            else -> ProtobufTreeView(fields = p.fields)
                                        }
                                    }
                                    if (dec.protobuf == null) {
                                        if (dec.formattedJson != null) {
                                            SyntaxHighlightedJsonBlock(
                                                json = dec.formattedJson,
                                                title = "Decrypted JSON",
                                                onCopy = { onCopyToast("Decrypted JSON copied") }
                                            )
                                        } else {
                                            val fallback = dec.utf8Text ?: dec.hex.ifBlank { "<Empty Body>" }
                                            SelectionContainer {
                                                Text(
                                                    text = fallback,
                                                    style = MaterialTheme.typography.labelMedium,
                                                    color = MaterialTheme.colorScheme.onSurface
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun JsonTabContent(
    packet: CapturedPacketEntity,
    reqDecodedText: String?,
    respDecodedText: String?,
    reqAnalysis: PayloadAnalysis,
    respAnalysis: PayloadAnalysis,
    onCopyAll: () -> Unit,
    onShare: () -> Unit,
    onCopyToast: (String) -> Unit
) {
    val clipboard = LocalClipboardManager.current
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier.fillMaxSize()
    ) {
        item {
            Row(
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Button(
                    onClick = onCopyAll,
                    modifier = Modifier
                        .weight(1f)
                        .testTag("json_tab_copy_button")
                ) {
                    Icon(AppIcons.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.action_copy_json))
                }
                OutlinedButton(
                    onClick = onShare,
                    modifier = Modifier
                        .weight(1f)
                        .testTag("json_tab_share_button")
                ) {
                    Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.action_export_json))
                }
            }
        }

        item {
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        text = "API Endpoint",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    SelectionContainer {
                        Text(
                            text = "${packet.method} ${packet.url}",
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }
        }

        item {
            SeparateDecodedJsonCard(
                title = "Request Decoded JSON",
                decodedText = reqDecodedText,
                analysis = reqAnalysis,
                onCopy = { text ->
                    clipboard.setText(AnnotatedString(text))
                    onCopyToast("Request decoded JSON copied")
                }
            )
        }

        item {
            SeparateDecodedJsonCard(
                title = "Response Decoded JSON",
                decodedText = respDecodedText,
                analysis = respAnalysis,
                onCopy = { text ->
                    clipboard.setText(AnnotatedString(text))
                    onCopyToast("Response decoded JSON copied")
                }
            )
        }
    }
}

@Composable
private fun SeparateDecodedJsonCard(
    title: String,
    decodedText: String?,
    analysis: PayloadAnalysis,
    onCopy: (String) -> Unit
) {
    if (decodedText != null && (analysis.protobuf != null || analysis.formattedJson != null)) {
        SyntaxHighlightedJsonBlock(
            json = decodedText,
            title = title,
            onCopy = { onCopy(decodedText) }
        )
    } else if (decodedText != null) {
        Surface(
            shape = RoundedCornerShape(14.dp),
            color = MaterialTheme.colorScheme.surface,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                    IconButton(onClick = { onCopy(decodedText) }, modifier = Modifier.size(36.dp)) {
                        Icon(
                            AppIcons.ContentCopy,
                            contentDescription = stringResource(R.string.cd_copy),
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(6.dp))
                SelectionContainer {
                    Text(
                        text = decodedText,
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    } else {
        Surface(
            shape = RoundedCornerShape(14.dp),
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.25f),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = if (analysis.classification == PayloadClassification.EMPTY) {
                        "Empty body (0 bytes)."
                    } else {
                        "No decodable JSON/Protobuf payload (${analysis.byteCount}B binary/encrypted — open Headers & Hex for raw hex)."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun HeadersAndHexTabContent(
    packet: CapturedPacketEntity,
    reqHeaders: Map<String, String>,
    respHeaders: Map<String, String>,
    reqAnalysis: PayloadAnalysis,
    respAnalysis: PayloadAnalysis,
    onCopyToast: (String) -> Unit
) {
    val clipboard = LocalClipboardManager.current
    // 0 = BOTH, 1 = REQUEST, 2 = RESPONSE
    var scopeMode by remember(packet.id) { mutableIntStateOf(0) }
    var showHeadersOnly by remember(packet.id) { mutableStateOf(false) }
    var spacedHex by remember(packet.id) { mutableStateOf(true) }

    val formattedReqBody by produceState(
        initialValue = if (packet.requestBodyHex.isBlank()) "<Empty Body>" else "",
        key1 = packet.requestBodyHex,
        key2 = spacedHex
    ) {
        value = withContext(Dispatchers.Default) {
            if (spacedHex) HexUtils.formatSpacedHex(packet.requestBodyHex)
            else HexUtils.sanitizeHex(packet.requestBodyHex).uppercase().ifBlank { "<Empty Body>" }
        }
    }
    val formattedRespBody by produceState(
        initialValue = if (packet.responseBodyHex.isBlank()) "<Empty Body>" else "",
        key1 = packet.responseBodyHex,
        key2 = spacedHex
    ) {
        value = withContext(Dispatchers.Default) {
            if (spacedHex) HexUtils.formatSpacedHex(packet.responseBodyHex)
            else HexUtils.sanitizeHex(packet.responseBodyHex).uppercase().ifBlank { "<Empty Body>" }
        }
    }

    val totalBodyBytes = when (scopeMode) {
        1 -> reqAnalysis.byteCount
        2 -> respAnalysis.byteCount
        else -> reqAnalysis.byteCount + respAnalysis.byteCount
    }
    val totalHeadersCount = when (scopeMode) {
        1 -> reqHeaders.size
        2 -> respHeaders.size
        else -> reqHeaders.size + respHeaders.size
    }

    Column(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
        ) {
            item {
                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    SegmentedButton(
                        selected = !showHeadersOnly,
                        onClick = { showHeadersOnly = false },
                        shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                    ) {
                        Text("BODY (${totalBodyBytes}B)")
                    }
                    SegmentedButton(
                        selected = showHeadersOnly,
                        onClick = { showHeadersOnly = true },
                        shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                    ) {
                        Text("HEADERS ($totalHeadersCount)")
                    }
                }
            }

            if (showHeadersOnly) {
                if (scopeMode == 0 || scopeMode == 1) {
                    item {
                        HeadersCard(
                            title = "Request Headers (${reqHeaders.size})",
                            headers = reqHeaders
                        )
                    }
                }
                if (scopeMode == 0 || scopeMode == 2) {
                    item {
                        HeadersCard(
                            title = "Response Headers (${respHeaders.size})",
                            headers = respHeaders
                        )
                    }
                }
            } else {
                item {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        FilterChip(
                            selected = spacedHex,
                            onClick = { spacedHex = true },
                            label = { Text("Format: Hex (Spaced)") }
                        )
                        FilterChip(
                            selected = !spacedHex,
                            onClick = { spacedHex = false },
                            label = { Text("Raw Hex") }
                        )
                    }
                }
                if (scopeMode == 0 || scopeMode == 1) {
                    item {
                        HexBlockCard(
                            title = "Request Body (${reqAnalysis.byteCount}B)",
                            displayHex = formattedReqBody,
                            hasBytes = packet.requestBodyHex.isNotBlank(),
                            onCopyHex = {
                                clipboard.setText(AnnotatedString(formattedReqBody))
                                onCopyToast("Request hex copied")
                            }
                        )
                    }
                }
                if (scopeMode == 0 || scopeMode == 2) {
                    item {
                        HexBlockCard(
                            title = "Response Body (${respAnalysis.byteCount}B)",
                            displayHex = formattedRespBody,
                            hasBytes = packet.responseBodyHex.isNotBlank(),
                            onCopyHex = {
                                clipboard.setText(AnnotatedString(formattedRespBody))
                                onCopyToast("Response hex copied")
                            }
                        )
                    }
                }
            }
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f))

        SingleChoiceSegmentedButtonRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp)
                .testTag("detail_request_response_switch")
        ) {
            SegmentedButton(
                selected = scopeMode == 0,
                onClick = { scopeMode = 0 },
                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 3)
            ) {
                Text("BOTH")
            }
            SegmentedButton(
                selected = scopeMode == 1,
                onClick = { scopeMode = 1 },
                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 3)
            ) {
                Text("REQUEST")
            }
            SegmentedButton(
                selected = scopeMode == 2,
                onClick = { scopeMode = 2 },
                shape = SegmentedButtonDefaults.itemShape(index = 2, count = 3)
            ) {
                Text("RESPONSE")
            }
        }
    }
}

@Composable
private fun HeadersCard(title: String, headers: Map<String, String>) {
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(8.dp))
            if (headers.isEmpty()) {
                Text(
                    "No headers recorded",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    headers.forEach { (k, v) ->
                        Column {
                            Text(
                                text = k,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary
                            )
                            SelectionContainer {
                                Text(
                                    text = v,
                                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                            }
                        }
                        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
                    }
                }
            }
        }
    }
}

@Composable
private fun HexBlockCard(
    title: String,
    displayHex: String,
    hasBytes: Boolean,
    onCopyHex: () -> Unit
) {
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                if (hasBytes) {
                    IconButton(onClick = onCopyHex, modifier = Modifier.size(36.dp)) {
                        Icon(
                            AppIcons.ContentCopy,
                            contentDescription = stringResource(R.string.cd_copy),
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(6.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                        RoundedCornerShape(10.dp)
                    )
                    .padding(12.dp)
            ) {
                SelectionContainer {
                    Text(
                        text = displayHex.ifBlank { "<Empty Body>" },
                        style = MaterialTheme.typography.labelMedium.copy(fontFamily = JetBrainsMonoFamily),
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}
