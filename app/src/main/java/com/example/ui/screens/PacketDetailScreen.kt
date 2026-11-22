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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DataObject
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
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
import androidx.compose.runtime.remember
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
import com.example.R
import com.example.data.db.CapturedPacketEntity
import com.example.decoder.DecryptMode
import com.example.decoder.JwtDecodeResult
import com.example.decoder.JwtDecoder
import com.example.decoder.PacketJsonSerializer
import com.example.decoder.PacketRawFormatter
import com.example.decoder.PayloadAnalysis
import com.example.decoder.PayloadAnalyzer
import com.example.decoder.PayloadClassification
import com.example.decoder.PayloadDecryptor
import com.example.decoder.ProtobufFieldsFormatter
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PacketDetailScreen(
    packet: CapturedPacketEntity,
    isPaneMode: Boolean,
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

    val packetJson = remember(packet) { PacketJsonSerializer.packetToFormattedJson(packet) }
    val reqHeaders = remember(packet.requestHeadersJson) {
        PacketJsonSerializer.parseHeadersMap(packet.requestHeadersJson)
    }
    val respHeaders = remember(packet.responseHeadersJson) {
        PacketJsonSerializer.parseHeadersMap(packet.responseHeadersJson)
    }
    val jwtDecoded = remember(packet.requestHeadersJson) {
        JwtDecoder.extractFromHeaders(packet.requestHeadersJson)
    }
    val reqAnalysis = remember(packet.requestBodyHex) {
        PayloadAnalyzer.analyze(packet.requestBodyHex)
    }
    val respAnalysis = remember(packet.responseBodyHex) {
        PayloadAnalyzer.analyze(packet.responseBodyHex)
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
                    text = { Text("Decode") },
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

            when (selectedTab) {
                0 -> DecodeTabContent(
                    packet = packet,
                    jwtDecoded = jwtDecoded,
                    reqAnalysis = reqAnalysis,
                    respAnalysis = respAnalysis,
                    onCopyToast = onCopyToast,
                    onSendToDecoderLab = onSendToDecoderLab
                )
                1 -> JsonTabContent(
                    packetJson = packetJson,
                    onCopy = {
                        clipboard.setText(AnnotatedString(packetJson))
                        onCopyToast("Packet JSON copied")
                    },
                    onShare = { onShareJson(packetJson) }
                )
                2 -> HeadersAndHexTabContent(
                    packet = packet,
                    reqHeaders = reqHeaders,
                    respHeaders = respHeaders,
                    reqAnalysis = reqAnalysis,
                    respAnalysis = respAnalysis,
                    onCopyToast = onCopyToast
                )
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
                            onClick = {
                                clipboard.setText(AnnotatedString(packetJson))
                                onCopyToast("Packet JSON copied")
                            },
                            modifier = Modifier.testTag("detail_copy_json_button")
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = stringResource(R.string.cd_copy))
                        }
                        IconButton(
                            onClick = { onShareJson(packetJson) },
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
                            onClick = {
                                clipboard.setText(AnnotatedString(packetJson))
                                onCopyToast("Packet JSON copied")
                            },
                            modifier = Modifier.testTag("detail_copy_json_button")
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = stringResource(R.string.cd_copy))
                        }
                        IconButton(
                            onClick = { onShareJson(packetJson) },
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
    jwtDecoded: JwtDecodeResult?,
    reqAnalysis: PayloadAnalysis,
    respAnalysis: PayloadAnalysis,
    onCopyToast: (String) -> Unit,
    onSendToDecoderLab: (String) -> Unit
) {
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        modifier = Modifier.fillMaxSize()
    ) {
        if (jwtDecoded != null) {
            item {
                JwtDecodedCard(jwt = jwtDecoded, onCopyToast = onCopyToast)
            }
        }

        item {
            PayloadDecodedSection(
                title = "Response Body Decoder",
                endpointPath = packet.path,
                analysis = respAnalysis,
                rawHex = packet.responseBodyHex,
                onCopyToast = onCopyToast,
                onSendToDecoderLab = onSendToDecoderLab
            )
        }

        item {
            PayloadDecodedSection(
                title = "Request Body Decoder",
                endpointPath = packet.path,
                analysis = reqAnalysis,
                rawHex = packet.requestBodyHex,
                onCopyToast = onCopyToast,
                onSendToDecoderLab = onSendToDecoderLab
            )
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
                    imageVector = Icons.Default.Key,
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
                    imageVector = if (showRawJson) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
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
    analysis: PayloadAnalysis,
    rawHex: String,
    onCopyToast: (String) -> Unit,
    onSendToDecoderLab: (String) -> Unit
) {
    var protoViewMode by remember(rawHex) { mutableIntStateOf(0) }
    var showDecryptor by remember(rawHex) { mutableStateOf(false) }
    var keyInput by remember { mutableStateOf("") }
    var ivInput by remember { mutableStateOf("") }
    var keyIsHex by remember { mutableStateOf(false) }
    var mode by remember { mutableStateOf(DecryptMode.AES_CBC_PKCS5) }
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
                    imageVector = Icons.Default.DataObject,
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
                TagChip(text = analysis.classification.name, color = badgeColor)
            }

            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = analysis.summary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            if (analysis.classification != PayloadClassification.EMPTY) {
                Spacer(modifier = Modifier.height(10.dp))

                analysis.protobuf?.let { proto ->
                    val asyncSnippet = remember(proto, endpointPath) {
                        ProtobufFieldsFormatter.formatAsyncSnippet(proto.fields, endpointPath)
                    }
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        listOf("Fields {}", "async def", "Tree", "JSON").forEachIndexed { idx, label ->
                            FilterChip(
                                selected = protoViewMode == idx,
                                onClick = { protoViewMode = idx },
                                label = { Text(label, style = MaterialTheme.typography.labelSmall) }
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    when (protoViewMode) {
                        0 -> PythonFieldsCodeBlock(
                            code = proto.fieldsDictFormatted,
                            title = "Protobuf Fields Dict",
                            onCopy = { onCopyToast("Protobuf fields copied") }
                        )
                        1 -> PythonFieldsCodeBlock(
                            code = asyncSnippet,
                            title = "Async Packet Builder Snippet",
                            onCopy = { onCopyToast("Async snippet copied") }
                        )
                        2 -> ProtobufTreeView(fields = proto.fields)
                        else -> SyntaxHighlightedJsonBlock(
                            json = proto.jsonFormatted,
                            title = "Decoded Protobuf JSON",
                            onCopy = { onCopyToast("Protobuf JSON copied") }
                        )
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
                    Spacer(modifier = Modifier.height(8.dp))
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        SelectionContainer {
                            Text(
                                text = analysis.hexDump,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.padding(12.dp)
                            )
                        }
                    }
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
                        Icon(Icons.Default.LockOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(if (showDecryptor) "Hide Key Tool" else "AES / XOR Key")
                    }
                    OutlinedButton(
                        onClick = { onSendToDecoderLab(rawHex) },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Code, contentDescription = null, modifier = Modifier.size(16.dp))
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
                            text = "Manual Cipher Decryptor",
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
                            label = { Text(if (keyIsHex) "Key (Hex)" else "Key (UTF-8)") },
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
                            Spacer(modifier = Modifier.width(8.dp))
                            Switch(checked = keyIsHex, onCheckedChange = { keyIsHex = it })
                            Spacer(modifier = Modifier.weight(1f))
                            Button(
                                onClick = {
                                    PayloadDecryptor.decrypt(
                                        payloadHex = rawHex,
                                        keyInput = keyInput,
                                        ivInput = ivInput,
                                        keyIsHex = keyIsHex,
                                        mode = mode
                                    ).fold(
                                        onSuccess = {
                                            decryptResult = it
                                            decryptError = null
                                        },
                                        onFailure = {
                                            decryptResult = null
                                            decryptError = it.message
                                        }
                                    )
                                }
                            ) {
                                Text("Decrypt")
                            }
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
                                        PythonFieldsCodeBlock(
                                            code = p.fieldsDictFormatted,
                                            title = "Decrypted Fields {}",
                                            onCopy = { onCopyToast("Decrypted fields copied") }
                                        )
                                        Spacer(modifier = Modifier.height(6.dp))
                                        ProtobufTreeView(fields = p.fields)
                                        Spacer(modifier = Modifier.height(6.dp))
                                    }
                                    if (dec.protobuf == null) {
                                        val fallback = dec.formattedJson ?: dec.utf8Text ?: dec.hexDump
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

@Composable
private fun JsonTabContent(
    packetJson: String,
    onCopy: () -> Unit,
    onShare: () -> Unit
) {
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
                    onClick = onCopy,
                    modifier = Modifier
                        .weight(1f)
                        .testTag("json_tab_copy_button")
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
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
            SyntaxHighlightedJsonBlock(
                json = packetJson,
                title = "Captured Request & Decoded Payload JSON",
                onCopy = onCopy
            )
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
    val rawDump = remember(packet) { PacketRawFormatter.formatPacket(packet) }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        modifier = Modifier.fillMaxSize()
    ) {
        item {
            PythonFieldsCodeBlock(
                code = rawDump,
                title = "Captured Raw Dump (Method, Headers, Hex)",
                onCopy = { onCopyToast("Raw packet dump copied") }
            )
        }
        item {
            HeadersCard(title = "Request Headers (${reqHeaders.size})", headers = reqHeaders)
        }
        item {
            HexBlockCard(
                title = "Request Body Hex (${reqAnalysis.byteCount}B)",
                rawHex = packet.requestBodyHex,
                hexDump = reqAnalysis.hexDump,
                onCopyHex = {
                    clipboard.setText(AnnotatedString(packet.requestBodyHex))
                    onCopyToast("Request hex copied")
                }
            )
        }
        item {
            HeadersCard(title = "Response Headers (${respHeaders.size})", headers = respHeaders)
        }
        item {
            HexBlockCard(
                title = "Response Body Hex (${respAnalysis.byteCount}B)",
                rawHex = packet.responseBodyHex,
                hexDump = respAnalysis.hexDump,
                onCopyHex = {
                    clipboard.setText(AnnotatedString(packet.responseBodyHex))
                    onCopyToast("Response hex copied")
                }
            )
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
    rawHex: String,
    hexDump: String,
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
                if (rawHex.isNotEmpty()) {
                    IconButton(onClick = onCopyHex, modifier = Modifier.size(36.dp)) {
                        Icon(
                            Icons.Default.ContentCopy,
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
                    .padding(10.dp)
            ) {
                SelectionContainer {
                    Text(
                        text = if (rawHex.isEmpty()) "<Empty Body>" else hexDump,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}
