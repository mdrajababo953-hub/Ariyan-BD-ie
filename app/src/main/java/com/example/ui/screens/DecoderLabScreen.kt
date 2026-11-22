package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.decoder.DecryptMode
import com.example.decoder.ProtobufFieldsFormatter
import com.example.ui.components.ProtobufTreeView
import com.example.ui.components.PythonFieldsCodeBlock
import com.example.ui.components.SyntaxHighlightedJsonBlock
import com.example.ui.components.TagChip
import com.example.ui.theme.AmberSignal
import com.example.ui.theme.CoralAlert
import com.example.ui.theme.EmeraldPulse
import com.example.ui.theme.JetBrainsMonoFamily
import com.example.ui.theme.VioletProto
import com.example.ui.viewmodel.DecoderLabState

private const val PRESET_CS_RANKING =
    "08f4f3c8cf3d102618ad0220ad02300170807d8001ad028801cc08a80101b001019a0200"

private const val PRESET_LEVEL_REWARDS =
    "0a0f081e100118a288a38703200528e7070a0f082810011888b9e0be01200528e7070a0f0832100118a288a38703200a28e7070a0f083c10011888b9e0be01200a28e707"

private const val PRESET_JWT =
    "eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxNjU0MTQzMjMwOCwibmlja25hbWUiOiJZUXhCVEFGeVdqbGFHMUE4Iiwibm90aV9yZWdpb24iOiJCRCIsImxvY2tfcmVnaW9uIjoiQkQiLCJjbGllbnRfdmVyc2lvbiI6IjEuMTI2LjE1IiwicmVsZWFzZV92ZXJzaW9uIjoiT0I1NCIsImV4cCI6MTc4NTAyNTU0N30.KHCBeyZRj66JhndGm7qtxu6drBV7U01egja0oYKdJaI"

@Composable
fun DecoderLabScreen(
    state: DecoderLabState,
    onInputChange: (String) -> Unit,
    onHeaderSkipChange: (Int) -> Unit,
    onUpdateCrypto: (key: String, iv: String, keyIsHex: Boolean, mode: DecryptMode) -> Unit,
    onRunDecrypt: () -> Unit,
    onCopyToast: (String) -> Unit
) {
    var protoViewMode by remember { mutableIntStateOf(0) }
    var decryptedViewMode by remember { mutableIntStateOf(0) }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        modifier = Modifier.fillMaxSize()
    ) {
        item {
            Column {
                Text(
                    text = "Decoder Lab",
                    style = MaterialTheme.typography.headlineSmall
                )
                Text(
                    text = "Decode Protobuf Hex to fields = { ... }, async def snippets, JWT & AES/XOR payloads",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        item {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                item {
                    OutlinedButton(onClick = { onInputChange(PRESET_CS_RANKING) }) {
                        Text("CS Ranking Hex")
                    }
                }
                item {
                    OutlinedButton(onClick = { onInputChange(PRESET_LEVEL_REWARDS) }) {
                        Text("Level Rewards Hex")
                    }
                }
                item {
                    OutlinedButton(onClick = { onInputChange(PRESET_JWT) }) {
                        Text("Sample JWT")
                    }
                }
            }
        }

        item {
            OutlinedTextField(
                value = state.inputText,
                onValueChange = onInputChange,
                label = { Text("Paste Hex, JWT Token, or JSON") },
                minLines = 3,
                maxLines = 6,
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("decoder_lab_input")
            )
        }

        if (state.jwtResult == null) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = "Packet Header Offset (Skip leading bytes e.g. 0E15)",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        listOf(0, 2, 4, 5, 6).forEach { skip ->
                            item {
                                FilterChip(
                                    selected = state.headerSkipBytes == skip,
                                    onClick = { onHeaderSkipChange(skip) },
                                    label = { Text(if (skip == 0) "No Header" else "Skip ${skip}B") }
                                )
                            }
                        }
                    }
                    if (state.headerHexPreview.isNotEmpty()) {
                        Text(
                            text = "Header ID: 0x${state.headerHexPreview}",
                            style = MaterialTheme.typography.labelMedium,
                            color = AmberSignal
                        )
                    }
                }
            }
        }

        state.jwtResult?.let { jwt ->
            item {
                JwtDecodedCard(jwt = jwt, onCopyToast = onCopyToast)
            }
        }

        if (state.jwtResult == null) {
            state.payloadAnalysis?.let { analysis ->
                item {
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = MaterialTheme.colorScheme.surface,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Detected Format", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                                TagChip(analysis.classification.name, VioletProto)
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = analysis.summary,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )

                            analysis.protobuf?.let { proto ->
                                val hdrHex = state.headerHexPreview.ifBlank { "0E15" }
                                val asyncSnippet = remember(proto, hdrHex) {
                                    ProtobufFieldsFormatter.formatAsyncSnippet(
                                        nodes = proto.fields,
                                        endpointOrPath = "Packet",
                                        packetHeaderHex = hdrHex
                                    )
                                }
                                Spacer(modifier = Modifier.height(10.dp))
                                LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    listOf("Fields {}", "async def", "Tree", "JSON").forEachIndexed { idx, label ->
                                        item {
                                            FilterChip(
                                                selected = protoViewMode == idx,
                                                onClick = { protoViewMode = idx },
                                                label = { Text(label) }
                                            )
                                        }
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
                                        title = "Protobuf JSON Output",
                                        onCopy = { onCopyToast("Decoded JSON copied") }
                                    )
                                }
                            }

                            if (analysis.protobuf == null && analysis.formattedJson != null) {
                                Spacer(modifier = Modifier.height(10.dp))
                                SyntaxHighlightedJsonBlock(
                                    json = analysis.formattedJson,
                                    title = "Formatted JSON",
                                    onCopy = { onCopyToast("JSON copied") }
                                )
                            }

                            if (analysis.protobuf == null && analysis.formattedJson == null) {
                                Spacer(modifier = Modifier.height(10.dp))
                                Text(
                                    text = analysis.utf8Text ?: analysis.hex.ifBlank { "<Empty Body>" },
                                    style = MaterialTheme.typography.labelMedium.copy(fontFamily = JetBrainsMonoFamily),
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                            }
                        }
                    }
                }
            }
        }

        // AES / XOR Key Workbench
        item {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, AmberSignal.copy(alpha = 0.45f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.padding(14.dp)
                ) {
                    Text("Cipher Decrypt Workbench", style = MaterialTheme.typography.titleSmall, color = AmberSignal)
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        items(DecryptMode.entries.size) { idx ->
                            val m = DecryptMode.entries[idx]
                            FilterChip(
                                selected = state.decryptMode == m,
                                onClick = {
                                    onUpdateCrypto(state.keyInput, state.ivInput, state.keyIsHex, m)
                                },
                                label = { Text(m.label) }
                            )
                        }
                    }
                    OutlinedTextField(
                        value = state.keyInput,
                        onValueChange = { onUpdateCrypto(it, state.ivInput, state.keyIsHex, state.decryptMode) },
                        label = { Text(if (state.keyIsHex) "Key (Hex)" else "Key (UTF-8)") },
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                        modifier = Modifier.fillMaxWidth()
                    )
                    if (state.decryptMode == DecryptMode.AES_CBC_PKCS5 || state.decryptMode == DecryptMode.AES_CBC_NOPAD) {
                        OutlinedTextField(
                            value = state.ivInput,
                            onValueChange = { onUpdateCrypto(state.keyInput, it, state.keyIsHex, state.decryptMode) },
                            label = { Text("IV (16 bytes, blank = zeros)") },
                            singleLine = true,
                            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Hex Key/IV", style = MaterialTheme.typography.bodySmall)
                        Spacer(modifier = Modifier.width(8.dp))
                        Switch(
                            checked = state.keyIsHex,
                            onCheckedChange = {
                                onUpdateCrypto(state.keyInput, state.ivInput, it, state.decryptMode)
                            }
                        )
                        Spacer(modifier = Modifier.weight(1f))
                        Button(onClick = onRunDecrypt) {
                            Text("Decrypt & Decode")
                        }
                    }

                    state.decryptError?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = CoralAlert)
                    }

                    state.decryptedAnalysis?.let { dec ->
                        Surface(
                            color = EmeraldPulse.copy(alpha = 0.08f),
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, EmeraldPulse.copy(alpha = 0.45f)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text(dec.summary, style = MaterialTheme.typography.labelMedium, color = EmeraldPulse)
                                Spacer(modifier = Modifier.height(6.dp))
                                dec.protobuf?.let { p ->
                                    val hdrHex = state.headerHexPreview.ifBlank { "0E15" }
                                    val asyncSnippet = remember(p, hdrHex) {
                                        ProtobufFieldsFormatter.formatAsyncSnippet(
                                            nodes = p.fields,
                                            endpointOrPath = "Packet",
                                            packetHeaderHex = hdrHex
                                        )
                                    }
                                    LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        listOf("Fields {}", "async def", "Tree", "JSON").forEachIndexed { idx, label ->
                                            item {
                                                FilterChip(
                                                    selected = decryptedViewMode == idx,
                                                    onClick = { decryptedViewMode = idx },
                                                    label = { Text(label) }
                                                )
                                            }
                                        }
                                    }
                                    Spacer(modifier = Modifier.height(6.dp))
                                    when (decryptedViewMode) {
                                        0 -> PythonFieldsCodeBlock(
                                            code = p.fieldsDictFormatted,
                                            title = "Decrypted Fields {}",
                                            onCopy = { onCopyToast("Decrypted fields copied") }
                                        )
                                        1 -> PythonFieldsCodeBlock(
                                            code = asyncSnippet,
                                            title = "Async Packet Builder Snippet",
                                            onCopy = { onCopyToast("Async snippet copied") }
                                        )
                                        2 -> ProtobufTreeView(fields = p.fields)
                                        else -> SyntaxHighlightedJsonBlock(
                                            json = p.jsonFormatted,
                                            title = "Decrypted Protobuf JSON",
                                            onCopy = { onCopyToast("JSON copied") }
                                        )
                                    }
                                } ?: Text(
                                    text = dec.formattedJson ?: dec.utf8Text ?: dec.hex.ifBlank { "<Empty Body>" },
                                    style = MaterialTheme.typography.labelMedium.copy(fontFamily = JetBrainsMonoFamily)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
