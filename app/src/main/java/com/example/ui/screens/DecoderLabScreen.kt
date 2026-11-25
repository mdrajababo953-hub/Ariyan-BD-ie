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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.decoder.ProtobufFieldsFormatter
import com.example.ui.components.ProtobufTreeView
import com.example.ui.components.PythonFieldsCodeBlock
import com.example.ui.components.SyntaxHighlightedJsonBlock
import com.example.ui.components.TagChip
import com.example.ui.theme.AmberSignal
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
    onDecodeClick: () -> Unit,
    onPresetClick: (String) -> Unit,
    onHeaderSkipChange: (Int) -> Unit,
    onCopyToast: (String) -> Unit
) {
    val clipboard = LocalClipboardManager.current
    var protoViewMode by remember { mutableIntStateOf(0) }

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
                    text = "Paste Response or Request Hex, JWT, or JSON below and tap Decode to build Python Package & Fields",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        item {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                item {
                    OutlinedButton(onClick = { onPresetClick(PRESET_CS_RANKING) }) {
                        Text("CS Ranking Hex")
                    }
                }
                item {
                    OutlinedButton(onClick = { onPresetClick(PRESET_LEVEL_REWARDS) }) {
                        Text("Level Rewards Hex")
                    }
                }
                item {
                    OutlinedButton(onClick = { onPresetClick(PRESET_JWT) }) {
                        Text("Sample JWT")
                    }
                }
            }
        }

        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = state.inputText,
                    onValueChange = onInputChange,
                    label = { Text("Paste Response / Request Hex, JWT Token, or JSON") },
                    minLines = 3,
                    maxLines = 6,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("decoder_lab_input")
                )

                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    OutlinedButton(
                        onClick = {
                            val clipText = clipboard.getText()?.text.orEmpty()
                            if (clipText.isNotBlank()) {
                                onInputChange(clipText)
                                onCopyToast("Hex pasted — tap Decode")
                            } else {
                                onCopyToast("Clipboard is empty")
                            }
                        },
                        modifier = Modifier.testTag("decoder_lab_paste_button")
                    ) {
                        Text("Paste")
                    }
                    OutlinedButton(
                        onClick = { onInputChange("") },
                        enabled = state.inputText.isNotEmpty(),
                        modifier = Modifier.testTag("decoder_lab_clear_button")
                    ) {
                        Text("Clear")
                    }
                    Button(
                        onClick = onDecodeClick,
                        enabled = state.inputText.isNotBlank(),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("decoder_lab_decode_button")
                    ) {
                        Text("Decode")
                    }
                }
            }
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
                                val packagePy = remember(proto, hdrHex) {
                                    ProtobufFieldsFormatter.formatSmartPythonPackage(
                                        nodes = proto.fields,
                                        endpointOrPath = "Packet",
                                        isResponse = false,
                                        packetHeaderHex = hdrHex
                                    )
                                }
                                val asyncSnippet = remember(proto, hdrHex) {
                                    ProtobufFieldsFormatter.formatAsyncSnippet(
                                        nodes = proto.fields,
                                        endpointOrPath = "Packet",
                                        packetHeaderHex = hdrHex
                                    )
                                }
                                Spacer(modifier = Modifier.height(10.dp))
                                LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    listOf("Package PY", "Fields {}", "async def", "Tree", "JSON").forEachIndexed { idx, label ->
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
                                        code = packagePy,
                                        title = "Pro Python Package Builder",
                                        onCopy = { onCopyToast("Python package copied") }
                                    )
                                    1 -> PythonFieldsCodeBlock(
                                        code = proto.fieldsDictFormatted,
                                        title = "Protobuf Fields Dict",
                                        onCopy = { onCopyToast("Protobuf fields copied") }
                                    )
                                    2 -> PythonFieldsCodeBlock(
                                        code = asyncSnippet,
                                        title = "Async Packet Builder Snippet",
                                        onCopy = { onCopyToast("Async snippet copied") }
                                    )
                                    3 -> ProtobufTreeView(fields = proto.fields)
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
    }
}
