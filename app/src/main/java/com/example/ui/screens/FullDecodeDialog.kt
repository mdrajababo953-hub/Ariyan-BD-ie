package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.decoder.FullDecodeScope
import com.example.ui.components.AppIcons
import com.example.ui.theme.CoralAlert
import com.example.ui.theme.EmeraldPulse
import com.example.ui.theme.JetBrainsMonoFamily
import com.example.ui.viewmodel.FullDecodeUiState

@Composable
fun FullDecodeDialog(
    state: FullDecodeUiState,
    onSelectAndRun: (FullDecodeScope) -> Unit,
    onShareJson: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var chosenScope by remember(state.isDialogOpen) { mutableStateOf(state.selectedScope) }

    AlertDialog(
        onDismissRequest = {
            if (!state.isRunning) onDismiss()
        },
        icon = {
            Icon(
                imageVector = if (state.result != null) Icons.Default.CheckCircle else AppIcons.AutoFixHigh,
                contentDescription = null,
                tint = if (state.result != null) EmeraldPulse else MaterialTheme.colorScheme.primary
            )
        },
        title = {
            Text(
                text = when {
                    state.isRunning -> "Decoding Payloads..."
                    state.result != null -> "Full Decode Saved"
                    else -> "Full Decode to Aryan Folder"
                },
                style = MaterialTheme.typography.titleLarge
            )
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                when {
                    state.isRunning -> {
                        val total = state.total.coerceAtLeast(1)
                        val progress = (state.processed.toFloat() / total.toFloat()).coerceIn(0f, 1f)
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(26.dp), strokeWidth = 2.5.dp)
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "Decoding ${state.selectedScope.label} hex & JWTs...",
                                    style = MaterialTheme.typography.bodyMedium
                                )
                                Text(
                                    text = "${state.processed} / ${state.total} requests",
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFamily),
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                        LinearProgressIndicator(
                            progress = { progress },
                            modifier = Modifier.fillMaxWidth()
                        )
                    }

                    state.result != null -> {
                        val res = state.result
                        Surface(
                            shape = RoundedCornerShape(12.dp),
                            color = EmeraldPulse.copy(alpha = 0.1f),
                            border = BorderStroke(1.dp, EmeraldPulse.copy(alpha = 0.4f)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                                modifier = Modifier.padding(12.dp)
                            ) {
                                Text(
                                    text = "${res.decodedCount} requests decoded into JSON",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = EmeraldPulse
                                )
                                Text(
                                    text = "Saved inside folder: Aryan",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    text = res.displayPath,
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFamily),
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }

                    else -> {
                        Text(
                            text = "Select which protocol folder to batch decode. All source links, headers, request hex, and response hex will be saved into one JSON file inside Documents/Aryan.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            FullDecodeScope.entries.forEach { scope ->
                                val selected = chosenScope == scope
                                Surface(
                                    shape = RoundedCornerShape(12.dp),
                                    color = if (selected) {
                                        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f)
                                    } else {
                                        MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)
                                    },
                                    border = BorderStroke(
                                        1.dp,
                                        if (selected) MaterialTheme.colorScheme.primary
                                        else MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)
                                    ),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(12.dp))
                                        .clickable { chosenScope = scope }
                                        .testTag("full_decode_scope_${scope.name.lowercase()}")
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                                    ) {
                                        RadioButton(
                                            selected = selected,
                                            onClick = { chosenScope = scope }
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                text = scope.label,
                                                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold)
                                            )
                                            Text(
                                                text = when (scope) {
                                                    FullDecodeScope.HTTP_HTTPS -> "REST/Game API requests & responses"
                                                    FullDecodeScope.UDP_DNS -> "Datagrams & DNS lookup packets"
                                                    FullDecodeScope.TCP -> "Raw TCP & HTTP/HTTPS socket streams"
                                                    FullDecodeScope.ALL -> "Every captured packet in session"
                                                },
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    }
                                }
                            }
                        }

                        state.error?.let { err ->
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = err,
                                style = MaterialTheme.typography.bodySmall,
                                color = CoralAlert
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            when {
                state.isRunning -> {}
                state.result != null -> {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { onShareJson(state.result.jsonContent) },
                            modifier = Modifier.testTag("full_decode_share_button")
                        ) {
                            Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Share")
                        }
                        Button(
                            onClick = onDismiss,
                            modifier = Modifier.testTag("full_decode_done_button")
                        ) {
                            Text("Done")
                        }
                    }
                }
                else -> {
                    Button(
                        onClick = { onSelectAndRun(chosenScope) },
                        modifier = Modifier.testTag("full_decode_start_button")
                    ) {
                        Icon(AppIcons.AutoFixHigh, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Decode & Save")
                    }
                }
            }
        },
        dismissButton = {
            if (!state.isRunning && state.result == null) {
                TextButton(onClick = onDismiss) {
                    Text("Cancel")
                }
            }
        }
    )
}
