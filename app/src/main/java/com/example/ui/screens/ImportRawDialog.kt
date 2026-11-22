package com.example.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.ui.theme.JetBrainsMonoFamily

private const val SAMPLE_IMPORT_TEMPLATE = """Method & URL : POST https://clientbp.ggpolarbear.com/GetPlayerCSRankingInfoByAccountID

Headers :
User-Agent: UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)
Releaseversion: OB54
Content-Type: application/x-www-form-urlencoded

Request body Hex:
14712cba0eac504d9ddd0070d3e9ed4f

Response body Hex:
08f4f3c8cf3d102618ad0220ad02300170807d8001ad028801cc08a80101b001019a0200"""

@Composable
fun ImportRawDialog(
    onDismiss: () -> Unit,
    onImport: (title: String, rawText: String) -> Unit
) {
    var title by remember { mutableStateOf("Imported Game Capture") }
    var rawText by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text("Import Raw HTTP / Hex Dump", style = MaterialTheme.typography.titleLarge)
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "Paste one or more captured requests (Method & URL, Headers, Request/Response Hex) to save as a JSON session and decode.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("Session Name") },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("import_title_input")
                )
                OutlinedTextField(
                    value = rawText,
                    onValueChange = { rawText = it },
                    label = { Text("Raw Capture Text") },
                    placeholder = { Text("Method & URL : POST https://...") },
                    minLines = 6,
                    maxLines = 10,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("import_raw_text_input")
                )
                Row(
                    horizontalArrangement = Arrangement.End,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    TextButton(
                        onClick = { rawText = SAMPLE_IMPORT_TEMPLATE },
                        modifier = Modifier.testTag("fill_sample_import_button")
                    ) {
                        Text("Load Template")
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (rawText.isNotBlank()) {
                        onImport(title, rawText)
                        onDismiss()
                    }
                },
                enabled = rawText.isNotBlank(),
                modifier = Modifier.testTag("confirm_import_button")
            ) {
                Text("Parse & Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}
