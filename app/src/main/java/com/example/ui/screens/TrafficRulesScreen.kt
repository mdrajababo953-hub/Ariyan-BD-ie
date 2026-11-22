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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.data.db.TrafficRuleEntity
import com.example.data.prefs.TargetAppSelection
import com.example.ui.components.TagChip
import com.example.ui.theme.AmberSignal
import com.example.ui.theme.CoralAlert
import com.example.ui.theme.EmeraldPulse
import com.example.ui.theme.JetBrainsMonoFamily

@Composable
fun TrafficRulesScreen(
    rules: List<TrafficRuleEntity>,
    targetApp: TargetAppSelection,
    onAddRule: (name: String, pattern: String, matchType: String, action: String, targetOnly: Boolean) -> Unit,
    onToggleRule: (Long, Boolean) -> Unit,
    onDeleteRule: (Long) -> Unit
) {
    var showAddDialog by remember { mutableStateOf(false) }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier.fillMaxSize()
    ) {
        item {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Traffic Control Rules",
                        style = MaterialTheme.typography.headlineSmall
                    )
                    Text(
                        text = "Block, allow, or highlight hosts, paths, and ports for the target app",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Button(
                    onClick = { showAddDialog = true },
                    modifier = Modifier.testTag("add_rule_button")
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Rule")
                }
            }
        }

        // Quick preset actions
        item {
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Quick Control Presets", style = MaterialTheme.typography.titleSmall)
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        OutlinedButton(
                            onClick = {
                                onAddRule("Block QUIC/UDP 443", "443", "PORT", "BLOCK", true)
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Force TCP (Block :443)", style = MaterialTheme.typography.labelSmall)
                        }
                        OutlinedButton(
                            onClick = {
                                onAddRule("Block Telemetry SDK", "crashlytics", "HOST", "BLOCK", true)
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Block Telemetry", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
        }

        if (rules.isEmpty()) {
            item {
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
                        Icon(
                            Icons.Default.Security,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(40.dp)
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("No active traffic rules", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Add a rule to block or highlight specific game endpoints.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        } else {
            items(rules, key = { it.id }) { rule ->
                val actionColor = when (rule.action) {
                    "BLOCK" -> CoralAlert
                    "ALLOW" -> EmeraldPulse
                    else -> AmberSignal
                }
                Surface(
                    shape = RoundedCornerShape(14.dp),
                    color = MaterialTheme.colorScheme.surface,
                    border = BorderStroke(
                        1.dp,
                        if (rule.isEnabled) actionColor.copy(alpha = 0.45f)
                        else MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("rule_card_${rule.id}")
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(14.dp)
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                TagChip(
                                    text = rule.action,
                                    color = actionColor,
                                    icon = if (rule.action == "BLOCK") Icons.Default.Block else null
                                )
                                TagChip(text = rule.matchType, color = MaterialTheme.colorScheme.primary)
                                if (rule.hitCount > 0) {
                                    Text(
                                        text = "${rule.hitCount} hits",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(rule.name, style = MaterialTheme.typography.titleSmall)
                            Text(
                                text = "Pattern: ${rule.pattern} • Scope: ${if (rule.targetPackage == "*") "All Targets" else rule.targetPackage}",
                                style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFamily),
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        Switch(
                            checked = rule.isEnabled,
                            onCheckedChange = { onToggleRule(rule.id, it) },
                            modifier = Modifier.testTag("toggle_rule_${rule.id}")
                        )
                        IconButton(
                            onClick = { onDeleteRule(rule.id) },
                            modifier = Modifier.testTag("delete_rule_${rule.id}")
                        ) {
                            Icon(
                                Icons.Default.DeleteOutline,
                                contentDescription = stringResource(R.string.cd_delete),
                                tint = CoralAlert
                            )
                        }
                    }
                }
            }
        }
    }

    if (showAddDialog) {
        AddRuleDialog(
            targetAppName = targetApp.appName,
            onDismiss = { showAddDialog = false },
            onConfirm = { name, pattern, matchType, action, targetOnly ->
                onAddRule(name, pattern, matchType, action, targetOnly)
                showAddDialog = false
            }
        )
    }
}

@Composable
private fun AddRuleDialog(
    targetAppName: String,
    onDismiss: () -> Unit,
    onConfirm: (name: String, pattern: String, matchType: String, action: String, targetOnly: Boolean) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var pattern by remember { mutableStateOf("") }
    var matchType by remember { mutableStateOf("HOST") }
    var action by remember { mutableStateOf("BLOCK") }
    var targetOnly by remember { mutableStateOf(true) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New Traffic Control Rule", style = MaterialTheme.typography.titleLarge) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Rule Name (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = pattern,
                    onValueChange = { pattern = it },
                    label = { Text("Match Pattern (e.g. clientbp.ggpolarbear.com)") },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("rule_pattern_input")
                )
                Text("Match Field", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf("HOST", "PATH", "PORT").forEach { type ->
                        FilterChip(
                            selected = matchType == type,
                            onClick = { matchType = type },
                            label = { Text(type) }
                        )
                    }
                }
                Text("Action", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf("BLOCK", "HIGHLIGHT", "ALLOW").forEach { act ->
                        FilterChip(
                            selected = action == act,
                            onClick = { action = act },
                            label = { Text(act) }
                        )
                    }
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = if (targetAppName.isNotBlank()) "Only $targetAppName" else "Current target app only",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.weight(1f)
                    )
                    Switch(checked = targetOnly, onCheckedChange = { targetOnly = it })
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(name, pattern, matchType, action, targetOnly) },
                enabled = pattern.isNotBlank(),
                modifier = Modifier.testTag("confirm_add_rule_button")
            ) {
                Text("Save Rule")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}
