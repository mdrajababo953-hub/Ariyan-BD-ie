package com.example.ui.components

import android.graphics.drawable.Drawable
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.example.R
import com.example.data.db.CapturedPacketEntity
import com.example.decoder.PayloadAnalyzer
import com.example.decoder.PayloadClassification
import com.example.decoder.ProtobufFieldNode
import com.example.ui.theme.AmberSignal
import com.example.ui.theme.CoralAlert
import com.example.ui.theme.ElectricCyan
import com.example.ui.theme.EmeraldPulse
import com.example.ui.theme.JetBrainsMonoFamily
import com.example.ui.theme.VioletProto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object Formatters {
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    private val fullFmt = SimpleDateFormat("MMM dd, HH:mm:ss", Locale.US)

    fun formatClock(ts: Long): String = timeFmt.format(Date(ts))
    fun formatDateTime(ts: Long): String = fullFmt.format(Date(ts))

    fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024L -> "$bytes B"
            bytes < 1024L * 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
            else -> String.format(Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0))
        }
    }
}

@Composable
fun AppIconAvatar(
    drawable: Drawable?,
    fallbackLetter: String,
    size: Dp = 44.dp,
    modifier: Modifier = Modifier
) {
    val bitmap = remember(drawable) {
        drawable?.let {
            runCatching { it.toBitmap(96, 96).asImageBitmap() }.getOrNull()
        }
    }
    if (bitmap != null) {
        Image(
            bitmap = bitmap,
            contentDescription = stringResource(R.string.cd_app_icon),
            modifier = modifier
                .size(size)
                .clip(RoundedCornerShape(12.dp))
        )
    } else {
        Box(
            contentAlignment = Alignment.Center,
            modifier = modifier
                .size(size)
                .clip(RoundedCornerShape(12.dp))
                .background(MaterialTheme.colorScheme.primaryContainer)
                .border(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.4f), RoundedCornerShape(12.dp))
        ) {
            Text(
                text = fallbackLetter.take(2).uppercase(),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )
        }
    }
}

@Composable
fun MethodBadge(method: String, isBlocked: Boolean = false) {
    val (bg, fg) = when {
        isBlocked -> CoralAlert.copy(alpha = 0.16f) to CoralAlert
        method == "POST" -> ElectricCyan.copy(alpha = 0.14f) to ElectricCyan
        method == "GET" -> EmeraldPulse.copy(alpha = 0.14f) to EmeraldPulse
        method == "TLS" || method == "HTTPS" -> VioletProto.copy(alpha = 0.16f) to VioletProto
        method == "DNS" || method == "UDP" -> AmberSignal.copy(alpha = 0.15f) to AmberSignal
        else -> MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurfaceVariant
    }

    Surface(
        color = bg,
        shape = RoundedCornerShape(6.dp),
        border = BorderStroke(1.dp, fg.copy(alpha = 0.35f))
    ) {
        Text(
            text = method,
            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
            color = fg,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun PacketRowCard(
    packet: CapturedPacketEntity,
    isSelected: Boolean,
    onClick: () -> Unit,
    onLongClick: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    val haptic = LocalHapticFeedback.current
    val primaryClassification by produceState(
        initialValue = PayloadClassification.EMPTY,
        key1 = packet.requestBodyHex,
        key2 = packet.responseBodyHex
    ) {
        value = withContext(Dispatchers.Default) {
            when {
                packet.requestBodyHex.isNotEmpty() -> PayloadAnalyzer.quickClassify(packet.requestBodyHex)
                packet.responseBodyHex.isNotEmpty() -> PayloadAnalyzer.quickClassify(packet.responseBodyHex)
                else -> PayloadClassification.EMPTY
            }
        }
    }

    val borderColor = when {
        isSelected -> MaterialTheme.colorScheme.primary
        packet.isBlocked -> CoralAlert.copy(alpha = 0.55f)
        else -> MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
    }

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .minimumInteractiveComponentSize()
            .clip(RoundedCornerShape(14.dp))
            .combinedClickable(
                onClick = onClick,
                onLongClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    onLongClick()
                }
            ),
        color = if (isSelected) {
            MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.25f)
        } else {
            MaterialTheme.colorScheme.surface
        },
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(if (isSelected) 1.5.dp else 1.dp, borderColor),
        tonalElevation = if (isSelected) 4.dp else 1.dp
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                MethodBadge(method = packet.method, isBlocked = packet.isBlocked)

                if (packet.isBlocked) {
                    TagChip(
                        text = "BLOCKED",
                        color = CoralAlert,
                        icon = AppIcons.Block
                    )
                } else if (packet.statusCode != null) {
                    val statusColor = if (packet.statusCode in 200..299) EmeraldPulse else AmberSignal
                    TagChip(
                        text = "${packet.statusCode}",
                        color = statusColor,
                        icon = Icons.Default.CheckCircle
                    )
                } else {
                    TagChip(
                        text = packet.protocol,
                        color = MaterialTheme.colorScheme.primary,
                        icon = Icons.Default.Lock
                    )
                }

                if (primaryClassification == PayloadClassification.PROTOBUF) {
                    TagChip(
                        text = "PROTO",
                        color = VioletProto,
                        icon = AppIcons.DataObject
                    )
                } else if (primaryClassification == PayloadClassification.ENCRYPTED_BLOCK) {
                    TagChip(
                        text = "16B ENC",
                        color = AmberSignal
                    )
                }

                Spacer(modifier = Modifier.weight(1f))

                Text(
                    text = Formatters.formatClock(packet.timestamp),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = packet.path.ifBlank { "/" },
                        style = MaterialTheme.typography.titleSmall.copy(fontFamily = JetBrainsMonoFamily),
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "${packet.host}:${packet.port}",
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFamily),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Spacer(modifier = Modifier.width(8.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "Decode",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            if (packet.bytesTx > 0 || packet.bytesRx > 0 || packet.blockReason != null) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "TX ${packet.bytesTx}B • RX ${packet.bytesRx}B",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (packet.durationMs > 0) {
                        Text(
                            text = "${packet.durationMs}ms",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    if (packet.blockReason != null) {
                        Text(
                            text = packet.blockReason,
                            style = MaterialTheme.typography.labelSmall,
                            color = CoralAlert,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun TagChip(
    text: String,
    color: Color,
    icon: androidx.compose.ui.graphics.vector.ImageVector? = null
) {
    Surface(
        color = color.copy(alpha = 0.13f),
        shape = RoundedCornerShape(6.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        ) {
            if (icon != null) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = color,
                    modifier = Modifier.size(11.dp)
                )
            }
            Text(
                text = text,
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
                color = color
            )
        }
    }
}

@Composable
fun SyntaxHighlightedJsonBlock(
    json: String,
    title: String? = null,
    onCopy: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val clipboard = LocalClipboardManager.current
    val keyColor = MaterialTheme.colorScheme.primary
    val strColor = EmeraldPulse
    val numColor = AmberSignal
    val punctColor = MaterialTheme.colorScheme.onSurfaceVariant

    val highlighted by produceState(
        initialValue = AnnotatedString(json),
        key1 = json,
        key2 = keyColor,
        key3 = punctColor
    ) {
        value = if (json.length > 24_000) {
            AnnotatedString(json)
        } else {
            withContext(Dispatchers.Default) {
                highlightJson(json, keyColor, strColor, numColor, punctColor)
            }
        }
    }

    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
    ) {
        Column {
            if (title != null) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surfaceContainerHigh.copy(alpha = 0.6f))
                        .padding(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    Text(
                        text = title,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.weight(1f))
                    IconButton(
                        onClick = {
                            clipboard.setText(AnnotatedString(json))
                            onCopy?.invoke()
                        },
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = AppIcons.ContentCopy,
                            contentDescription = stringResource(R.string.cd_copy),
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }
            SelectionContainer {
                Text(
                    text = highlighted,
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = JetBrainsMonoFamily,
                        fontSize = 12.sp,
                        lineHeight = 18.sp
                    ),
                    modifier = Modifier
                        .horizontalScroll(rememberScrollState())
                        .padding(12.dp)
                )
            }
        }
    }
}

private fun highlightJson(
    json: String,
    keyColor: Color,
    strColor: Color,
    numColor: Color,
    punctColor: Color
): AnnotatedString {
    val tokenRegex = Regex("(\"(?:\\\\.|[^\"\\\\])*\")(\\s*:)?|(\\btrue\\b|\\bfalse\\b|\\bnull\\b|-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?)")
    return buildAnnotatedString {
        var lastIndex = 0
        for (match in tokenRegex.findAll(json)) {
            if (match.range.first > lastIndex) {
                withStyle(SpanStyle(color = punctColor)) {
                    append(json.substring(lastIndex, match.range.first))
                }
            }
            val stringToken = match.groups[1]?.value
            val colonSuffix = match.groups[2]?.value
            val literalToken = match.groups[3]?.value

            when {
                stringToken != null && colonSuffix != null -> {
                    withStyle(SpanStyle(color = keyColor, fontWeight = FontWeight.SemiBold)) {
                        append(stringToken)
                    }
                    withStyle(SpanStyle(color = punctColor)) {
                        append(colonSuffix)
                    }
                }
                stringToken != null -> {
                    withStyle(SpanStyle(color = strColor)) {
                        append(stringToken)
                    }
                }
                literalToken != null -> {
                    withStyle(SpanStyle(color = numColor)) {
                        append(literalToken)
                    }
                }
            }
            lastIndex = match.range.last + 1
        }
        if (lastIndex < json.length) {
            withStyle(SpanStyle(color = punctColor)) {
                append(json.substring(lastIndex))
            }
        }
    }
}

@Composable
fun ProtobufTreeView(
    fields: List<ProtobufFieldNode>,
    depth: Int = 0
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        fields.forEach { node ->
            ProtobufNodeCard(node = node, depth = depth)
        }
    }
}

@Composable
private fun ProtobufNodeCard(node: ProtobufFieldNode, depth: Int) {
    var expanded by remember { mutableStateOf(true) }
    val hasChildren = node.children.isNotEmpty()

    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(10.dp),
        border = BorderStroke(
            1.dp,
            if (hasChildren) VioletProto.copy(alpha = 0.45f) else MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)
        ),
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = (depth * 10).dp)
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .then(
                        if (hasChildren) Modifier.clickable { expanded = !expanded } else Modifier
                    )
            ) {
                Surface(
                    color = MaterialTheme.colorScheme.primaryContainer,
                    shape = CircleShape
                ) {
                    Text(
                        text = "#${node.fieldNumber}",
                        style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                    )
                }

                Spacer(modifier = Modifier.width(8.dp))

                Surface(
                    color = VioletProto.copy(alpha = 0.14f),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = node.wireTypeName,
                        style = MaterialTheme.typography.labelSmall,
                        color = VioletProto,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }

                Spacer(modifier = Modifier.width(8.dp))

                SelectionContainer(modifier = Modifier.weight(1f)) {
                    Text(
                        text = node.displayValue,
                        style = MaterialTheme.typography.bodyMedium.copy(
                            fontFamily = JetBrainsMonoFamily,
                            fontWeight = FontWeight.SemiBold
                        ),
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }

                if (hasChildren) {
                    Icon(
                        imageVector = if (expanded) AppIcons.ExpandLess else AppIcons.ExpandMore,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            if (node.rawDetail.isNotBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = node.rawDetail,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            AnimatedVisibility(visible = hasChildren && expanded) {
                Column(modifier = Modifier.padding(top = 8.dp)) {
                    ProtobufTreeView(fields = node.children, depth = depth + 1)
                }
            }
        }
    }
}

@Composable
fun PythonFieldsCodeBlock(
    code: String,
    title: String,
    onCopy: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val clipboard = LocalClipboardManager.current
    val kwColor = VioletProto
    val keyColor = MaterialTheme.colorScheme.primary
    val strColor = EmeraldPulse
    val numColor = AmberSignal
    val defaultColor = MaterialTheme.colorScheme.onSurface

    val highlighted by produceState(
        initialValue = AnnotatedString(code),
        key1 = code,
        key2 = keyColor,
        key3 = defaultColor
    ) {
        value = if (code.length > 24_000) {
            AnnotatedString(code)
        } else {
            withContext(Dispatchers.Default) {
                highlightPythonCode(code, kwColor, keyColor, strColor, numColor, defaultColor)
            }
        }
    }

    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, VioletProto.copy(alpha = 0.45f))
    ) {
        Column {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceContainerHigh.copy(alpha = 0.65f))
                    .padding(horizontal = 12.dp, vertical = 6.dp)
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.labelMedium,
                    color = VioletProto
                )
                Spacer(modifier = Modifier.weight(1f))
                IconButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(code))
                        onCopy?.invoke()
                    },
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = AppIcons.ContentCopy,
                        contentDescription = stringResource(R.string.cd_copy),
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
            SelectionContainer {
                Text(
                    text = highlighted,
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = JetBrainsMonoFamily,
                        fontSize = 12.sp,
                        lineHeight = 18.sp
                    ),
                    modifier = Modifier
                        .horizontalScroll(rememberScrollState())
                        .padding(12.dp)
                )
            }
        }
    }
}

private fun highlightPythonCode(
    code: String,
    kwColor: Color,
    keyColor: Color,
    strColor: Color,
    numColor: Color,
    defaultColor: Color
): AnnotatedString {
    val commentColor = defaultColor.copy(alpha = 0.52f)
    val regex = Regex(
        "(#[^\\n]*)|" +
            "(\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*')|" +
            "(\\b(?:async|def|return|await|if|is|None|fields|P|response_fields|packet_id|raw)\\b)|" +
            "(\\b(?:pb|enc|gZ|iZ|get_server_time|CrEaTe_ProTo|GeneRaTePk|bytes|fromhex|str|hex)\\b)|" +
            "(\\[\\d+\\]|\\b\\d+\\s*:)|" +
            "(\\b\\d+\\b)"
    )
    return buildAnnotatedString {
        var last = 0
        for (m in regex.findAll(code)) {
            if (m.range.first > last) {
                withStyle(SpanStyle(color = defaultColor)) {
                    append(code.substring(last, m.range.first))
                }
            }
            val comment = m.groups[1]?.value
            val str = m.groups[2]?.value
            val kw = m.groups[3]?.value
            val fnCall = m.groups[4]?.value
            val fieldKey = m.groups[5]?.value
            val num = m.groups[6]?.value
            when {
                comment != null -> withStyle(SpanStyle(color = commentColor)) { append(comment) }
                str != null -> withStyle(SpanStyle(color = strColor)) { append(str) }
                kw != null -> withStyle(SpanStyle(color = kwColor, fontWeight = FontWeight.Bold)) { append(kw) }
                fnCall != null -> withStyle(SpanStyle(color = keyColor, fontWeight = FontWeight.SemiBold)) { append(fnCall) }
                fieldKey != null -> withStyle(SpanStyle(color = keyColor, fontWeight = FontWeight.Bold)) { append(fieldKey) }
                num != null -> withStyle(SpanStyle(color = numColor)) { append(num) }
            }
            last = m.range.last + 1
        }
        if (last < code.length) {
            withStyle(SpanStyle(color = defaultColor)) {
                append(code.substring(last))
            }
        }
    }
}
