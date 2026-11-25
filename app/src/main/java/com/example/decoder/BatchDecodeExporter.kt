package com.example.decoder

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import com.example.data.db.CaptureSessionEntity
import com.example.data.db.CapturedPacketEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class FullDecodeScope(val label: String, val shortCode: String) {
    HTTP_HTTPS("HTTP / HTTPS", "HTTPS"),
    UDP_DNS("UDP / DNS", "UDP"),
    TCP("TCP Streams", "TCP"),
    ALL("All Protocols", "ALL")
}

data class FullDecodeResult(
    val fileName: String,
    val displayPath: String,
    val decodedCount: Int,
    val packageContent: String,
    val jsonContent: String,
    val savedUri: Uri?
)

object BatchDecodeExporter {

    fun filterPacketsByScope(
        packets: List<CapturedPacketEntity>,
        scope: FullDecodeScope
    ): List<CapturedPacketEntity> {
        return when (scope) {
            FullDecodeScope.HTTP_HTTPS -> packets.filter { pkt ->
                val isHttpProto = pkt.protocol.equals("HTTP", true) || pkt.protocol.equals("HTTPS", true)
                val isRawTls = pkt.method.equals("TLS", true) || pkt.method.equals("TLS_PIN", true)
                val looksRawTlsHex = pkt.requestBodyHex.startsWith("1603") || pkt.requestBodyHex.startsWith("1703")
                val decodable = PayloadAnalyzer.hasDecodablePayload(pkt.requestBodyHex, pkt.responseBodyHex)
                isHttpProto && !isRawTls && !(pkt.method.equals("SYN", true) || (pkt.path == "/Passthrough" && looksRawTlsHex)) && decodable
            }
            FullDecodeScope.UDP_DNS -> packets.filter { pkt ->
                (pkt.protocol.equals("UDP", true) || pkt.protocol.equals("DNS", true)) &&
                    PayloadAnalyzer.hasDecodablePayload(pkt.requestBodyHex, pkt.responseBodyHex)
            }
            FullDecodeScope.TCP -> packets.filter { pkt ->
                val isTcpScope = pkt.protocol.equals("TCP", true) || pkt.protocol.equals("HTTP", true) || pkt.protocol.equals("HTTPS", true)
                val isRawTls = pkt.method.equals("TLS", true) || pkt.method.equals("TLS_PIN", true) || pkt.method.equals("SYN", true)
                isTcpScope && !isRawTls && PayloadAnalyzer.hasDecodablePayload(pkt.requestBodyHex, pkt.responseBodyHex)
            }
            FullDecodeScope.ALL -> packets.filter { pkt ->
                val isRawTls = pkt.method.equals("TLS", true) || pkt.method.equals("TLS_PIN", true) || pkt.method.equals("SYN", true)
                !isRawTls && PayloadAnalyzer.hasDecodablePayload(pkt.requestBodyHex, pkt.responseBodyHex)
            }
        }
    }

    private fun isCleanExportableSide(
        analysis: PayloadAnalysis,
        endpointHint: String
    ): Boolean {
        val proto = analysis.protobuf
        if (proto != null) {
            return ProtobufFieldsFormatter.isCleanPackageProtobuf(proto.fields, endpointHint)
        }
        val json = analysis.formattedJson
        if (json != null) {
            // Skip massive catalog/inventory JSON array dumps
            val trimmed = json.trimStart()
            return json.length <= 3500 && !trimmed.startsWith("[")
        }
        return false
    }

    fun buildPremiumPackageReport(
        session: CaptureSessionEntity?,
        packets: List<CapturedPacketEntity>,
        scope: FullDecodeScope,
        onProgress: (processed: Int, total: Int) -> Unit = { _, _ -> }
    ): Pair<String, JSONArray> {
        val total = packets.size
        val requestsArray = JSONArray()
        val entryBlocks = mutableListOf<String>()

        packets.forEachIndexed { index, pkt ->
            onProgress(index + 1, total)
            val fullUrl = pkt.url.ifBlank {
                val pathPart = pkt.path.ifBlank { "/" }
                "${pkt.protocol.lowercase(Locale.US)}://${pkt.host}$pathPart"
            }
            val endpointHint = pkt.path.ifBlank { fullUrl.substringAfter("://").substringAfter("/", "Packet") }

            val reqAnalysis = PayloadAnalyzer.analyze(pkt.requestBodyHex)
            val respAnalysis = PayloadAnalyzer.analyze(pkt.responseBodyHex)

            val reqClean = isCleanExportableSide(reqAnalysis, endpointHint)
            val respClean = isCleanExportableSide(respAnalysis, endpointHint)

            // Skip entries whose ONLY decodable part is a bulk repeated-item list / catalog dump
            if (reqClean || respClean) {
                val item = PacketJsonSerializer.packetToJsonObject(pkt)
                if (!item.isNull("request") || !item.isNull("response")) {
                    requestsArray.put(item)
                    entryBlocks += formatSinglePackageEntry(
                        pkt = pkt,
                        fullUrl = fullUrl,
                        endpointHint = endpointHint,
                        reqAnalysis = reqAnalysis,
                        respAnalysis = respAnalysis,
                        reqClean = reqClean,
                        respClean = respClean
                    )
                }
            }
        }

        val generatedAt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        val targetLabel = session?.targetAppName?.takeIf { it.isNotBlank() } ?: "Captured Session"
        val report = buildString {
            appendLine("# ARIYAN A9X BD CAPTURE — PRO PACKAGE DECODE REPORT")
            appendLine("# Scope: ${scope.label} | Target: $targetLabel | Packages: ${entryBlocks.size} | Generated: $generatedAt")
            appendLine()
            appendLine()
            append(entryBlocks.joinToString("\n\n\n\n\n\n"))
        }
        return report to requestsArray
    }

    fun formatSinglePackageEntry(pkt: CapturedPacketEntity): String {
        val fullUrl = pkt.url.ifBlank {
            val pathPart = pkt.path.ifBlank { "/" }
            "${pkt.protocol.lowercase(Locale.US)}://${pkt.host}$pathPart"
        }
        val endpointHint = pkt.path.ifBlank { fullUrl.substringAfter("://").substringAfter("/", "Packet") }
        val reqAnalysis = PayloadAnalyzer.analyze(pkt.requestBodyHex)
        val respAnalysis = PayloadAnalyzer.analyze(pkt.responseBodyHex)
        return formatSinglePackageEntry(
            pkt = pkt,
            fullUrl = fullUrl,
            endpointHint = endpointHint,
            reqAnalysis = reqAnalysis,
            respAnalysis = respAnalysis,
            reqClean = isCleanExportableSide(reqAnalysis, endpointHint),
            respClean = isCleanExportableSide(respAnalysis, endpointHint)
        )
    }

    private fun formatSinglePackageEntry(
        pkt: CapturedPacketEntity,
        fullUrl: String,
        endpointHint: String,
        reqAnalysis: PayloadAnalysis,
        respAnalysis: PayloadAnalysis,
        reqClean: Boolean,
        respClean: Boolean
    ): String {
        val reqHexClean = HexUtils.sanitizeHex(pkt.requestBodyHex).ifBlank { "<Empty>" }
        val respHexClean = HexUtils.sanitizeHex(pkt.responseBodyHex).ifBlank { "<Empty>" }

        val reqDecodedBlock = if (reqClean) {
            formatDecodedBlock(reqAnalysis, endpointHint, isResponse = false)
        } else {
            skippedComment(reqAnalysis)
        }
        val respDecodedBlock = if (respClean) {
            formatDecodedBlock(respAnalysis, endpointHint, isResponse = true)
        } else {
            skippedComment(respAnalysis)
        }

        return buildString {
            appendLine(fullUrl)
            appendLine()
            appendLine("Request Hex:")
            appendLine(reqHexClean)
            appendLine()
            appendLine("Response Hex:")
            appendLine(respHexClean)
            appendLine()
            appendLine(reqDecodedBlock)
            appendLine()
            append(respDecodedBlock)
        }
    }

    private fun skippedComment(analysis: PayloadAnalysis): String {
        return when {
            analysis.classification == PayloadClassification.EMPTY -> "# <Empty>"
            analysis.protobuf != null -> "# <Skipped repeated catalog list>"
            analysis.formattedJson != null -> "# <Skipped bulk JSON array>"
            else -> "# <${analysis.classification.name} (${analysis.byteCount}B)>"
        }
    }

    private fun formatDecodedBlock(
        analysis: PayloadAnalysis,
        endpointHint: String,
        isResponse: Boolean
    ): String {
        val proto = analysis.protobuf
        return when {
            proto != null -> {
                ProtobufFieldsFormatter.formatSmartPythonPackage(
                    nodes = proto.fields,
                    endpointOrPath = endpointHint,
                    isResponse = isResponse
                )
            }
            analysis.formattedJson != null -> analysis.formattedJson
            analysis.utf8Text != null && analysis.classification == PayloadClassification.TEXT -> analysis.utf8Text
            analysis.classification == PayloadClassification.EMPTY -> "# <Empty>"
            else -> "# <${analysis.classification.name} (${analysis.byteCount}B)>"
        }
    }

    suspend fun decodeAndSaveToAryanFolder(
        context: Context,
        session: CaptureSessionEntity?,
        packets: List<CapturedPacketEntity>,
        scope: FullDecodeScope,
        onProgress: (processed: Int, total: Int) -> Unit
    ): Result<FullDecodeResult> = withContext(Dispatchers.IO) {
        runCatching {
            val matching = filterPacketsByScope(packets, scope)
            require(matching.isNotEmpty()) {
                "No decodable ${scope.label} payloads found in this session."
            }

            val (packageReport, requestsArray) = buildPremiumPackageReport(
                session = session,
                packets = matching,
                scope = scope,
                onProgress = onProgress
            )

            require(requestsArray.length() > 0) {
                "No clean packageable ${scope.label} payloads found (bulk catalog lists skipped)."
            }

            val tsFmt = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val rootJson = requestsArray.toString(2)
            val fileName = "ARIYAN_A9X_${scope.shortCode}_${tsFmt}.txt"
            val (displayPath, savedUri) = writeToAryanDirectory(context, fileName, packageReport)

            FullDecodeResult(
                fileName = fileName,
                displayPath = displayPath,
                decodedCount = requestsArray.length(),
                packageContent = packageReport,
                jsonContent = rootJson,
                savedUri = savedUri
            )
        }
    }

    private fun writeToAryanDirectory(
        context: Context,
        fileName: String,
        content: String
    ): Pair<String, Uri?> {
        val bytes = content.toByteArray(Charsets.UTF_8)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val resolver = context.contentResolver
            val candidates = listOf(
                Triple(MediaStore.Files.getContentUri("external"), "${Environment.DIRECTORY_DOCUMENTS}/Aryan", "text/plain"),
                Triple(MediaStore.Files.getContentUri("external"), Environment.DIRECTORY_DOCUMENTS, "text/plain"),
                Triple(MediaStore.Downloads.getContentUri("external"), "${Environment.DIRECTORY_DOWNLOADS}/Aryan", "text/plain"),
                Triple(MediaStore.Downloads.getContentUri("external"), Environment.DIRECTORY_DOWNLOADS, "text/plain")
            )
            for ((collectionUri, relPath, mime) in candidates) {
                val saved = runCatching {
                    val values = ContentValues().apply {
                        put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                        put(MediaStore.MediaColumns.MIME_TYPE, mime)
                        put(MediaStore.MediaColumns.RELATIVE_PATH, relPath)
                        put(MediaStore.MediaColumns.IS_PENDING, 1)
                    }
                    val uri = resolver.insert(collectionUri, values) ?: return@runCatching null
                    val ok = runCatching {
                        resolver.openOutputStream(uri, "w")?.use { out ->
                            out.write(bytes)
                            out.flush()
                        } ?: error("Null output stream")
                        resolver.update(
                            uri,
                            ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) },
                            null,
                            null
                        )
                        "$relPath/$fileName" to uri
                    }
                    if (ok.isFailure) {
                        runCatching { resolver.delete(uri, null, null) }
                        null
                    } else {
                        ok.getOrNull()
                    }
                }.getOrNull()
                if (saved != null) return saved
            }
        }

        val dirCandidates = buildList {
            @Suppress("DEPRECATION")
            add(File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS), "Aryan"))
            @Suppress("DEPRECATION")
            add(File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "Aryan"))
            context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS)?.let { add(File(it, "Aryan")) }
            add(File(context.filesDir, "Aryan"))
        }
        for (dir in dirCandidates) {
            val written = runCatching {
                if (!dir.exists()) dir.mkdirs()
                val f = File(dir, fileName)
                f.writeBytes(bytes)
                f
            }.getOrNull()
            if (written != null && written.exists()) {
                return written.absolutePath to Uri.fromFile(written)
            }
        }
        val fallback = File(context.filesDir, fileName).apply { writeBytes(bytes) }
        return fallback.absolutePath to Uri.fromFile(fallback)
    }
}
