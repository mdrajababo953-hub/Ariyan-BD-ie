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
                val decodable = PayloadAnalyzer.isStructuredDecodable(pkt.requestBodyHex)
                isHttpProto && !isRawTls && !(pkt.method.equals("SYN", true) || (pkt.path == "/Passthrough" && looksRawTlsHex)) && decodable
            }
            FullDecodeScope.UDP_DNS -> packets.filter { pkt ->
                (pkt.protocol.equals("UDP", true) || pkt.protocol.equals("DNS", true)) &&
                    PayloadAnalyzer.isStructuredDecodable(pkt.requestBodyHex)
            }
            FullDecodeScope.TCP -> packets.filter { pkt ->
                val isTcpScope = pkt.protocol.equals("TCP", true) || pkt.protocol.equals("HTTP", true) || pkt.protocol.equals("HTTPS", true)
                val isRawTls = pkt.method.equals("TLS", true) || pkt.method.equals("TLS_PIN", true) || pkt.method.equals("SYN", true)
                isTcpScope && !isRawTls && PayloadAnalyzer.isStructuredDecodable(pkt.requestBodyHex)
            }
            FullDecodeScope.ALL -> packets.filter { pkt ->
                val isRawTls = pkt.method.equals("TLS", true) || pkt.method.equals("TLS_PIN", true) || pkt.method.equals("SYN", true)
                !isRawTls && PayloadAnalyzer.isStructuredDecodable(pkt.requestBodyHex)
            }
        }
    }

    private fun isCleanExportableSide(
        analysis: PayloadAnalysis,
        endpointHint: String
    ): Boolean {
        val proto = analysis.protobuf
        if (proto != null) {
            if (proto.fields.isEmpty()) return analysis.byteCount > 0
            return ProtobufFieldsFormatter.isCleanPackageProtobuf(proto.fields, endpointHint)
        }
        val json = analysis.formattedJson
        if (json != null) {
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
            val reqClean = isCleanExportableSide(reqAnalysis, endpointHint)

            if (reqClean) {
                val item = PacketJsonSerializer.packetToJsonObject(pkt)
                if (!item.isNull("request")) {
                    requestsArray.put(item)
                    entryBlocks += formatSinglePackageEntry(
                        pkt = pkt,
                        fullUrl = fullUrl,
                        endpointHint = endpointHint,
                        reqAnalysis = reqAnalysis
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

    fun formatRequestPackageOnly(pkt: CapturedPacketEntity): String {
        val fullUrl = pkt.url.ifBlank {
            val pathPart = pkt.path.ifBlank { "/" }
            "${pkt.protocol.lowercase(Locale.US)}://${pkt.host}$pathPart"
        }
        val endpointHint = pkt.path.ifBlank { fullUrl.substringAfter("://").substringAfter("/", "Packet") }
        val reqAnalysis = PayloadAnalyzer.analyze(pkt.requestBodyHex)
        val reqHexClean = HexUtils.sanitizeHex(pkt.requestBodyHex).ifBlank { "<Empty>" }
        val reqDecodedBlock = ProtobufFieldsFormatter.formatFallbackRequestPackage(
            analysis = reqAnalysis,
            endpointOrPath = endpointHint
        )
        return buildString {
            appendLine(fullUrl)
            appendLine()
            appendLine("Request Hex:")
            appendLine(reqHexClean)
            appendLine()
            append(reqDecodedBlock)
        }
    }

    fun formatSinglePackageEntry(pkt: CapturedPacketEntity): String {
        val fullUrl = pkt.url.ifBlank {
            val pathPart = pkt.path.ifBlank { "/" }
            "${pkt.protocol.lowercase(Locale.US)}://${pkt.host}$pathPart"
        }
        val endpointHint = pkt.path.ifBlank { fullUrl.substringAfter("://").substringAfter("/", "Packet") }
        val reqAnalysis = PayloadAnalyzer.analyze(pkt.requestBodyHex)
        return formatSinglePackageEntry(
            pkt = pkt,
            fullUrl = fullUrl,
            endpointHint = endpointHint,
            reqAnalysis = reqAnalysis
        )
    }

    private fun formatSinglePackageEntry(
        pkt: CapturedPacketEntity,
        fullUrl: String,
        endpointHint: String,
        reqAnalysis: PayloadAnalysis
    ): String {
        val reqHexClean = HexUtils.sanitizeHex(pkt.requestBodyHex).ifBlank { "<Empty>" }
        val respHexClean = HexUtils.sanitizeHex(pkt.responseBodyHex).ifBlank { "<Empty>" }
        val reqDecodedBlock = ProtobufFieldsFormatter.formatFallbackRequestPackage(
            analysis = reqAnalysis,
            endpointOrPath = endpointHint
        )

        return buildString {
            appendLine(fullUrl)
            appendLine()
            appendLine("Request Hex:")
            appendLine(reqHexClean)
            appendLine()
            appendLine("Response Hex:")
            appendLine(respHexClean)
            appendLine()
            append(reqDecodedBlock)
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
