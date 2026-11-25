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
            val item = PacketJsonSerializer.packetToJsonObject(pkt)
            if (!item.isNull("request") || !item.isNull("response")) {
                requestsArray.put(item)
                entryBlocks += formatSinglePackageEntry(pkt)
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
        val reqHexClean = HexUtils.sanitizeHex(pkt.requestBodyHex).ifBlank { "<Empty>" }
        val respHexClean = HexUtils.sanitizeHex(pkt.responseBodyHex).ifBlank { "<Empty>" }

        val reqAnalysis = PayloadAnalyzer.analyze(pkt.requestBodyHex)
        val respAnalysis = PayloadAnalyzer.analyze(pkt.responseBodyHex)

        val endpointHint = pkt.path.ifBlank { fullUrl.substringAfter("://").substringAfter("/", "Packet") }

        val reqDecodedBlock = formatDecodedBlock(
            analysis = reqAnalysis,
            endpointHint = endpointHint,
            isResponse = false
        )
        val respDecodedBlock = formatDecodedBlock(
            analysis = respAnalysis,
            endpointHint = endpointHint,
            isResponse = true
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
            appendLine("# === Request Decoded Package ===")
            appendLine(reqDecodedBlock)
            appendLine()
            appendLine("# === Response Decoded Package ===")
            append(respDecodedBlock)
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
                "No decodable ${scope.label} payloads found in this session."
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
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
                put(MediaStore.MediaColumns.RELATIVE_PATH, "${Environment.DIRECTORY_DOCUMENTS}/Aryan")
            }
            val uri = resolver.insert(MediaStore.Files.getContentUri("external"), values)
            if (uri != null) {
                resolver.openOutputStream(uri)?.use { out ->
                    out.write(bytes)
                    out.flush()
                }
                return "Documents/Aryan/$fileName" to uri
            }
        }

        // Fallback for API 24-28 (or if MediaStore insert returns null)
        @Suppress("DEPRECATION")
        val publicDocs = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
        val publicAryan = File(publicDocs, "Aryan")
        val targetFile = runCatching {
            if (!publicAryan.exists()) publicAryan.mkdirs()
            val f = File(publicAryan, fileName)
            f.writeBytes(bytes)
            f
        }.getOrElse {
            val appDocs = context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS) ?: context.filesDir
            val appAryan = File(appDocs, "Aryan")
            if (!appAryan.exists()) appAryan.mkdirs()
            File(appAryan, fileName).apply { writeBytes(bytes) }
        }
        return targetFile.absolutePath to Uri.fromFile(targetFile)
    }
}
