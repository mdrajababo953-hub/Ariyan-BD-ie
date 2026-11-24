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
            FullDecodeScope.UDP_DNS -> packets.filter {
                it.protocol.equals("UDP", true) || it.protocol.equals("DNS", true)
            }
            FullDecodeScope.TCP -> packets.filter {
                it.protocol.equals("TCP", true) || it.protocol.equals("HTTP", true) || it.protocol.equals("HTTPS", true)
            }
            FullDecodeScope.ALL -> packets
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
                "No ${scope.label} packets found in this session to decode."
            }

            val total = matching.size
            val requestsArray = JSONArray()

            matching.forEachIndexed { index, pkt ->
                onProgress(index + 1, total)
                requestsArray.put(PacketJsonSerializer.packetToJsonObject(pkt))
            }

            val tsFmt = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val rootJson = requestsArray.toString(2)

            val fileName = "NetTrace_${scope.shortCode}_${tsFmt}.json"
            val (displayPath, savedUri) = writeToAryanDirectory(context, fileName, rootJson)

            FullDecodeResult(
                fileName = fileName,
                displayPath = displayPath,
                decodedCount = total,
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
                put(MediaStore.MediaColumns.MIME_TYPE, "application/json")
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
