package com.example.decoder

import android.util.Base64
import com.example.data.db.CaptureSessionEntity
import com.example.data.db.CapturedPacketEntity
import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.text.SimpleDateFormat
import java.util.Date
import java.util.LinkedHashMap
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object HexUtils {
    fun sanitizeHex(input: String): String {
        return input
            .replace("0x", "", ignoreCase = true)
            .replace(Regex("[^0-9a-fA-F]"), "")
            .lowercase(Locale.US)
    }

    fun hexToBytes(hex: String): ByteArray {
        val clean = sanitizeHex(hex)
        if (clean.length < 2) return ByteArray(0)
        val evenLen = clean.length - (clean.length % 2)
        val out = ByteArray(evenLen / 2)
        for (i in 0 until evenLen step 2) {
            out[i / 2] = clean.substring(i, i + 2).toInt(16).toByte()
        }
        return out
    }

    fun bytesToHex(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append(HEX_CHARS[v ushr 4])
            sb.append(HEX_CHARS[v and 0x0F])
        }
        return sb.toString()
    }

    fun formatHexDump(bytes: ByteArray, maxBytes: Int = 8192): String {
        if (bytes.isEmpty()) return "<Empty Body>"
        val limit = minOf(bytes.size, maxBytes)
        val slice = if (limit == bytes.size) bytes else bytes.copyOf(limit)
        val cleanHex = bytesToHex(slice)
        return if (bytes.size > maxBytes) {
            "$cleanHex\n... (${bytes.size - maxBytes} more bytes truncated)"
        } else {
            cleanHex
        }
    }

    fun formatSpacedHex(hexInput: String, maxBytes: Int = 16384): String {
        val clean = sanitizeHex(hexInput)
        if (clean.length < 2) return "<Empty Body>"
        val evenLen = clean.length - (clean.length % 2)
        val totalBytes = evenLen / 2
        val limitBytes = minOf(totalBytes, maxBytes)
        val upper = clean.uppercase(Locale.US)
        val sb = StringBuilder(limitBytes * 3)
        for (i in 0 until limitBytes) {
            if (i > 0) sb.append(' ')
            val pos = i * 2
            sb.append(upper[pos])
            sb.append(upper[pos + 1])
        }
        if (totalBytes > maxBytes) {
            sb.append("\n... (${totalBytes - maxBytes} more bytes truncated)")
        }
        return sb.toString()
    }

    fun toBase64(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    private val HEX_CHARS = "0123456789abcdef".toCharArray()
}

data class JwtDecodeResult(
    val rawToken: String,
    val headerJson: String,
    val payloadJson: String,
    val signatureHex: String,
    val claims: Map<String, String>,
    val expirationText: String?,
    val isExpired: Boolean?
)

object JwtDecoder {
    private val jwtRegex = Regex("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*")

    fun extractFromHeaders(headersJson: String): JwtDecodeResult? {
        val match = jwtRegex.find(headersJson) ?: return null
        return decode(match.value)
    }

    fun decode(input: String): JwtDecodeResult? {
        val token = jwtRegex.find(input.trim())?.value ?: input.trim()
        val parts = token.split(".")
        if (parts.size < 2) return null
        return try {
            val headerBytes = decodeBase64Url(parts[0])
            val payloadBytes = decodeBase64Url(parts[1])
            val sigBytes = if (parts.size >= 3 && parts[2].isNotEmpty()) decodeBase64Url(parts[2]) else ByteArray(0)

            val headerObj = JSONObject(String(headerBytes, Charsets.UTF_8))
            val payloadObj = JSONObject(String(payloadBytes, Charsets.UTF_8))

            val claims = linkedMapOf<String, String>()
            val keys = payloadObj.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                claims[k] = payloadObj.opt(k)?.toString() ?: ""
            }

            val expSeconds = payloadObj.optLong("exp", -1L)
            var expText: String? = null
            var isExpired: Boolean? = null
            if (expSeconds > 0) {
                val expMs = expSeconds * 1000L
                val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)
                expText = fmt.format(Date(expMs))
                isExpired = expMs < System.currentTimeMillis()
            }

            JwtDecodeResult(
                rawToken = token,
                headerJson = headerObj.toString(2),
                payloadJson = payloadObj.toString(2),
                signatureHex = HexUtils.bytesToHex(sigBytes),
                claims = claims,
                expirationText = expText,
                isExpired = isExpired
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun decodeBase64Url(segment: String): ByteArray {
        return Base64.decode(segment, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }
}

data class ProtobufFieldNode(
    val fieldNumber: Int,
    val wireType: Int,
    val wireTypeName: String,
    val displayValue: String,
    val rawDetail: String,
    val jsonValue: Any,
    val children: List<ProtobufFieldNode> = emptyList(),
    val isEmptyMessage: Boolean = false
)

data class ProtobufDecodeResult(
    val fields: List<ProtobufFieldNode>,
    val jsonFormatted: String,
    val fieldsDictFormatted: String,
    val byteCount: Int
)

object ProtobufWireDecoder {
    fun decode(bytes: ByteArray, depth: Int = 0): ProtobufDecodeResult? {
        if (bytes.isEmpty() || depth > 8) return null
        val nodes = mutableListOf<ProtobufFieldNode>()
        var idx = 0

        while (idx < bytes.size) {
            val tagRes = readVarint(bytes, idx, maxBytes = 5) ?: return null
            val tag = tagRes.first
            idx = tagRes.second
            if (tag <= 0L) return null

            val fieldNumber = (tag ushr 3).toInt()
            val wireType = (tag and 0x07).toInt()
            if (fieldNumber <= 0 || fieldNumber > 100_000) return null

            when (wireType) {
                0 -> { // Varint
                    val valRes = readVarint(bytes, idx, maxBytes = 10) ?: return null
                    val raw = valRes.first
                    idx = valRes.second
                    val zigZag = (raw ushr 1) xor -(raw and 1L)
                    val detail = buildString {
                        append("uint64=").append(raw)
                        if (zigZag != raw) append(" | sint64=").append(zigZag)
                        append(" | hex=0x").append(java.lang.Long.toHexString(raw))
                    }
                    nodes.add(
                        ProtobufFieldNode(
                            fieldNumber = fieldNumber,
                            wireType = wireType,
                            wireTypeName = "VARINT",
                            displayValue = raw.toString(),
                            rawDetail = detail,
                            jsonValue = raw
                        )
                    )
                }
                1 -> { // 64-bit
                    if (idx + 8 > bytes.size) return null
                    val buf = ByteBuffer.wrap(bytes, idx, 8).order(ByteOrder.LITTLE_ENDIAN)
                    val fixed64 = buf.long
                    val dbl = java.lang.Double.longBitsToDouble(fixed64)
                    val hexSlice = HexUtils.bytesToHex(bytes.copyOfRange(idx, idx + 8))
                    idx += 8
                    val display = if (dbl.isFinite() && kotlin.math.abs(dbl) in 1e-6..1e12) {
                        "$fixed64 (double: $dbl)"
                    } else {
                        fixed64.toString()
                    }
                    nodes.add(
                        ProtobufFieldNode(
                            fieldNumber = fieldNumber,
                            wireType = wireType,
                            wireTypeName = "FIXED64",
                            displayValue = display,
                            rawDetail = "hex=$hexSlice",
                            jsonValue = fixed64
                        )
                    )
                }
                2 -> { // Length-delimited
                    val lenRes = readVarint(bytes, idx, maxBytes = 5) ?: return null
                    val lenLong = lenRes.first
                    idx = lenRes.second
                    if (lenLong < 0 || lenLong > (bytes.size - idx)) return null
                    val len = lenLong.toInt()
                    val slice = bytes.copyOfRange(idx, idx + len)
                    idx += len

                    if (len == 0) {
                        nodes.add(
                            ProtobufFieldNode(
                                fieldNumber = fieldNumber,
                                wireType = wireType,
                                wireTypeName = "MSG/BYTES (0B)",
                                displayValue = "{}",
                                rawDetail = "length=0 (empty message/bytes)",
                                jsonValue = JSONObject(),
                                isEmptyMessage = true
                            )
                        )
                    } else {
                        val printableText = tryDecodeUtf8Text(slice)
                        val pureAscii = isPurePrintableAscii(slice)
                        val nested = if (!pureAscii && (printableText == null || slice.size >= 4)) {
                            decode(slice, depth + 1)
                        } else {
                            null
                        }

                        if (printableText != null && (pureAscii || nested == null)) {
                            nodes.add(
                                ProtobufFieldNode(
                                    fieldNumber = fieldNumber,
                                    wireType = wireType,
                                    wireTypeName = "STRING (${len}B)",
                                    displayValue = "\"$printableText\"",
                                    rawDetail = "utf8 | hex=${HexUtils.bytesToHex(slice)}",
                                    jsonValue = printableText
                                )
                            )
                        } else if (nested != null && nested.fields.isNotEmpty()) {
                            val nestedJson = JSONObject(nested.jsonFormatted)
                            nodes.add(
                                ProtobufFieldNode(
                                    fieldNumber = fieldNumber,
                                    wireType = wireType,
                                    wireTypeName = "MESSAGE (${len}B)",
                                    displayValue = "{ ${nested.fields.size} fields }",
                                    rawDetail = "nested message | hex=${HexUtils.bytesToHex(slice)}",
                                    jsonValue = nestedJson,
                                    children = nested.fields
                                )
                            )
                        } else {
                            val hex = HexUtils.bytesToHex(slice)
                            nodes.add(
                                ProtobufFieldNode(
                                    fieldNumber = fieldNumber,
                                    wireType = wireType,
                                    wireTypeName = "BYTES (${len}B)",
                                    displayValue = "0x$hex",
                                    rawDetail = "raw bytes (${len}B)",
                                    jsonValue = hex
                                )
                            )
                        }
                    }
                }
                5 -> { // 32-bit
                    if (idx + 4 > bytes.size) return null
                    val buf = ByteBuffer.wrap(bytes, idx, 4).order(ByteOrder.LITTLE_ENDIAN)
                    val fixed32 = buf.int
                    val flt = java.lang.Float.intBitsToFloat(fixed32)
                    val hexSlice = HexUtils.bytesToHex(bytes.copyOfRange(idx, idx + 4))
                    idx += 4
                    val display = if (flt.isFinite() && kotlin.math.abs(flt) in 1e-5f..1e9f) {
                        "$fixed32 (float: $flt)"
                    } else {
                        fixed32.toString()
                    }
                    nodes.add(
                        ProtobufFieldNode(
                            fieldNumber = fieldNumber,
                            wireType = wireType,
                            wireTypeName = "FIXED32",
                            displayValue = display,
                            rawDetail = "hex=$hexSlice",
                            jsonValue = fixed32
                        )
                    )
                }
                else -> return null
            }
        }

        if (nodes.isEmpty()) return null
        if (depth == 0 && nodes.all { it.wireTypeName.startsWith("BYTES") }) {
            // Avoid false-positive Protobuf hits on random/encrypted binary blobs split by stray tags
            return null
        }
        val jsonObj = nodesToJsonObject(nodes)
        val fieldsDict = ProtobufFieldsFormatter.formatFieldsDict(nodes)
        return ProtobufDecodeResult(
            fields = nodes,
            jsonFormatted = jsonObj.toString(2),
            fieldsDictFormatted = fieldsDict,
            byteCount = bytes.size
        )
    }

    private fun nodesToJsonObject(nodes: List<ProtobufFieldNode>): JSONObject {
        val grouped = nodes.groupBy { it.fieldNumber }
        val obj = JSONObject()
        for ((fieldNum, items) in grouped) {
            val key = fieldNum.toString()
            if (items.size == 1) {
                obj.put(key, items.first().jsonValue)
            } else {
                val arr = JSONArray()
                items.forEach { arr.put(it.jsonValue) }
                obj.put(key, arr)
            }
        }
        return obj
    }

    private fun readVarint(bytes: ByteArray, start: Int, maxBytes: Int = 10): Pair<Long, Int>? {
        var result = 0L
        var shift = 0
        var i = start
        var count = 0
        while (i < bytes.size && shift <= 63 && count < maxBytes) {
            val b = bytes[i].toInt() and 0xFF
            result = result or ((b.toLong() and 0x7FL) shl shift)
            i++
            count++
            if ((b and 0x80) == 0) {
                return result to i
            }
            shift += 7
        }
        return null
    }

    private fun tryDecodeUtf8Text(slice: ByteArray): String? {
        if (slice.isEmpty()) return null
        val str = try {
            String(slice, Charsets.UTF_8)
        } catch (_: Exception) {
            return null
        }
        if (str.contains('\uFFFD')) return null
        val valid = str.all { ch ->
            !ch.isISOControl() || ch == '\n' || ch == '\r' || ch == '\t'
        }
        return if (valid) str else null
    }

    private fun isPurePrintableAscii(slice: ByteArray): Boolean {
        if (slice.isEmpty()) return false
        return slice.all { b ->
            val v = b.toInt() and 0xFF
            v in 32..126 || v == 10 || v == 13 || v == 9
        }
    }
}

enum class PayloadClassification {
    EMPTY,
    PROTOBUF,
    JSON,
    TEXT,
    ENCRYPTED_BLOCK,
    RAW_BINARY
}

data class PayloadAnalysis(
    val hex: String,
    val byteCount: Int,
    val classification: PayloadClassification,
    val summary: String,
    val protobuf: ProtobufDecodeResult? = null,
    val formattedJson: String? = null,
    val utf8Text: String? = null,
    val hexDump: String = "",
    val base64: String = ""
)

object PayloadAnalyzer {
    private const val MAX_INPUT_SCAN_CHARS = 524_288
    private const val MAX_DECODE_HEX_CHARS = 262_144
    private const val STANDARD_GAME_AES_KEY = "Yg&tc%DEuh6%Zc^8"
    private const val STANDARD_GAME_AES_IV = "6oyZDr22E3ychjM%"

    private val classificationCache = object : LinkedHashMap<String, PayloadClassification>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, PayloadClassification>?): Boolean {
            return size > 256
        }
    }

    fun quickClassify(hexInput: String): PayloadClassification {
        if (hexInput.isBlank()) return PayloadClassification.EMPTY
        val boundedInput = if (hexInput.length > MAX_INPUT_SCAN_CHARS) {
            hexInput.substring(0, MAX_INPUT_SCAN_CHARS)
        } else {
            hexInput
        }
        val cleanHex = HexUtils.sanitizeHex(boundedInput).let {
            if (it.length > MAX_DECODE_HEX_CHARS) it.substring(0, MAX_DECODE_HEX_CHARS) else it
        }
        if (cleanHex.length < 2) return PayloadClassification.EMPTY

        synchronized(classificationCache) {
            classificationCache[cleanHex]
        }?.let { return it }

        val bytes = HexUtils.hexToBytes(cleanHex)
        val result = if (bytes.isEmpty()) {
            PayloadClassification.EMPTY
        } else {
            val textCandidate = tryReadableUtf8(bytes)
            when {
                textCandidate != null && isValidJson(textCandidate.trim()) -> PayloadClassification.JSON
                textCandidate != null && isCleanReadableText(textCandidate) -> PayloadClassification.TEXT
                ProtobufWireDecoder.decode(bytes) != null -> PayloadClassification.PROTOBUF
                bytes.size >= 16 && bytes.size % 16 == 0 -> classifyEncryptedBlock(bytes)
                else -> PayloadClassification.RAW_BINARY
            }
        }

        if (cleanHex.length <= 16_384) {
            synchronized(classificationCache) {
                classificationCache[cleanHex] = result
            }
        }
        return result
    }

    private fun classifyEncryptedBlock(bytes: ByteArray): PayloadClassification {
        val plain = tryStandardGameDecrypt(bytes) ?: return PayloadClassification.ENCRYPTED_BLOCK
        if (plain.isEmpty()) return PayloadClassification.PROTOBUF
        val plainText = tryReadableUtf8(plain)
        return when {
            plainText != null && isValidJson(plainText.trim()) -> PayloadClassification.JSON
            plainText != null && isCleanReadableText(plainText) -> PayloadClassification.TEXT
            ProtobufWireDecoder.decode(plain) != null -> PayloadClassification.PROTOBUF
            else -> PayloadClassification.ENCRYPTED_BLOCK
        }
    }

    fun isStructuredDecodable(hexInput: String): Boolean {
        val cls = quickClassify(hexInput)
        return cls == PayloadClassification.PROTOBUF || cls == PayloadClassification.JSON
    }

    fun hasDecodablePayload(requestBodyHex: String, responseBodyHex: String): Boolean {
        return isStructuredDecodable(requestBodyHex) || isStructuredDecodable(responseBodyHex)
    }

    fun analyze(hexInput: String): PayloadAnalysis {
        val boundedInput = if (hexInput.length > MAX_INPUT_SCAN_CHARS) {
            hexInput.substring(0, MAX_INPUT_SCAN_CHARS)
        } else {
            hexInput
        }
        val cleanHex = HexUtils.sanitizeHex(boundedInput).let {
            if (it.length > MAX_DECODE_HEX_CHARS) it.substring(0, MAX_DECODE_HEX_CHARS) else it
        }
        val bytes = HexUtils.hexToBytes(cleanHex)
        if (bytes.isEmpty()) {
            return PayloadAnalysis(
                hex = "",
                byteCount = 0,
                classification = PayloadClassification.EMPTY,
                summary = "Empty body (0 bytes)",
                hexDump = "<Empty Body>"
            )
        }

        val hexDump = HexUtils.formatHexDump(bytes)
        val base64 = HexUtils.toBase64(bytes)

        // 1. Check UTF-8 JSON or readable text
        val textCandidate = tryReadableUtf8(bytes)
        if (textCandidate != null) {
            val trimmed = textCandidate.trim()
            if ((trimmed.startsWith("{") && trimmed.endsWith("}")) ||
                (trimmed.startsWith("[") && trimmed.endsWith("]"))
            ) {
                val pretty = tryFormatJson(trimmed)
                if (pretty != null) {
                    return PayloadAnalysis(
                        hex = cleanHex,
                        byteCount = bytes.size,
                        classification = PayloadClassification.JSON,
                        summary = "UTF-8 JSON (${bytes.size} bytes)",
                        formattedJson = pretty,
                        utf8Text = textCandidate,
                        hexDump = hexDump,
                        base64 = base64
                    )
                }
            }
            if (isCleanReadableText(textCandidate)) {
                return PayloadAnalysis(
                    hex = cleanHex,
                    byteCount = bytes.size,
                    classification = PayloadClassification.TEXT,
                    summary = "Plaintext / Form Data (${bytes.size} bytes)",
                    utf8Text = textCandidate,
                    hexDump = hexDump,
                    base64 = base64
                )
            }
        }

        // 2. Check Protobuf wire format
        val proto = ProtobufWireDecoder.decode(bytes)
        if (proto != null) {
            return PayloadAnalysis(
                hex = cleanHex,
                byteCount = bytes.size,
                classification = PayloadClassification.PROTOBUF,
                summary = "Protobuf Wire Format • ${proto.fields.size} top-level fields (${bytes.size} bytes)",
                protobuf = proto,
                formattedJson = proto.jsonFormatted,
                hexDump = hexDump,
                base64 = base64
            )
        }

        // 3. Check 16-byte AES block alignment & transparently decode game payloads
        if (bytes.size >= 16 && bytes.size % 16 == 0) {
            val plain = tryStandardGameDecrypt(bytes)
            if (plain != null) {
                if (plain.isEmpty()) {
                    val emptyProto = ProtobufDecodeResult(
                        fields = emptyList(),
                        jsonFormatted = "{}",
                        fieldsDictFormatted = "fields = {}",
                        byteCount = 0
                    )
                    return PayloadAnalysis(
                        hex = cleanHex,
                        byteCount = bytes.size,
                        classification = PayloadClassification.PROTOBUF,
                        summary = "Protobuf Wire Format • 0 fields (${bytes.size}B decoded)",
                        protobuf = emptyProto,
                        formattedJson = emptyProto.jsonFormatted,
                        hexDump = hexDump,
                        base64 = base64
                    )
                }
                val plainText = tryReadableUtf8(plain)
                if (plainText != null) {
                    val trimmedPlain = plainText.trim()
                    if ((trimmedPlain.startsWith("{") && trimmedPlain.endsWith("}")) ||
                        (trimmedPlain.startsWith("[") && trimmedPlain.endsWith("]"))
                    ) {
                        val pretty = tryFormatJson(trimmedPlain)
                        if (pretty != null) {
                            return PayloadAnalysis(
                                hex = cleanHex,
                                byteCount = bytes.size,
                                classification = PayloadClassification.JSON,
                                summary = "UTF-8 JSON (${bytes.size}B decoded)",
                                formattedJson = pretty,
                                utf8Text = plainText,
                                hexDump = hexDump,
                                base64 = base64
                            )
                        }
                    }
                    if (isCleanReadableText(plainText)) {
                        return PayloadAnalysis(
                            hex = cleanHex,
                            byteCount = bytes.size,
                            classification = PayloadClassification.TEXT,
                            summary = "Plaintext / Form Data (${bytes.size}B decoded)",
                            utf8Text = plainText,
                            hexDump = hexDump,
                            base64 = base64
                        )
                    }
                }
                val decodedProto = ProtobufWireDecoder.decode(plain)
                if (decodedProto != null) {
                    return PayloadAnalysis(
                        hex = cleanHex,
                        byteCount = bytes.size,
                        classification = PayloadClassification.PROTOBUF,
                        summary = "Protobuf Wire Format • ${decodedProto.fields.size} top-level fields (${bytes.size}B decoded)",
                        protobuf = decodedProto,
                        formattedJson = decodedProto.jsonFormatted,
                        hexDump = hexDump,
                        base64 = base64
                    )
                }
            }

            return PayloadAnalysis(
                hex = cleanHex,
                byteCount = bytes.size,
                classification = PayloadClassification.ENCRYPTED_BLOCK,
                summary = "Binary payload (${bytes.size} bytes)",
                hexDump = hexDump,
                base64 = base64
            )
        }

        return PayloadAnalysis(
            hex = cleanHex,
            byteCount = bytes.size,
            classification = PayloadClassification.RAW_BINARY,
            summary = "Raw binary payload (${bytes.size} bytes)",
            hexDump = hexDump,
            base64 = base64
        )
    }

    private fun tryStandardGameDecrypt(bytes: ByteArray): ByteArray? {
        if (bytes.size < 16 || bytes.size % 16 != 0) return null
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(STANDARD_GAME_AES_KEY.toByteArray(Charsets.UTF_8), "AES"),
                IvParameterSpec(STANDARD_GAME_AES_IV.toByteArray(Charsets.UTF_8))
            )
            cipher.doFinal(bytes)
        } catch (_: Exception) {
            null
        }
    }

    private fun tryReadableUtf8(bytes: ByteArray): String? {
        return try {
            val s = String(bytes, Charsets.UTF_8)
            if (s.contains('\uFFFD')) null else s
        } catch (_: Exception) {
            null
        }
    }

    private fun isCleanReadableText(text: String): Boolean {
        if (text.isEmpty()) return false
        val printable = text.count { !it.isISOControl() || it == '\n' || it == '\r' || it == '\t' }
        return printable == text.length
    }

    private fun isValidJson(raw: String): Boolean {
        if (!((raw.startsWith("{") && raw.endsWith("}")) || (raw.startsWith("[") && raw.endsWith("]")))) {
            return false
        }
        return try {
            if (raw.startsWith("{")) JSONObject(raw) else JSONArray(raw)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun tryFormatJson(raw: String): String? {
        return try {
            if (raw.startsWith("{")) JSONObject(raw).toString(2)
            else JSONArray(raw).toString(2)
        } catch (_: Exception) {
            null
        }
    }
}

object PacketJsonSerializer {
    fun parseHeadersMap(headersJson: String): Map<String, String> {
        val result = linkedMapOf<String, String>()
        try {
            val obj = JSONObject(headersJson)
            val keys = obj.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                result[k] = obj.optString(k)
            }
        } catch (_: Exception) {
        }
        return result
    }

    fun decodePayloadValue(hex: String): Any {
        val cleanHex = HexUtils.sanitizeHex(hex)
        if (cleanHex.length < 2) return JSONObject.NULL
        val analysis = PayloadAnalyzer.analyze(cleanHex)
        return when {
            analysis.protobuf != null -> JSONObject(analysis.protobuf.jsonFormatted)
            analysis.formattedJson != null -> {
                runCatching {
                    val trimmed = analysis.formattedJson.trim()
                    if (trimmed.startsWith("[")) JSONArray(trimmed) else JSONObject(trimmed)
                }.getOrElse { analysis.formattedJson }
            }
            analysis.classification == PayloadClassification.TEXT && analysis.utf8Text != null -> analysis.utf8Text
            else -> JSONObject.NULL
        }
    }

    fun decodePayloadFormattedText(hex: String): String? {
        val cleanHex = HexUtils.sanitizeHex(hex)
        if (cleanHex.length < 2) return null
        val analysis = PayloadAnalyzer.analyze(cleanHex)
        return when {
            analysis.protobuf != null -> analysis.protobuf.jsonFormatted
            analysis.formattedJson != null -> analysis.formattedJson
            analysis.classification == PayloadClassification.TEXT && analysis.utf8Text != null -> analysis.utf8Text
            else -> null
        }
    }

    fun packetToJsonObject(packet: CapturedPacketEntity): JSONObject {
        val apiEndpoint = if (packet.method.isNotBlank() && packet.url.isNotBlank()) {
            "${packet.method} ${packet.url}"
        } else {
            packet.url.ifBlank { "${packet.method} ${packet.host}${packet.path}".trim() }
        }
        return JSONObject().apply {
            put("api", apiEndpoint)
            put("request", decodePayloadValue(packet.requestBodyHex))
        }
    }

    fun packetToFormattedJson(packet: CapturedPacketEntity): String {
        return packetToJsonObject(packet).toString(2)
    }

    fun sessionToFormattedJson(
        session: CaptureSessionEntity,
        packets: List<CapturedPacketEntity>
    ): String {
        val arr = JSONArray()
        packets.forEach { arr.put(packetToJsonObject(it)) }
        return arr.toString(2)
    }
}

object ProtobufFieldsFormatter {

    fun formatFieldsDict(nodes: List<ProtobufFieldNode>): String {
        return buildString {
            append("fields = ")
            append(formatObject(nodes, indentLevel = 0))
        }
    }

    fun formatAsyncSnippet(
        nodes: List<ProtobufFieldNode>,
        endpointOrPath: String,
        packetHeaderHex: String = "0E15"
    ): String {
        val cleanName = endpointOrPath
            .substringAfterLast("/")
            .replace(Regex("[^A-Za-z0-9_]"), "")
            .ifBlank { "Packet" }
        val fnName = if (cleanName.startsWith("Send", ignoreCase = true)) cleanName else "Send$cleanName"
        val body = formatObject(nodes, indentLevel = 1)
        return buildString {
            appendLine("async def $fnName(key, iv):")
            appendLine("    fields = $body")
            append("    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), '$packetHeaderHex', key, iv)")
        }
    }

    fun formatSmartPythonPackage(
        nodes: List<ProtobufFieldNode>,
        endpointOrPath: String,
        isResponse: Boolean = false,
        packetHeaderHex: String = "0E15"
    ): String {
        if (!isResponse && isLoginPayload(nodes, endpointOrPath)) {
            return formatLoginPayloadPython(nodes)
        }
        val cleanTarget = endpointOrPath
            .substringBefore("?")
            .substringAfterLast("/")
            .ifBlank { "Packet" }
        val fnEndpoint = if (isResponse) "${cleanTarget}_response" else cleanTarget
        return formatEndpointPackagePython(nodes, fnEndpoint, packetHeaderHex)
    }

    fun formatFallbackRequestPackage(
        analysis: PayloadAnalysis,
        endpointOrPath: String,
        packetHeaderHex: String = "0E15"
    ): String {
        val proto = analysis.protobuf
        if (proto != null) {
            return formatSmartPythonPackage(
                nodes = proto.fields,
                endpointOrPath = endpointOrPath,
                isResponse = false,
                packetHeaderHex = packetHeaderHex
            )
        }
        val fnName = toSnakeCaseEndpoint(endpointOrPath)
        return buildString {
            appendLine("def $fnName(K, V):")
            appendLine("    packet_id = '$packetHeaderHex'")
            when {
                analysis.formattedJson != null -> {
                    appendLine("    payload = ${analysis.formattedJson.replace("\n", "\n    ")}")
                    append("    return payload")
                }
                analysis.classification == PayloadClassification.TEXT && analysis.utf8Text != null -> {
                    appendLine("    payload = \"${escapePythonStr(analysis.utf8Text)}\"")
                    append("    return payload")
                }
                analysis.classification == PayloadClassification.EMPTY -> {
                    appendLine("    fields = {}")
                    append("    return iZ(str(gZ(fields).hex()), packet_id, K, V)")
                }
                else -> {
                    appendLine("    # Encrypted / Binary Request Body (${analysis.byteCount}B)")
                    appendLine("    raw_hex = \"${analysis.hex}\"")
                    append("    return raw_hex")
                }
            }
        }
    }

    fun isCleanPackageProtobuf(nodes: List<ProtobufFieldNode>, endpointOrPath: String = ""): Boolean {
        if (nodes.isEmpty()) return false
        if (isLoginPayload(nodes, endpointOrPath)) return true
        var totalNodes = 0
        fun walk(list: List<ProtobufFieldNode>): Boolean {
            val grouped = list.groupBy { it.fieldNumber }
            for ((_, items) in grouped) {
                totalNodes += items.size
                if (totalNodes > 80) return false
                // Repeated message objects ([{1: 1001, ...}, {1: 1001, ...}]) are catalog/inventory dumps
                if (items.size >= 2 && items.any { it.children.isNotEmpty() || it.isEmptyMessage }) {
                    return false
                }
                for (item in items) {
                    if (item.children.isNotEmpty() && !walk(item.children)) {
                        return false
                    }
                }
            }
            return true
        }
        return walk(nodes)
    }

    fun isLoginPayload(nodes: List<ProtobufFieldNode>, endpointOrPath: String): Boolean {
        val tail = endpointOrPath.substringAfterLast("/").substringBefore("?").lowercase(java.util.Locale.US)
        if (tail.contains("getlogindata") || tail == "login" || tail.startsWith("logindata")) {
            return true
        }
        val byField = nodes.associateBy { it.fieldNumber }
        val f4Str = byField[4]?.takeIf { it.wireTypeName.startsWith("STRING") }?.jsonValue?.toString()?.lowercase(java.util.Locale.US)
        if (f4Str != null && (f4Str.contains("free fire") || f4Str.contains("freefire"))) {
            return true
        }
        return byField.containsKey(22) && byField.containsKey(26) && byField.containsKey(29)
    }

    fun detectLoginRegion(nodes: List<ProtobufFieldNode>): String {
        val raw = nodes.firstOrNull { it.fieldNumber == 26 && it.wireTypeName.startsWith("STRING") }
            ?.jsonValue?.toString()?.trim()?.uppercase(java.util.Locale.US)
        return if (!raw.isNullOrBlank() && raw.length in 2..6) raw else "BD"
    }

    fun formatLoginPayloadPython(nodes: List<ProtobufFieldNode>): String {
        val region = detectLoginRegion(nodes)
        return buildString {
            appendLine("def build_login_payload(access_token, open_id, region=\"$region\", server_time_str=None):")
            appendLine("    if server_time_str is None:")
            appendLine("        server_time_str = get_server_time()")
            appendLine()
            appendLine("    P = {}")
            appendLine()
            val grouped = nodes.groupBy { it.fieldNumber }.toSortedMap()
            grouped.forEach { (fieldNum, items) ->
                val padNum = if (fieldNum < 10) " " else ""
                if (items.size == 1) {
                    val item = items.first()
                    val isStr = item.wireTypeName.startsWith("STRING")
                    val rawStr = item.jsonValue.toString()
                    when {
                        fieldNum == 3 && isStr -> {
                            appendLine("    P[3] $padNum= server_time_str  # \"${escapePythonStr(rawStr)}\"")
                        }
                        fieldNum == 22 && isStr -> {
                            val preview = if (rawStr.length > 24) "${rawStr.take(24)}..." else rawStr
                            appendLine("    P[22] = access_token  # \"${escapePythonStr(preview)}\"")
                        }
                        fieldNum == 26 && isStr -> {
                            appendLine("    P[26] = region  # \"${escapePythonStr(rawStr)}\"")
                        }
                        fieldNum == 29 && isStr -> {
                            val preview = if (rawStr.length > 24) "${rawStr.take(24)}..." else rawStr
                            appendLine("    P[29] = open_id  # \"${escapePythonStr(preview)}\"")
                        }
                        else -> {
                            appendBracketEntry(
                                out = this,
                                prefix = "P[$fieldNum]",
                                node = item,
                                indent = "    ",
                                eqPadding = padNum
                            )
                        }
                    }
                } else if (items.any { it.children.isNotEmpty() || it.isEmptyMessage }) {
                    appendLine("    P[$fieldNum]$padNum = {}")
                    items.forEachIndexed { subIdx, subNode ->
                        appendBracketEntry(
                            out = this,
                            prefix = "P[$fieldNum][$subIdx]",
                            node = subNode,
                            indent = "    "
                        )
                    }
                } else {
                    val listItems = items.joinToString(", ") { formatSingleValue(it, 2) }
                    appendLine("    P[$fieldNum]$padNum = [$listItems]")
                }
            }
            appendLine()
            appendLine("    raw = pb(P)")
            append("    return enc(xK, xV, raw)")
        }
    }

    fun formatEndpointPackagePython(
        nodes: List<ProtobufFieldNode>,
        endpointOrPath: String,
        packetHeaderHex: String = "0E15"
    ): String {
        val fnName = toSnakeCaseEndpoint(endpointOrPath)
        val body = formatBracketDict(nodes, varName = "fields", indent = "    ")
        return buildString {
            appendLine("def $fnName(K, V):")
            appendLine("    packet_id = '$packetHeaderHex'")
            appendLine(body)
            append("    return iZ(str(gZ(fields).hex()), packet_id, K, V)")
        }
    }

    fun formatBracketDict(
        nodes: List<ProtobufFieldNode>,
        varName: String = "fields",
        indent: String = ""
    ): String {
        return buildString {
            append("$indent$varName = {}")
            if (nodes.isNotEmpty()) {
                appendLine()
                val grouped = nodes.groupBy { it.fieldNumber }
                val entries = grouped.entries.toList()
                entries.forEachIndexed { idx, (fieldNum, items) ->
                    val isLastGroup = idx == entries.lastIndex
                    val target = "$varName[$fieldNum]"
                    if (items.size == 1) {
                        appendBracketEntry(
                            out = this,
                            prefix = target,
                            node = items.first(),
                            indent = indent,
                            trailingNewline = !isLastGroup
                        )
                    } else if (items.any { it.children.isNotEmpty() || it.isEmptyMessage }) {
                        appendLine("$indent$target = {}")
                        items.forEachIndexed { subIdx, subNode ->
                            val isLastItem = isLastGroup && subIdx == items.lastIndex
                            appendBracketEntry(
                                out = this,
                                prefix = "$target[$subIdx]",
                                node = subNode,
                                indent = indent,
                                trailingNewline = !isLastItem
                            )
                        }
                    } else {
                        val listItems = items.joinToString(", ") { formatSingleValue(it, 1) }
                        if (!isLastGroup) {
                            appendLine("$indent$target = [$listItems]")
                        } else {
                            append("$indent$target = [$listItems]")
                        }
                    }
                }
            }
        }
    }

    private fun appendBracketEntry(
        out: StringBuilder,
        prefix: String,
        node: ProtobufFieldNode,
        indent: String,
        eqPadding: String = "",
        trailingNewline: Boolean = true
    ) {
        when {
            node.isEmptyMessage -> {
                if (trailingNewline) out.appendLine("$indent$prefix$eqPadding = {}")
                else out.append("$indent$prefix$eqPadding = {}")
            }
            node.children.isNotEmpty() -> {
                out.appendLine("$indent$prefix$eqPadding = {}")
                val grouped = node.children.groupBy { it.fieldNumber }
                val entries = grouped.entries.toList()
                entries.forEachIndexed { idx, (subNum, subItems) ->
                    val isLast = idx == entries.lastIndex
                    val subPrefix = "$prefix[$subNum]"
                    if (subItems.size == 1) {
                        appendBracketEntry(
                            out = out,
                            prefix = subPrefix,
                            node = subItems.first(),
                            indent = indent,
                            trailingNewline = if (isLast) trailingNewline else true
                        )
                    } else if (subItems.any { it.children.isNotEmpty() || it.isEmptyMessage }) {
                        out.appendLine("$indent$subPrefix = {}")
                        subItems.forEachIndexed { subIdx, childItem ->
                            val isLastChild = isLast && subIdx == subItems.lastIndex
                            appendBracketEntry(
                                out = out,
                                prefix = "$subPrefix[$subIdx]",
                                node = childItem,
                                indent = indent,
                                trailingNewline = if (isLastChild) trailingNewline else true
                            )
                        }
                    } else {
                        val listItems = subItems.joinToString(", ") { formatSingleValue(it, 1) }
                        if (!isLast || trailingNewline) {
                            out.appendLine("$indent$subPrefix = [$listItems]")
                        } else {
                            out.append("$indent$subPrefix = [$listItems]")
                        }
                    }
                }
            }
            else -> {
                val scalar = formatSingleValue(node, 0)
                if (trailingNewline) out.appendLine("$indent$prefix$eqPadding = $scalar")
                else out.append("$indent$prefix$eqPadding = $scalar")
            }
        }
    }

    private fun toSnakeCaseEndpoint(endpointOrPath: String): String {
        val raw = endpointOrPath
            .substringBefore("?")
            .substringAfterLast("/")
            .substringAfterLast(":")
            .replace(Regex("[^A-Za-z0-9_]"), "_")
            .trim('_')
        if (raw.isBlank()) return "packet_payload"
        val snake = raw
            .replace(Regex("([a-z0-9])([A-Z])"), "$1_$2")
            .replace(Regex("([A-Z]+)([A-Z][a-z])"), "$1_$2")
            .lowercase(java.util.Locale.US)
            .replace(Regex("_+"), "_")
            .trim('_')
        return if (snake.firstOrNull()?.isDigit() == true) "pkt_$snake" else snake.ifBlank { "packet_payload" }
    }

    private fun escapePythonStr(input: String): String {
        return input
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\r", "\\r")
            .replace("\n", "\\n")
            .replace("\t", "\\t")
    }

    private fun formatObject(nodes: List<ProtobufFieldNode>, indentLevel: Int): String {
        if (nodes.isEmpty()) return "{}"
        val pad = "    ".repeat(indentLevel + 1)
        val closePad = "    ".repeat(indentLevel)
        val grouped = nodes.groupBy { it.fieldNumber }
        return buildString {
            appendLine("{")
            val entries = grouped.entries.toList()
            entries.forEachIndexed { idx, (fieldNum, items) ->
                val valueStr = if (items.size == 1) {
                    formatSingleValue(items.first(), indentLevel + 1)
                } else {
                    formatRepeatedList(items, indentLevel + 1)
                }
                val comma = if (idx < entries.lastIndex) "," else ","
                appendLine("$pad$fieldNum: $valueStr$comma")
            }
            append("$closePad}")
        }
    }

    private fun formatRepeatedList(items: List<ProtobufFieldNode>, indentLevel: Int): String {
        val pad = "    ".repeat(indentLevel + 1)
        val closePad = "    ".repeat(indentLevel)
        return buildString {
            appendLine("[")
            items.forEachIndexed { idx, item ->
                val v = formatSingleValue(item, indentLevel + 1)
                val comma = if (idx < items.lastIndex) "," else ","
                appendLine("$pad$v$comma")
            }
            append("$closePad]")
        }
    }

    private fun formatSingleValue(node: ProtobufFieldNode, indentLevel: Int): String {
        return when {
            node.isEmptyMessage -> "{}"
            node.children.isNotEmpty() -> formatObject(node.children, indentLevel)
            node.wireTypeName.startsWith("STRING") -> {
                "\"${escapePythonStr(node.jsonValue.toString())}\""
            }
            node.wireTypeName.startsWith("BYTES") -> {
                "bytes.fromhex(\"${node.jsonValue}\")"
            }
            else -> node.jsonValue.toString()
        }
    }
}

object PacketRawFormatter {
    fun formatPacket(packet: CapturedPacketEntity): String {
        val headers = PacketJsonSerializer.parseHeadersMap(packet.requestHeadersJson)
        return buildString {
            appendLine("Method & URL : ${packet.method} ${packet.url}")
            appendLine()
            appendLine("Headers :")
            if (headers.isEmpty()) {
                appendLine("<None>")
            } else {
                headers.forEach { (k, v) -> appendLine("$k: $v") }
            }
            appendLine()
            appendLine("Request body Hex:")
            appendLine(packet.requestBodyHex.ifBlank { "<Empty Body>" })
            appendLine()
            appendLine("Response body Hex:")
            append(packet.responseBodyHex.ifBlank { "<Empty Body>" })
        }
    }
}
