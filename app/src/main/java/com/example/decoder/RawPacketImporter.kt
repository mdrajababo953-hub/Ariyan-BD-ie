package com.example.decoder

import android.net.Uri
import com.example.data.db.CapturedPacketEntity
import org.json.JSONObject

object RawPacketImporter {

    fun parseRawText(rawText: String, sessionId: Long): List<CapturedPacketEntity> {
        val trimmed = rawText.trim()
        if (trimmed.isEmpty()) return emptyList()

        // Split into blocks whenever "Method & URL :" or standard HTTP method lines start
        val lines = trimmed.lines()
        val blocks = mutableListOf<List<String>>()
        var current = mutableListOf<String>()

        for (line in lines) {
            val isNewBlock = line.trim().startsWith("Method & URL", ignoreCase = true) ||
                Regex("^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\s+https?://.*").matches(line.trim())
            if (isNewBlock && current.any { it.isNotBlank() }) {
                blocks.add(current)
                current = mutableListOf()
            }
            current.add(line)
        }
        if (current.any { it.isNotBlank() }) {
            blocks.add(current)
        }

        val now = System.currentTimeMillis()
        return blocks.mapIndexedNotNull { idx, blockLines ->
            parseSingleBlock(blockLines, sessionId, now + idx)
        }
    }

    private fun parseSingleBlock(
        lines: List<String>,
        sessionId: Long,
        timestamp: Long
    ): CapturedPacketEntity? {
        var method = "POST"
        var url = ""
        val headers = linkedMapOf<String, String>()
        var reqHex = ""
        var respHex = ""

        var mode = ParseSection.NONE

        for (rawLine in lines) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue

            when {
                line.startsWith("Method & URL", ignoreCase = true) -> {
                    val value = line.substringAfter(":", "").trim()
                    val parts = value.split(Regex("\\s+"), limit = 2)
                    if (parts.size == 2) {
                        method = parts[0].uppercase()
                        url = parts[1]
                    } else if (value.startsWith("http", ignoreCase = true)) {
                        url = value
                    }
                    mode = ParseSection.NONE
                }
                Regex("^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\s+https?://.*").matches(line) -> {
                    val parts = line.split(Regex("\\s+"), limit = 2)
                    method = parts[0].uppercase()
                    url = parts.getOrElse(1) { "" }
                    mode = ParseSection.HEADERS
                }
                line.startsWith("Headers", ignoreCase = true) && line.contains(":") && line.substringAfter(":").isBlank() -> {
                    mode = ParseSection.HEADERS
                }
                line.startsWith("Request body Hex", ignoreCase = true) -> {
                    val inline = line.substringAfter(":", "").trim()
                    if (inline.isNotEmpty() && !inline.equals("<Empty Body>", ignoreCase = true)) {
                        reqHex = HexUtils.sanitizeHex(inline)
                    }
                    mode = ParseSection.REQ_BODY
                }
                line.startsWith("Response body Hex", ignoreCase = true) -> {
                    val inline = line.substringAfter(":", "").trim()
                    if (inline.isNotEmpty() && !inline.equals("<Empty Body>", ignoreCase = true)) {
                        respHex = HexUtils.sanitizeHex(inline)
                    }
                    mode = ParseSection.RESP_BODY
                }
                line.equals("<Empty Body>", ignoreCase = true) -> {
                    mode = ParseSection.NONE
                }
                else -> {
                    when (mode) {
                        ParseSection.REQ_BODY -> {
                            val cleaned = HexUtils.sanitizeHex(line)
                            if (cleaned.isNotEmpty()) reqHex += cleaned
                        }
                        ParseSection.RESP_BODY -> {
                            val cleaned = HexUtils.sanitizeHex(line)
                            if (cleaned.isNotEmpty()) respHex += cleaned
                        }
                        ParseSection.HEADERS, ParseSection.NONE -> {
                            if (line.contains(":")) {
                                val k = line.substringBefore(":").trim()
                                val v = line.substringAfter(":").trim()
                                if (k.isNotEmpty() && !k.contains(" ")) {
                                    headers[k] = v
                                }
                            }
                        }
                    }
                }
            }
        }

        if (url.isBlank()) return null

        val uri = Uri.parse(url)
        val host = uri.host ?: headers["Host"] ?: "unknown"
        val path = uri.encodedPath?.ifEmpty { "/" } ?: "/"
        val scheme = uri.scheme?.uppercase() ?: "HTTPS"
        val port = if (uri.port > 0) uri.port else if (scheme == "HTTP") 80 else 443

        val headersJson = JSONObject().apply {
            headers.forEach { (k, v) -> put(k, v) }
        }.toString()

        val reqBytes = reqHex.length / 2
        val respBytes = respHex.length / 2

        return CapturedPacketEntity(
            sessionId = sessionId,
            timestamp = timestamp,
            method = method,
            url = url,
            host = host,
            path = path,
            port = port,
            protocol = scheme,
            statusCode = 200,
            requestHeadersJson = headersJson,
            requestBodyHex = reqHex,
            responseHeadersJson = "{\"Content-Type\":\"application/x-protobuf\"}",
            responseBodyHex = respHex,
            durationMs = 42L,
            bytesTx = reqBytes,
            bytesRx = respBytes,
            isBlocked = false
        )
    }

    private enum class ParseSection { NONE, HEADERS, REQ_BODY, RESP_BODY }
}
