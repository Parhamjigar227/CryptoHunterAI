package com.duolink.app.messaging

import com.duolink.app.crypto.ByteEncoding
import java.net.HttpURLConnection

/**
 * JSON codec for relay envelopes.
 *
 * Hand-written rather than reflective: the envelope is a fixed, small, security-relevant shape, and an
 * explicit encoder means the wire format cannot change silently because a library changed its defaults.
 *
 * Encoding is canonical: every binary field is unpadded base64url (matching the server's own canonical
 * check, which rejects a padded encoding that decodes to the same bytes).
 */
object EnvelopeJson {
    fun encode(envelope: SealedMessageEnvelope): String = buildString {
        append('{')
        append("\"id\":\"").append(ByteEncoding.encodeBase64Url(envelope.messageId)).append("\",")
        append("\"from\":\"").append(ByteEncoding.encodeBase64Url(envelope.senderDeviceId)).append("\",")
        append("\"to\":\"").append(ByteEncoding.encodeBase64Url(envelope.recipientDeviceId)).append("\",")
        append("\"seq\":").append(envelope.sequenceNumber).append(',')
        append("\"iv\":\"").append(ByteEncoding.encodeBase64Url(envelope.iv)).append("\",")
        append("\"ct\":\"").append(ByteEncoding.encodeBase64Url(envelope.ciphertextAndTag)).append('"')
        append('}')
    }

    /**
     * Parses one envelope object. Returns null on any structural problem; the caller treats null as
     * "not a valid envelope" and never as "an empty message".
     */
    fun decode(json: String): SealedMessageEnvelope? {
        val fields = FlatJson.parseObject(json) ?: return null
        val id = fields.string("id")?.let { decodeStrict(it) } ?: return null
        val from = fields.string("from")?.let { decodeStrict(it) } ?: return null
        val to = fields.string("to")?.let { decodeStrict(it) } ?: return null
        val iv = fields.string("iv")?.let { decodeStrict(it) } ?: return null
        val ct = fields.string("ct")?.let { decodeStrict(it) } ?: return null
        val seq = fields.long("seq") ?: return null
        if (id.size != MessageCipher.MESSAGE_ID_BYTES) return null
        if (from.size != MessageCipher.DEVICE_ID_BYTES || to.size != MessageCipher.DEVICE_ID_BYTES) return null
        if (iv.size !in 12..16) return null
        if (ct.size < 17) return null
        return SealedMessageEnvelope(
            protocolVersion = SealedMessageEnvelope.PROTOCOL_VERSION,
            messageId = id,
            senderDeviceId = from,
            recipientDeviceId = to,
            sequenceNumber = seq,
            iv = iv,
            ciphertextAndTag = ct
        )
    }

    private fun decodeStrict(value: String): ByteArray? = try {
        ByteEncoding.decodeBase64UrlStrict(value)
    } catch (t: Throwable) {
        null
    }
}

/** Minimal flat-JSON reader: strings, numbers, and nested objects of one level. */
internal object FlatJson {
    class Fields(private val map: Map<String, Any?>) {
        fun string(key: String): String? = map[key] as? String
        fun long(key: String): Long? = when (val value = map[key]) {
            is Long -> value
            is Int -> value.toLong()
            is Double -> if (value == value.toLong().toDouble()) value.toLong() else null
            else -> null
        }
    }

    fun parseObject(json: String): Fields? {
        val parser = Parser(json)
        return try {
            parser.skipWhitespace()
            val map = parser.readObject()
            parser.skipWhitespace()
            if (!parser.atEnd()) null else Fields(map)
        } catch (t: Throwable) {
            null
        }
    }

    /** Parses an array of objects out of a `{"envelopes": [ ... ]}` style payload. */
    fun readArray(json: String, key: String): List<String>? {
        val index = json.indexOf("\"$key\"")
        if (index < 0) return null
        val start = json.indexOf('[', index)
        if (start < 0) return null
        val out = mutableListOf<String>()
        var depth = 0
        var objectStart = -1
        var inString = false
        var escaped = false
        var i = start
        while (i < json.length) {
            val c = json[i]
            when {
                escaped -> escaped = false
                c == '\\' && inString -> escaped = true
                c == '"' -> inString = !inString
                inString -> Unit
                c == '{' -> {
                    if (depth == 0) objectStart = i
                    depth++
                }
                c == '}' -> {
                    depth--
                    if (depth == 0 && objectStart >= 0) {
                        out += json.substring(objectStart, i + 1)
                        objectStart = -1
                    }
                }
                c == ']' && depth == 0 -> return out
            }
            i++
        }
        return null
    }

    private class Parser(private val text: String) {
        private var position = 0
        fun atEnd(): Boolean = position >= text.length
        fun skipWhitespace() {
            while (position < text.length && text[position].isWhitespace()) position++
        }

        fun readObject(): Map<String, Any?> {
            expect('{')
            val map = mutableMapOf<String, Any?>()
            skipWhitespace()
            if (peek() == '}') { position++; return map }
            while (true) {
                skipWhitespace()
                val key = readString()
                skipWhitespace()
                expect(':')
                skipWhitespace()
                val value: Any? = when (val c = peek()) {
                    '"' -> readString()
                    '{' -> readObject()
                    '[' -> readArrayValue()
                    't', 'f' -> readBoolean()
                    'n' -> readNull()
                    else -> if (c == '-' || c.isDigit()) readNumber() else throw IllegalStateException("bad value")
                }
                map[key] = value
                skipWhitespace()
                when (peek()) {
                    ',' -> { position++; continue }
                    '}' -> { position++; return map }
                    else -> throw IllegalStateException("expected , or }")
                }
            }
        }

        private fun readArrayValue(): List<Any?> {
            expect('[')
            val list = mutableListOf<Any?>()
            skipWhitespace()
            if (peek() == ']') { position++; return list }
            while (true) {
                skipWhitespace()
                val value: Any? = when (val c = peek()) {
                    '"' -> readString()
                    '{' -> readObject()
                    't', 'f' -> readBoolean()
                    'n' -> readNull()
                    else -> if (c == '-' || c.isDigit()) readNumber() else throw IllegalStateException("bad array value")
                }
                list += value
                skipWhitespace()
                when (peek()) {
                    ',' -> { position++; continue }
                    ']' -> { position++; return list }
                    else -> throw IllegalStateException("expected , or ]")
                }
            }
        }

        private fun readString(): String {
            expect('"')
            val builder = StringBuilder()
            while (true) {
                if (position >= text.length) throw IllegalStateException("unterminated string")
                val c = text[position++]
                when {
                    c == '"' -> return builder.toString()
                    c == '\\' -> {
                        if (position >= text.length) throw IllegalStateException("bad escape")
                        when (val escape = text[position++]) {
                            '"' -> builder.append('"')
                            '\\' -> builder.append('\\')
                            '/' -> builder.append('/')
                            'b' -> builder.append('\b')
                            'f' -> builder.append('\u000C')
                            'n' -> builder.append('\n')
                            'r' -> builder.append('\r')
                            't' -> builder.append('\t')
                            'u' -> {
                                if (position + 4 > text.length) throw IllegalStateException("bad unicode escape")
                                val code = text.substring(position, position + 4).toInt(16)
                                builder.append(code.toChar())
                                position += 4
                            }
                            else -> throw IllegalStateException("unknown escape $escape")
                        }
                    }
                    else -> builder.append(c)
                }
            }
        }

        private fun readNumber(): Any {
            val start = position
            if (peek() == '-') position++
            while (position < text.length && (text[position].isDigit() || text[position] == '.' ||
                    text[position] == 'e' || text[position] == 'E' || text[position] == '+' || text[position] == '-')
            ) position++
            val raw = text.substring(start, position)
            return raw.toLongOrNull() ?: raw.toDouble()
        }

        private fun readBoolean(): Any = when {
            text.startsWith("true", position) -> { position += 4; true }
            text.startsWith("false", position) -> { position += 5; false }
            else -> throw IllegalStateException("bad literal")
        }

        private fun readNull(): Any? {
            if (!text.startsWith("null", position)) throw IllegalStateException("bad literal")
            position += 4
            return null
        }

        private fun peek(): Char {
            if (position >= text.length) throw IllegalStateException("unexpected end")
            return text[position]
        }

        private fun expect(c: Char) {
            if (peek() != c) throw IllegalStateException("expected '$c'")
            position++
        }
    }
}

/**
 * HTTP fallback for the relay.
 *
 * Uses `HttpURLConnection` because the app already depends on it for signaling, and because adding a
 * second HTTP stack for four endpoints would be more code to trust than to write.
 *
 * Every request is bounded: connect/read timeouts, a capped response body, and `no-store` responses.
 */
class HttpRelayClient(
    private val connectTimeoutMs: Int = 10_000,
    private val readTimeoutMs: Int = 15_000
) {
    fun send(baseUrl: String, envelope: SealedMessageEnvelope) {
        val body = """{"fromDeviceId":"${ByteEncoding.encodeBase64Url(envelope.senderDeviceId)}","envelope":${EnvelopeJson.encode(envelope)}}"""
        val response = post("$baseUrl/v1/relay/messages", body)
        if (response.status !in 200..299) {
            throw java.io.IOException("relay rejected envelope: ${response.status}")
        }
    }

    fun fetchSince(baseUrl: String, deviceId: ByteArray, sinceSequence: Long): List<SealedMessageEnvelope> {
        val device = ByteEncoding.encodeBase64Url(deviceId)
        val response = get("$baseUrl/v1/relay/messages?deviceId=$device&sinceSeq=$sinceSequence")
        if (response.status !in 200..299) {
            throw java.io.IOException("relay fetch failed: ${response.status}")
        }
        val objects = FlatJson.readArray(response.body, "envelopes") ?: return emptyList()
        return objects.mapNotNull { EnvelopeJson.decode(it) }
    }

    fun sendReceipt(baseUrl: String, kind: String, messageIdHex: String, fromDeviceB64u: String) {
        // The receipt names the sender; the server binds it to the authenticated connection when the
        // socket is used and to the body when HTTP is used. Failure is non-fatal by design (see
        // ConversationEngine.markRead): a lost receipt must never lose the message.
        runCatching {
            post(
                "$baseUrl/v1/relay/receipts",
                """{"kind":"$kind","messageId":"$messageIdHex","from":"$fromDeviceB64u"}"""
            )
        }
    }

    fun acknowledge(baseUrl: String, deviceId: ByteArray, messageIdHex: String) {
        runCatching {
            post(
                "$baseUrl/v1/relay/ack",
                """{"deviceId":"${ByteEncoding.encodeBase64Url(deviceId)}","messageId":"$messageIdHex"}"""
            )
        }
    }

    private data class Response(val status: Int, val body: String)

    private fun get(url: String): Response = request("GET", url, null)

    private fun post(url: String, body: String): Response = request("POST", url, body)

    private fun request(method: String, url: String, body: String?): Response {
        var connection: HttpURLConnection? = null
        try {
            connection = java.net.URI(url).toURL().openConnection() as HttpURLConnection
            connection.requestMethod = method
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Accept", "application/json")
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.let { readCapped(it) } ?: ""
            return Response(status, text)
        } finally {
            connection?.disconnect()
        }
    }

    private fun readCapped(stream: java.io.InputStream): String {
        val buffer = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(8192)
        while (true) {
            val read = stream.read(chunk)
            if (read < 0) break
            buffer.write(chunk, 0, read)
            if (buffer.size() > MAX_RESPONSE_BYTES) {
                throw java.io.IOException("relay response too large")
            }
        }
        return buffer.toString(Charsets.UTF_8.name())
    }

    private companion object {
        /** 4 MiB: enough for a page of envelopes, small enough that a hostile server cannot OOM us. */
        const val MAX_RESPONSE_BYTES = 4 * 1024 * 1024
    }
}
