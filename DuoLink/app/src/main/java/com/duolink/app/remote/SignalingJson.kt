package com.duolink.app.remote

/**
 * Small, strict, allocation-bounded JSON reader for signaling responses.
 *
 * Scope: it understands exactly the shapes the protocol returns — objects, arrays, strings, numbers,
 * booleans and `null`. It is *not* a general-purpose JSON library and deliberately does not try to be:
 * anything outside the documented grammar is rejected with [RemoteFailure.CIPHERTEXT_MALFORMED]-style
 * failures, and no attempt is made to "fix up" a malformed document.
 *
 * Why not a dependency: responses are small and fully specified, and a 250-line parser whose behaviour
 * is pinned by tests is a smaller trusted surface than a general parser plus its transitive deps.
 * Nesting depth and total size are both capped so a hostile server cannot blow the stack or the heap.
 */
object SignalingJson {

    sealed class Value {
        data class Obj(val fields: Map<String, Value>) : Value()
        data class Arr(val items: List<Value>) : Value()
        data class Str(val value: String) : Value()
        data class Num(val value: Double) : Value()
        data class Bool(val value: Boolean) : Value()
        data object Null : Value()

        fun asStringOrNull(): String? = (this as? Str)?.value
        fun asBooleanOrNull(): Boolean? = (this as? Bool)?.value
        fun asLongOrNull(): Long? = (this as? Num)?.value?.toLong()
        fun asObjectOrNull(): Obj? = this as? Obj
        fun asArrayOrNull(): Arr? = this as? Arr
    }

    class ParseException(message: String) : Exception(message)

    private const val MAX_DEPTH = 16

    fun parse(text: String): Value {
        if (text.length > SignalingHttpClient.MAX_RESPONSE_BYTES) {
            throw ParseException("JSON document exceeds the protocol size limit")
        }
        val reader = Reader(text)
        reader.skipWhitespace()
        val value = reader.readValue(0)
        reader.skipWhitespace()
        if (!reader.atEnd()) throw ParseException("trailing content after JSON value")
        return value
    }

    /** Parses and returns the root object, or throws [RemotePairingException] with a typed failure. */
    fun parseObject(text: String): Value.Obj {
        val value = try {
            parse(text)
        } catch (e: ParseException) {
            throw RemotePairingException(
                RemoteFailure.SERVER_REJECTED_REQUEST,
                "پاسخ سرور واسط ساختار JSON معتبر نداشت",
                e
            )
        }
        return value as? Value.Obj
            ?: throw RemotePairingException(
                RemoteFailure.SERVER_REJECTED_REQUEST,
                "پاسخ سرور واسط باید یک شیء JSON باشد"
            )
    }

    /** Required string field; missing or wrong-typed fields are a protocol violation, not a default. */
    fun requireString(obj: Value.Obj, field: String): String =
        obj.fields[field]?.asStringOrNull()
            ?: throw RemotePairingException(
                RemoteFailure.SERVER_REJECTED_REQUEST,
                "فیلد «$field» در پاسخ سرور واسط موجود یا معتبر نیست"
            )

    fun optionalString(obj: Value.Obj, field: String): String? =
        obj.fields[field]?.asStringOrNull()

    fun requireBool(obj: Value.Obj, field: String): Boolean =
        obj.fields[field]?.asBooleanOrNull()
            ?: throw RemotePairingException(
                RemoteFailure.SERVER_REJECTED_REQUEST,
                "فیلد «$field» در پاسخ سرور واسط موجود یا معتبر نیست"
            )

    fun optionalBool(obj: Value.Obj, field: String): Boolean? =
        obj.fields[field]?.asBooleanOrNull()

    fun requireLong(obj: Value.Obj, field: String): Long =
        obj.fields[field]?.asLongOrNull()
            ?: throw RemotePairingException(
                RemoteFailure.SERVER_REJECTED_REQUEST,
                "فیلد «$field» در پاسخ سرور واسط موجود یا معتبر نیست"
            )

    fun optionalLong(obj: Value.Obj, field: String): Long? =
        obj.fields[field]?.asLongOrNull()

    fun requireObject(obj: Value.Obj, field: String): Value.Obj =
        obj.fields[field]?.asObjectOrNull()
            ?: throw RemotePairingException(
                RemoteFailure.SERVER_REJECTED_REQUEST,
                "فیلد «$field» در پاسخ سرور واسط موجود یا معتبر نیست"
            )

    fun optionalObject(obj: Value.Obj, field: String): Value.Obj? =
        obj.fields[field]?.asObjectOrNull()

    /** Decodes a strict base64url field into raw bytes. */
    fun requireBytes(obj: Value.Obj, field: String): ByteArray =
        decodeBytes(requireString(obj, field), field)

    fun optionalBytes(obj: Value.Obj, field: String): ByteArray? =
        optionalString(obj, field)?.let { decodeBytes(it, field) }

    fun decodeBytes(encoded: String, field: String): ByteArray = try {
        com.duolink.app.crypto.ByteEncoding.decodeBase64UrlStrict(encoded)
    } catch (e: IllegalArgumentException) {
        throw RemotePairingException(
            RemoteFailure.SERVER_REJECTED_REQUEST,
            "فیلد «$field» کدگذاری Base64URL معتبر ندارد",
            e
        )
    }

    private class Reader(private val text: String) {
        private var index = 0

        fun atEnd(): Boolean = index >= text.length

        fun skipWhitespace() {
            while (index < text.length && text[index].isWhitespace()) index++
        }

        fun readValue(depth: Int): Value {
            if (depth > MAX_DEPTH) throw ParseException("JSON nesting too deep")
            if (atEnd()) throw ParseException("unexpected end of JSON document")
            return when (val ch = text[index]) {
                '{' -> readObject(depth)
                '[' -> readArray(depth)
                '"' -> Value.Str(readString())
                't' -> readLiteral("true", Value.Bool(true))
                'f' -> readLiteral("false", Value.Bool(false))
                'n' -> readLiteral("null", Value.Null)
                else -> if (ch == '-' || ch.isDigit()) readNumber() else throw ParseException("unexpected character '$ch'")
            }
        }

        private fun readLiteral(literal: String, value: Value): Value {
            if (index + literal.length > text.length || text.substring(index, index + literal.length) != literal) {
                throw ParseException("invalid literal")
            }
            index += literal.length
            return value
        }

        private fun readObject(depth: Int): Value {
            expect('{')
            val fields = LinkedHashMap<String, Value>()
            skipWhitespace()
            if (peek() == '}') {
                index++
                return Value.Obj(fields)
            }
            while (true) {
                skipWhitespace()
                if (peek() != '"') throw ParseException("object key must be a string")
                val key = readString()
                skipWhitespace()
                expect(':')
                skipWhitespace()
                if (fields.containsKey(key)) throw ParseException("duplicate object key '$key'")
                fields[key] = readValue(depth + 1)
                skipWhitespace()
                when (peek()) {
                    ',' -> {
                        index++
                        continue
                    }
                    '}' -> {
                        index++
                        return Value.Obj(fields)
                    }
                    else -> throw ParseException("expected ',' or '}'")
                }
            }
        }

        private fun readArray(depth: Int): Value {
            expect('[')
            val items = ArrayList<Value>()
            skipWhitespace()
            if (peek() == ']') {
                index++
                return Value.Arr(items)
            }
            while (true) {
                skipWhitespace()
                items.add(readValue(depth + 1))
                skipWhitespace()
                when (peek()) {
                    ',' -> {
                        index++
                        continue
                    }
                    ']' -> {
                        index++
                        return Value.Arr(items)
                    }
                    else -> throw ParseException("expected ',' or ']'")
                }
            }
        }

        private fun readString(): String {
            expect('"')
            val builder = StringBuilder()
            while (true) {
                if (atEnd()) throw ParseException("unterminated string")
                val ch = text[index++]
                when {
                    ch == '"' -> return builder.toString()
                    ch == '\\' -> {
                        if (atEnd()) throw ParseException("unterminated escape")
                        when (val esc = text[index++]) {
                            '"' -> builder.append('"')
                            '\\' -> builder.append('\\')
                            '/' -> builder.append('/')
                            'b' -> builder.append('\b')
                            'f' -> builder.append('\u000C')
                            'n' -> builder.append('\n')
                            'r' -> builder.append('\r')
                            't' -> builder.append('\t')
                            'u' -> {
                                if (index + 4 > text.length) throw ParseException("truncated unicode escape")
                                val hex = text.substring(index, index + 4)
                                val code = hex.toIntOrNull(16) ?: throw ParseException("invalid unicode escape")
                                builder.append(code.toChar())
                                index += 4
                            }
                            else -> throw ParseException("invalid escape '\\$esc'")
                        }
                    }
                    ch < ' ' -> throw ParseException("raw control character in string")
                    else -> builder.append(ch)
                }
                if (builder.length > MAX_STRING_LENGTH) throw ParseException("string too long")
            }
        }

        private fun readNumber(): Value {
            val start = index
            if (peek() == '-') index++
            var digits = 0
            while (!atEnd() && text[index].isDigit()) {
                index++
                digits++
            }
            if (digits == 0) throw ParseException("invalid number")
            if (!atEnd() && text[index] == '.') {
                index++
                var fraction = 0
                while (!atEnd() && text[index].isDigit()) {
                    index++
                    fraction++
                }
                if (fraction == 0) throw ParseException("invalid fraction")
            }
            if (!atEnd() && (text[index] == 'e' || text[index] == 'E')) {
                index++
                if (!atEnd() && (text[index] == '+' || text[index] == '-')) index++
                var exponent = 0
                while (!atEnd() && text[index].isDigit()) {
                    index++
                    exponent++
                }
                if (exponent == 0) throw ParseException("invalid exponent")
            }
            val raw = text.substring(start, index)
            return Value.Num(raw.toDoubleOrNull() ?: throw ParseException("invalid number"))
        }

        private fun peek(): Char? = if (atEnd()) null else text[index]

        private fun expect(expected: Char) {
            if (atEnd() || text[index] != expected) throw ParseException("expected '$expected'")
            index++
        }

        companion object {
            private const val MAX_STRING_LENGTH = 32 * 1024
        }
    }
}
