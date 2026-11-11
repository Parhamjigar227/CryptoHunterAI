package com.duolink.app.crypto

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

object ByteEncoding {
    private val urlEncoder = Base64.getUrlEncoder().withoutPadding()
    private val urlDecoder = Base64.getUrlDecoder()
    private val urlSafePattern = Regex("^[A-Za-z0-9_-]+$")
    private val hexLowerPattern = Regex("^[0-9a-f]+$")

    fun encodeBase64Url(bytes: ByteArray): String {
        require(bytes.isNotEmpty()) { "Cannot Base64URL-encode empty byte array" }
        return urlEncoder.encodeToString(bytes)
    }

    /**
     * Strict canonical Base64URL decoder (no padding, no whitespace, no non-zero trailing bits).
     */
    fun decodeBase64UrlStrict(encoded: String): ByteArray {
        require(encoded.isNotEmpty() && urlSafePattern.matches(encoded)) {
            "Non-canonical Base64URL characters"
        }
        val decoded = try {
            urlDecoder.decode(encoded)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Malformed Base64URL input", e)
        }
        require(decoded.isNotEmpty()) { "Decoded Base64URL payload is empty" }
        val canonical = urlEncoder.encodeToString(decoded)
        require(canonical == encoded) { "Non-canonical Base64URL trailing bits rejected" }
        return decoded
    }

    fun toHexLower(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        val digits = "0123456789abcdef"
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            out[i * 2] = digits[v ushr 4]
            out[i * 2 + 1] = digits[v and 0x0F]
        }
        return String(out)
    }

    fun toHexUpper(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        val digits = "0123456789ABCDEF"
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            out[i * 2] = digits[v ushr 4]
            out[i * 2 + 1] = digits[v and 0x0F]
        }
        return String(out)
    }

    fun fromHexStrict(hex: String): ByteArray {
        require(hex.isNotEmpty() && hex.length % 2 == 0 && hexLowerPattern.matches(hex)) {
            "Invalid lowercase hex string"
        }
        return ByteArray(hex.length / 2) { idx ->
            val hi = Character.digit(hex[idx * 2], 16)
            val lo = Character.digit(hex[idx * 2 + 1], 16)
            ((hi shl 4) or lo).toByte()
        }
    }

    fun compareLexicographically(a: ByteArray, b: ByteArray): Int {
        val minLen = minOf(a.size, b.size)
        for (i in 0 until minLen) {
            val av = a[i].toInt() and 0xFF
            val bv = b[i].toInt() and 0xFF
            if (av != bv) return av - bv
        }
        return a.size - b.size
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)
}

fun ByteArray.zeroize() {
    fill(0)
}

/**
 * Deterministic length-prefixed big-endian binary transcript builder.
 * Prevents ambiguity or field-boundary collision attacks in signed transcripts.
 */
class TranscriptBuilder {
    private val out = ByteArrayOutputStream(256)

    fun putBytes(bytes: ByteArray): TranscriptBuilder {
        val lenBuf = ByteBuffer.allocate(4).putInt(bytes.size).array()
        out.write(lenBuf)
        out.write(bytes)
        return this
    }

    fun putUtf8(value: String): TranscriptBuilder =
        putBytes(value.toByteArray(StandardCharsets.UTF_8))

    /**
     * Writes UTF-8 bytes with **no** length prefix.
     *
     * Needed only for protocol domain separators, which the Method B server emits verbatim
     * (`Buffer.concat([utf8(domain), ...])` in `server/src/protocol.js`). Purely additive: it changes no
     * existing Method A encoding, and every data field must keep using [putBytes]/[putUtf8] so field
     * boundaries stay unambiguous.
     */
    fun putRawUtf8(value: String): TranscriptBuilder {
        out.write(value.toByteArray(StandardCharsets.UTF_8))
        return this
    }

    fun putInt32(value: Int): TranscriptBuilder {
        out.write(ByteBuffer.allocate(4).putInt(value).array())
        return this
    }

    fun putInt64(value: Long): TranscriptBuilder {
        out.write(ByteBuffer.allocate(8).putLong(value).array())
        return this
    }

    fun build(): ByteArray = out.toByteArray()
}
