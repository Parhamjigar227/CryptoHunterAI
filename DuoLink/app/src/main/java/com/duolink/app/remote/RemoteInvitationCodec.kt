package com.duolink.app.remote

import com.duolink.app.crypto.ByteEncoding
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * One-time activation code for Method B remote pairing.
 *
 * Security role: an invitation mechanism, **not** an authentication mechanism. Possession of the
 * code lets a peer join the handshake; it never makes either device trusted. Trust is established
 * only after both users independently compare the full 60-digit Safety Number derived from the
 * three-DH transcript.
 *
 * Format: `DL1-XXXX-XXXX-XXXX-XXXX` where each `X` is drawn from a 32-symbol alphabet with the
 * visually ambiguous glyphs (`I`, `O`, `0`, `1`) removed. 16 symbols => 80 bits of CSPRNG entropy,
 * single use, short lifetime. The `DL1` prefix is a protocol/version marker so a future code format
 * can never be silently interpreted under the current rules.
 */
data class ActivationCode private constructor(val canonical: String) {

    /** Grouped, user-facing form: `DL1-ABCD-EFGH-JKLM-NPQR`. */
    val displayForm: String get() = canonical

    /** Compact form for QR payloads (no separators). */
    val compactForm: String get() = canonical.replace("-", "")

    /** `true` when this instance carries the `DL1` protocol marker. */
    val isProtocolV1: Boolean get() = canonical.startsWith(PREFIX_V1)

    override fun toString(): String = canonical

    companion object {
        const val PREFIX_V1 = "DL1"
        const val GROUP_COUNT = 4
        const val GROUP_SIZE = 4
        const val RANDOM_SYMBOLS = GROUP_COUNT * GROUP_SIZE

        /** Entropy carried by a freshly generated code, in bits (log2(32) * 16). */
        const val ENTROPY_BITS = 5 * RANDOM_SYMBOLS

        /**
         * Crockford-style alphabet: no `I`, `L`, `O`, `U`, `0`, `1` so a code read aloud or typed on a
         * phone keypad cannot be confused with a different valid code.
         */
        const val ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"

        private val CANONICAL_PATTERN = Regex("^DL1(-[$ALPHABET]{4}){${GROUP_COUNT}}$")
        private val COMPACT_PATTERN = Regex("^DL1[$ALPHABET]{${RANDOM_SYMBOLS}}$")

        fun generate(secureRandom: SecureRandom = SecureRandom()): ActivationCode {
            val builder = StringBuilder(RANDOM_SYMBOLS)
            repeat(RANDOM_SYMBOLS) {
                builder.append(ALPHABET[secureRandom.nextInt(ALPHABET.length)])
            }
            val raw = builder.toString()
            val grouped = (0 until GROUP_COUNT).joinToString("-") { index ->
                raw.substring(index * GROUP_SIZE, (index + 1) * GROUP_SIZE)
            }
            return ActivationCode("$PREFIX_V1-$grouped")
        }

        /**
         * Parses user input leniently but verifies strictly.
         *
         * Lenient: surrounding whitespace, any non-alphanumeric separators (spaces, dashes, dots,
         * Persian/Arabic digits are NOT transliterated — ambiguity is refused, not guessed), and
         * lower-case input are normalised.
         *
         * Strict: the result must be a canonical `DL1` code drawn from the alphabet; otherwise
         * `null` is returned and the caller shows an explicit Persian failure. A rejected code must
         * never be coerced into a plausible one.
         */
        fun parse(input: String?): ActivationCode? {
            if (input == null) return null
            val cleaned = input.trim().uppercase()
            if (cleaned.isEmpty() || cleaned.length > 64) return null
            val compact = cleaned.filter { it.isLetterOrDigit() }
            if (!compact.startsWith(PREFIX_V1)) return null
            val body = compact.removePrefix(PREFIX_V1)
            if (body.length != RANDOM_SYMBOLS) return null
            if (body.any { it !in ALPHABET }) return null
            if (!COMPACT_PATTERN.matches(compact)) return null
            val grouped = (0 until GROUP_COUNT).joinToString("-") { index ->
                body.substring(index * GROUP_SIZE, (index + 1) * GROUP_SIZE)
            }
            val canonical = "$PREFIX_V1-$grouped"
            if (!CANONICAL_PATTERN.matches(canonical)) return null
            return ActivationCode(canonical)
        }

        fun fromCompact(compact: String): ActivationCode? =
            parse(compact)
    }
}

/**
 * The invitation QR payload shown by the owner device.
 *
 * `duolink://invite/v1?c=<compact activation code>&s=<base64url server label>`
 *
 * The QR carries the same secret as the spoken/typed activation code — no additional secret, no
 * extra authority. `s` is a *non-secret* hint describing which signaling endpoint the invitation
 * belongs to, so a scanner can warn when the two devices are pointed at different servers instead of
 * failing later with an opaque error. It is never used for authentication.
 */
data class RemoteInvitationPayload(
    val activationCode: ActivationCode,
    val signalingHint: String?
) {
    val qrText: String
        get() {
            val base = "${SCHEME}${HOST_PATH}?$PARAM_CODE=${activationCode.compactForm}"
            return if (signalingHint.isNullOrBlank()) base else "$base&$PARAM_SERVER=${encodeHint(signalingHint)}"
        }

    companion object {
        const val SCHEME = "duolink://"
        const val HOST_PATH = "invite/v1"
        const val PARAM_CODE = "c"
        const val PARAM_SERVER = "s"
        private val URI_PREFIX = "$SCHEME$HOST_PATH"

        fun build(activationCode: ActivationCode, signalingHint: String?): RemoteInvitationPayload =
            RemoteInvitationPayload(activationCode, signalingHint?.trim()?.takeIf { it.isNotEmpty() })

        /**
         * Parses an invitation QR payload. Returns `null` for anything that is not a v1 DuoLink
         * invitation: a partially-matching URI must never be half-trusted.
         */
        fun parseQrText(raw: String?): RemoteInvitationPayload? {
            val text = raw?.trim() ?: return null
            if (text.length > MAX_QR_LENGTH) return null
            if (!text.startsWith(URI_PREFIX)) return null
            val queryIndex = text.indexOf('?')
            if (queryIndex <= 0 || queryIndex == text.lastIndex) return null
            if (text.substring(0, queryIndex) != URI_PREFIX) return null
            val params = text.substring(queryIndex + 1).split('&')
                .filter { it.isNotEmpty() }
                .mapNotNull { pair ->
                    val idx = pair.indexOf('=')
                    if (idx <= 0) null else pair.substring(0, idx) to pair.substring(idx + 1)
                }
            val known = setOf(PARAM_CODE, PARAM_SERVER)
            if (params.any { it.first !in known }) return null
            if (params.count { it.first == PARAM_CODE } != 1) return null
            if (params.count { it.first == PARAM_SERVER } > 1) return null
            val compact = params.first { it.first == PARAM_CODE }.second
            val code = ActivationCode.fromCompact(compact) ?: return null
            val hint = params.firstOrNull { it.first == PARAM_SERVER }?.second?.let { decodeHint(it) }
            return RemoteInvitationPayload(code, hint)
        }

        private fun encodeHint(hint: String): String =
            ByteEncoding.encodeBase64Url(hint.toByteArray(StandardCharsets.UTF_8))

        private fun decodeHint(encoded: String): String? = try {
            val bytes = ByteEncoding.decodeBase64UrlStrict(encoded)
            if (bytes.size > 256) {
                null
            } else {
                val text = String(bytes, StandardCharsets.UTF_8)
                if (text.all { it.code in 0x20..0x7E }) text else null
            }
        } catch (_: IllegalArgumentException) {
            null
        }

        const val MAX_QR_LENGTH = 512
    }
}

/**
 * Canonical server-side hash of an activation code.
 *
 * Mirrors `hashActivationCode()` in `DuoLink/server/src/crypto.js`. Used **only** so the Android
 * client can prove, in a test, that it derives the same digest the server stores; the client still
 * transmits the plaintext code exactly once, during redemption, over TLS.
 */
object ActivationCodeDigest {
    private val DOMAIN = "DUOLINK-ACTIVATION-CODE-V1".toByteArray(StandardCharsets.UTF_8)

    fun sha256(canonicalCode: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(DOMAIN)
        digest.update(canonicalCode.toByteArray(StandardCharsets.UTF_8))
        return digest.digest()
    }
}
