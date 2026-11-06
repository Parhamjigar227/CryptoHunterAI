package com.duolink.app.remote

import com.duolink.app.crypto.ByteEncoding
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * One-time activation code for Method B remote pairing.
 *
 * Security role: an invitation mechanism, **not** an authentication mechanism. Possession of the code
 * lets a peer join the handshake; it never makes either device trusted. Trust is established only after
 * both users independently compare the full 60-digit Safety Number derived from the two-DH transcript.
 *
 * Format: `XXXX-XXXX-XXXX-XXXX` — 16 symbols drawn from a 32-symbol alphabet with the visually
 * ambiguous glyphs (`I`, `L`, `O`, `U`, `0`, `1`) removed, giving 80 bits of CSPRNG entropy. Single
 * use, short lifetime, exactly one canonical form.
 *
 * There is deliberately no version prefix. An earlier revision required a `DL1` marker and produced
 * 20-symbol codes, while the signalling server emits and accepts exactly 16 unprefixed symbols
 * (`generateActivationCode()` / `normaliseActivationCode()` in `server/src/crypto.js`); the two were
 * mutually unparseable, so a real invitation could never be redeemed. The server format wins because
 * it is the implemented, tested and documented one. See `RemoteActivationCodeInteropTest`.
 */
data class ActivationCode private constructor(val canonical: String) {

    /** Grouped, user-facing form: `ABCD-EFGH-JKMN-PQRS`. */
    val displayForm: String get() = canonical

    /** Compact form for QR payloads (no separators). */
    val compactForm: String get() = canonical.replace("-", "")

    override fun toString(): String = canonical

    companion object {
        const val GROUP_COUNT = 4
        const val GROUP_SIZE = 4

        /** Number of random symbols in a code. */
        const val RANDOM_SYMBOLS = GROUP_COUNT * GROUP_SIZE

        /** Entropy carried by a freshly generated code, in bits (log2(32) * 16 = 80). */
        const val ENTROPY_BITS = 5 * RANDOM_SYMBOLS

        /**
         * Crockford base32: `A-Z` minus `I` and `O`, plus digits `2-9`. Excluded glyphs are the four that
         * get confused when a code is read aloud or typed — `I`/`1`, `O`/`0` — plus `1` and `0` themselves.
         *
         * MUST equal `CODE_ALPHABET` in `server/src/crypto.js` **exactly**, character for character. An
         * earlier revision used a 30-symbol alphabet here (dropping `L` and `U` as well) with no `L` in the
         * client encoder, while the server emits 32 symbols including `L` and `U`. Codes produced by the
         * server were therefore unparseable on the client, and the reverse. A 32-symbol alphabet also makes
         * [ENTROPY_BITS] exactly 80 rather than ~78.5.
         */
        const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

        private val CANONICAL_PATTERN = Regex("^([$ALPHABET]{4}-){${GROUP_COUNT - 1}}[$ALPHABET]{4}$")
        private val COMPACT_PATTERN = Regex("^[$ALPHABET]{${RANDOM_SYMBOLS}}$")

        /**
         * Generates a code from a CSPRNG.
         *
         * The **owner** generates the code rather than the server, because the owner's invitation
         * transcript binds the code hash (Decision B) and that signature must exist before anything is
         * uploaded. The code is shown to the human and typed or scanned on the other device; the server
         * only ever stores its salted digest, and it still rejects anything outside the alphabet/length.
         */
        fun generate(secureRandom: SecureRandom = SecureRandom()): ActivationCode {
            val builder = StringBuilder(RANDOM_SYMBOLS)
            repeat(RANDOM_SYMBOLS) {
                builder.append(ALPHABET[secureRandom.nextInt(ALPHABET.length)])
            }
            val raw = builder.toString()
            val grouped = (0 until GROUP_COUNT).joinToString("-") { index ->
                raw.substring(index * GROUP_SIZE, (index + 1) * GROUP_SIZE)
            }
            return ActivationCode(grouped)
        }

        /**
         * Parses user input leniently but verifies strictly.
         *
         * Lenient: surrounding whitespace, any non-alphanumeric separators (spaces, dashes, dots) and
         * lower-case input are normalised. Persian/Arabic digits are NOT transliterated — ambiguity is
         * refused, not guessed.
         *
         * Strict: the result must be 16 symbols drawn from [ALPHABET]; otherwise `null` is returned and
         * the caller shows an explicit Persian failure. A rejected code is never coerced into a plausible
         * one.
         */
        fun parse(input: String?): ActivationCode? {
            if (input == null) return null
            val cleaned = input.trim().uppercase()
            if (cleaned.isEmpty() || cleaned.length > 64) return null
            val compact = cleaned.filter { it.isLetterOrDigit() }
            if (!COMPACT_PATTERN.matches(compact)) return null
            val grouped = (0 until GROUP_COUNT).joinToString("-") { index ->
                compact.substring(index * GROUP_SIZE, (index + 1) * GROUP_SIZE)
            }
            if (!CANONICAL_PATTERN.matches(grouped)) return null
            return ActivationCode(grouped)
        }

        fun fromCompact(compact: String): ActivationCode? = parse(compact)
    }
}

/**
 * Canonical hash of an activation code, as stored by the signalling server.
 *
 * Mirrors `hashActivationCode()` in `DuoLink/server/src/crypto.js` exactly: salted, domain-separated
 * SHA-256 over the **canonical grouped form**. Used so the Android client can (a) sign an invitation
 * transcript that binds the code without revealing it and (b) prove, in a test, that it derives the same
 * digest the server stores. The plaintext code is transmitted exactly once, during redemption, over TLS.
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

/**
 * A v1 invitation QR payload.
 *
 * `duolink://invite/v1?c=<compact activation code>&i=<invitationId>&s=<base64url server label>`
 *
 * The QR carries the same secret as the spoken/typed activation code — no additional secret, no extra
 * authority. `i` is the client-assigned invitation id, required because the frozen redeem transcript
 * binds it and the recipient has no other channel to the owner before redeeming; it is not a secret,
 * since redemption still requires the activation code and every request is token-scoped. `s` is a
 * *non-secret* hint describing which signalling endpoint the invitation belongs to, so a scanner can warn
 * when two devices point at different servers instead of failing later with an opaque error. Neither is
 * ever used for authentication.
 */
data class RemoteInvitationPayload(
    val activationCode: ActivationCode,
    val signalingHint: String?,
    val invitationId: String
) {
    val qrText: String
        get() {
            var text = "$SCHEME$HOST_PATH?$PARAM_CODE=${activationCode.compactForm}&$PARAM_INVITATION=$invitationId"
            if (!signalingHint.isNullOrBlank()) text += "&$PARAM_SERVER=${encodeHint(signalingHint)}"
            return text
        }

    companion object {
        const val SCHEME = "duolink://"
        const val HOST_PATH = "invite/v1"
        const val PARAM_CODE = "c"
        const val PARAM_SERVER = "s"
        const val PARAM_INVITATION = "i"
        private val URI_PREFIX = "$SCHEME$HOST_PATH"

        fun build(
            activationCode: ActivationCode,
            signalingHint: String?,
            invitationId: String
        ): RemoteInvitationPayload = RemoteInvitationPayload(
            activationCode = activationCode,
            signalingHint = signalingHint?.trim()?.takeIf { it.isNotEmpty() },
            invitationId = invitationId
        )

        /**
         * Parses an invitation QR payload. Returns `null` for anything that is not a complete v1 DuoLink
         * invitation: a partially-matching URI must never be half-trusted, and a payload without an
         * invitation id cannot produce a verifiable redeem transcript.
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
            val known = setOf(PARAM_CODE, PARAM_SERVER, PARAM_INVITATION)
            if (params.any { it.first !in known }) return null
            if (params.count { it.first == PARAM_CODE } != 1) return null
            if (params.count { it.first == PARAM_SERVER } > 1) return null
            if (params.count { it.first == PARAM_INVITATION } != 1) return null
            val compact = params.first { it.first == PARAM_CODE }.second
            val code = ActivationCode.fromCompact(compact) ?: return null
            val hint = params.firstOrNull { it.first == PARAM_SERVER }?.second?.let { decodeHint(it) }
            val invitationId = decodeInvitationId(params.first { it.first == PARAM_INVITATION }.second)
                ?: return null
            return RemoteInvitationPayload(code, hint, invitationId)
        }

        /** Invitation ids are `[A-Za-z0-9_-]` and length-bounded, so they are carried verbatim. */
        private fun decodeInvitationId(value: String): String? {
            if (value.isEmpty() || value.length > 40) return null
            if (!value.all { it.isLetterOrDigit() || it == '_' || it == '-' }) return null
            return value
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
