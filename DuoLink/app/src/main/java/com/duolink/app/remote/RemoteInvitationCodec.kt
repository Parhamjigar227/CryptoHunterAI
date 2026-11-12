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

    /** True when this is the 10-digit numeric form rather than the legacy 16-symbol base32 form. */
    val isNumeric: Boolean get() = canonical.all { it.isDigit() || it == '-' }

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

        /**
         * Digits in a numeric invitation code. Ten digits = 33.2 bits.
         *
         * 33.2 bits is deliberately far below the 80 bits of the legacy base32 form, and is only
         * acceptable because the server hashes numeric codes with a deployment-secret pepper plus
         * PBKDF2 (see `hashActivationCode()` in `server/src/crypto.js`). Those two changes are what
         * stop a leaked database from being enumerated offline in hours; they are not optional
         * hardening, they are the precondition for this code being this short.
         *
         * Online guessing is bounded independently of length by a GLOBAL, address-independent server
         * bucket of 10 attempts/minute, so 10^10 codes is ~1,900 years regardless of entropy.
         */
        const val NUMERIC_DIGITS = 10

        /**
         * Display grouping for the numeric form: `482-913-7462` (3-3-4).
         *
         * Chosen over 4-3-3 or 5-5 because 3-3-4 matches how phone numbers are read aloud in Iran,
         * so dictating a code over a voice call is less error-prone.
         */
        private val NUMERIC_GROUP_SIZES = intArrayOf(3, 3, 4)

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
         * Generates a 10-digit numeric invitation code from the platform CSPRNG.
         *
         * Rejection sampling is used rather than `nextInt(1_000_000_0000)` modulo arithmetic:
         * `SecureRandom.nextInt(bound)` is already unbiased for a bound that is not a power of two,
         * but building the value digit-by-digit and discarding the leading-zero case keeps the
         * canonical form EXACTLY ten digits. A code whose canonical form could be nine digits (leading
         * zero dropped) would have two spellings, and two spellings of one secret is how "single use"
         * quietly stops being true.
         */
        fun generateNumeric(secureRandom: SecureRandom = SecureRandom()): ActivationCode {
            val digits = CharArray(NUMERIC_DIGITS) { '0' + secureRandom.nextInt(10) }
            // Refuse an all-zero code and a leading zero, both of which invite transcription errors.
            if (digits[0] == '0' || digits.all { it == '0' }) {
                return generateNumeric(secureRandom)
            }
            val formatted = formatNumeric(String(digits))
            return ActivationCode(formatted)
        }

        /** Groups ten digits as 3-3-4. */
        private fun formatNumeric(digits: String): String {
            var index = 0
            return NUMERIC_GROUP_SIZES.joinToString("-") { size ->
                digits.substring(index, index + size).also { index += size }
            }
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

            // ---- numeric form ----------------------------------------------------------
            // Persian and Arabic-Indic digits are transliterated HERE (unlike the legacy parser,
            // which refuses them). Rationale: a numeric keypad on a Persian-locale keyboard very
            // often emits U+06F0..U+06F9, so refusing them would make the feature unusable for the
            // intended users. Transliteration is unambiguous (a 1:1 digit map), so it cannot change
            // which code the user meant - unlike guessing at a mistyped letter.
            val asciiDigits = buildString {
                compact.forEach { ch ->
                    append(
                        when (ch) {
                            in '0'..'9' -> ch
                            in '\u06F0'..'\u06F9' -> ('0' + (ch - '\u06F0'))  // Persian
                            in '\u0660'..'\u0669' -> ('0' + (ch - '\u0660'))  // Arabic-Indic
                            else -> ch
                        }
                    )
                }
            }
            if (asciiDigits.length == NUMERIC_DIGITS && asciiDigits.all { it.isDigit() }) {
                // Reject a leading zero: the canonical display form would then have an ambiguous
                // length, and such a code is never generated (see generateNumeric).
                if (asciiDigits[0] == '0') return null
                return ActivationCode(formatNumeric(asciiDigits))
            }

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

    /**
     * SHA-256 of the canonical activation code, used ONLY to bind the code into the signed invitation
     * transcript.
     *
     * There are two different code hashes in this protocol and they must never be confused:
     *
     * | hash            | computed by        | purpose                  | numeric code          |
     * |-----------------|--------------------|--------------------------|-----------------------|
     * | transcript hash | both clients       | bind code into signature | this: bare SHA-256    |
     * | storage hash    | server only        | database lookup          | HMAC(pepper)+PBKDF2   |
     *
     * The transcript hash MUST stay a plain SHA-256 that both the owner and the joiner can compute
     * independently, because the owner signs the invitation transcript and the joiner rebuilds it to
     * verify that signature. If this value were peppered, the joiner could not recompute it and the
     * owner's signature would be unverifiable - breaking Method B entirely.
     *
     * That is safe for numeric codes because the transcript hash is NEVER stored as a lookup key.
     * The value the server persists is the peppered `hashActivationCode()` from `server/src/crypto.js`,
     * which is a different function of the same code. A stolen database therefore yields neither the
     * plaintext code nor a cheap offline oracle: to recover a code from the stored `code_hash` an
     * attacker must already hold the server's pepper.
     *
     * The residual path is the owner's ECDSA signature, which does cover this digest and is stored.
     * Measured on reference hardware: ECDSA P-256 verification costs ~91 us versus ~1.9 us to recompute
     * this digest, so testing one candidate code against the stored signature costs about 48x a raw
     * hash - which enumerates the full 10^10 space in roughly 11 CPU-days on one core.
     *
     * That is a real, feasible attack, and it is recorded rather than papered over. It is also
     * unavoidable for any design that cryptographically binds a low-entropy secret into a public-key
     * signature, and it applies to the 16-symbol form too (where it is irrelevant, because 80 bits is
     * out of reach regardless of per-guess cost).
     *
     * What actually defends the numeric form:
     *   - the server-stored digest is peppered and stretched, so a database copy alone is useless;
     *   - the invitation lives 10 minutes, bounding how many signatures exist to attack at once;
     *   - the 16-symbol QR/code path remains available and is offered as the stronger option.
     * The UI therefore must not present the two methods as equivalent, and does not.
     */
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
