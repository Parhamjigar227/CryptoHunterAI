package com.duolink.app.remote

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.TranscriptBuilder
import com.duolink.app.crypto.zeroize
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

/**
 * The encrypted commit: what each device actually proves to the other, end-to-end.
 *
 * A commit is a **directional AES-256-GCM envelope** sealed under `K_env_c2r` (owner → recipient) or
 * `K_env_r2c` (recipient → owner) with the invitation id and direction bound as AAD. Its plaintext is:
 *
 * ```
 * transcript  = commitPlaintextTranscript(...)        // binds both identities, root key, safety number
 * hmac        = HMAC-SHA256(K_confirm_sender, transcript)
 * certificate = ECDSA(IK_sig_sender, transcript || hmac)   // non-repudiable identity binding
 * ```
 *
 * The receiver opens the envelope with the *other* direction's key and then checks, in order:
 *  1. AEAD authentication (wrong key / any tampering ⇒ failure);
 *  2. the transcript it recomputes matches the one inside the envelope byte for byte;
 *  3. the HMAC under `K_confirm_peer` verifies (constant-time);
 *  4. the ECDSA certificate verifies against the peer's pinned `IK_sig` public key;
 *  5. the digest of the ciphertext equals the digest the server advertised at quorum.
 *
 * Why all five: (1) is confidentiality/integrity against the relay, (2) stops a relay from splicing a
 * payload from a different pairing, (3) proves the peer holds the same derived secret, (4) binds that
 * to a long-term identity the user just compared a Safety Number for, and (5) detects a relay that
 * swaps ciphertexts after the quorum barrier.
 *
 * The server sees none of this. It records a SHA-256 digest of the opaque envelope and, at mutual
 * receipt, deletes the envelope entirely.
 */
object RemoteCommitCodec {

    const val ENVELOPE_VERSION: Byte = 0x02
    private const val MIN_PLAINTEXT = 1 + 4 + 32 + 4 + 32 + 4 + 1
    private const val MAX_PLAINTEXT = 4096

    /**
     * Decoded commit plaintext.
     *
     * [issuedAtEpochSec] is the trailing timestamp of [transcript]. It is carried explicitly because the
     * verifier must rebuild the transcript with the *peer's* timestamp; without it every peer commit
     * failed verification (and the previous code referenced this field without ever declaring it).
     */
    data class CommitContents(
        val transcript: ByteArray,
        val hmac: ByteArray,
        val certificate: ByteArray,
        val issuedAtEpochSec: Long
    )

    /** Result of a successful peer-commit verification, including what was actually proven. */
    data class VerifiedPeerCommit(
        val peerDeviceId: ByteArray,
        val peerIdentityDeviceIdMatches: Boolean,
        val ciphertextDigest: ByteArray,
        val safetyNumberNormalised: String,
        val issuedAtEpochSec: Long,
        val hmacVerified: Boolean,
        val certificateVerified: Boolean,
        val transcriptMatched: Boolean
    )

    /**
     * Builds the plaintext and seals it.
     *
     * @param keys the caller's derived key set (only `encryptKey`/`ownConfirmKey` are used)
     */
    fun encodeCommit(
        invitationId: String,
        role: RemoteRole,
        keys: RemoteKeySchedule.RemoteKeySet,
        localDeviceId: ByteArray,
        peerDeviceId: ByteArray,
        ephemeralPublicSpki: ByteArray,
        spkPublicSpki: ByteArray,
        safetyNumber: String,
        issuedAtEpochSec: Long,
        signWithIdentityKey: (ByteArray) -> ByteArray,
        secureRandom: SecureRandom = SecureRandom()
    ): ByteArray {
        require(keys.role == role.wireValue) { "key set role does not match the committing role" }
        val transcript = RemoteTranscripts.commitPlaintextTranscript(
            invitationId = invitationId,
            role = role.wireValue,
            deviceId = localDeviceId,
            peerDeviceId = peerDeviceId,
            rootKey = keys.rootKey,
            ephemeralPublicSpki = ephemeralPublicSpki,
            spkPublicSpki = spkPublicSpki,
            safetyNumber = safetyNumber,
            issuedAtEpochSec = issuedAtEpochSec
        )
        val hmac = RemoteKeySchedule.ConfirmTag.compute(keys.ownConfirmKey, transcript)
        val certificate = signWithIdentityKey(transcript + hmac)
        val plaintext = encodePlaintext(transcript, hmac, certificate)
        val aad = RemoteKeySchedule.ConfirmTag.envelopeAssociatedData(
            invitationId,
            role.wireValue,
            PURPOSE_COMMIT
        )
        return try {
            RemoteKeySchedule.Envelope.seal(keys.encryptKey, plaintext, aad, secureRandom)
        } finally {
            plaintext.zeroize()
            hmac.zeroize()
        }
    }

    /**
     * Opens and fully verifies a peer commit.
     *
     * Throws [RemotePairingException] with a specific [RemoteFailure] for every distinct failure mode, so
     * the UI can explain exactly what went wrong and the log can distinguish "network retry will help"
     * from "someone tampered with us".
     */
    fun verifyPeerCommit(
        invitationId: String,
        peerRole: RemoteRole,
        keys: RemoteKeySchedule.RemoteKeySet,
        peerDeviceId: ByteArray,
        peerIdentitySpki: ByteArray,
        expectedLocalDeviceId: ByteArray,
        sealedCommit: ByteArray,
        advertisedDigest: ByteArray,
        expectedEphemeralPublicSpki: ByteArray,
        expectedSpkPublicSpki: ByteArray,
        expectedSafetyNumber: String,
        verifyPeerSignature: (ByteArray, ByteArray) -> Boolean
    ): VerifiedPeerCommit {
        require(keys.role == peerRole.peerRole.wireValue) { "key set role does not belong to this verifier" }

        // (5) Digest binding first (cheap, and catches a swapped blob before any crypto work).
        val actualDigest = ByteEncoding.sha256(sealedCommit)
        if (!ByteEncoding.constantTimeEquals(actualDigest, advertisedDigest)) {
            throw RemotePairingException(
                RemoteFailure.TRANSCRIPT_MISMATCH,
                "خلاصه پیام تأیید دستگاه مقابل با داده دریافتی مطابقت ندارد"
            )
        }

        // (1) AEAD open under the *peer direction* key.
        val aad = RemoteKeySchedule.ConfirmTag.envelopeAssociatedData(invitationId, peerRole.wireValue, PURPOSE_COMMIT)
        val plaintext = RemoteKeySchedule.Envelope.open(keys.decryptKey, sealedCommit, aad)

        val contents = try {
            decodePlaintext(plaintext)
        } finally {
            plaintext.zeroize()
        }

        // (2) Recompute the exact transcript this device must be able to derive independently.
        val expectedTranscript = RemoteTranscripts.commitPlaintextTranscript(
            invitationId = invitationId,
            role = peerRole.wireValue,
            deviceId = peerDeviceId,
            peerDeviceId = expectedLocalDeviceId,
            rootKey = keys.rootKey,
            ephemeralPublicSpki = expectedEphemeralPublicSpki,
            spkPublicSpki = expectedSpkPublicSpki,
            safetyNumber = expectedSafetyNumber,
            issuedAtEpochSec = contents.issuedAtEpochSec
        )
        val transcriptMatched = ByteEncoding.constantTimeEquals(expectedTranscript, contents.transcript)

        // (3) HMAC under the key only a genuine peer can derive.
        val hmacVerified = RemoteKeySchedule.ConfirmTag.verify(keys.peerConfirmKey, contents.transcript, contents.hmac)

        // (4) Long-term identity certificate.
        val certificateVerified = verifyPeerSignature(contents.transcript + contents.hmac, contents.certificate)

        // The peer's deviceId must be the one bound to its identity key (fail closed on mismatch).
        val peerIdMatches = try {
            ByteEncoding.constantTimeEquals(
                peerDeviceId,
                com.duolink.app.crypto.EcP256Crypto.computeDeviceId(peerIdentitySpki)
            )
        } catch (_: Exception) {
            false
        }

        if (!transcriptMatched) {
            throw RemotePairingException(
                RemoteFailure.TRANSCRIPT_MISMATCH,
                "محتوای تأیید دستگاه مقابل با این جلسه جفت‌سازی هم‌خوانی ندارد"
            )
        }
        if (!hmacVerified) {
            throw RemotePairingException(RemoteFailure.CONFIRMATION_HMAC_INVALID)
        }
        if (!certificateVerified) {
            throw RemotePairingException(RemoteFailure.ACK_SIGNATURE_INVALID)
        }
        if (!peerIdMatches) {
            throw RemotePairingException(RemoteFailure.DEVICE_ID_MISMATCH)
        }

        return VerifiedPeerCommit(
            peerDeviceId = peerDeviceId.copyOf(),
            peerIdentityDeviceIdMatches = peerIdMatches,
            ciphertextDigest = actualDigest,
            safetyNumberNormalised = RemoteTranscripts.normaliseSafetyNumber(expectedSafetyNumber),
            issuedAtEpochSec = contents.issuedAtEpochSec,
            hmacVerified = hmacVerified,
            certificateVerified = certificateVerified,
            transcriptMatched = transcriptMatched
        )
    }

    /**
     * Plaintext layout: `version(1) || len+transcript || len+hmac(32) || len+certificate(64..80)`.
     *
     * Every field is length-prefixed and the decoder requires the buffer to be exactly consumed, so a
     * truncated or extended plaintext (which can only come from a peer holding the right key) is still
     * rejected rather than partially accepted.
     */
    fun encodePlaintext(transcript: ByteArray, hmac: ByteArray, certificate: ByteArray): ByteArray {
        require(hmac.size == 32) { "HMAC must be 32 bytes" }
        require(certificate.size in 64..80) { "ECDSA certificate must be 64..80 bytes" }
        return ByteBuffer.allocate(1 + 4 + transcript.size + 4 + hmac.size + 4 + certificate.size).also { buffer ->
            buffer.put(ConsoleVersion)
            buffer.putInt(transcript.size)
            buffer.put(transcript)
            buffer.putInt(hmac.size)
            buffer.put(hmac)
            buffer.putInt(certificate.size)
            buffer.put(certificate)
        }.array()
    }

    fun decodePlaintext(plaintext: ByteArray): CommitContents {
        if (plaintext.size < MIN_PLAINTEXT || plaintext.size > MAX_PLAINTEXT) {
            throw RemotePairingException(RemoteFailure.CIPHERTEXT_MALFORMED, "اندازه محتوای پیام تأیید نامعتبر است")
        }
        val buffer = ByteBuffer.wrap(plaintext)
        if (buffer.get() != ConsoleVersion) {
            throw RemotePairingException(RemoteFailure.CIPHERTEXT_MALFORMED, "نسخه محتوای پیام تأیید پشتیبانی نمی‌شود")
        }
        val transcript = readField(buffer, MAX_PLAINTEXT)
        val hmac = readField(buffer, 32)
        val certificate = readField(buffer, 80)
        if (hmac.size != 32) {
            throw RemotePairingException(RemoteFailure.CIPHERTEXT_MALFORMED, "طول HMAC نامعتبر است")
        }
        if (certificate.size !in 64..80) {
            throw RemotePairingException(RemoteFailure.CIPHERTEXT_MALFORMED, "طول امضای دیجیتال نامعتبر است")
        }
        if (buffer.hasRemaining()) {
            throw RemotePairingException(RemoteFailure.CIPHERTEXT_MALFORMED, "داده اضافی در پیام تأیید")
        }
        val issuedAt = extractIssuedAt(transcript)
            ?: throw RemotePairingException(
                RemoteFailure.CIPHERTEXT_MALFORMED,
                "زمان صدور پیام تأیید در محتوا موجود نیست"
            )
        return CommitContents(transcript, hmac, certificate, issuedAt)
    }

    /** Extracts the trailing `issuedAtEpochSec` so the receiver can rebuild the transcript exactly. */
    fun extractIssuedAt(transcript: ByteArray): Long? {
        if (transcript.size < 8) return null
        return ByteBuffer.wrap(transcript, transcript.size - 8, 8).long
    }

    private fun readField(buffer: ByteBuffer, max: Int): ByteArray {
        if (buffer.remaining() < 4) {
            throw RemotePairingException(RemoteFailure.CIPHERTEXT_MALFORMED, "طول فیلد پیام تأیید ناقص است")
        }
        val length = buffer.int
        if (length < 0 || length > max || buffer.remaining() < length) {
            throw RemotePairingException(RemoteFailure.CIPHERTEXT_MALFORMED, "طول فیلد پیام تأیید نامعتبر است")
        }
        return ByteArray(length).also { buffer.get(it) }
    }

    /** Envelope version byte used inside the commit plaintext (distinct from the AEAD envelope version). */
    private val ConsoleVersion: Byte = 0x01

    const val PURPOSE_COMMIT = "commit"

    /** Transcript used as the pre-image of the ACK's public commitment, for diagnostics only. */
    fun publicTranscriptId(invitationId: String, commitDigestOwner: ByteArray, commitDigestRecipient: ByteArray): String {
        val digest = ByteEncoding.sha256(
            TranscriptBuilder()
                .putUtf8("DuoLink-RemoteCommitPair-v1")
                .putUtf8(invitationId)
                .putBytes(commitDigestOwner)
                .putBytes(commitDigestRecipient)
                .build()
        )
        val hex = ByteEncoding.toHexUpper(digest.copyOfRange(0, 6))
        return "${hex.substring(0, 4)}-${hex.substring(4, 8)}-${hex.substring(8, 12)}"
    }

    /** UTF-8 length of a canonical safety number, used only for sanity checks in tests. */
    fun canonicalSafetyBytes(safetyNumber: String): ByteArray =
        RemoteTranscripts.normaliseSafetyNumber(safetyNumber).toByteArray(StandardCharsets.UTF_8)
}
