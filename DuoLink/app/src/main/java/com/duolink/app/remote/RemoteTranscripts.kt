package com.duolink.app.remote

import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.TranscriptBuilder
import java.nio.charset.StandardCharsets

/**
 * Canonical, domain-separated transcripts for Method B remote pairing.
 *
 * ENCODING CONVENTION — the domain string is written **raw** (no length prefix), because
 * `buildTranscript()` in `server/src/protocol.js` does `Buffer.concat([utf8(domain), ...parts])`.
 * Every *data* field after it is length-prefixed. An earlier revision used `.putUtf8(domain)`, which
 * prepends a 4-byte length and made every transcript differ from the server by 4 bytes — the two sides
 * would then sign and derive different values while each looked locally consistent.
 *
 * MIRROR CONTRACT: every constructor here must produce byte-identical output to its counterpart in
 * `DuoLink/server/src/protocol.js`. `RemoteTranscriptParityTest` pins golden hex vectors emitted by
 * the server's `parityVectors()` so a unilateral change on either side fails a test rather than a
 * real pairing attempt.
 *
 * Encoding rules (identical on both sides):
 *  - UTF-8 domain string, then fields in the documented order;
 *  - variable-length fields as `uint32_be(len) || bytes` ([TranscriptBuilder.putBytes]);
 *  - fixed-width fields raw (16-byte deviceIds, 32-byte digests/keys);
 *  - integers big-endian: `putInt32` / `putInt64`.
 *
 * Why length prefixes: without them, `("ab","c")` and `("a","bc")` serialise identically and a
 * signature could be re-bound across field boundaries. Why a domain string: a signature over an ACK
 * transcript must not be interchangeable with a signature over a receipt transcript.
 */
object RemoteTranscripts {

    const val PROTOCOL_VERSION = 1

    const val DOMAIN_ACK = "DUOLINK-REMOTE-ACK-V1"
    const val DOMAIN_RECEIPT = "DUOLINK-REMOTE-RECEIPT-V1"
    const val DOMAIN_COMMIT = "DUOLINK-REMOTE-COMMIT-V1"
    const val DOMAIN_REDEEM = "DUOLINK-REMOTE-REDEEM-V1"
    const val DOMAIN_INVITATION_QR = "DUOLINK-REMOTE-INVITE-QR-V1"

    /** SPK self-signature domain. Shared verbatim with Method A — do not rename. */
    const val DOMAIN_SPK = "DuoLink-SPK-v1"

    /** Role strings are part of signed bytes: an owner ACK can never be replayed as a recipient ACK. */
    object Role {
        const val OWNER = "owner"
        const val RECIPIENT = "recipient"
    }

    /**
     * Persistence-ACK transcript, signed with the sender's identity key `IK_sig`.
     *
     * Binds protocol version, invitation id, role, sender device identity, and the exact pair of
     * commit ciphertext digests. Everything in it is public: the server is able to verify this
     * signature (that is the point of Correction A), while learning nothing secret.
     */
    fun ackTranscript(
        invitationId: String,
        role: String,
        deviceId: ByteArray,
        commitDigestOwner: ByteArray,
        commitDigestRecipient: ByteArray
    ): ByteArray {
        require(role == Role.OWNER || role == Role.RECIPIENT) { "invalid role" }
        require(deviceId.size == 16) { "deviceId must be 16 bytes" }
        require(commitDigestOwner.size == 32 && commitDigestRecipient.size == 32) {
            "commit digests must be 32 bytes"
        }
        return TranscriptBuilder()
            .putRawUtf8(DOMAIN_ACK)
            .putInt32(PROTOCOL_VERSION)
            .putUtf8(invitationId)
            .putUtf8(role)
            .putBytes(deviceId)
            .putBytes(commitDigestOwner)
            .putBytes(commitDigestRecipient)
            .build()
    }

    /**
     * Server receipt transcript: what the server signs to prove it *recorded* an ACK.
     *
     * Security meaning: transport evidence only. It proves the server observed an ACK for these exact
     * digests. It is **not** proof of peer consent and it is never displayed as "pairing complete".
     */
    fun receiptTranscript(
        invitationId: String,
        role: String,
        deviceId: ByteArray,
        commitDigestOwner: ByteArray,
        commitDigestRecipient: ByteArray,
        ackDigest: ByteArray
    ): ByteArray = TranscriptBuilder()
        .putRawUtf8(DOMAIN_RECEIPT)
        .putInt32(PROTOCOL_VERSION)
        .putUtf8(invitationId)
        .putUtf8(role)
        .putBytes(deviceId)
        .putBytes(commitDigestOwner)
        .putBytes(commitDigestRecipient)
        .putBytes(ackDigest)
        .build()

    /**
     * Commit plaintext transcript — **client-only**, never transmitted.
     *
     * This is the authenticated data that binds the commit envelope to the safety number the user
     * just compared, to both device identities, to the pairing root key, and to the ephemeral/public
     * keys used in the three-DH derivation. Because it includes `K_pair_root`, a commit forged by a
     * third party who somehow obtained the invitation id cannot be made to decrypt or verify.
     */
    fun commitPlaintextTranscript(
        invitationId: String,
        role: String,
        deviceId: ByteArray,
        peerDeviceId: ByteArray,
        rootKey: ByteArray,
        ephemeralPublicSpki: ByteArray,
        spkPublicSpki: ByteArray,
        safetyNumber: String,
        issuedAtEpochSec: Long
    ): ByteArray {
        require(role == Role.OWNER || role == Role.RECIPIENT) { "invalid role" }
        require(deviceId.size == 16 && peerDeviceId.size == 16) { "deviceIds must be 16 bytes" }
        require(rootKey.size == 32) { "root key must be 32 bytes" }
        return TranscriptBuilder()
            .putRawUtf8(DOMAIN_COMMIT)
            .putInt32(PROTOCOL_VERSION)
            .putUtf8(invitationId)
            .putUtf8(role)
            .putBytes(deviceId)
            .putBytes(peerDeviceId)
            .putBytes(rootKey)
            .putBytes(ephemeralPublicSpki)
            .putBytes(spkPublicSpki)
            .putUtf8(normaliseSafetyNumber(safetyNumber))
            .putInt64(issuedAtEpochSec)
            .build()
    }

    /**
     * Canonical Signed Pre-Key self-signature transcript.
     *
     * FROZEN CONTRACT — byte-identical to `EcP256Crypto.buildSpkTranscript()` in the Method A crypto
     * layer and to `spkTranscript()` in `DuoLink/server/src/protocol.js`. It deliberately reuses the
     * pre-existing Method A layout (no length prefixes on the numeric fields) so the *unmodified*
     * `PeerTrustStore` decoder can validate a remote peer's SPK. Changing this breaks Method A.
     *
     * Layout: `"DuoLink-SPK-v1" || deviceId(16) || spkId(int32_be) || createdAt(int64_be) ||
     *          uint32_be(len) || spki`
     */
    fun spkTranscript(
        deviceId: ByteArray,
        spkId: Int,
        spkCreatedAtEpochSec: Long,
        spkPublicKeySpki: ByteArray
    ): ByteArray {
        require(deviceId.size == 16) { "deviceId must be 16 bytes" }
        require(spkPublicKeySpki.size == 91) { "SPK must be an uncompressed P-256 SPKI key" }
        // Delegated on purpose: re-implementing the layout here is how the two encodings would drift.
        return EcP256Crypto.buildSpkTranscript(deviceId, spkId, spkPublicKeySpki, spkCreatedAtEpochSec)
    }

    /**
     * Owner-side invitation transcript, signed with `IK_sig`.
     *
     * FROZEN CONTRACT — byte-identical to `invitationTranscript()` in `DuoLink/server/src/protocol.js`,
     * pinned by the cross-language parity test.
     *
     * Decision B: binds the **activation code hash**, never the plaintext activation code. The hash is
     * the SHA-256 of the canonical code — the same value the server stores — so the recipient can
     * re-derive and verify the transcript from the code it was given, while the plaintext code never
     * enters a signature, a log, or the server database.
     *
     * Decision A: also binds the SPK self-signature, so one signature covers both "this identity claims
     * this signed pre-key" and "this invitation belongs to this identity".
     */
    fun invitationTranscript(
        invitationId: String,
        activationCodeHash: ByteArray,
        deviceId: ByteArray,
        spkId: Int,
        spkCreatedAtEpochSec: Long,
        spkSignature: ByteArray,
        identityPublicSpki: ByteArray,
        ackPublicSpki: ByteArray,
        spkPublicSpki: ByteArray,
        ephemeralPublicSpki: ByteArray,
        nonce: ByteArray,
        expiresAtEpochSec: Long
    ): ByteArray {
        require(activationCodeHash.size == 32) { "activation code hash must be 32 bytes" }
        require(deviceId.size == 16) { "deviceId must be 16 bytes" }
        require(nonce.size == NONCE_BYTES) { "nonce must be $NONCE_BYTES bytes" }
        return TranscriptBuilder()
            .putRawUtf8(DOMAIN_INVITATION_QR)
            .putInt32(PROTOCOL_VERSION)
            .putUtf8(invitationId)
            .putBytes(activationCodeHash)
            .putBytes(deviceId)
            .putInt32(spkId)
            .putInt64(spkCreatedAtEpochSec)
            .putBytes(spkSignature)
            .putBytes(identityPublicSpki)
            .putBytes(ackPublicSpki)
            .putBytes(spkPublicSpki)
            .putBytes(ephemeralPublicSpki)
            .putBytes(nonce)
            .putInt64(expiresAtEpochSec)
            .build()
    }

    /**
     * Redemption transcript, signed with the recipient's `IK_sig` and verified by the owner client.
     *
     * FROZEN CONTRACT — byte-identical to `redeemTranscript()` in `server/src/protocol.js`.
     * Binds the invitation id, the recipient's identity, its signed pre-key (plus the SPK
     * self-signature) and its nonce, proving to the owner that the relayed material belongs to the
     * device that redeemed the code. The server can never check this signature.
     */
    fun redeemTranscript(
        invitationId: String,
        deviceId: ByteArray,
        spkId: Int,
        spkCreatedAtEpochSec: Long,
        spkSignature: ByteArray,
        identityPublicSpki: ByteArray,
        ackPublicSpki: ByteArray,
        spkPublicSpki: ByteArray,
        ephemeralPublicSpki: ByteArray,
        nonce: ByteArray
    ): ByteArray {
        require(deviceId.size == 16) { "deviceId must be 16 bytes" }
        require(nonce.size == NONCE_BYTES) { "nonce must be $NONCE_BYTES bytes" }
        return TranscriptBuilder()
            .putRawUtf8(DOMAIN_REDEEM)
            .putInt32(PROTOCOL_VERSION)
            .putUtf8(invitationId)
            .putBytes(deviceId)
            .putInt32(spkId)
            .putInt64(spkCreatedAtEpochSec)
            .putBytes(spkSignature)
            .putBytes(identityPublicSpki)
            .putBytes(ackPublicSpki)
            .putBytes(spkPublicSpki)
            .putBytes(ephemeralPublicSpki)
            .putBytes(nonce)
            .build()
    }

    /**
     * Normalises a 60-digit Safety Number to single-space-separated groups before it enters a signed
     * transcript. Newlines exist only for human readability; a signature must not depend on where a
     * line wraps on a narrow screen.
     */
    fun normaliseSafetyNumber(safetyNumber: String): String =
        safetyNumber.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ")

    /** Nonce length in bytes for both roles (128-bit). */
    const val NONCE_BYTES = 16

    /** Number of digit groups in a full Safety Number (12 groups x 5 digits = 60 digits). */
    const val SAFETY_NUMBER_GROUPS = 12
    const val SAFETY_NUMBER_DIGITS = SAFETY_NUMBER_GROUPS * 5

    fun countDigits(safetyNumber: String): Int = safetyNumber.count { it.isDigit() }

    fun isFullSafetyNumber(safetyNumber: String): Boolean =
        countDigits(safetyNumber) == SAFETY_NUMBER_DIGITS

    /** UTF-8 helper kept public so callers do not re-implement encoding differently. */
    fun utf8(value: String): ByteArray = value.toByteArray(StandardCharsets.UTF_8)
}
