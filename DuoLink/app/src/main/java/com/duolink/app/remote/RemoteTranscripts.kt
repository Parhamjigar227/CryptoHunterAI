package com.duolink.app.remote

import com.duolink.app.crypto.TranscriptBuilder
import java.nio.charset.StandardCharsets

/**
 * Canonical, domain-separated transcripts for Method B remote pairing.
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
            .putUtf8(DOMAIN_ACK)
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
        .putUtf8(DOMAIN_RECEIPT)
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
            .putUtf8(DOMAIN_COMMIT)
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
     * Redemption transcript, signed with `IK_sig` and sent inside the redeem request.
     *
     * Purpose: prove to the *peer* (not to the server, which cannot check it) that the device that
     * redeemed the code holds the identity key it claims. The signature is verified by the owner
     * client once the server relays the recipient's public material.
     */
    fun redeemTranscript(
        invitationId: String,
        deviceId: ByteArray,
        identityPublicSpki: ByteArray,
        ackPublicSpki: ByteArray,
        spkPublicSpki: ByteArray,
        ephemeralPublicSpki: ByteArray
    ): ByteArray = TranscriptBuilder()
        .putUtf8(DOMAIN_REDEEM)
        .putInt32(PROTOCOL_VERSION)
        .putUtf8(invitationId)
        .putBytes(deviceId)
        .putBytes(identityPublicSpki)
        .putBytes(ackPublicSpki)
        .putBytes(spkPublicSpki)
        .putBytes(ephemeralPublicSpki)
        .build()

    /** Owner-side invitation QR transcript: binds the activation code to the owner's public material. */
    fun invitationQrTranscript(
        invitationId: String,
        activationCodeCompact: String,
        deviceId: ByteArray,
        identityPublicSpki: ByteArray,
        ackPublicSpki: ByteArray,
        spkPublicSpki: ByteArray,
        ephemeralPublicSpki: ByteArray,
        expiresAtEpochSec: Long
    ): ByteArray = TranscriptBuilder()
        .putUtf8(DOMAIN_INVITATION_QR)
        .putInt32(PROTOCOL_VERSION)
        .putUtf8(invitationId)
        .putUtf8(activationCodeCompact)
        .putBytes(deviceId)
        .putBytes(identityPublicSpki)
        .putBytes(ackPublicSpki)
        .putBytes(spkPublicSpki)
        .putBytes(ephemeralPublicSpki)
        .putInt64(expiresAtEpochSec)
        .build()

    /**
     * Normalises a 60-digit Safety Number to single-space-separated groups before it enters a signed
     * transcript. Newlines exist only for human readability; a signature must not depend on where a
     * line wraps on a narrow screen.
     */
    fun normaliseSafetyNumber(safetyNumber: String): String =
        safetyNumber.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ")

    /** Number of digit groups in a full Safety Number (12 groups x 5 digits = 60 digits). */
    const val SAFETY_NUMBER_GROUPS = 12
    const val SAFETY_NUMBER_DIGITS = SAFETY_NUMBER_GROUPS * 5

    fun countDigits(safetyNumber: String): Int = safetyNumber.count { it.isDigit() }

    fun isFullSafetyNumber(safetyNumber: String): Boolean =
        countDigits(safetyNumber) == SAFETY_NUMBER_DIGITS

    /** UTF-8 helper kept public so callers do not re-implement encoding differently. */
    fun utf8(value: String): ByteArray = value.toByteArray(StandardCharsets.UTF_8)
}
