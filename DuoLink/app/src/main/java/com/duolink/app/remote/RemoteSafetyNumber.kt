package com.duolink.app.remote

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.EcP256Crypto
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale

/**
 * Method B Safety Number: the 60-digit value both users MUST compare in full, out of band, before
 * either device pins the other.
 *
 * Design constraints that differ from the Method A (QR) fingerprint:
 *
 *  - Method A could hash only the two long-term identity keys, because the QR payload was itself the
 *    authenticated channel that proved the ephemeral material.
 *  - Method B receives ephemeral/public material over a *relay* the two users do not control. Hashing
 *    only the identities would therefore leave a relay free to substitute ephemeral keys and mount a
 *    MITM with a "correct-looking" Safety Number. So this value commits to the entire handshake
 *    binding (every public key, both nonces, both device ids, the invitation id) **and** to the DH
 *    shared secret, which only the two real endpoints can compute.
 *
 * Consequence: any relay substitution changes the 60 digits on at least one side, which is exactly
 * the property the manual comparison relies on.
 *
 * Ordering: the two device-facing inputs are canonicalised by sorting on `deviceId`, so both devices
 * produce the same digits without either side having to be told "you are first". This is what makes
 * the comparison meaningful rather than accidentally role-dependent.
 *
 * Iteration: 5,200 SHA-512 rounds, matching the Method A fingerprint's work factor. Iteration is not
 * a substitute for the comparison; it only slows down offline grinding of a *visually similar* pair of
 * digit strings.
 */
object RemoteSafetyNumber {

    private const val VERSION: Short = 1
    private const val ITERATIONS = 5200
    private val DOMAIN = "DuoLink-RemoteSafetyNumber-v1".toByteArray(StandardCharsets.UTF_8)

    /**
     * Computes the Safety Number.
     *
     * @param binding the full public handshake binding the two devices agreed on
     * @param dhSecret the concatenated DH material (same bytes on both sides)
     */
    fun compute(binding: RemoteKeySchedule.HandshakeBinding, dhSecret: ByteArray): String {
        EcP256Crypto.decodeAndValidateP256PublicKey(binding.ownerIdentitySpki)
        EcP256Crypto.decodeAndValidateP256PublicKey(binding.recipientIdentitySpki)

        val ownerBlock = identityBlock(binding.ownerDeviceId, binding.ownerIdentitySpki)
        val recipientBlock = identityBlock(binding.recipientDeviceId, binding.recipientIdentitySpki)
        val cmp = ByteEncoding.compareLexicographically(ownerBlock, recipientBlock)
        require(cmp != 0) { "Cannot compute a Safety Number between identical device identities" }
        val (lowBlock, highBlock) = if (cmp < 0) ownerBlock to recipientBlock else recipientBlock to ownerBlock

        val canonical = TranscriptBuilder()
            .putBytes(DOMAIN)
            .putInt32(VERSION.toInt())
            .putBytes(lowBlock)
            .putBytes(highBlock)
            .putInt32(binding.protocolVersion)
            .putUtf8(binding.invitationId)
            .putBytes(binding.ownerEphemeralSpki)
            .putBytes(binding.recipientEphemeralSpki)
            .putBytes(binding.ownerSpkSpki)
            .putBytes(binding.recipientSpkSpki)
            .putBytes(binding.ownerNonce)
            .putBytes(binding.recipientNonce)
            .putBytes(binding.recipientIdentitySignature)
            .putBytes(dhSecret)
            .build()

        val digest = MessageDigest.getInstance("SHA-512")
        var current = canonical
        repeat(ITERATIONS) {
            digest.reset()
            digest.update(current)
            digest.update(canonical)
            current = digest.digest()
        }

        val groups = ArrayList<String>(RemoteTranscripts.SAFETY_NUMBER_GROUPS)
        for (index in 0 until RemoteTranscripts.SAFETY_NUMBER_GROUPS) {
            val offset = index * 5
            val chunk =
                ((current[offset].toLong() and 0xFFL) shl 32) or
                    ((current[offset + 1].toLong() and 0xFFL) shl 24) or
                    ((current[offset + 2].toLong() and 0xFFL) shl 16) or
                    ((current[offset + 3].toLong() and 0xFFL) shl 8) or
                    (current[offset + 4].toLong() and 0xFFL)
            groups.add(String.format(Locale.US, "%05d", chunk % 100_000L))
        }

        // Visual layout only: four rows of three groups. The signed/compared value is the digit
        // sequence; layout never enters a transcript.
        return buildString(76) {
            for (i in groups.indices) {
                append(groups[i])
                when {
                    i == RemoteTranscripts.SAFETY_NUMBER_GROUPS - 1 -> {}
                    (i + 1) % 3 == 0 -> append('\n')
                    else -> append(' ')
                }
            }
        }
    }

    /**
     * Splits a displayed Safety Number into its digit groups, for the "compare group by group" UI.
     * Returns an empty list if the input does not contain exactly 60 digits, so a truncated display can
     * never be confirmed by accident.
     */
    fun digitGroups(safetyNumber: String): List<String> {
        if (!RemoteTranscripts.isFullSafetyNumber(safetyNumber)) return emptyList()
        val digits = safetyNumber.filter { it.isDigit() }
        return (0 until RemoteTranscripts.SAFETY_NUMBER_GROUPS).map { index ->
            digits.substring(index * 5, (index + 1) * 5)
        }
    }

    /** Row-oriented layout used by the comparison screen (three groups per row). */
    fun digitRows(safetyNumber: String): List<List<String>> =
        digitGroups(safetyNumber).chunked(3)

    private fun identityBlock(deviceId: ByteArray, identitySpki: ByteArray): ByteArray =
        TranscriptBuilder().putBytes(deviceId).putBytes(identitySpki).build()
}
