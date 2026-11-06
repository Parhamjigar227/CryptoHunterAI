package com.duolink.app.crypto

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Computes canonical, role-symmetric 60-digit Safety Numbers (12 groups of 5 digits)
 * using 5,200 rounds of iterated SHA-512 over canonically ordered peer identities,
 * plus a handshake-specific Session Verification Code.
 */
object SafetyFingerprint {
    private const val ITERATIONS = 5200
    private val VERSION_TAG = "DUOLINK-SAFETY-NUMBER-V1".toByteArray(StandardCharsets.UTF_8)

    /**
     * Computes the 60-digit Safety Number formatted as 12 space-separated 5-digit groups.
     * Output is strictly identical on Device A and Device B regardless of initiator/responder role.
     */
    fun computeSafetyNumber(
        localDeviceId: String,
        localIkSpki: ByteArray,
        peerDeviceId: String,
        peerIkSpki: ByteArray
    ): String {
        require(localDeviceId != peerDeviceId) { "Cannot compute safety number with identical device IDs" }
        EcP256Crypto.validateAndParsePublicKey(localIkSpki)
        EcP256Crypto.validateAndParsePublicKey(peerIkSpki)
        require(EcP256Crypto.computeDeviceId(localIkSpki) == localDeviceId) { "Local deviceId mismatch" }
        require(EcP256Crypto.computeDeviceId(peerIkSpki) == peerDeviceId) { "Peer deviceId mismatch" }

        val firstPart = computeHalfDigest(localDeviceId, localIkSpki)
        val secondPart = computeHalfDigest(peerDeviceId, peerIkSpki)

        return if (localDeviceId < peerDeviceId) {
            "$firstPart $secondPart"
        } else {
            "$secondPart $firstPart"
        }
    }

    /**
     * Computes a human-readable 30-digit half-fingerprint (6 groups of 5 digits) for one identity
     * using 5,200 rounds of SHA-512. Concatenating the two sorted halves yields 60 digits (12 groups).
     */
    fun computeSingleIdentityDigits(deviceId: String, ikSpki: ByteArray): String {
        EcP256Crypto.validateAndParsePublicKey(ikSpki)
        require(EcP256Crypto.computeDeviceId(ikSpki) == deviceId) { "deviceId mismatch" }
        return computeHalfDigest(deviceId, ikSpki)
    }

    private fun computeHalfDigest(deviceId: String, ikSpki: ByteArray): String {
        val seed = TranscriptBuilder()
            .putBytes(VERSION_TAG)
            .putUtf8(deviceId)
            .putBytes(ikSpki)
            .build()

        val sha512 = MessageDigest.getInstance("SHA-512")
        var current = seed
        repeat(ITERATIONS) {
            sha512.reset()
            sha512.update(current)
            sha512.update(ikSpki)
            current = sha512.digest()
        }

        // Extract 6 chunks of 5 bytes (uint40 mod 100000) -> 6 groups of 5 decimal digits = 30 digits
        val groups = ArrayList<String>(6)
        for (chunkIdx in 0 until 6) {
            val off = chunkIdx * 5
            var value = 0L
            for (b in 0 until 5) {
                value = (value shl 8) or (current[off + b].toLong() and 0xFFL)
            }
            val fiveDigits = (value % 100_000L).toString().padStart(5, '0')
            groups.add(fiveDigits)
        }
        return groups.joinToString(" ")
    }

    /**
     * Computes a 12-hex-character (XXXX-XXXX-XXXX) session verification code binding the specific
     * QR Offer + Accept handshake nonces and transcript digest.
     */
    fun computeSessionVerificationCode(
        sessionId: String,
        offerDigest: ByteArray,
        offerNonce: ByteArray,
        acceptNonce: ByteArray
    ): String {
        val transcript = TranscriptBuilder()
            .putUtf8("DUOLINK-SESSION-SAS-V1")
            .putUtf8(sessionId)
            .putBytes(offerDigest)
            .putBytes(offerNonce)
            .putBytes(acceptNonce)
            .build()
        val hash = ByteEncoding.sha256(transcript)
        val hex = ByteEncoding.toHexLower(hash.copyOfRange(0, 6)).uppercase()
        return "${hex.substring(0, 4)}-${hex.substring(4, 8)}-${hex.substring(8, 12)}"
    }

    /**
     * Formats 60-digit safety number into 3 lines of 4 groups for clean Persian/LTR display.
     */
    fun formatMultiline(safetyNumber: String): String {
        val parts = safetyNumber.trim().split(Regex("\\s+"))
        if (parts.size != 12) return safetyNumber
        return buildString {
            append(parts.subList(0, 4).joinToString("  "))
            append('\n')
            append(parts.subList(4, 8).joinToString("  "))
            append('\n')
            append(parts.subList(8, 12).joinToString("  "))
        }
    }
}
