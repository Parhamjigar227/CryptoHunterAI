package com.duolink.app.crypto

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Symmetric, order-independent 60-digit Safety Number generator modeled on Signal's numeric
 * fingerprint scheme (`SHA-512` iterated 5,200 rounds over sorted canonical identity records).
 *
 * Security role distinction (CRITICAL):
 * - [computeSafetyNumber] produces the **60-digit (12 × 5-digit) Safety Number** over both peers'
 *   long-term `IK_sig` public keys and `deviceId`s. Both users MUST compare the **entire 60-digit
 *   Safety Number** through an independent trusted out-of-band channel (in person or direct trusted
 *   voice call) before confirming pairing to defeat active MITM / QR substitution attacks.
 * - [computePublicHandshakeTranscriptId] produces a **12-hex-character public diagnostic identifier**
 *   derived strictly from public QR handshake fields (`sessionId`, `offerDigest`, `offerNonce`,
 *   `acceptNonce`). It is **NOT** a secret authentication token and **MUST NEVER** replace comparing
 *   the complete 60-digit Safety Number.
 */
object SafetyFingerprint {
    private const val VERSION: Short = 1
    private const val ITERATIONS = 5200
    private val DOMAIN_PREFIX = "DuoLink-SafetyNumber-v1".toByteArray(StandardCharsets.UTF_8)

    fun computeSafetyNumber(
        localDeviceId: ByteArray,
        localIdentityPublicKeySpki: ByteArray,
        peerDeviceId: ByteArray,
        peerIdentityPublicKeySpki: ByteArray
    ): String {
        require(localDeviceId.size == 16 && peerDeviceId.size == 16) {
            "Both deviceIds must be 16 bytes"
        }
        EcP256Crypto.decodeAndValidateP256PublicKey(localIdentityPublicKeySpki)
        EcP256Crypto.decodeAndValidateP256PublicKey(peerIdentityPublicKeySpki)

        val firstBlock = buildIdentityBlock(localDeviceId, localIdentityPublicKeySpki)
        val secondBlock = buildIdentityBlock(peerDeviceId, peerIdentityPublicKeySpki)

        val cmp = ByteEncoding.compareLexicographically(firstBlock, secondBlock)
        require(cmp != 0) { "Cannot compute safety number between identical device identities" }

        val (lowBlock, highBlock) = if (cmp < 0) {
            firstBlock to secondBlock
        } else {
            secondBlock to firstBlock
        }

        val canonicalPair = ByteArray(DOMAIN_PREFIX.size + 2 + lowBlock.size + highBlock.size)
        val headerBuf = ByteBuffer.wrap(canonicalPair)
        headerBuf.put(DOMAIN_PREFIX)
        headerBuf.putShort(VERSION)
        headerBuf.put(lowBlock)
        headerBuf.put(highBlock)

        val sha512 = MessageDigest.getInstance("SHA-512")
        var current = canonicalPair
        repeat(ITERATIONS) {
            sha512.reset()
            sha512.update(current)
            sha512.update(canonicalPair)
            current = sha512.digest()
        }

        val groups = ArrayList<String>(12)
        for (groupIndex in 0 until 12) {
            val offset = groupIndex * 5
            val chunkValue =
                ((current[offset].toLong() and 0xFFL) shl 32) or
                    ((current[offset + 1].toLong() and 0xFFL) shl 24) or
                    ((current[offset + 2].toLong() and 0xFFL) shl 16) or
                    ((current[offset + 3].toLong() and 0xFFL) shl 8) or
                    (current[offset + 4].toLong() and 0xFFL)
            val fiveDigits = (chunkValue % 100_000L).toInt()
            groups.add(String.format(java.util.Locale.US, "%05d", fiveDigits))
        }

        return buildString(75) {
            for (i in groups.indices) {
                append(groups[i])
                when {
                    i == 11 -> {}
                    (i + 1) % 4 == 0 -> append('\n')
                    else -> append(' ')
                }
            }
        }
    }

    /**
     * Public, non-secret 12-hex-character handshake diagnostic ID (`XXXX-XXXX-XXXX`) derived from
     * public QR handshake fields (`sessionId`, `offerDigest`, `offerNonce`, `acceptNonce`).
     *
     * WARNING: Because all inputs appear in QR payloads, an active MITM relaying modified QRs can
     * observe public fields; this identifier exists solely to help users spot stale/mismatched QR
     * scans and MUST NOT be used as a security verification substitute for [computeSafetyNumber].
     */
    fun computePublicHandshakeTranscriptId(
        sessionId: ByteArray,
        offerDigest: ByteArray,
        offerNonce: ByteArray,
        acceptNonce: ByteArray
    ): String {
        val sha256 = MessageDigest.getInstance("SHA-256")
        sha256.update("DuoLink-PublicTranscriptId-v1".toByteArray(StandardCharsets.UTF_8))
        sha256.update(sessionId)
        sha256.update(offerDigest)
        sha256.update(offerNonce)
        sha256.update(acceptNonce)
        val digest = sha256.digest()
        val hex = ByteEncoding.toHexUpper(digest.copyOfRange(0, 6))
        return "${hex.substring(0, 4)}-${hex.substring(4, 8)}-${hex.substring(8, 12)}"
    }

    private fun buildIdentityBlock(deviceId: ByteArray, publicKeySpki: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(16 + 4 + publicKeySpki.size)
        buf.put(deviceId)
        buf.putInt(publicKeySpki.size)
        buf.put(publicKeySpki)
        return buf.array()
    }
}
