package com.duolink.app.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

/**
 * Standard IETF RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF-SHA256).
 * Uses standard JCA HmacSHA256 — no custom cryptographic algorithms.
 */
object HkdfSha256 {
    private const val HMAC_ALG = "HmacSHA256"
    private const val HASH_LEN = 32
    private const val MAX_OUTPUT_LEN = 255 * HASH_LEN

    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        require(ikm.isNotEmpty()) { "IKM must not be empty" }
        val effectiveSalt = if (salt == null || salt.isEmpty()) ByteArray(HASH_LEN) else salt
        val mac = Mac.getInstance(HMAC_ALG)
        mac.init(SecretKeySpec(effectiveSalt, HMAC_ALG))
        return mac.doFinal(ikm)
    }

    fun expand(prk: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
        require(prk.size >= HASH_LEN) { "PRK must be at least $HASH_LEN bytes" }
        require(outputLength in 1..MAX_OUTPUT_LEN) { "Invalid HKDF output length: $outputLength" }

        val mac = Mac.getInstance(HMAC_ALG)
        mac.init(SecretKeySpec(prk, HMAC_ALG))

        val okm = ByteArray(outputLength)
        var previousBlock = ByteArray(0)
        var offset = 0
        var counter = 1

        try {
            while (offset < outputLength) {
                mac.reset()
                mac.update(previousBlock)
                mac.update(info)
                mac.update(counter.toByte())
                val nextBlock = mac.doFinal()
                previousBlock.zeroize()
                previousBlock = nextBlock

                val toCopy = min(HASH_LEN, outputLength - offset)
                System.arraycopy(previousBlock, 0, okm, offset, toCopy)
                offset += toCopy
                counter++
            }
            return okm
        } finally {
            previousBlock.zeroize()
        }
    }

    fun deriveKey(ikm: ByteArray, salt: ByteArray?, info: ByteArray, outputLength: Int): ByteArray {
        val prk = extract(salt, ikm)
        return try {
            expand(prk, info, outputLength)
        } finally {
            prk.zeroize()
        }
    }
}
