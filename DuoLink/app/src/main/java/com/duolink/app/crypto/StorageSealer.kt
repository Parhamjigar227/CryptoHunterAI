package com.duolink.app.crypto

import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Authenticated local storage sealer (AES-256-GCM with mandatory context AAD).
 * On Android devices, backed by non-exportable AndroidKeyStore AES-256-GCM key.
 */
interface StorageSealer {
    fun seal(plaintext: ByteArray, aad: ByteArray): ByteArray
    fun unseal(sealedBlob: ByteArray, aad: ByteArray): ByteArray
}

object SealedBlobFormat {
    const val FORMAT_VERSION: Byte = 0x01
    const val GCM_IV_BYTES: Int = 12
    const val GCM_TAG_BITS: Int = 128
    const val GCM_TAG_BYTES: Int = GCM_TAG_BITS / 8

    fun pack(iv: ByteArray, ciphertextWithTag: ByteArray): ByteArray {
        require(iv.size == GCM_IV_BYTES) { "Expected $GCM_IV_BYTES-byte GCM IV, got ${iv.size}" }
        require(ciphertextWithTag.size >= GCM_TAG_BYTES) { "Ciphertext shorter than GCM tag" }
        val out = ByteArray(2 + iv.size + ciphertextWithTag.size)
        out[0] = FORMAT_VERSION
        out[1] = iv.size.toByte()
        System.arraycopy(iv, 0, out, 2, iv.size)
        System.arraycopy(ciphertextWithTag, 0, out, 2 + iv.size, ciphertextWithTag.size)
        return out
    }

    fun unpack(sealedBlob: ByteArray): Pair<ByteArray, ByteArray> {
        if (sealedBlob.size < 2 + GCM_IV_BYTES + GCM_TAG_BYTES) {
            throw GeneralSecurityException("Sealed blob truncated or malformed")
        }
        if (sealedBlob[0] != FORMAT_VERSION) {
            throw GeneralSecurityException("Unsupported sealed blob version: ${sealedBlob[0]}")
        }
        val ivLen = sealedBlob[1].toInt() and 0xFF
        if (ivLen != GCM_IV_BYTES || sealedBlob.size < 2 + ivLen + GCM_TAG_BYTES) {
            throw GeneralSecurityException("Invalid GCM IV length in sealed blob: $ivLen")
        }
        val iv = sealedBlob.copyOfRange(2, 2 + ivLen)
        val ciphertext = sealedBlob.copyOfRange(2 + ivLen, sealedBlob.size)
        return iv to ciphertext
    }
}

/**
 * Standard JCA AES-256-GCM sealer with fresh 96-bit CSPRNG IV per encryption.
 */
class JcaAesGcmSealer(
    private val secretKey: SecretKey = generateRandomAes256Key(),
    private val secureRandom: SecureRandom = SecureRandom()
) : StorageSealer {

    override fun seal(plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(aad.isNotEmpty()) { "Associated data (AAD) is mandatory for sealed storage" }
        val iv = ByteArray(SealedBlobFormat.GCM_IV_BYTES).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(SealedBlobFormat.GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext)
        return SealedBlobFormat.pack(iv, ciphertext)
    }

    override fun unseal(sealedBlob: ByteArray, aad: ByteArray): ByteArray {
        require(aad.isNotEmpty()) { "Associated data (AAD) is mandatory for sealed storage" }
        val (iv, ciphertext) = SealedBlobFormat.unpack(sealedBlob)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(SealedBlobFormat.GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    companion object {
        fun generateRandomAes256Key(): SecretKey {
            val kg = KeyGenerator.getInstance("AES")
            kg.init(256, SecureRandom())
            return kg.generateKey()
        }
    }
}
