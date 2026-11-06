package com.duolink.app.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Exact protection tier of an individual cryptographic key on the device.
 *
 * Security accuracy rules:
 * - [STRONGBOX_HARDWARE] and [TEE_HARDWARE] are genuinely hardware-backed (`AndroidKeyStore` + secure hardware).
 * - [ANDROID_KEYSTORE_OS_SOFTWARE] resides inside `AndroidKeyStore` (`encoded == null`, OS daemon isolation),
 *   but the device lacks hardware-backed Keymaster/KeyMint (`isInsideSecureHardware == false`).
 * - [SOFTWARE_WRAPPED_AT_REST] means the private key was generated in app JVM heap memory, encrypted at rest
 *   under an AES-256-GCM wrapping key (`MSK`), and decrypted transiently in heap memory during cryptographic
 *   use (e.g., `SPK_dh` ECDH on Android API 26–30). It is NEITHER hardware-backed NOR non-exportable from RAM.
 * - [JVM_TEST_SOFTWARE] is used strictly by JVM unit tests outside Android.
 */
enum class KeyProtectionTier {
    STRONGBOX_HARDWARE,
    TEE_HARDWARE,
    ANDROID_KEYSTORE_OS_SOFTWARE,
    SOFTWARE_WRAPPED_AT_REST,
    JVM_TEST_SOFTWARE;

    val isHardwareBacked: Boolean
        get() = this == STRONGBOX_HARDWARE || this == TEE_HARDWARE

    val isKeystoreNonExportable: Boolean
        get() = this == STRONGBOX_HARDWARE ||
            this == TEE_HARDWARE ||
            this == ANDROID_KEYSTORE_OS_SOFTWARE
}

/**
 * Protection report for one specific cryptographic key.
 */
data class SingleKeyProtectionStatus(
    val keyRolePersian: String,
    val algorithm: String,
    val tier: KeyProtectionTier,
    val persianDescription: String
) {
    val isHardwareBacked: Boolean get() = tier.isHardwareBacked
    val isKeystoreNonExportable: Boolean get() = tier.isKeystoreNonExportable
}

/**
 * Separate, per-key protection report covering all three device keys:
 * 1. [identitySigningKey] (`IK_sig`, ECDSA P-256)
 * 2. [storageWrappingKey] (`MSK`, AES-256-GCM)
 * 3. [activeSignedPreKey] (`SPK_dh`, ECDH P-256)
 */
data class KeyProtectionReport(
    val identitySigningKey: SingleKeyProtectionStatus,
    val storageWrappingKey: SingleKeyProtectionStatus,
    val activeSignedPreKey: SingleKeyProtectionStatus
)

/**
 * Authenticated local envelope encryption (`AES-256-GCM`) used to protect:
 * 1. The paired peer's pinned trust record, historical identity archive, and replay ledger at rest.
 * 2. Software-generated ECDH Signed Pre-Keys (`SPK_dh`) at rest on Android 8.0–11 (API 26–30) or when
 *    KeyMint hardware ECDH is unavailable on API 31+.
 *
 * Wire format of a sealed blob:
 * `[version = 0x01 (1 byte)] || [ivLength (1 byte)] || [iv (ivLength bytes)] || [ciphertext + 128-bit GCM tag]`
 */
interface StorageSealer {
    fun seal(plaintext: ByteArray, associatedData: ByteArray): ByteArray
    fun unseal(sealedBlob: ByteArray, associatedData: ByteArray): ByteArray
    fun queryProtectionStatus(): SingleKeyProtectionStatus
}

/**
 * Pure JCA `AES-256-GCM` implementation backed by an in-memory 256-bit key for deterministic JVM unit tests.
 * Production Android runtime uses `AndroidKeystoreSealer` (`AndroidKeyStore` AES-256-GCM key).
 */
class JcaAesGcmSealer(
    rawKeyBytes: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) },
    private val secureRandom: SecureRandom = SecureRandom()
) : StorageSealer {

    private val secretKey: SecretKeySpec

    init {
        require(rawKeyBytes.size == 32) { "AES-256 key must be 32 bytes" }
        secretKey = SecretKeySpec(rawKeyBytes.copyOf(), "AES")
    }

    override fun seal(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        val iv = ByteArray(GCM_IV_BYTES)
        secureRandom.nextBytes(iv)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        if (associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData)
        }
        val ciphertextAndTag = cipher.doFinal(plaintext)
        return encodeSealedEnvelope(iv, ciphertextAndTag)
    }

    override fun unseal(sealedBlob: ByteArray, associatedData: ByteArray): ByteArray {
        val (iv, ciphertextAndTag) = decodeSealedEnvelope(sealedBlob)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        if (associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData)
        }
        return cipher.doFinal(ciphertextAndTag)
    }

    override fun queryProtectionStatus(): SingleKeyProtectionStatus {
        return SingleKeyProtectionStatus(
            keyRolePersian = "کلید پوششی ذخیره‌سازی محلی (MSK)",
            algorithm = "AES-256-GCM",
            tier = KeyProtectionTier.JVM_TEST_SOFTWARE,
            persianDescription = "محیط تست JVM (کلید AES-256 در حافظه آزمایشی؛ غیرسخت‌افزاری)"
        )
    }

    companion object {
        const val ENVELOPE_VERSION: Byte = 0x01
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
        const val TRANSFORMATION = "AES/GCM/NoPadding"

        fun encodeSealedEnvelope(iv: ByteArray, ciphertextAndTag: ByteArray): ByteArray {
            require(iv.size in 12..16) { "Unexpected GCM IV length: ${iv.size}" }
            val out = ByteArray(2 + iv.size + ciphertextAndTag.size)
            out[0] = ENVELOPE_VERSION
            out[1] = iv.size.toByte()
            System.arraycopy(iv, 0, out, 2, iv.size)
            System.arraycopy(ciphertextAndTag, 0, out, 2 + iv.size, ciphertextAndTag.size)
            return out
        }

        fun decodeSealedEnvelope(sealedBlob: ByteArray): Pair<ByteArray, ByteArray> {
            require(sealedBlob.size >= 2 + GCM_IV_BYTES + (GCM_TAG_BITS / 8)) {
                "Sealed envelope too short (${sealedBlob.size} bytes)"
            }
            val version = sealedBlob[0]
            require(version == ENVELOPE_VERSION) { "Unsupported sealed envelope version: $version" }
            val ivLen = sealedBlob[1].toInt() and 0xFF
            require(ivLen in 12..16) { "Invalid IV length in sealed envelope: $ivLen" }
            require(sealedBlob.size >= 2 + ivLen + (GCM_TAG_BITS / 8)) {
                "Truncated sealed envelope payload"
            }
            val iv = sealedBlob.copyOfRange(2, 2 + ivLen)
            val ciphertextAndTag = sealedBlob.copyOfRange(2 + ivLen, sealedBlob.size)
            return iv to ciphertextAndTag
        }
    }
}
