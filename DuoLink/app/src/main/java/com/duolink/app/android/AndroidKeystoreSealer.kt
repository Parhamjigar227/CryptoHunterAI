package com.duolink.app.android

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.duolink.app.crypto.JcaAesGcmSealer
import com.duolink.app.crypto.KeyProtectionTier
import com.duolink.app.crypto.SingleKeyProtectionStatus
import com.duolink.app.crypto.StorageSealer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Production Android `AES-256-GCM` envelope sealer backed by `AndroidKeyStore`.
 *
 * Security properties:
 * - Key material is managed by `AndroidKeyStore` (`encoded == null`).
 * - Hardware backing (StrongBox / TEE) vs OS-software Keystore is queried dynamically via [KeyInfo]
 *   and reported truthfully in [queryProtectionStatus].
 * - Randomized 96-bit IVs are enforced by `AndroidKeyStore` (`setRandomizedEncryptionRequired(true)`).
 */
class AndroidKeystoreSealer(
    private val keyAlias: String = DEFAULT_MASTER_KEY_ALIAS
) : StorageSealer {

    override fun seal(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(JcaAesGcmSealer.TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        if (associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData)
        }
        val ciphertextAndTag = cipher.doFinal(plaintext)
        val iv = cipher.iv ?: error("AndroidKeyStore AES-GCM cipher did not emit an IV")
        return JcaAesGcmSealer.encodeSealedEnvelope(iv, ciphertextAndTag)
    }

    override fun unseal(sealedBlob: ByteArray, associatedData: ByteArray): ByteArray {
        val (iv, ciphertextAndTag) = JcaAesGcmSealer.decodeSealedEnvelope(sealedBlob)
        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(JcaAesGcmSealer.TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            secretKey,
            GCMParameterSpec(JcaAesGcmSealer.GCM_TAG_BITS, iv)
        )
        if (associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData)
        }
        return cipher.doFinal(ciphertextAndTag)
    }

    override fun queryProtectionStatus(): SingleKeyProtectionStatus {
        val secretKey = getOrCreateSecretKey()
        val tier = try {
            val skf = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            val keyInfo = skf.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo
            classifyKeystoreKeyInfo(keyInfo)
        } catch (_: Exception) {
            KeyProtectionTier.ANDROID_KEYSTORE_OS_SOFTWARE
        }
        return SingleKeyProtectionStatus(
            keyRolePersian = "کلید پوششی ذخیره‌سازی محلی (MSK)",
            algorithm = "AES-256-GCM",
            tier = tier,
            persianDescription = describeKeystoreTierPersian(tier)
        )
    }

    /**
     * Deletes the Keystore AES key (used strictly by isolated instrumentation test cleanup).
     */
    internal fun deleteKeyForTesting() {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (ks.containsAlias(keyAlias)) {
            ks.deleteEntry(keyAlias)
        }
    }

    @Synchronized
    private fun getOrCreateSecretKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val existing = ks.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry
        if (existing != null) {
            return existing.secretKey
        }
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        )
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    companion object {
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val DEFAULT_MASTER_KEY_ALIAS = "duolink_msk_aes256_v1"

        internal fun classifyKeystoreKeyInfo(keyInfo: KeyInfo): KeyProtectionTier {
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyProtectionTier.STRONGBOX_HARDWARE
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                    KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> KeyProtectionTier.TEE_HARDWARE
                    else -> KeyProtectionTier.ANDROID_KEYSTORE_OS_SOFTWARE
                }
            } else {
                @Suppress("DEPRECATION")
                if (keyInfo.isInsideSecureHardware) {
                    KeyProtectionTier.TEE_HARDWARE
                } else {
                    KeyProtectionTier.ANDROID_KEYSTORE_OS_SOFTWARE
                }
            }
        }

        internal fun describeKeystoreTierPersian(tier: KeyProtectionTier): String {
            return when (tier) {
                KeyProtectionTier.STRONGBOX_HARDWARE ->
                    "سخت‌افزار امن ایزوله StrongBox (غیرقابل استخراج در Android Keystore)"
                KeyProtectionTier.TEE_HARDWARE ->
                    "محیط امن سخت‌افزاری TEE (غیرقابل استخراج در Android Keystore)"
                KeyProtectionTier.ANDROID_KEYSTORE_OS_SOFTWARE ->
                    "سرویس Android Keystore سیستم‌عامل (غیرقابل استخراج از فرایند، اما فاقد سخت‌افزار امن اختصاصی روی این دستگاه)"
                KeyProtectionTier.SOFTWARE_WRAPPED_AT_REST ->
                    "نرم‌افزاری (تولیدشده در برنامه و رمزنگاری‌شده در حافظه با کلید AES-256-GCM؛ غیرسخت‌افزاری و موقتاً در RAM هنگام ECDH)"
                KeyProtectionTier.JVM_TEST_SOFTWARE ->
                    "محیط تست نرم‌افزاری JVM"
            }
        }
    }
}
