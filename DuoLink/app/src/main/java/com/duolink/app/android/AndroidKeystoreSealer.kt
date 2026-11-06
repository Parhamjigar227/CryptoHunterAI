package com.duolink.app.android

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.duolink.app.crypto.SealedBlobFormat
import com.duolink.app.crypto.StorageSealer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed AndroidKeyStore AES-256-GCM sealer.
 * Private/secret key bytes never leave Android Keystore (TEE / StrongBox).
 */
class AndroidKeystoreSealer(
    private val appContext: Context,
    private val keyAlias: String = DEFAULT_MASTER_KEY_ALIAS
) : StorageSealer {

    @Synchronized
    override fun seal(plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(aad.isNotEmpty()) { "AAD is required for AndroidKeyStore AES-GCM sealing" }
        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // AndroidKeyStore enforces hardware-generated random 12-byte IV when initialized without IV spec
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext)
        val iv = cipher.iv ?: throw IllegalStateException("AndroidKeyStore cipher returned null IV")
        return SealedBlobFormat.pack(iv, ciphertext)
    }

    @Synchronized
    override fun unseal(sealedBlob: ByteArray, aad: ByteArray): ByteArray {
        require(aad.isNotEmpty()) { "AAD is required for AndroidKeyStore AES-GCM unsealing" }
        val (iv, ciphertext) = SealedBlobFormat.unpack(sealedBlob)
        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            secretKey,
            GCMParameterSpec(SealedBlobFormat.GCM_TAG_BITS, iv)
        )
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    private fun getOrCreateSecretKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = ks.getKey(keyAlias, null) as? SecretKey
        if (existing != null) return existing

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        ) {
            try {
                return generateAesKey(useStrongBox = true)
            } catch (_: Exception) {
                // Fall back cleanly to standard TEE / Keystore if StrongBox rejects AES-256-GCM
            }
        }
        return generateAesKey(useStrongBox = false)
    }

    private fun generateAesKey(useStrongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)

        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        kg.init(builder.build())
        return kg.generateKey()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val DEFAULT_MASTER_KEY_ALIAS = "duolink_master_wrap_v1"
    }
}
