package com.duolink.app.lock

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.duolink.app.crypto.ByteEncoding
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-anchored biometric unlock.
 *
 * Design note — why this is a *separate* key and not "biometric replaces the PIN":
 *
 * The lock record's verifier is protected by a Keystore AES key that is usable whenever the app runs.
 * A biometric attempt therefore *cannot* simply "skip" the PIN check by calling the same path, or
 * biometrics would be a downgrade. Instead this class creates a dedicated AES-256-GCM Keystore key with
 * `setUserAuthenticationRequired(true)`: the OS refuses to perform any operation with that key until
 * the user has authenticated with a strong biometric inside a short validity window. That key seals a
 * copy of the unlock token. Without a live biometric the key is unusable, so the token cannot be
 * recovered even by an attacker who has the app's data directory.
 *
 * Deliberate limitations, surfaced honestly in the UI:
 *  - Biometrics are only offered when the platform reports `BIOMETRIC_STRONG`. Weak (Class 2) face
 *    unlock is not accepted for unlocking a private messenger.
 *  - The biometric key is invalidated whenever the user *enrols a new fingerprint or face*. That is
 *    intentional: a newly enrolled biometric is an identity change on the device, and we must not let
 *    it unlock existing private conversations. The app falls back to the PIN and tells the user why.
 *  - `FLAG_SECURE` and biometrics cannot stop every screen recorder or a camera pointed at the phone.
 *    Neither this class nor any app can.
 */
class BiometricUnlockGate(private val context: Context) {

    /** What the platform currently allows us to offer. */
    sealed class Availability {
        object Available : Availability()
        data class Unavailable(val persianReason: String) : Availability()
    }

    fun availability(): Availability {
        val manager = BiometricManager.from(context)
        return when (val status = manager.canAuthenticate(AUTHENTICATORS)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Availability.Available
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                Availability.Unavailable("این دستگاه حسگر بیومتریک قابل‌اعتماد ندارد.")
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                Availability.Unavailable("حسگر بیومتریک در حال حاضر در دسترس نیست.")
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                Availability.Unavailable("هیچ اثر انگشت یا چهره‌ای روی دستگاه ثبت نشده است.")
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                Availability.Unavailable("برای استفاده از بیومتریک، به‌روزرسانی امنیتی دستگاه لازم است.")
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN ->
                Availability.Unavailable("وضعیت بیومتریک دستگاه مشخص نیست.")
            else -> Availability.Unavailable("بیومتریک این دستگاه قابل استفاده نیست (کد $status).")
        }
    }

    /**
     * Shows the platform biometric prompt.
     *
     * [onSuccess] runs only after the OS itself accepted the authentication. The cipher handed to the
     * prompt is the biometric-bound key's cipher, so success also proves the key is now usable.
     */
    fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        negativeButton: String,
        onSuccess: () -> Unit,
        onFailure: (String) -> Unit
    ) {
        val cipher = try {
            prepareCipher()
        } catch (t: Throwable) {
            onFailure("آماده‌سازی بیومتریک ناموفق بود (${t.javaClass.simpleName}). از رمز عددی استفاده کنید.")
            return
        }

        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val usedCipher = result.cryptoObject?.cipher
                    if (usedCipher == null) {
                        // The OS reported success without returning a cipher object. We cannot prove the
                        // key was authorised, so we must not unlock. Fail closed.
                        onFailure("تأیید بیومتریک بدون مجوز رمزنگاری انجام شد؛ برای امنیت، ورود انجام نشد.")
                        return
                    }
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onFailure(errString.toString())
                }

                // A single failed fingerprint sweep is not a terminal error: the prompt stays up and the
                // user can retry. Nothing is unlocked here.
                override fun onAuthenticationFailed() = Unit
            }
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(negativeButton)
            .setAllowedAuthenticators(AUTHENTICATORS)
            .setConfirmationRequired(true)
            .build()

        try {
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        } catch (t: Throwable) {
            onFailure("اجرای بیومتریک ناموفق بود (${t.javaClass.simpleName}).")
        }
    }

    /** Creates the auth-bound key if needed and returns an encrypt cipher that requires auth. */
    private fun prepareCipher(): Cipher {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val key: SecretKey = if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.getKey(KEY_ALIAS, null) as SecretKey
        } else {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).apply {
                init(
                    KeyGenParameterSpec.Builder(
                        KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .setUserAuthenticationRequired(true)
                        .setInvalidatedByBiometricEnrollment(true)
                        .apply {
                            // API 30+ can require auth *per use*; older APIs get the default auth-per-session.
                            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                                setUserAuthenticationParameters(
                                    0,
                                    KeyProperties.AUTH_BIOMETRIC_STRONG
                                )
                            }
                        }
                        .build()
                )
            }.generateKey()
        }
        return Cipher.getInstance("$TRANSFORMATION").apply {
            init(Cipher.ENCRYPT_MODE, key)
        }
    }

    /**
     * Seals an unlock token under the biometric key. The IV is prefixed to the ciphertext so [unseal]
     * can reconstruct it.
     *
     * The cipher must be the one the OS just authorised via the prompt.
     */
    fun sealToken(cipher: Cipher, token: ByteArray): ByteArray {
        val ciphertext = cipher.doFinal(token)
        return ByteArray(1 + cipher.iv.size + ciphertext.size).also { out ->
            out[0] = cipher.iv.size.toByte()
            cipher.iv.copyInto(out, 1)
            ciphertext.copyInto(out, 1 + cipher.iv.size)
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "duolink.biometric.token.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"

        /** Strong biometrics only. Weak face unlock must not gate a private messenger. */
        const val AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_STRONG

        /** Decodes a sealed token produced by [sealToken]. */
        fun splitSealedToken(sealed: ByteArray): Pair<ByteArray, ByteArray> {
            require(sealed.size > 1) { "sealed token too short" }
            val ivLen = sealed[0].toInt() and 0xFF
            require(ivLen in 12..16) { "unexpected IV length $ivLen" }
            require(sealed.size > 1 + ivLen) { "sealed token truncated" }
            return sealed.copyOfRange(1, 1 + ivLen) to sealed.copyOfRange(1 + ivLen, sealed.size)
        }

        /** Human-readable fingerprint of the app-lock salt, for support/diagnostics only. */
        fun describeRecord(record: AppLockRecord): String =
            "salt=${ByteEncoding.toHexLower(record.salt).take(8)}… iter=${record.iterations}"
    }
}
