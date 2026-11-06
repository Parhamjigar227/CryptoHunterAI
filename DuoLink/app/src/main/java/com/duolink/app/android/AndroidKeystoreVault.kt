package com.duolink.app.android

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.duolink.app.crypto.DeviceKeyVault
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.SignedPreKeyPublic
import com.duolink.app.crypto.StorageSealer
import com.duolink.app.crypto.zeroize
import com.duolink.app.pairing.DirectoryFileByteStore
import com.duolink.app.pairing.KeyValueByteStore
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec

/**
 * Production Android implementation of [DeviceKeyVault] supporting API 26–35+.
 *
 * - Long-term Identity Signing Key (IK_sig): Non-exportable EC P-256 (secp256r1) inside AndroidKeyStore
 *   (StrongBox or TEE hardware-backed where supported).
 * - Signed Pre-Key (SPK_dh): Uses AndroidKeyStore PURPOSE_AGREE_KEY on API 31+ where supported,
 *   and falls back seamlessly on API 26–30 (or unsupported vendor HALs) to BoringSSL EC P-256 ECDH
 *   with PKCS#8 private key material encrypted at rest under [AndroidKeystoreSealer] AES-256-GCM.
 */
class AndroidKeystoreVault(
    private val appContext: Context,
    private val sealer: StorageSealer = AndroidKeystoreSealer(appContext),
    private val byteStore: KeyValueByteStore = DirectoryFileByteStore(
        File(appContext.filesDir, "duolink_key_vault")
    )
) : DeviceKeyVault {

    private data class StoredSpkEntry(
        val publicPart: SignedPreKeyPublic,
        val usesHardwareKeystore: Boolean,
        val keystoreAliasOrEmpty: String,
        val sealedPkcs8OrEmpty: ByteArray
    )

    override val isHardwareBacked: Boolean
        get() = queryIdentityHardwareStatus().first

    override val hardwareDescription: String
        get() = queryIdentityHardwareStatus().second

    init {
        ensureIdentityKeyPair()
        ensureCurrentSignedPreKey(System.currentTimeMillis() / 1000L)
    }

    @Synchronized
    override fun getIdentityPublicKeySpki(): ByteArray {
        ensureIdentityKeyPair()
        val ks = loadAndroidKeyStore()
        val cert = ks.getCertificate(IDENTITY_KEY_ALIAS)
            ?: throw GeneralSecurityException("Missing certificate for $IDENTITY_KEY_ALIAS")
        return cert.publicKey.encoded
    }

    @Synchronized
    override fun getDeviceId(): String = EcP256Crypto.computeDeviceId(getIdentityPublicKeySpki())

    @Synchronized
    override fun signWithIdentity(transcript: ByteArray): ByteArray {
        ensureIdentityKeyPair()
        val ks = loadAndroidKeyStore()
        val privateKey = ks.getKey(IDENTITY_KEY_ALIAS, null) as? PrivateKey
            ?: throw GeneralSecurityException("Missing private key for $IDENTITY_KEY_ALIAS")
        val signer = Signature.getInstance(EcP256Crypto.SIGNATURE_ALG)
        signer.initSign(privateKey)
        signer.update(transcript)
        return signer.sign()
    }

    @Synchronized
    override fun getCurrentSignedPreKey(nowEpochSec: Long): SignedPreKeyPublic =
        ensureCurrentSignedPreKey(nowEpochSec)

    @Synchronized
    override fun rotateSignedPreKey(nowEpochSec: Long): SignedPreKeyPublic {
        val entries = loadStoredSpkEntries().toMutableList()
        val nextId = (entries.maxOfOrNull { it.publicPart.spkId } ?: 0) + 1
        val created = generateSignedPreKeyEntry(nextId, nowEpochSec)
        entries.add(created)

        // Retain up to 3 recent signed pre-keys and clean up retired Keystore aliases
        while (entries.size > MAX_RETAINED_SPK) {
            val retired = entries.removeAt(0)
            if (retired.usesHardwareKeystore && retired.keystoreAliasOrEmpty.isNotEmpty()) {
                runCatching {
                    val ks = loadAndroidKeyStore()
                    if (ks.containsAlias(retired.keystoreAliasOrEmpty)) {
                        ks.deleteEntry(retired.keystoreAliasOrEmpty)
                    }
                }
            }
        }
        saveStoredSpkEntries(entries)
        return created.publicPart
    }

    @Synchronized
    override fun agreeWithSignedPreKey(localSpkId: Int, peerDhPublicKeySpki: ByteArray): ByteArray {
        val entry = loadStoredSpkEntries().firstOrNull { it.publicPart.spkId == localSpkId }
            ?: throw GeneralSecurityException("Signed pre-key $localSpkId not found")

        if (entry.usesHardwareKeystore) {
            val ks = loadAndroidKeyStore()
            val priv = ks.getKey(entry.keystoreAliasOrEmpty, null) as? PrivateKey
                ?: throw GeneralSecurityException("Hardware SPK alias missing: ${entry.keystoreAliasOrEmpty}")
            return EcP256Crypto.computeEcdhSharedSecret(
                localPrivateKey = priv,
                peerPublicKeySpki = peerDhPublicKeySpki,
                provider = ANDROID_KEYSTORE
            )
        }

        val aad = spkPkcs8Aad(localSpkId)
        val pkcs8 = sealer.unseal(entry.sealedPkcs8OrEmpty, aad)
        return try {
            val priv = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            EcP256Crypto.computeEcdhSharedSecret(priv, peerDhPublicKeySpki)
        } finally {
            pkcs8.zeroize()
        }
    }

    @Synchronized
    override fun resetIdentityKeys(nowEpochSec: Long) {
        val ks = loadAndroidKeyStore()
        for (entry in loadStoredSpkEntries()) {
            if (entry.usesHardwareKeystore && entry.keystoreAliasOrEmpty.isNotEmpty()) {
                runCatching {
                    if (ks.containsAlias(entry.keystoreAliasOrEmpty)) {
                        ks.deleteEntry(entry.keystoreAliasOrEmpty)
                    }
                }
            }
        }
        byteStore.delete(KEY_SPK_LIST)
        if (ks.containsAlias(IDENTITY_KEY_ALIAS)) {
            ks.deleteEntry(IDENTITY_KEY_ALIAS)
        }
        ensureIdentityKeyPair()
        rotateSignedPreKey(nowEpochSec)
    }

    private fun ensureCurrentSignedPreKey(nowEpochSec: Long): SignedPreKeyPublic {
        val entries = loadStoredSpkEntries()
        val latest = entries.maxByOrNull { it.publicPart.spkId }
        if (latest != null && nowEpochSec < latest.publicPart.expiresAtEpochSec) {
            return latest.publicPart
        }
        return rotateSignedPreKey(nowEpochSec)
    }

    private fun ensureIdentityKeyPair() {
        val ks = loadAndroidKeyStore()
        if (ks.containsAlias(IDENTITY_KEY_ALIAS) && ks.getCertificate(IDENTITY_KEY_ALIAS) != null) {
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        ) {
            try {
                generateIdentityKeyPair(useStrongBox = true)
                return
            } catch (_: Exception) {
                // Fall back cleanly to TEE
            }
        }
        generateIdentityKeyPair(useStrongBox = false)
    }

    private fun generateIdentityKeyPair(useStrongBox: Boolean): KeyPair {
        val builder = KeyGenParameterSpec.Builder(
            IDENTITY_KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec(EcP256Crypto.CURVE_STD_NAME))
            .setDigests(KeyProperties.DIGEST_SHA256)

        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        kpg.initialize(builder.build())
        return kpg.generateKeyPair()
    }

    private fun generateSignedPreKeyEntry(spkId: Int, nowEpochSec: Long): StoredSpkEntry {
        val expiresAt = nowEpochSec + EcP256Crypto.DEFAULT_SPK_VALIDITY_SEC
        val deviceId = getDeviceId()

        // On Android 12+ (API 31+), try hardware-backed PURPOSE_AGREE_KEY first
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val alias = "duolink_spk_dh_v1_$spkId"
            val hwSpki = tryGenerateHardwareAgreeKey(alias)
            if (hwSpki != null) {
                val transcript = EcP256Crypto.buildSignedPreKeyTranscript(
                    deviceId = deviceId,
                    spkId = spkId,
                    issuedAtEpochSec = nowEpochSec,
                    expiresAtEpochSec = expiresAt,
                    spkPublicKeySpki = hwSpki
                )
                val sig = signWithIdentity(transcript)
                return StoredSpkEntry(
                    publicPart = SignedPreKeyPublic(
                        spkId = spkId,
                        publicKeySpki = hwSpki,
                        issuedAtEpochSec = nowEpochSec,
                        expiresAtEpochSec = expiresAt,
                        signature = sig
                    ),
                    usesHardwareKeystore = true,
                    keystoreAliasOrEmpty = alias,
                    sealedPkcs8OrEmpty = ByteArray(0)
                )
            }
        }

        // API 26–30 (or HAL without ECDH support): BoringSSL EC P-256 wrapped by AndroidKeyStore AES-256-GCM
        val kp = EcP256Crypto.generateSoftwareEcP256KeyPair()
        val pkcs8 = kp.private.encoded
        val spki = kp.public.encoded
        val sealedPkcs8 = try {
            sealer.seal(pkcs8, spkPkcs8Aad(spkId))
        } finally {
            pkcs8.zeroize()
        }

        val transcript = EcP256Crypto.buildSignedPreKeyTranscript(
            deviceId = deviceId,
            spkId = spkId,
            issuedAtEpochSec = nowEpochSec,
            expiresAtEpochSec = expiresAt,
            spkPublicKeySpki = spki
        )
        val sig = signWithIdentity(transcript)
        return StoredSpkEntry(
            publicPart = SignedPreKeyPublic(
                spkId = spkId,
                publicKeySpki = spki,
                issuedAtEpochSec = nowEpochSec,
                expiresAtEpochSec = expiresAt,
                signature = sig
            ),
            usesHardwareKeystore = false,
            keystoreAliasOrEmpty = "",
            sealedPkcs8OrEmpty = sealedPkcs8
        )
    }

    private fun tryGenerateHardwareAgreeKey(alias: String): ByteArray? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
        return try {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec(EcP256Crypto.CURVE_STD_NAME))
                .build()
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            kpg.initialize(spec)
            kpg.generateKeyPair().public.encoded
        } catch (_: Exception) {
            null
        }
    }

    private fun queryIdentityHardwareStatus(): Pair<Boolean, String> {
        return try {
            ensureIdentityKeyPair()
            val ks = loadAndroidKeyStore()
            val priv = ks.getKey(IDENTITY_KEY_ALIAS, null) as? PrivateKey
                ?: return false to "نامشخص"
            val factory = KeyFactory.getInstance(priv.algorithm, ANDROID_KEYSTORE)
            val keyInfo = factory.getKeySpec(priv, KeyInfo::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX ->
                        true to "StrongBox سخت‌افزاری (Android Keystore)"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                        true to "محیط امن سخت‌افزاری TEE (Android Keystore)"
                    else ->
                        false to "Android Keystore (محافظت سطح سیستم‌عامل)"
                }
            } else {
                @Suppress("DEPRECATION")
                if (keyInfo.isInsideSecureHardware) {
                    true to "سخت‌افزار امن (Android Keystore)"
                } else {
                    false to "Android Keystore (محافظت سطح سیستم‌عامل)"
                }
            }
        } catch (_: Exception) {
            false to "Android Keystore"
        }
    }

    private fun loadStoredSpkEntries(): List<StoredSpkEntry> {
        val sealed = byteStore.read(KEY_SPK_LIST) ?: return emptyList()
        return try {
            val plain = sealer.unseal(sealed, AAD_SPK_LIST)
            val buf = ByteBuffer.wrap(plain)
            val count = buf.int
            require(count in 0..MAX_RETAINED_SPK)
            List(count) {
                val spkId = buf.int
                val pubSpki = readChunk(buf)
                val iat = buf.long
                val exp = buf.long
                val sig = readChunk(buf)
                val usesHw = buf.get().toInt() != 0
                val alias = String(readChunk(buf), StandardCharsets.UTF_8)
                val sealedPkcs8 = readChunk(buf)
                StoredSpkEntry(
                    publicPart = SignedPreKeyPublic(spkId, pubSpki, iat, exp, sig),
                    usesHardwareKeystore = usesHw,
                    keystoreAliasOrEmpty = alias,
                    sealedPkcs8OrEmpty = sealedPkcs8
                )
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun saveStoredSpkEntries(entries: List<StoredSpkEntry>) {
        val out = ByteArrayOutputStream(512)
        out.write(ByteBuffer.allocate(4).putInt(entries.size).array())
        for (e in entries) {
            out.write(ByteBuffer.allocate(4).putInt(e.publicPart.spkId).array())
            writeChunk(out, e.publicPart.publicKeySpki)
            out.write(ByteBuffer.allocate(8).putLong(e.publicPart.issuedAtEpochSec).array())
            out.write(ByteBuffer.allocate(8).putLong(e.publicPart.expiresAtEpochSec).array())
            writeChunk(out, e.publicPart.signature)
            out.write(if (e.usesHardwareKeystore) 1 else 0)
            writeChunk(out, e.keystoreAliasOrEmpty.toByteArray(StandardCharsets.UTF_8))
            writeChunk(out, e.sealedPkcs8OrEmpty)
        }
        byteStore.write(KEY_SPK_LIST, sealer.seal(out.toByteArray(), AAD_SPK_LIST))
    }

    private fun spkPkcs8Aad(spkId: Int): ByteArray =
        "duolink:android_spk_pkcs8:v1|$spkId".toByteArray(StandardCharsets.UTF_8)

    private fun writeChunk(out: ByteArrayOutputStream, b: ByteArray) {
        out.write(ByteBuffer.allocate(4).putInt(b.size).array())
        out.write(b)
    }

    private fun readChunk(buf: ByteBuffer): ByteArray {
        val len = buf.int
        require(len in 0..8192 && buf.remaining() >= len)
        return ByteArray(len).also { buf.get(it) }
    }

    private fun loadAndroidKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val IDENTITY_KEY_ALIAS = "duolink_identity_sig_v1"
        private const val KEY_SPK_LIST = "spk_entries_v1"
        private const val MAX_RETAINED_SPK = 3
        private val AAD_SPK_LIST = "duolink:android_spk_meta:v1".toByteArray(StandardCharsets.UTF_8)
    }
}
