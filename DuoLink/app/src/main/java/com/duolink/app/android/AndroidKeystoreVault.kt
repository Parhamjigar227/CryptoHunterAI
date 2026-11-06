package com.duolink.app.android

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.duolink.app.crypto.DeviceKeyVault
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.KeyProtectionReport
import com.duolink.app.crypto.KeyProtectionTier
import com.duolink.app.crypto.KeyValueByteStore
import com.duolink.app.crypto.KeyVaultStorageCorruptedException
import com.duolink.app.crypto.LocalIdentityPublic
import com.duolink.app.crypto.RawStoreRead
import com.duolink.app.crypto.SignedPreKeyPublic
import com.duolink.app.crypto.SingleKeyProtectionStatus
import com.duolink.app.crypto.SpkMetadataStoreCodec
import com.duolink.app.crypto.StorageSealer
import com.duolink.app.crypto.VaultHealth
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.util.Arrays

/**
 * Production Android implementation of [DeviceKeyVault] compatible with `minSdk = 26` through `targetSdk = 35`.
 *
 * Per-key protection architecture (reported separately and accurately via [getKeyProtectionReport]):
 * 1. `IK_sig` (`secp256r1`, `PURPOSE_SIGN | PURPOSE_VERIFY`, `SHA256withECDSA`):
 *    Generated inside `AndroidKeyStore` on API 26+. Actual TEE / StrongBox vs OS-software Keystore
 *    backing is queried dynamically via [KeyInfo].
 * 2. `MSK` (`AES-256-GCM`):
 *    Generated inside `AndroidKeyStore` via [AndroidKeystoreSealer]; queried dynamically via [KeyInfo].
 * 3. `SPK_dh` (`secp256r1` ECDH):
 *    - On Android 12+ (`API 31+`) when KeyMint supports `KeyProperties.PURPOSE_AGREE_KEY` (and
 *      [forceSoftwareSpkFallback] is `false`), generated inside `AndroidKeyStore`.
 *    - On Android 8.0–11 (`API 26–30`) or when `PURPOSE_AGREE_KEY` is unsupported by the device HAL,
 *      generated in software via JCA (`EC secp256r1`), signed by `IK_sig`, encrypted at rest under
 *      `MSK` (`AES-256-GCM`) with `deviceId`-bound AAD, and decrypted transiently in heap RAM only
 *      during [agreeWithSignedPreKey] (immediately zeroized in `finally`). It is NEVER described as
 *      hardware-backed or non-exportable.
 *
 * Fail-closed persistence rule:
 * - Corrupted, tampered, truncated, or deleted `spk_entries_v2`, `vault_init_v2`, or `sealed_spk_v2_<id>`
 *   blobs NEVER fall back to `emptyList()` or silent key regeneration; they surface [VaultHealth.Corrupted]
 *   and throw [KeyVaultStorageCorruptedException].
 */
class AndroidKeystoreVault(
    private val packageManager: PackageManager,
    private val sealer: StorageSealer,
    private val byteStore: KeyValueByteStore,
    private val maxRetainedSignedPreKeys: Int = 3,
    private val aliasPrefix: String = DEFAULT_ALIAS_PREFIX,
    private val forceSoftwareSpkFallback: Boolean = false
) : DeviceKeyVault {

    private val aliasIkSig: String = "${aliasPrefix}_ik_sig_p256_v1"

    @Synchronized
    override fun checkVaultHealth(): VaultHealth {
        return try {
            val ks = openAndroidKeyStore()
            if (!ks.containsAlias(aliasIkSig)) {
                if (byteStore.readState(SpkMetadataStoreCodec.KEY_VAULT_INIT_MARKER) !is RawStoreRead.Missing ||
                    byteStore.readState(SpkMetadataStoreCodec.KEY_SPK_METADATA) !is RawStoreRead.Missing
                ) {
                    return VaultHealth.Corrupted(
                        "Identity key '$aliasIkSig' missing from AndroidKeyStore while SPK metadata exists on disk"
                    )
                }
                return VaultHealth.Healthy
            }

            val ikPair = loadExistingIdentityKeyPairOrThrow(ks)
            val ikSpki = ikPair.public.encoded
            val deviceId = EcP256Crypto.computeDeviceId(ikSpki)
            val catalog = SpkMetadataStoreCodec.loadCatalogStrict(
                store = byteStore,
                sealer = sealer,
                deviceId = deviceId,
                identitySigningPublicKeySpki = ikSpki
            ) ?: return VaultHealth.Corrupted(
                "SPK metadata catalog missing while AndroidKeyStore identity key exists"
            )

            for (entry in catalog.entries) {
                if (entry.usesHardwareKeystore) {
                    val alias = hwSpkAlias(entry.publicPart.spkId)
                    if (!ks.containsAlias(alias)) {
                        return VaultHealth.Corrupted(
                            "AndroidKeyStore ECDH pre-key '$alias' missing for persisted SPK #${entry.publicPart.spkId}"
                        )
                    }
                } else {
                    val pkcs8 = loadAndUnsealSoftwareSpkPkcs8Strict(deviceId, entry.publicPart.spkId)
                    Arrays.fill(pkcs8, 0.toByte())
                }
            }
            VaultHealth.Healthy
        } catch (e: Exception) {
            VaultHealth.Corrupted(e.message ?: "AndroidKeystoreVault integrity check failed")
        }
    }

    @Synchronized
    override fun getOrCreateLocalIdentity(nowEpochSec: Long): LocalIdentityPublic {
        val ks = openAndroidKeyStore()
        if (!ks.containsAlias(aliasIkSig)) {
            if (byteStore.readState(SpkMetadataStoreCodec.KEY_VAULT_INIT_MARKER) !is RawStoreRead.Missing ||
                byteStore.readState(SpkMetadataStoreCodec.KEY_SPK_METADATA) !is RawStoreRead.Missing
            ) {
                throw KeyVaultStorageCorruptedException(
                    "Orphaned SPK metadata found on disk while AndroidKeyStore identity key is absent"
                )
            }
            return initializeFreshVault(nowEpochSec)
        }

        val ikPair = loadExistingIdentityKeyPairOrThrow(ks)
        val ikSpki = ikPair.public.encoded
        val deviceId = EcP256Crypto.computeDeviceId(ikSpki)
        val catalog = SpkMetadataStoreCodec.loadCatalogStrict(
            store = byteStore,
            sealer = sealer,
            deviceId = deviceId,
            identitySigningPublicKeySpki = ikSpki
        ) ?: throw KeyVaultStorageCorruptedException(
            "SPK metadata catalog missing while AndroidKeyStore identity key exists"
        )
        val active = catalog.entries.maxByOrNull { it.publicPart.spkId }
            ?: throw KeyVaultStorageCorruptedException("Empty SPK metadata catalog")
        verifyActiveSpkBackingPresentOrThrow(ks, deviceId, active)

        return LocalIdentityPublic(
            deviceId = deviceId,
            identitySigningPublicKeySpki = ikSpki,
            currentSignedPreKey = active.publicPart
        )
    }

    @Synchronized
    override fun signWithIdentityKey(payload: ByteArray): ByteArray {
        val ks = openAndroidKeyStore()
        val ikPair = loadExistingIdentityKeyPairOrThrow(ks)
        return EcP256Crypto.signSha256Ecdsa(ikPair.private, payload)
    }

    @Synchronized
    override fun agreeWithSignedPreKey(localSpkId: Int, peerPublicKeySpki: ByteArray): ByteArray {
        val ks = openAndroidKeyStore()
        val ikPair = loadExistingIdentityKeyPairOrThrow(ks)
        val ikSpki = ikPair.public.encoded
        val deviceId = EcP256Crypto.computeDeviceId(ikSpki)
        val catalog = SpkMetadataStoreCodec.loadCatalogStrict(
            store = byteStore,
            sealer = sealer,
            deviceId = deviceId,
            identitySigningPublicKeySpki = ikSpki
        ) ?: throw KeyVaultStorageCorruptedException("Missing SPK metadata catalog")

        val entry = catalog.entries.firstOrNull { it.publicPart.spkId == localSpkId }
            ?: throw GeneralSecurityException("Signed pre-key $localSpkId is unknown or expired")

        if (entry.usesHardwareKeystore) {
            val privKey = ks.getKey(hwSpkAlias(localSpkId), null) as? PrivateKey
                ?: throw KeyVaultStorageCorruptedException(
                    "AndroidKeyStore ECDH key missing for SPK #$localSpkId"
                )
            return EcP256Crypto.ecdhSharedSecret(
                localPrivateKey = privKey,
                peerPublicKeySpki = peerPublicKeySpki,
                provider = KEYSTORE_PROVIDER
            )
        } else {
            val pkcs8 = loadAndUnsealSoftwareSpkPkcs8Strict(deviceId, localSpkId)
            return try {
                val privKey = EcP256Crypto.decodeSoftwarePrivateKey(pkcs8)
                EcP256Crypto.ecdhSharedSecret(privKey, peerPublicKeySpki)
            } finally {
                Arrays.fill(pkcs8, 0.toByte())
            }
        }
    }

    @Synchronized
    override fun rotateSignedPreKey(nowEpochSec: Long): SignedPreKeyPublic {
        val ks = openAndroidKeyStore()
        val ikPair = loadExistingIdentityKeyPairOrThrow(ks)
        val ikSpki = ikPair.public.encoded
        val deviceId = EcP256Crypto.computeDeviceId(ikSpki)
        val catalog = SpkMetadataStoreCodec.loadCatalogStrict(
            store = byteStore,
            sealer = sealer,
            deviceId = deviceId,
            identitySigningPublicKeySpki = ikSpki
        ) ?: throw KeyVaultStorageCorruptedException("Missing SPK metadata catalog during rotation")

        val nextId = catalog.highestIssuedSpkId + 1
        val created = generateAndPersistSpk(ikPair, deviceId, nextId, nowEpochSec)
        val merged = (catalog.entries + created).sortedBy { it.publicPart.spkId }
        val retained = if (merged.size > maxRetainedSignedPreKeys) {
            val evicted = merged.dropLast(maxRetainedSignedPreKeys)
            evicted.forEach { old -> deleteSpkMaterial(ks, old) }
            merged.takeLast(maxRetainedSignedPreKeys)
        } else {
            merged
        }
        SpkMetadataStoreCodec.saveCatalog(
            store = byteStore,
            sealer = sealer,
            deviceId = deviceId,
            highestIssuedSpkId = nextId,
            entries = retained
        )
        return created.publicPart
    }

    @Synchronized
    override fun resetIdentityKeys(nowEpochSec: Long): LocalIdentityPublic {
        purgeAllVaultEntriesInternal()
        return initializeFreshVault(nowEpochSec)
    }

    @Synchronized
    override fun getKeyProtectionReport(nowEpochSec: Long): KeyProtectionReport {
        getOrCreateLocalIdentity(nowEpochSec)
        val ks = openAndroidKeyStore()
        val ikPair = loadExistingIdentityKeyPairOrThrow(ks)
        val ikSpki = ikPair.public.encoded
        val deviceId = EcP256Crypto.computeDeviceId(ikSpki)
        val catalog = SpkMetadataStoreCodec.loadCatalogStrict(
            store = byteStore,
            sealer = sealer,
            deviceId = deviceId,
            identitySigningPublicKeySpki = ikSpki
        ) ?: throw KeyVaultStorageCorruptedException("Missing SPK metadata catalog")
        val active = catalog.entries.maxByOrNull { it.publicPart.spkId }
            ?: throw KeyVaultStorageCorruptedException("Empty SPK metadata catalog")

        val ikTier = inspectEcPrivateKeyTier(ikPair.private)
        val ikStatus = SingleKeyProtectionStatus(
            keyRolePersian = "کلید امضای هویت دستگاه (IK_sig)",
            algorithm = "ECDSA P-256 (SHA-256)",
            tier = ikTier,
            persianDescription = AndroidKeystoreSealer.describeKeystoreTierPersian(ikTier)
        )

        val mskStatus = sealer.queryProtectionStatus()

        val spkStatus = if (active.usesHardwareKeystore) {
            val spkPriv = ks.getKey(hwSpkAlias(active.publicPart.spkId), null) as? PrivateKey
                ?: throw KeyVaultStorageCorruptedException("Missing active AndroidKeyStore SPK key")
            val spkTier = inspectEcPrivateKeyTier(spkPriv)
            SingleKeyProtectionStatus(
                keyRolePersian = "پیش‌کلید امضاشده توافق کلید (SPK_dh #${active.publicPart.spkId})",
                algorithm = "ECDH P-256 (AndroidKeyStore API 31+)",
                tier = spkTier,
                persianDescription = AndroidKeystoreSealer.describeKeystoreTierPersian(spkTier)
            )
        } else {
            SingleKeyProtectionStatus(
                keyRolePersian = "پیش‌کلید امضاشده توافق کلید (SPK_dh #${active.publicPart.spkId})",
                algorithm = "ECDH P-256 (پوشش‌داده‌شده با MSK)",
                tier = KeyProtectionTier.SOFTWARE_WRAPPED_AT_REST,
                persianDescription = AndroidKeystoreSealer.describeKeystoreTierPersian(
                    KeyProtectionTier.SOFTWARE_WRAPPED_AT_REST
                )
            )
        }

        return KeyProtectionReport(
            identitySigningKey = ikStatus,
            storageWrappingKey = mskStatus,
            activeSignedPreKey = spkStatus
        )
    }

    /**
     * Purges Keystore aliases and byteStore records created under [aliasPrefix] (used by instrumentation tests).
     */
    internal fun purgeAllForTesting() {
        purgeAllVaultEntriesInternal()
    }

    private fun purgeAllVaultEntriesInternal() {
        val ks = openAndroidKeyStore()
        // Delete any SPK entries known on disk or within reasonable ID window.
        val aliases = ks.aliases().toList()
        val spkPrefix = "${aliasPrefix}_spk_dh_v1_"
        for (alias in aliases) {
            if (alias == aliasIkSig || alias.startsWith(spkPrefix)) {
                ks.deleteEntry(alias)
            }
        }
        for (spkId in 1..64) {
            byteStore.delete(sealedSpkStoreKey(spkId))
        }
        byteStore.delete(SpkMetadataStoreCodec.KEY_SPK_METADATA)
        byteStore.delete(SpkMetadataStoreCodec.KEY_VAULT_INIT_MARKER)
    }

    private fun initializeFreshVault(nowEpochSec: Long): LocalIdentityPublic {
        val ikPair = createNewIdentityKeyPairInKeystore()
        val ikSpki = ikPair.public.encoded
        val deviceId = EcP256Crypto.computeDeviceId(ikSpki)
        SpkMetadataStoreCodec.writeInitMarker(byteStore, sealer, deviceId)
        val firstSpk = generateAndPersistSpk(ikPair, deviceId, 1, nowEpochSec)
        SpkMetadataStoreCodec.saveCatalog(
            store = byteStore,
            sealer = sealer,
            deviceId = deviceId,
            highestIssuedSpkId = 1,
            entries = listOf(firstSpk)
        )
        return LocalIdentityPublic(
            deviceId = deviceId,
            identitySigningPublicKeySpki = ikSpki,
            currentSignedPreKey = firstSpk.publicPart
        )
    }

    private fun openAndroidKeyStore(): KeyStore =
        KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    private fun loadExistingIdentityKeyPairOrThrow(ks: KeyStore): KeyPair {
        val existingEntry = ks.getEntry(aliasIkSig, null) as? KeyStore.PrivateKeyEntry
            ?: throw KeyVaultStorageCorruptedException("Identity key '$aliasIkSig' not found in AndroidKeyStore")
        return KeyPair(existingEntry.certificate.publicKey, existingEntry.privateKey)
    }

    private fun createNewIdentityKeyPairInKeystore(): KeyPair {
        val tryStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (tryStrongBox) {
            try {
                return generateKeystoreSigningKeyPair(strongBox = true)
            } catch (_: Exception) {
                // Fall back to standard Keystore provider if StrongBox rejects EC P-256 on this OEM.
            }
        }
        return generateKeystoreSigningKeyPair(strongBox = false)
    }

    private fun generateKeystoreSigningKeyPair(strongBox: Boolean): KeyPair {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
        val builder = KeyGenParameterSpec.Builder(
            aliasIkSig,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec(EcP256Crypto.CURVE_NAME))
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && strongBox) {
            builder.setIsStrongBoxBacked(true)
        }
        kpg.initialize(builder.build())
        return kpg.generateKeyPair()
    }

    private fun generateAndPersistSpk(
        ikPair: KeyPair,
        deviceId: ByteArray,
        spkId: Int,
        nowEpochSec: Long
    ): SpkMetadataStoreCodec.PersistedSpkMetadata {
        if (!forceSoftwareSpkFallback && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                val alias = hwSpkAlias(spkId)
                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
                val spec = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_AGREE_KEY
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec(EcP256Crypto.CURVE_NAME))
                    .build()
                kpg.initialize(spec)
                val spkPair = kpg.generateKeyPair()
                val spki = spkPair.public.encoded
                val transcript = EcP256Crypto.buildSpkTranscript(deviceId, spkId, spki, nowEpochSec)
                val sig = EcP256Crypto.signSha256Ecdsa(ikPair.private, transcript)
                return SpkMetadataStoreCodec.PersistedSpkMetadata(
                    publicPart = SignedPreKeyPublic(spkId, spki, sig, nowEpochSec),
                    usesHardwareKeystore = true
                )
            } catch (_: Exception) {
                // Device KeyMint HAL does not support PURPOSE_AGREE_KEY; fall through to MSK-sealed software SPK.
            }
        }

        val swPair = EcP256Crypto.generateSoftwareP256KeyPair()
        val spki = swPair.public.encoded
        val pkcs8 = swPair.private.encoded
        val sealedPriv = try {
            sealer.seal(pkcs8, SpkMetadataStoreCodec.aadForSoftwareSpkPrivateKey(deviceId, spkId))
        } finally {
            Arrays.fill(pkcs8, 0.toByte())
        }
        byteStore.write(sealedSpkStoreKey(spkId), sealedPriv)
        val transcript = EcP256Crypto.buildSpkTranscript(deviceId, spkId, spki, nowEpochSec)
        val sig = EcP256Crypto.signSha256Ecdsa(ikPair.private, transcript)
        return SpkMetadataStoreCodec.PersistedSpkMetadata(
            publicPart = SignedPreKeyPublic(spkId, spki, sig, nowEpochSec),
            usesHardwareKeystore = false
        )
    }

    private fun verifyActiveSpkBackingPresentOrThrow(
        ks: KeyStore,
        deviceId: ByteArray,
        entry: SpkMetadataStoreCodec.PersistedSpkMetadata
    ) {
        if (entry.usesHardwareKeystore) {
            if (!ks.containsAlias(hwSpkAlias(entry.publicPart.spkId))) {
                throw KeyVaultStorageCorruptedException(
                    "AndroidKeyStore ECDH key missing for active SPK #${entry.publicPart.spkId}"
                )
            }
        } else {
            val pkcs8 = loadAndUnsealSoftwareSpkPkcs8Strict(deviceId, entry.publicPart.spkId)
            Arrays.fill(pkcs8, 0.toByte())
        }
    }

    private fun loadAndUnsealSoftwareSpkPkcs8Strict(deviceId: ByteArray, spkId: Int): ByteArray {
        return when (val raw = byteStore.readState(sealedSpkStoreKey(spkId))) {
            is RawStoreRead.Missing -> throw KeyVaultStorageCorruptedException(
                "Sealed SPK #$spkId private key file missing from storage"
            )
            is RawStoreRead.CorruptedIo -> throw KeyVaultStorageCorruptedException(
                "Sealed SPK #$spkId private key I/O corruption: ${raw.detail}"
            )
            is RawStoreRead.Present -> {
                try {
                    sealer.unseal(
                        raw.bytes,
                        SpkMetadataStoreCodec.aadForSoftwareSpkPrivateKey(deviceId, spkId)
                    )
                } catch (e: Exception) {
                    throw KeyVaultStorageCorruptedException(
                        "Sealed SPK #$spkId private key failed AEAD authentication under MSK",
                        e
                    )
                }
            }
        }
    }

    private fun inspectEcPrivateKeyTier(privateKey: PrivateKey): KeyProtectionTier {
        return try {
            val kf = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
            val keyInfo = kf.getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
            AndroidKeystoreSealer.classifyKeystoreKeyInfo(keyInfo)
        } catch (_: Exception) {
            KeyProtectionTier.ANDROID_KEYSTORE_OS_SOFTWARE
        }
    }

    private fun deleteSpkMaterial(ks: KeyStore, entry: SpkMetadataStoreCodec.PersistedSpkMetadata) {
        if (entry.usesHardwareKeystore) {
            val alias = hwSpkAlias(entry.publicPart.spkId)
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias)
            }
        } else {
            byteStore.delete(sealedSpkStoreKey(entry.publicPart.spkId))
        }
    }

    private fun hwSpkAlias(spkId: Int): String = "${aliasPrefix}_spk_dh_v1_$spkId"
    private fun sealedSpkStoreKey(spkId: Int): String = "${aliasPrefix}_sealed_spk_v2_$spkId"

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val DEFAULT_ALIAS_PREFIX = "duolink"
    }
}
