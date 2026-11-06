package com.duolink.app.crypto

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays
import javax.crypto.KeyAgreement

/**
 * Raised when persisted key-vault metadata (`spk_entries_v2`, `vault_init_v2`, or sealed SPK private
 * key blobs) fails AEAD authentication, schema validation, signature verification, or is deleted
 * after vault initialization. Callers MUST fail closed rather than silently regenerating keys.
 */
class KeyVaultStorageCorruptedException(
    message: String,
    cause: Throwable? = null
) : GeneralSecurityException(message, cause)

/**
 * Health check result for local key-vault metadata.
 */
sealed class VaultHealth {
    data object Healthy : VaultHealth()
    data class Corrupted(val reason: String) : VaultHealth()
}

/**
 * Public metadata of a device's Signed Pre-Key (`SPK_dh`, NIST P-256 ECDH keypair) signed by `IK_sig`.
 */
data class SignedPreKeyPublic(
    val spkId: Int,
    val publicKeySpki: ByteArray,
    val signatureByIdentityKey: ByteArray,
    val createdAtEpochSec: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignedPreKeyPublic) return false
        return spkId == other.spkId &&
            createdAtEpochSec == other.createdAtEpochSec &&
            publicKeySpki.contentEquals(other.publicKeySpki) &&
            signatureByIdentityKey.contentEquals(other.signatureByIdentityKey)
    }

    override fun hashCode(): Int {
        var result = spkId
        result = 31 * result + publicKeySpki.contentHashCode()
        result = 31 * result + signatureByIdentityKey.contentHashCode()
        result = 31 * result + createdAtEpochSec.hashCode()
        return result
    }
}

/**
 * Immutable public identity bundle for this device.
 */
data class LocalIdentityPublic(
    val deviceId: ByteArray,
    val identitySigningPublicKeySpki: ByteArray,
    val currentSignedPreKey: SignedPreKeyPublic
) {
    val deviceIdHex: String get() = ByteEncoding.toHexLower(deviceId)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LocalIdentityPublic) return false
        return deviceId.contentEquals(other.deviceId) &&
            identitySigningPublicKeySpki.contentEquals(other.identitySigningPublicKeySpki) &&
            currentSignedPreKey == other.currentSignedPreKey
    }

    override fun hashCode(): Int {
        var result = deviceId.contentHashCode()
        result = 31 * result + identitySigningPublicKeySpki.contentHashCode()
        result = 31 * result + currentSignedPreKey.hashCode()
        return result
    }
}

/**
 * Abstraction over the device's cryptographic key vault.
 *
 * Production Android implementation: `AndroidKeystoreVault`
 *   - `IK_sig` (`secp256r1` ECDSA): generated inside `AndroidKeyStore`.
 *   - `MSK` (`AES-256-GCM`): generated inside `AndroidKeyStore`.
 *   - `SPK_dh` (`secp256r1` ECDH):
 *       - Android 12+ (API 31+) when KeyMint supports `PURPOSE_AGREE_KEY`: generated inside `AndroidKeyStore`.
 *       - Android 8.0–11 (API 26–30) or HAL fallback: software-generated in app memory, encrypted at rest
 *         under `MSK` (`AES-256-GCM`), and decrypted transiently in heap memory during `agreeWithSignedPreKey`.
 *         Reported honestly as [KeyProtectionTier.SOFTWARE_WRAPPED_AT_REST] (neither hardware-backed nor
 *         non-exportable from process RAM).
 */
interface DeviceKeyVault {
    fun checkVaultHealth(): VaultHealth
    fun getOrCreateLocalIdentity(nowEpochSec: Long): LocalIdentityPublic
    fun signWithIdentityKey(payload: ByteArray): ByteArray
    fun agreeWithSignedPreKey(localSpkId: Int, peerPublicKeySpki: ByteArray): ByteArray
    fun rotateSignedPreKey(nowEpochSec: Long): SignedPreKeyPublic
    fun resetIdentityKeys(nowEpochSec: Long): LocalIdentityPublic
    fun getKeyProtectionReport(nowEpochSec: Long): KeyProtectionReport
}

/**
 * Canonical JCA operations for NIST P-256 (`secp256r1`) signatures, ECDH key agreement, and `deviceId` derivation.
 *
 * Provider selection note:
 * - Calls use standard JCA factory methods (`getInstance(algorithm)`) without hardcoding a provider name,
 *   except when `AndroidKeyStore` is explicitly requested by `AndroidKeystoreVault` for API 31+ `KeyAgreement`.
 * - On Android runtime, software EC/ECDH/ECDSA operations resolve via default JCA priority to `AndroidOpenSSL`
 *   (Conscrypt / BoringSSL), whereas `AndroidKeyStore` private keys route via JCA delayed provider selection to
 *   the platform Keystore provider.
 * - On OpenJDK 17 JVM unit tests, default JCA priority resolves to `SunEC` / `SunJCE`.
 */
object EcP256Crypto {
    const val CURVE_NAME = "secp256r1"
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    const val KEY_AGREEMENT_ALGORITHM = "ECDH"
    private val SPK_SIG_DOMAIN = "DuoLink-SPK-v1".toByteArray(StandardCharsets.UTF_8)

    /**
     * Expected X.509 SubjectPublicKeyInfo prefix for uncompressed NIST P-256 (`secp256r1`) public keys (26 bytes),
     * followed by `0x04 || X (32B) || Y (32B)` = 91 bytes total.
     */
    private val P256_UNCOMPRESSED_SPKI_PREFIX = byteArrayOf(
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86.toByte(),
        0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00, 0x04
    )

    fun generateSoftwareP256KeyPair(secureRandom: SecureRandom = SecureRandom()): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec(CURVE_NAME), secureRandom)
        return kpg.generateKeyPair()
    }

    /**
     * Strictly parses and validates a 91-byte X.509 SPKI uncompressed NIST P-256 public key.
     * Rejects non-P-256 curves, compressed/infinity encodings, and malformed DER headers.
     */
    fun decodeAndValidateP256PublicKey(spkiBytes: ByteArray): PublicKey {
        if (spkiBytes.size != 91) {
            throw GeneralSecurityException("Invalid P-256 SPKI length: ${spkiBytes.size} (expected 91)")
        }
        for (i in P256_UNCOMPRESSED_SPKI_PREFIX.indices) {
            if (spkiBytes[i] != P256_UNCOMPRESSED_SPKI_PREFIX[i]) {
                throw GeneralSecurityException("SPKI header does not match uncompressed NIST P-256")
            }
        }
        val kf = KeyFactory.getInstance("EC")
        return kf.generatePublic(X509EncodedKeySpec(spkiBytes))
    }

    fun decodeSoftwarePrivateKey(pkcs8Bytes: ByteArray): PrivateKey {
        val kf = KeyFactory.getInstance("EC")
        return kf.generatePrivate(PKCS8EncodedKeySpec(pkcs8Bytes))
    }

    /**
     * `deviceId = SHA-256("DuoLink-DeviceId-v1" || IK_sig_pub_spki)[0..15]` (16 bytes / 128 bits).
     */
    fun computeDeviceId(identitySigningPublicKeySpki: ByteArray): ByteArray {
        decodeAndValidateP256PublicKey(identitySigningPublicKeySpki)
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("DuoLink-DeviceId-v1".toByteArray(StandardCharsets.UTF_8))
        digest.update(identitySigningPublicKeySpki)
        return digest.digest().copyOfRange(0, 16)
    }

    /**
     * Canonical domain-separated transcript signed by `IK_sig` to bind `SPK_dh` to `deviceId` and timestamp.
     */
    fun buildSpkTranscript(
        deviceId: ByteArray,
        spkId: Int,
        spkPublicKeySpki: ByteArray,
        createdAtEpochSec: Long
    ): ByteArray {
        require(deviceId.size == 16) { "deviceId must be 16 bytes" }
        val buf = ByteBuffer.allocate(SPK_SIG_DOMAIN.size + 16 + 4 + 8 + 4 + spkPublicKeySpki.size)
        buf.put(SPK_SIG_DOMAIN)
        buf.put(deviceId)
        buf.putInt(spkId)
        buf.putLong(createdAtEpochSec)
        buf.putInt(spkPublicKeySpki.size)
        buf.put(spkPublicKeySpki)
        return buf.array()
    }

    fun signSha256Ecdsa(privateKey: PrivateKey, message: ByteArray): ByteArray {
        val sig = Signature.getInstance(SIGNATURE_ALGORITHM)
        sig.initSign(privateKey)
        sig.update(message)
        return sig.sign()
    }

    fun verifySha256Ecdsa(publicKeySpki: ByteArray, message: ByteArray, signatureBytes: ByteArray): Boolean {
        if (signatureBytes.isEmpty() || signatureBytes.size > 80) return false
        return try {
            val pubKey = decodeAndValidateP256PublicKey(publicKeySpki)
            val sig = Signature.getInstance(SIGNATURE_ALGORITHM)
            sig.initVerify(pubKey)
            sig.update(message)
            sig.verify(signatureBytes)
        } catch (_: Exception) {
            false
        }
    }

    fun verifySignedPreKey(
        deviceId: ByteArray,
        identitySigningPublicKeySpki: ByteArray,
        spk: SignedPreKeyPublic
    ): Boolean {
        if (spk.spkId <= 0) return false
        val expectedDeviceId = try {
            computeDeviceId(identitySigningPublicKeySpki)
        } catch (_: Exception) {
            return false
        }
        if (!ByteEncoding.constantTimeEquals(deviceId, expectedDeviceId)) return false
        return try {
            decodeAndValidateP256PublicKey(spk.publicKeySpki)
            val transcript = buildSpkTranscript(deviceId, spk.spkId, spk.publicKeySpki, spk.createdAtEpochSec)
            verifySha256Ecdsa(identitySigningPublicKeySpki, transcript, spk.signatureByIdentityKey)
        } catch (_: Exception) {
            false
        }
    }

    fun ecdhSharedSecret(
        localPrivateKey: PrivateKey,
        peerPublicKeySpki: ByteArray,
        provider: String? = null
    ): ByteArray {
        val peerPublic = decodeAndValidateP256PublicKey(peerPublicKeySpki)
        val ka = if (provider != null) {
            KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM, provider)
        } else {
            KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
        }
        ka.init(localPrivateKey)
        ka.doPhase(peerPublic, true)
        val secret = ka.generateSecret()
        if (secret.size != 32) {
            throw GeneralSecurityException("Unexpected P-256 ECDH shared secret size: ${secret.size}")
        }
        var allZero = 0
        for (b in secret) {
            allZero = allZero or (b.toInt() and 0xFF)
        }
        if (allZero == 0) {
            throw GeneralSecurityException("Rejected degenerate all-zero ECDH shared secret")
        }
        return secret
    }
}

/**
 * Shared fail-closed binary codec & validator for Signed Pre-Key (`SPK_dh`) metadata persisted in
 * [KeyValueByteStore] by both `AndroidKeystoreVault` and [SealedSoftwareKeyVault].
 *
 * Security invariants:
 * 1. Sealed under `MSK` (`AES-256-GCM`) with `AAD = "duolink:spk_meta:v2|" || deviceIdHex`, binding the
 *    metadata list cryptographically to the active `IK_sig` identity key.
 * 2. Stores a monotonic `highestIssuedSpkId` header so `spkId` never rolls back even after rotation pruning.
 * 3. Every loaded `SignedPreKeyPublic` is re-verified against `IK_sig` on load; any bit-flip, truncation,
 *    AAD mismatch, or missing `spk_entries_v2` alongside `vault_init_v2` throws [KeyVaultStorageCorruptedException].
 */
internal object SpkMetadataStoreCodec {
    const val KEY_VAULT_INIT_MARKER = "vault_init_v2"
    const val KEY_SPK_METADATA = "spk_entries_v2"
    private const val SCHEMA_VERSION: Byte = 2
    private val INIT_MAGIC = "DUOLINK_VAULT_INIT_V2".toByteArray(StandardCharsets.UTF_8)

    data class PersistedSpkMetadata(
        val publicPart: SignedPreKeyPublic,
        val usesHardwareKeystore: Boolean
    )

    data class LoadedSpkCatalog(
        val highestIssuedSpkId: Int,
        val entries: List<PersistedSpkMetadata>
    )

    fun aadForInitMarker(deviceId: ByteArray): ByteArray =
        ("duolink:vault_init:v2|" + ByteEncoding.toHexLower(deviceId)).toByteArray(StandardCharsets.UTF_8)

    fun aadForSpkMetadata(deviceId: ByteArray): ByteArray =
        ("duolink:spk_meta:v2|" + ByteEncoding.toHexLower(deviceId)).toByteArray(StandardCharsets.UTF_8)

    fun aadForSoftwareSpkPrivateKey(deviceId: ByteArray, spkId: Int): ByteArray =
        ("duolink:spk_priv:v2|" + ByteEncoding.toHexLower(deviceId) + "|$spkId").toByteArray(StandardCharsets.UTF_8)

    fun writeInitMarker(
        store: KeyValueByteStore,
        sealer: StorageSealer,
        deviceId: ByteArray
    ) {
        val payload = INIT_MAGIC + deviceId
        val sealed = sealer.seal(payload, aadForInitMarker(deviceId))
        store.write(KEY_VAULT_INIT_MARKER, sealed)
    }

    fun verifyInitMarkerIfPresent(
        store: KeyValueByteStore,
        sealer: StorageSealer,
        expectedDeviceId: ByteArray
    ): Boolean {
        return when (val state = store.readState(KEY_VAULT_INIT_MARKER)) {
            is RawStoreRead.Missing -> false
            is RawStoreRead.CorruptedIo -> throw KeyVaultStorageCorruptedException(
                "Corrupted vault initialization marker: ${state.detail}"
            )
            is RawStoreRead.Present -> {
                val plain = try {
                    sealer.unseal(state.bytes, aadForInitMarker(expectedDeviceId))
                } catch (e: Exception) {
                    throw KeyVaultStorageCorruptedException(
                        "Vault initialization marker failed AEAD authentication (identity mismatch or tampering)",
                        e
                    )
                }
                val expected = INIT_MAGIC + expectedDeviceId
                if (!ByteEncoding.constantTimeEquals(plain, expected)) {
                    throw KeyVaultStorageCorruptedException("Vault initialization marker payload mismatch")
                }
                true
            }
        }
    }

    fun saveCatalog(
        store: KeyValueByteStore,
        sealer: StorageSealer,
        deviceId: ByteArray,
        highestIssuedSpkId: Int,
        entries: List<PersistedSpkMetadata>
    ) {
        require(highestIssuedSpkId > 0) { "highestIssuedSpkId must be positive" }
        require(entries.isNotEmpty()) { "SPK catalog must retain at least the active SPK" }
        val totalSize = 1 + 4 + 4 + entries.sumOf {
            4 + 8 + 1 + 4 + it.publicPart.publicKeySpki.size + 4 + it.publicPart.signatureByIdentityKey.size
        }
        val buf = ByteBuffer.allocate(totalSize)
        buf.put(SCHEMA_VERSION)
        buf.putInt(highestIssuedSpkId)
        buf.putInt(entries.size)
        for (entry in entries) {
            buf.putInt(entry.publicPart.spkId)
            buf.putLong(entry.publicPart.createdAtEpochSec)
            buf.put(if (entry.usesHardwareKeystore) 1.toByte() else 0.toByte())
            buf.putInt(entry.publicPart.publicKeySpki.size)
            buf.put(entry.publicPart.publicKeySpki)
            buf.putInt(entry.publicPart.signatureByIdentityKey.size)
            buf.put(entry.publicPart.signatureByIdentityKey)
        }
        val sealed = sealer.seal(buf.array(), aadForSpkMetadata(deviceId))
        store.write(KEY_SPK_METADATA, sealed)
    }

    /**
     * Loads and cryptographically validates the persisted SPK catalog.
     * Returns `null` ONLY when neither `vault_init_v2` nor `spk_entries_v2` exists (genuine first initialization).
     * Any partial deletion, I/O corruption, AEAD tag failure, or signature failure throws [KeyVaultStorageCorruptedException].
     */
    fun loadCatalogStrict(
        store: KeyValueByteStore,
        sealer: StorageSealer,
        deviceId: ByteArray,
        identitySigningPublicKeySpki: ByteArray
    ): LoadedSpkCatalog? {
        val markerInitialized = verifyInitMarkerIfPresent(store, sealer, deviceId)
        return when (val raw = store.readState(KEY_SPK_METADATA)) {
            is RawStoreRead.Missing -> {
                if (markerInitialized) {
                    throw KeyVaultStorageCorruptedException(
                        "SPK metadata file missing after vault initialization (possible file deletion attack)"
                    )
                }
                null
            }
            is RawStoreRead.CorruptedIo -> throw KeyVaultStorageCorruptedException(
                "SPK metadata file I/O corruption: ${raw.detail}"
            )
            is RawStoreRead.Present -> {
                val plain = try {
                    sealer.unseal(raw.bytes, aadForSpkMetadata(deviceId))
                } catch (e: Exception) {
                    throw KeyVaultStorageCorruptedException(
                        "SPK metadata failed AEAD authentication under MSK",
                        e
                    )
                }
                parseAndVerifyCatalog(plain, deviceId, identitySigningPublicKeySpki)
            }
        }
    }

    private fun parseAndVerifyCatalog(
        plain: ByteArray,
        deviceId: ByteArray,
        identitySigningPublicKeySpki: ByteArray
    ): LoadedSpkCatalog {
        try {
            val buf = ByteBuffer.wrap(plain)
            if (buf.remaining() < 9) {
                throw KeyVaultStorageCorruptedException("SPK metadata truncated header")
            }
            val version = buf.get()
            if (version != SCHEMA_VERSION) {
                throw KeyVaultStorageCorruptedException("Unsupported SPK metadata schema version: $version")
            }
            val highestSpkId = buf.int
            val count = buf.int
            if (highestSpkId <= 0 || count !in 1..8) {
                throw KeyVaultStorageCorruptedException(
                    "Invalid SPK catalog bounds (highest=$highestSpkId, count=$count)"
                )
            }
            val list = ArrayList<PersistedSpkMetadata>(count)
            val seenIds = HashSet<Int>(count)
            for (i in 0 until count) {
                val spkId = buf.int
                val createdAt = buf.long
                val hwFlag = buf.get().toInt()
                if (hwFlag != 0 && hwFlag != 1) {
                    throw KeyVaultStorageCorruptedException("Invalid SPK hardware flag: $hwFlag")
                }
                val spkiLen = buf.int
                if (spkiLen != 91 || buf.remaining() < spkiLen + 4) {
                    throw KeyVaultStorageCorruptedException("Invalid SPK SPKI length: $spkiLen")
                }
                val spki = ByteArray(spkiLen).also { buf.get(it) }
                val sigLen = buf.int
                if (sigLen !in 1..80 || buf.remaining() < sigLen) {
                    throw KeyVaultStorageCorruptedException("Invalid SPK signature length: $sigLen")
                }
                val sig = ByteArray(sigLen).also { buf.get(it) }
                val pubPart = SignedPreKeyPublic(spkId, spki, sig, createdAt)
                if (!seenIds.add(spkId) || spkId > highestSpkId) {
                    throw KeyVaultStorageCorruptedException("Inconsistent SPK ID sequence ($spkId > $highestSpkId)")
                }
                if (!EcP256Crypto.verifySignedPreKey(deviceId, identitySigningPublicKeySpki, pubPart)) {
                    throw KeyVaultStorageCorruptedException("Persisted SPK #$spkId failed IK_sig verification")
                }
                list.add(PersistedSpkMetadata(pubPart, hwFlag == 1))
            }
            if (buf.hasRemaining()) {
                throw KeyVaultStorageCorruptedException("Trailing unexpected bytes in SPK metadata")
            }
            return LoadedSpkCatalog(highestSpkId, list)
        } catch (e: KeyVaultStorageCorruptedException) {
            throw e
        } catch (e: Exception) {
            throw KeyVaultStorageCorruptedException("Malformed SPK metadata binary structure", e)
        }
    }
}

/**
 * Persistent software-sealed [DeviceKeyVault] backed by [StorageSealer] and [KeyValueByteStore].
 *
 * Used for deterministic JVM unit/regression tests (including restart persistence and fail-closed
 * SPK metadata/key corruption tests) using the exact same [SpkMetadataStoreCodec] as `AndroidKeystoreVault`.
 */
class SealedSoftwareKeyVault(
    private val sealer: StorageSealer = JcaAesGcmSealer(),
    private val byteStore: KeyValueByteStore = InMemoryByteStore(),
    private val secureRandom: SecureRandom = SecureRandom(),
    private val maxRetainedSignedPreKeys: Int = 3
) : DeviceKeyVault {

    @Synchronized
    override fun checkVaultHealth(): VaultHealth {
        return try {
            val ikPair = loadExistingIdentityKeyPairStrict() ?: return VaultHealth.Healthy
            val deviceId = EcP256Crypto.computeDeviceId(ikPair.second)
            val catalog = SpkMetadataStoreCodec.loadCatalogStrict(
                store = byteStore,
                sealer = sealer,
                deviceId = deviceId,
                identitySigningPublicKeySpki = ikPair.second
            ) ?: throw KeyVaultStorageCorruptedException(
                "Identity key exists in store without SPK metadata catalog"
            )
            // Verify every retained SPK private key blob is readable and authenticates under MSK.
            for (entry in catalog.entries) {
                loadAndUnsealSpkPrivateKeyStrict(deviceId, entry.publicPart.spkId)
            }
            VaultHealth.Healthy
        } catch (e: Exception) {
            VaultHealth.Corrupted(e.message ?: "Corrupted software key vault")
        }
    }

    @Synchronized
    override fun getOrCreateLocalIdentity(nowEpochSec: Long): LocalIdentityPublic {
        val existingIk = loadExistingIdentityKeyPairStrict()
        if (existingIk == null) {
            // Confirm no orphaned init marker or SPK catalog exists without IK_sig.
            if (byteStore.readState(SpkMetadataStoreCodec.KEY_VAULT_INIT_MARKER) !is RawStoreRead.Missing ||
                byteStore.readState(SpkMetadataStoreCodec.KEY_SPK_METADATA) !is RawStoreRead.Missing
            ) {
                throw KeyVaultStorageCorruptedException(
                    "Orphaned SPK metadata found while identity signing key is missing"
                )
            }
            return initializeFreshVault(nowEpochSec)
        }

        val (privBytes, ikSpki) = existingIk
        Arrays.fill(privBytes, 0.toByte())
        val deviceId = EcP256Crypto.computeDeviceId(ikSpki)
        val catalog = SpkMetadataStoreCodec.loadCatalogStrict(
            store = byteStore,
            sealer = sealer,
            deviceId = deviceId,
            identitySigningPublicKeySpki = ikSpki
        ) ?: throw KeyVaultStorageCorruptedException(
            "SPK metadata catalog missing while identity signing key exists"
        )
        val active = catalog.entries.maxByOrNull { it.publicPart.spkId }
            ?: throw KeyVaultStorageCorruptedException("Empty SPK catalog")
        // Verify active private key blob is intact before returning identity.
        val activePrivBytes = loadAndUnsealSpkPrivateKeyStrict(deviceId, active.publicPart.spkId)
        Arrays.fill(activePrivBytes, 0.toByte())

        return LocalIdentityPublic(
            deviceId = deviceId,
            identitySigningPublicKeySpki = ikSpki,
            currentSignedPreKey = active.publicPart
        )
    }

    @Synchronized
    override fun signWithIdentityKey(payload: ByteArray): ByteArray {
        val (pkcs8, _) = loadExistingIdentityKeyPairStrict()
            ?: throw GeneralSecurityException("Identity key not initialized")
        return try {
            val privKey = EcP256Crypto.decodeSoftwarePrivateKey(pkcs8)
            EcP256Crypto.signSha256Ecdsa(privKey, payload)
        } finally {
            Arrays.fill(pkcs8, 0.toByte())
        }
    }

    @Synchronized
    override fun agreeWithSignedPreKey(localSpkId: Int, peerPublicKeySpki: ByteArray): ByteArray {
        val (ikPkcs8, ikSpki) = loadExistingIdentityKeyPairStrict()
            ?: throw GeneralSecurityException("Identity key not initialized")
        Arrays.fill(ikPkcs8, 0.toByte())
        val deviceId = EcP256Crypto.computeDeviceId(ikSpki)
        val catalog = SpkMetadataStoreCodec.loadCatalogStrict(
            store = byteStore,
            sealer = sealer,
            deviceId = deviceId,
            identitySigningPublicKeySpki = ikSpki
        ) ?: throw KeyVaultStorageCorruptedException("Missing SPK catalog")
        if (catalog.entries.none { it.publicPart.spkId == localSpkId }) {
            throw GeneralSecurityException("Signed pre-key ID $localSpkId not found or expired")
        }
        val pkcs8 = loadAndUnsealSpkPrivateKeyStrict(deviceId, localSpkId)
        return try {
            val privKey = EcP256Crypto.decodeSoftwarePrivateKey(pkcs8)
            EcP256Crypto.ecdhSharedSecret(privKey, peerPublicKeySpki)
        } finally {
            Arrays.fill(pkcs8, 0.toByte())
        }
    }

    @Synchronized
    override fun rotateSignedPreKey(nowEpochSec: Long): SignedPreKeyPublic {
        val (ikPkcs8, ikSpki) = loadExistingIdentityKeyPairStrict()
            ?: throw GeneralSecurityException("Identity key not initialized")
        return try {
            val deviceId = EcP256Crypto.computeDeviceId(ikSpki)
            val catalog = SpkMetadataStoreCodec.loadCatalogStrict(
                store = byteStore,
                sealer = sealer,
                deviceId = deviceId,
                identitySigningPublicKeySpki = ikSpki
            ) ?: throw KeyVaultStorageCorruptedException("Missing SPK catalog during rotation")
            val nextSpkId = catalog.highestIssuedSpkId + 1
            val newMeta = generateAndPersistSpk(
                ikPrivateKey = EcP256Crypto.decodeSoftwarePrivateKey(ikPkcs8),
                deviceId = deviceId,
                spkId = nextSpkId,
                nowEpochSec = nowEpochSec
            )
            val merged = (catalog.entries + newMeta).sortedBy { it.publicPart.spkId }
            val retained = if (merged.size > maxRetainedSignedPreKeys) {
                val evicted = merged.dropLast(maxRetainedSignedPreKeys)
                evicted.forEach { byteStore.delete(spkPrivateKeyStoreKey(it.publicPart.spkId)) }
                merged.takeLast(maxRetainedSignedPreKeys)
            } else {
                merged
            }
            SpkMetadataStoreCodec.saveCatalog(
                store = byteStore,
                sealer = sealer,
                deviceId = deviceId,
                highestIssuedSpkId = nextSpkId,
                entries = retained
            )
            newMeta.publicPart
        } finally {
            Arrays.fill(ikPkcs8, 0.toByte())
        }
    }

    @Synchronized
    override fun resetIdentityKeys(nowEpochSec: Long): LocalIdentityPublic {
        // Purge known keys cleanly before generating a brand-new identity.
        for (spkId in 1..64) {
            byteStore.delete(spkPrivateKeyStoreKey(spkId))
        }
        byteStore.delete(SpkMetadataStoreCodec.KEY_SPK_METADATA)
        byteStore.delete(SpkMetadataStoreCodec.KEY_VAULT_INIT_MARKER)
        byteStore.delete(KEY_SEALED_IK)
        return initializeFreshVault(nowEpochSec)
    }

    @Synchronized
    override fun getKeyProtectionReport(nowEpochSec: Long): KeyProtectionReport {
        getOrCreateLocalIdentity(nowEpochSec)
        return KeyProtectionReport(
            identitySigningKey = SingleKeyProtectionStatus(
                keyRolePersian = "کلید امضای هویت دستگاه (IK_sig)",
                algorithm = "ECDSA P-256 (SHA-256)",
                tier = KeyProtectionTier.JVM_TEST_SOFTWARE,
                persianDescription = "محیط تست JVM (کلید امضای نرم‌افزاری رمزنگاری‌شده؛ غیرسخت‌افزاری)"
            ),
            storageWrappingKey = sealer.queryProtectionStatus(),
            activeSignedPreKey = SingleKeyProtectionStatus(
                keyRolePersian = "پیش‌کلید امضاشده توافق کلید (SPK_dh)",
                algorithm = "ECDH P-256",
                tier = KeyProtectionTier.SOFTWARE_WRAPPED_AT_REST,
                persianDescription = "نرم‌افزاری (رمزنگاری‌شده در حافظه با کلید AES-256-GCM؛ غیرسخت‌افزاری و موقتاً در RAM هنگام ECDH)"
            )
        )
    }

    private fun initializeFreshVault(nowEpochSec: Long): LocalIdentityPublic {
        val ikKp = EcP256Crypto.generateSoftwareP256KeyPair(secureRandom)
        val ikSpki = ikKp.public.encoded
        val ikPkcs8 = ikKp.private.encoded
        val deviceId = EcP256Crypto.computeDeviceId(ikSpki)
        try {
            val ikBlob = ByteBuffer.allocate(1 + 4 + ikSpki.size + 4 + ikPkcs8.size).apply {
                put(1.toByte())
                putInt(ikSpki.size)
                put(ikSpki)
                putInt(ikPkcs8.size)
                put(ikPkcs8)
            }.array()
            byteStore.write(KEY_SEALED_IK, sealer.seal(ikBlob, AAD_IK))
            SpkMetadataStoreCodec.writeInitMarker(byteStore, sealer, deviceId)
            val firstSpk = generateAndPersistSpk(
                ikPrivateKey = ikKp.private,
                deviceId = deviceId,
                spkId = 1,
                nowEpochSec = nowEpochSec
            )
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
        } finally {
            Arrays.fill(ikPkcs8, 0.toByte())
        }
    }

    private fun generateAndPersistSpk(
        ikPrivateKey: PrivateKey,
        deviceId: ByteArray,
        spkId: Int,
        nowEpochSec: Long
    ): SpkMetadataStoreCodec.PersistedSpkMetadata {
        val kp = EcP256Crypto.generateSoftwareP256KeyPair(secureRandom)
        val spki = kp.public.encoded
        val pkcs8 = kp.private.encoded
        try {
            val transcript = EcP256Crypto.buildSpkTranscript(deviceId, spkId, spki, nowEpochSec)
            val sig = EcP256Crypto.signSha256Ecdsa(ikPrivateKey, transcript)
            val sealedPriv = sealer.seal(
                pkcs8,
                SpkMetadataStoreCodec.aadForSoftwareSpkPrivateKey(deviceId, spkId)
            )
            byteStore.write(spkPrivateKeyStoreKey(spkId), sealedPriv)
            return SpkMetadataStoreCodec.PersistedSpkMetadata(
                publicPart = SignedPreKeyPublic(
                    spkId = spkId,
                    publicKeySpki = spki,
                    signatureByIdentityKey = sig,
                    createdAtEpochSec = nowEpochSec
                ),
                usesHardwareKeystore = false
            )
        } finally {
            Arrays.fill(pkcs8, 0.toByte())
        }
    }

    private fun loadExistingIdentityKeyPairStrict(): Pair<ByteArray, ByteArray>? {
        return when (val raw = byteStore.readState(KEY_SEALED_IK)) {
            is RawStoreRead.Missing -> null
            is RawStoreRead.CorruptedIo -> throw KeyVaultStorageCorruptedException(
                "Identity signing key file I/O corruption: ${raw.detail}"
            )
            is RawStoreRead.Present -> {
                val plain = try {
                    sealer.unseal(raw.bytes, AAD_IK)
                } catch (e: Exception) {
                    throw KeyVaultStorageCorruptedException(
                        "Identity signing key failed AEAD authentication under MSK",
                        e
                    )
                }
                try {
                    val buf = ByteBuffer.wrap(plain)
                    val ver = buf.get()
                    if (ver != 1.toByte()) {
                        throw KeyVaultStorageCorruptedException("Unsupported sealed IK schema: $ver")
                    }
                    val spkiLen = buf.int
                    if (spkiLen != 91 || buf.remaining() < spkiLen + 4) {
                        throw KeyVaultStorageCorruptedException("Invalid sealed IK SPKI length")
                    }
                    val spki = ByteArray(spkiLen).also { buf.get(it) }
                    EcP256Crypto.decodeAndValidateP256PublicKey(spki)
                    val pkcs8Len = buf.int
                    if (pkcs8Len !in 32..512 || buf.remaining() != pkcs8Len) {
                        throw KeyVaultStorageCorruptedException("Invalid sealed IK PKCS#8 length")
                    }
                    val pkcs8 = ByteArray(pkcs8Len).also { buf.get(it) }
                    pkcs8 to spki
                } catch (e: KeyVaultStorageCorruptedException) {
                    throw e
                } catch (e: Exception) {
                    throw KeyVaultStorageCorruptedException("Malformed sealed IK blob", e)
                }
            }
        }
    }

    private fun loadAndUnsealSpkPrivateKeyStrict(deviceId: ByteArray, spkId: Int): ByteArray {
        return when (val raw = byteStore.readState(spkPrivateKeyStoreKey(spkId))) {
            is RawStoreRead.Missing -> throw KeyVaultStorageCorruptedException(
                "Sealed SPK #$spkId private key blob missing from store"
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
                        "Sealed SPK #$spkId private key failed AEAD authentication",
                        e
                    )
                }
            }
        }
    }

    private fun spkPrivateKeyStoreKey(spkId: Int): String = "sealed_spk_v2_$spkId"

    companion object {
        private val AAD_IK = "duolink:ik_sig:v2".toByteArray(StandardCharsets.UTF_8)
        private const val KEY_SEALED_IK = "sealed_ik_v2"
    }
}
