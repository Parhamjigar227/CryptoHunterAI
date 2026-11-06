package com.duolink.app.crypto

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

data class SignedPreKeyPublic(
    val spkId: Int,
    val publicKeySpki: ByteArray,
    val issuedAtEpochSec: Long,
    val expiresAtEpochSec: Long,
    val signature: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignedPreKeyPublic) return false
        return spkId == other.spkId &&
            issuedAtEpochSec == other.issuedAtEpochSec &&
            expiresAtEpochSec == other.expiresAtEpochSec &&
            publicKeySpki.contentEquals(other.publicKeySpki) &&
            signature.contentEquals(other.signature)
    }

    override fun hashCode(): Int {
        var result = spkId
        result = 31 * result + publicKeySpki.contentHashCode()
        result = 31 * result + issuedAtEpochSec.hashCode()
        result = 31 * result + expiresAtEpochSec.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

/**
 * Standard NIST P-256 (secp256r1) cryptographic validation, signature verification,
 * ECDH key agreement, and HKDF root key derivation.
 */
object EcP256Crypto {
    const val CURVE_STD_NAME = "secp256r1"
    const val SIGNATURE_ALG = "SHA256withECDSA"
    const val ECDH_ALG = "ECDH"
    const val DEFAULT_SPK_VALIDITY_SEC: Long = 30L * 24L * 3600L // 30 days
    private const val MAX_DER_SIG_BYTES = 80
    private const val MIN_DER_SIG_BYTES = 64

    // Official FIPS 186-4 / SEC 2 secp256r1 domain parameters
    private val P256_P = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    private val P256_A = BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)
    private val P256_B = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    private val P256_GX = BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
    private val P256_GY = BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
    private val P256_N = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

    /**
     * Parses X.509 SubjectPublicKeyInfo DER bytes and strictly validates:
     * 1. Key type is ECPublicKey on exact NIST P-256 (secp256r1) parameters.
     * 2. Point Q is not infinity, coordinates in [0, p-1], and satisfies y^2 = x^3 + ax + b (mod p)
     *    (defends against invalid-curve / twist attacks prior to ECDH).
     * 3. Canonical DER round-trip matches input byte-for-byte (prevents DER malleability).
     */
    fun validateAndParsePublicKey(spkiBytes: ByteArray): ECPublicKey {
        if (spkiBytes.size !in 88..96) {
            throw GeneralSecurityException("Unexpected EC P-256 SPKI key length: ${spkiBytes.size}")
        }
        val kf = KeyFactory.getInstance("EC")
        val pub = kf.generatePublic(X509EncodedKeySpec(spkiBytes)) as? ECPublicKey
            ?: throw GeneralSecurityException("Decoded key is not an ECPublicKey")

        val params = pub.params
        val field = params.curve.field as? ECFieldFp
            ?: throw GeneralSecurityException("EC key does not use prime field Fp")

        if (field.p != P256_P ||
            params.curve.a != P256_A ||
            params.curve.b != P256_B ||
            params.generator.affineX != P256_GX ||
            params.generator.affineY != P256_GY ||
            params.order != P256_N ||
            params.cofactor != 1
        ) {
            throw GeneralSecurityException("EC key parameters do not match secp256r1")
        }

        val w = pub.w
        if (w == ECPoint.POINT_INFINITY) {
            throw GeneralSecurityException("Invalid EC public key: point at infinity")
        }
        val x = w.affineX
        val y = w.affineY
        if (x < BigInteger.ZERO || x >= P256_P || y < BigInteger.ZERO || y >= P256_P) {
            throw GeneralSecurityException("EC public key coordinates out of field range")
        }
        val lhs = y.modPow(BigInteger.TWO, P256_P)
        val rhs = (x.modPow(BigInteger.valueOf(3), P256_P) + P256_A.multiply(x) + P256_B).mod(P256_P)
        if (lhs != rhs) {
            throw GeneralSecurityException("Invalid EC public key: point does not lie on secp256r1")
        }

        val reEncoded = pub.encoded ?: throw GeneralSecurityException("EC public key re-encoding failed")
        if (!ByteEncoding.constantTimeEquals(reEncoded, spkiBytes)) {
            throw GeneralSecurityException("Non-canonical X.509 SPKI DER encoding rejected")
        }
        return pub
    }

    /**
     * Deterministically binds 128-bit deviceId (32 lowercase hex chars) to IK_sig public key.
     */
    fun computeDeviceId(ikSigPublicKeySpki: ByteArray): String {
        validateAndParsePublicKey(ikSigPublicKeySpki)
        val prefix = "DUOLINK-DEVICE-ID-V1\u0000".toByteArray(StandardCharsets.UTF_8)
        val buf = ByteArray(prefix.size + ikSigPublicKeySpki.size)
        System.arraycopy(prefix, 0, buf, 0, prefix.size)
        System.arraycopy(ikSigPublicKeySpki, 0, buf, prefix.size, ikSigPublicKeySpki.size)
        val digest = ByteEncoding.sha256(buf)
        return ByteEncoding.toHexLower(digest.copyOfRange(0, 16))
    }

    fun buildSignedPreKeyTranscript(
        deviceId: String,
        spkId: Int,
        issuedAtEpochSec: Long,
        expiresAtEpochSec: Long,
        spkPublicKeySpki: ByteArray
    ): ByteArray = TranscriptBuilder()
        .putUtf8("DUOLINK-SPK-V1")
        .putUtf8(deviceId)
        .putInt32(spkId)
        .putInt64(issuedAtEpochSec)
        .putInt64(expiresAtEpochSec)
        .putBytes(spkPublicKeySpki)
        .build()

    fun verifyIdentitySignature(
        ikSigPublicKeySpki: ByteArray,
        transcript: ByteArray,
        signatureBytes: ByteArray
    ): Boolean {
        if (signatureBytes.size !in MIN_DER_SIG_BYTES..MAX_DER_SIG_BYTES) return false
        return try {
            val pubKey = validateAndParsePublicKey(ikSigPublicKeySpki)
            val verifier = Signature.getInstance(SIGNATURE_ALG)
            verifier.initVerify(pubKey)
            verifier.update(transcript)
            verifier.verify(signatureBytes)
        } catch (_: Exception) {
            false
        }
    }

    fun verifySignedPreKey(
        deviceId: String,
        ikSigPublicKeySpki: ByteArray,
        spk: SignedPreKeyPublic
    ): Boolean {
        if (spk.spkId <= 0 || spk.expiresAtEpochSec <= spk.issuedAtEpochSec) return false
        return try {
            if (computeDeviceId(ikSigPublicKeySpki) != deviceId) return false
            validateAndParsePublicKey(spk.publicKeySpki)
            // Enforce key-purpose separation: SPK_dh must never equal IK_sig
            if (ByteEncoding.constantTimeEquals(ikSigPublicKeySpki, spk.publicKeySpki)) return false
            val transcript = buildSignedPreKeyTranscript(
                deviceId = deviceId,
                spkId = spk.spkId,
                issuedAtEpochSec = spk.issuedAtEpochSec,
                expiresAtEpochSec = spk.expiresAtEpochSec,
                spkPublicKeySpki = spk.publicKeySpki
            )
            verifyIdentitySignature(ikSigPublicKeySpki, transcript, spk.signature)
        } catch (_: Exception) {
            false
        }
    }

    fun generateSoftwareEcP256KeyPair(secureRandom: SecureRandom = SecureRandom()): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec(CURVE_STD_NAME), secureRandom)
        return kpg.generateKeyPair()
    }

    fun computeEcdhSharedSecret(localPrivateKey: PrivateKey, peerPublicKeySpki: ByteArray, provider: String? = null): ByteArray {
        val peerPub = validateAndParsePublicKey(peerPublicKeySpki)
        val ka = if (provider != null) {
            KeyAgreement.getInstance(ECDH_ALG, provider)
        } else {
            KeyAgreement.getInstance(ECDH_ALG)
        }
        ka.init(localPrivateKey)
        ka.doPhase(peerPub, true)
        val secret = ka.generateSecret()
        if (secret.size != 32 || secret.all { it == 0.toByte() }) {
            secret.zeroize()
            throw GeneralSecurityException("Invalid ECDH shared secret")
        }
        return secret
    }

    /**
     * Derives the 256-bit Root Pairing Key (RPK) from mutual ECDH + nonces + full identity binding.
     * Raw dhSharedSecret is zeroized before returning.
     */
    fun deriveRootPairingKey(
        dhSharedSecret: ByteArray,
        sessionId: String,
        offerNonce: ByteArray,
        acceptNonce: ByteArray,
        offerDeviceId: String,
        offerIkSpki: ByteArray,
        acceptDeviceId: String,
        acceptIkSpki: ByteArray
    ): ByteArray {
        try {
            val saltInput = TranscriptBuilder()
                .putUtf8("DUOLINK-PAIR-SALT-V1")
                .putBytes(offerNonce)
                .putBytes(acceptNonce)
                .build()
            val salt = ByteEncoding.sha256(saltInput)
            val info = TranscriptBuilder()
                .putUtf8("DUOLINK-PAIR-ROOT-V1")
                .putUtf8(sessionId)
                .putUtf8(offerDeviceId)
                .putBytes(offerIkSpki)
                .putUtf8(acceptDeviceId)
                .putBytes(acceptIkSpki)
                .build()
            return HkdfSha256.deriveKey(
                ikm = dhSharedSecret,
                salt = salt,
                info = info,
                outputLength = 32
            )
        } finally {
            dhSharedSecret.zeroize()
        }
    }
}

/**
 * Abstraction for local device identity signing and signed pre-key ECDH operations.
 * Private keys never leave the vault implementation.
 */
interface DeviceKeyVault {
    val isHardwareBacked: Boolean
    val hardwareDescription: String
    fun getIdentityPublicKeySpki(): ByteArray
    fun getDeviceId(): String
    fun signWithIdentity(transcript: ByteArray): ByteArray
    fun getCurrentSignedPreKey(nowEpochSec: Long): SignedPreKeyPublic
    fun rotateSignedPreKey(nowEpochSec: Long): SignedPreKeyPublic
    fun agreeWithSignedPreKey(localSpkId: Int, peerDhPublicKeySpki: ByteArray): ByteArray
    fun resetIdentityKeys(nowEpochSec: Long)
}

/**
 * JCA-backed vault sealing all private key material under a StorageSealer (used in JVM unit tests).
 * Private keys are never exposed through any public method.
 */
class SealedSoftwareKeyVault(
    private val sealer: StorageSealer = JcaAesGcmSealer(),
    initialNowEpochSec: Long = System.currentTimeMillis() / 1000L,
    private val secureRandom: SecureRandom = SecureRandom()
) : DeviceKeyVault {

    override val isHardwareBacked: Boolean = false
    override val hardwareDescription: String = "JCA Sealed Vault (JVM)"

    private var sealedIdentityPkcs8: ByteArray = ByteArray(0)
    private var identityPublicSpki: ByteArray = ByteArray(0)
    private var nextSpkId: Int = 1
    private val sealedSpkPkcs8ById = LinkedHashMap<Int, ByteArray>()
    private var currentSpkPublic: SignedPreKeyPublic? = null

    init {
        resetIdentityKeys(initialNowEpochSec)
    }

    override fun getIdentityPublicKeySpki(): ByteArray = identityPublicSpki.copyOf()

    override fun getDeviceId(): String = EcP256Crypto.computeDeviceId(identityPublicSpki)

    override fun signWithIdentity(transcript: ByteArray): ByteArray {
        val pkcs8 = sealer.unseal(sealedIdentityPkcs8, AAD_IDENTITY)
        return try {
            val priv = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            val sig = Signature.getInstance(EcP256Crypto.SIGNATURE_ALG)
            sig.initSign(priv, secureRandom)
            sig.update(transcript)
            sig.sign()
        } finally {
            pkcs8.zeroize()
        }
    }

    override fun getCurrentSignedPreKey(nowEpochSec: Long): SignedPreKeyPublic {
        val existing = currentSpkPublic
        if (existing != null && nowEpochSec < existing.expiresAtEpochSec) {
            return existing
        }
        return rotateSignedPreKey(nowEpochSec)
    }

    override fun rotateSignedPreKey(nowEpochSec: Long): SignedPreKeyPublic {
        val spkId = nextSpkId++
        val kp = EcP256Crypto.generateSoftwareEcP256KeyPair(secureRandom)
        val pkcs8 = kp.private.encoded
        val spki = kp.public.encoded
        val aad = "duolink:spk_dh:v1|$spkId".toByteArray(StandardCharsets.UTF_8)
        try {
            sealedSpkPkcs8ById[spkId] = sealer.seal(pkcs8, aad)
            // Keep at most 3 recent pre-keys to bound storage and retire old private keys
            while (sealedSpkPkcs8ById.size > 3) {
                val oldest = sealedSpkPkcs8ById.keys.first()
                sealedSpkPkcs8ById.remove(oldest)
            }
        } finally {
            pkcs8.zeroize()
        }
        val expiresAt = nowEpochSec + EcP256Crypto.DEFAULT_SPK_VALIDITY_SEC
        val deviceId = getDeviceId()
        val transcript = EcP256Crypto.buildSignedPreKeyTranscript(
            deviceId = deviceId,
            spkId = spkId,
            issuedAtEpochSec = nowEpochSec,
            expiresAtEpochSec = expiresAt,
            spkPublicKeySpki = spki
        )
        val sig = signWithIdentity(transcript)
        return SignedPreKeyPublic(
            spkId = spkId,
            publicKeySpki = spki,
            issuedAtEpochSec = nowEpochSec,
            expiresAtEpochSec = expiresAt,
            signature = sig
        ).also { currentSpkPublic = it }
    }

    override fun agreeWithSignedPreKey(localSpkId: Int, peerDhPublicKeySpki: ByteArray): ByteArray {
        val sealedPkcs8 = sealedSpkPkcs8ById[localSpkId]
            ?: throw GeneralSecurityException("Signed pre-key ID $localSpkId not found or retired")
        val aad = "duolink:spk_dh:v1|$localSpkId".toByteArray(StandardCharsets.UTF_8)
        val pkcs8 = sealer.unseal(sealedPkcs8, aad)
        return try {
            val priv = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            EcP256Crypto.computeEcdhSharedSecret(priv, peerDhPublicKeySpki)
        } finally {
            pkcs8.zeroize()
        }
    }

    override fun resetIdentityKeys(nowEpochSec: Long) {
        sealedSpkPkcs8ById.clear()
        currentSpkPublic = null
        val kp = EcP256Crypto.generateSoftwareEcP256KeyPair(secureRandom)
        val pkcs8 = kp.private.encoded
        try {
            sealedIdentityPkcs8 = sealer.seal(pkcs8, AAD_IDENTITY)
            identityPublicSpki = kp.public.encoded
        } finally {
            pkcs8.zeroize()
        }
        rotateSignedPreKey(nowEpochSec)
    }

    companion object {
        private val AAD_IDENTITY = "duolink:ik_sig:v1".toByteArray(StandardCharsets.UTF_8)
    }
}
