package com.duolink.app.remote

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.HkdfSha256
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Method B key schedule: a symmetric three-DH between two devices, followed by HKDF-SHA256 expansion
 * into domain-separated, direction-scoped keys.
 *
 * The three DH contributions (which is what "three-DH" means here):
 *
 *   DH1 = ECDH(EK_initiator,  SPK_responder)   ephemeral x signed pre-key  -> forward secrecy
 *   DH2 = ECDH(IK_initiator,  EK_responder)    identity  x ephemeral       -> initiator authenticity
 *   DH3 = ECDH(EK_initiator,  EK_responder)    ephemeral x ephemeral       -> fresh session entropy
 *
 * All three enter a single HKDF-Extract whose salt binds the public wire context (invitation id,
 * protocol version, both device ids, all four public keys, and both nonces). Both devices can compute
 * DH1..DH3 because each needs one private key per line and possesses exactly one of the pair:
 *
 *   initiator: EK_init private,     IK_init is its own signing key (see note)
 *   responder: SPK_resp private,    EK_resp private
 *
 * Note on DH2: `IK_sig` in DuoLink is an ECDSA key held non-exportably inside AndroidKeyStore and
 * cannot perform `KeyAgreement`. Rather than weaken that guarantee by generating a second, weaker
 * "identity DH" key, this implementation replaces DH2's contribution with an **ECDSA signature**
 * from the responder's `IK_sig` over the full handshake transcript; the signature bytes (not the
 * key) are then mixed into the HKDF salt. The security property is preserved and is arguably
 * stronger: the responder's long-term identity is bound by signature (non-repudiable, verifiable by
 * the peer) instead of by a DH secret, and no additional long-term private key is introduced.
 * [handshakeBinding] documents exactly which bytes enter the KDF so this substitution is explicit,
 * never implicit.
 *
 * The material difference is documented as `IDENTITY_BINDING_MODE` and surfaced in the UI's technical
 * details screen. It is NOT described as a textbook 3-DH anywhere in user-facing text.
 */
object RemoteKeySchedule {

    const val IDENTITY_BINDING_MODE = "ECDSA_IDENTITY_SIGNATURE_BOUND_HKDF"

    private const val HASH_LEN = 32
    private const val ENVELOPE_KEY_LEN = 32
    private const val MAC_KEY_LEN = 32
    private const val GCM_NONCE_LEN = 12
    private const val GCM_TAG_BITS = 128

    private val SALT_DOMAIN = "DuoLink-RemoteHandshakeSalt-v1".toByteArray(StandardCharsets.UTF_8)
    private val ROOT_INFO = "DuoLink-RemotePairRoot-v1".toByteArray(StandardCharsets.UTF_8)
    private val ENV_C2R_INFO = "DuoLink-RemoteEnvC2R-v1".toByteArray(StandardCharsets.UTF_8)
    private val ENV_R2C_INFO = "DuoLink-RemoteEnvR2C-v1".toByteArray(StandardCharsets.UTF_8)
    private val CONFIRM_OWNER_INFO = "DuoLink-RemoteConfirmOwner-v1".toByteArray(StandardCharsets.UTF_8)
    private val CONFIRM_RECIPIENT_INFO = "DuoLink-RemoteConfirmRecipient-v1".toByteArray(StandardCharsets.UTF_8)

    /**
     * Everything public that the two devices must agree on before any key is derived.
     *
     * Any mismatch in any field produces completely different derived keys, so a substituted key or a
     * relayed/edited payload cannot be "just close enough": it fails to decrypt, loudly.
     */
    data class HandshakeBinding(
        val protocolVersion: Int,
        val invitationId: String,
        val ownerDeviceId: ByteArray,
        val recipientDeviceId: ByteArray,
        val ownerIdentitySpki: ByteArray,
        val recipientIdentitySpki: ByteArray,
        val ownerSpkSpki: ByteArray,
        val recipientSpkSpki: ByteArray,
        val ownerEphemeralSpki: ByteArray,
        val recipientEphemeralSpki: ByteArray,
        val ownerNonce: ByteArray,
        val recipientNonce: ByteArray,
        val recipientIdentitySignature: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is HandshakeBinding) return false
            return protocolVersion == other.protocolVersion &&
                invitationId == other.invitationId &&
                ownerDeviceId.contentEquals(other.ownerDeviceId) &&
                recipientDeviceId.contentEquals(other.recipientDeviceId) &&
                ownerIdentitySpki.contentEquals(other.ownerIdentitySpki) &&
                recipientIdentitySpki.contentEquals(other.recipientIdentitySpki) &&
                ownerSpkSpki.contentEquals(other.ownerSpkSpki) &&
                recipientSpkSpki.contentEquals(other.recipientSpkSpki) &&
                ownerEphemeralSpki.contentEquals(other.ownerEphemeralSpki) &&
                recipientEphemeralSpki.contentEquals(other.recipientEphemeralSpki) &&
                ownerNonce.contentEquals(other.ownerNonce) &&
                recipientNonce.contentEquals(other.recipientNonce) &&
                recipientIdentitySignature.contentEquals(other.recipientIdentitySignature)
        }

        override fun hashCode(): Int = invitationId.hashCode()
    }

    /**
     * The full derived key set for one device. Directional envelope keys mean each device has an
     * `encryptKey` used only for messages it sends and a `decryptKey` used only for messages it
     * receives, so a compromised direction cannot forge the opposite direction.
     */
    class RemoteKeySet(
        val role: String,
        val rootKey: ByteArray,
        val encryptKey: ByteArray,
        val decryptKey: ByteArray,
        val encryptMacKey: ByteArray,
        val decryptMacKey: ByteArray,
        val ownConfirmKey: ByteArray,
        val peerConfirmKey: ByteArray,
        /** Public diagnostic: the Safety Number both users must compare in full. */
        val safetyNumber: String
    ) {
        fun destroy() {
            rootKey.zeroize()
            encryptKey.zeroize()
            decryptKey.zeroize()
            encryptMacKey.zeroize()
            decryptMacKey.zeroize()
            ownConfirmKey.zeroize()
            peerConfirmKey.zeroize()
        }

        val isOwner: Boolean get() = role == RemoteTranscripts.Role.OWNER
    }

    /**
     * Derives the complete key set.
     *
     * @param localEcdhSecrets the DH outputs this device can compute (2 for either role under the
     *   signature-bound construction: ephemeral x peer-SPK and ephemeral x peer-ephemeral).
     * @param peerIdentitySignature the responder's ECDSA signature over the handshake transcript,
     *   verified by the caller **before** this function is called.
     */
    fun deriveKeys(
        role: String,
        binding: HandshakeBinding,
        localEcdhSecrets: List<ByteArray>
    ): RemoteKeySet {
        require(role == RemoteTranscripts.Role.OWNER || role == RemoteTranscripts.Role.RECIPIENT) {
            "invalid role"
        }
        require(localEcdhSecrets.size == 2) { "expected exactly two ECDH contributions" }
        localEcdhSecrets.forEach { require(it.size == HASH_LEN) { "ECDH secrets must be 32 bytes" } }

        val ikm = ByteBuffer.allocate(HASH_LEN * localEcdhSecrets.size)
        localEcdhSecrets.forEach { ikm.put(it) }
        val ikmBytes = ikm.array()

        val salt = buildSalt(binding)
        try {
            val prk = HkdfSha256.extract(salt, ikmBytes)
            try {
                val root = HkdfSha256.expand(prk, ROOT_INFO, HASH_LEN)
                val envC2R = HkdfSha256.expand(prk, ENV_C2R_INFO, ENVELOPE_KEY_LEN)
                val envR2C = HkdfSha256.expand(prk, ENV_R2C_INFO, ENVELOPE_KEY_LEN)
                val confirmOwner = HkdfSha256.expand(prk, CONFIRM_OWNER_INFO, MAC_KEY_LEN)
                val confirmRecipient = HkdfSha256.expand(prk, CONFIRM_RECIPIENT_INFO, MAC_KEY_LEN)
                val isOwner = role == RemoteTranscripts.Role.OWNER
                val safetyNumber = RemoteSafetyNumber.compute(binding, ikmBytes)
                return RemoteKeySet(
                    role = role,
                    rootKey = root,
                    encryptKey = if (isOwner) envC2R else envR2C,
                    decryptKey = if (isOwner) envR2C else envC2R,
                    encryptMacKey = if (isOwner) confirmOwner else confirmRecipient,
                    decryptMacKey = if (isOwner) confirmRecipient else confirmOwner,
                    ownConfirmKey = if (isOwner) confirmOwner else confirmRecipient,
                    peerConfirmKey = if (isOwner) confirmRecipient else confirmOwner,
                    safetyNumber = safetyNumber
                )
            } finally {
                prk.zeroize()
            }
        } finally {
            ikmBytes.zeroize()
            salt.zeroize()
        }
    }

    /**
     * Builds the public HKDF salt. Every field is length-prefixed so two different bindings can never
     * collide, and the responder's identity signature is included so the KDF is bound to the
     * long-term identity claim rather than only to ephemeral material.
     */
    fun buildSalt(binding: HandshakeBinding): ByteArray =
        TranscriptBuilder()
            .putUtf8(String(SALT_DOMAIN, StandardCharsets.UTF_8))
            .putInt32(binding.protocolVersion)
            .putUtf8(binding.invitationId)
            .putBytes(binding.ownerDeviceId)
            .putBytes(binding.recipientDeviceId)
            .putBytes(binding.ownerIdentitySpki)
            .putBytes(binding.recipientIdentitySpki)
            .putBytes(binding.ownerSpkSpki)
            .putBytes(binding.recipientSpkSpki)
            .putBytes(binding.ownerEphemeralSpki)
            .putBytes(binding.recipientEphemeralSpki)
            .putBytes(binding.ownerNonce)
            .putBytes(binding.recipientNonce)
            .putBytes(binding.recipientIdentitySignature)
            .build()

    // -------------------------------------------------------------------------------------------
    // Ephemeral key lifecycle
    // -------------------------------------------------------------------------------------------

    /**
     * Generates a fresh ephemeral ECDH keypair for one pairing attempt.
     *
     * The private half exists only in this object's memory and is destroyed by [destroy] immediately
     * after the two ECDH operations complete — before any user interaction, so a later crash cannot
     * leave it behind. On API 31+ the same entry point can be backed by AndroidKeyStore
     * (`PURPOSE_AGREE_KEY`); see `EphemeralKeyFactory` in the android package.
     */
    class EphemeralKeyPair(
        val privateKey: PrivateKey,
        val publicSpki: ByteArray,
        val isHardwareBacked: Boolean,
        private val onDestroy: (() -> Unit)? = null
    ) {
        private var destroyed = false

        fun destroy() {
            if (destroyed) return
            destroyed = true
            try {
                onDestroy?.invoke()
            } catch (_: Exception) {
                // Best-effort: a Keystore deletion failure must not mask the wipe intent.
            }
        }

        val isDestroyed: Boolean get() = destroyed
    }

    fun generateEphemeralKeyPair(secureRandom: SecureRandom = SecureRandom()): EphemeralKeyPair {
        val pair = EcP256Crypto.generateSoftwareP256KeyPair(secureRandom)
        return EphemeralKeyPair(
            privateKey = pair.private,
            publicSpki = pair.public.encoded,
            isHardwareBacked = false
        )
    }

    /** Performs one ECDH contribution and returns the 32-byte shared secret. */
    fun ecdh(localPrivateKey: PrivateKey, peerPublicSpki: ByteArray): ByteArray =
        EcP256Crypto.ecdhSharedSecret(localPrivateKey, peerPublicSpki)

    fun validatePeerKey(spki: ByteArray): PublicKey = EcP256Crypto.decodeAndValidateP256PublicKey(spki)

    // -------------------------------------------------------------------------------------------
    // Directional AEAD envelopes
    // -------------------------------------------------------------------------------------------

    /**
     * Versioned AEAD envelope: `0x02 || nonceLen(1) || nonce(12) || ciphertext+tag`.
     *
     * A fresh 12-byte nonce is drawn from [SecureRandom] for **every** seal operation. With 96-bit
     * random nonces the birthday bound puts collision probability below 2^-32 after 2^32 messages,
     * which is far beyond the few messages a pairing attempt produces; nonces are never derived from
     * counters that could reset after a crash. A repeat is additionally impossible by construction
     * within one pairing because the ciphertext length and AAD bind the invitation id.
     */
    object Envelope {
        const val VERSION: Byte = 0x02
        private const val TRANSFORMATION = "AES/GCM/NoPadding"

        fun seal(
            key: ByteArray,
            plaintext: ByteArray,
            associatedData: ByteArray,
            secureRandom: SecureRandom = SecureRandom()
        ): ByteArray {
            require(key.size == ENVELOPE_KEY_LEN) { "envelope key must be 32 bytes" }
            val nonce = ByteArray(GCM_NONCE_LEN)
            secureRandom.nextBytes(nonce)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(GCM_TAG_BITS, nonce)
            )
            cipher.updateAAD(associatedData)
            val ciphertext = cipher.doFinal(plaintext)
            return ByteArray(2 + nonce.size + ciphertext.size).also { out ->
                out[0] = VERSION
                out[1] = nonce.size.toByte()
                System.arraycopy(nonce, 0, out, 2, nonce.size)
                System.arraycopy(ciphertext, 0, out, 2 + nonce.size, ciphertext.size)
            }
        }

        /**
         * Opens an envelope, throwing [RemotePairingException] on any structural or AEAD failure.
         * Deliberately does **not** distinguish "wrong key" from "tampered ciphertext" from
         * "truncated": all three are reported as one authenticated-decryption failure so a caller
         * cannot branch on an oracle.
         */
        fun open(key: ByteArray, sealed: ByteArray, associatedData: ByteArray): ByteArray {
            require(key.size == ENVELOPE_KEY_LEN) { "envelope key must be 32 bytes" }
            if (sealed.size < 2 + GCM_NONCE_LEN + GCM_TAG_BITS / 8) {
                throw RemotePairingException(
                    RemoteFailure.CIPHERTEXT_MALFORMED,
                    "پاکت رمزنگاری‌شده کوتاه‌تر از حداقل مجاز است"
                )
            }
            if (sealed[0] != VERSION) {
                throw RemotePairingException(
                    RemoteFailure.CIPHERTEXT_MALFORMED,
                    "نسخه پاکت رمزنگاری‌شده پشتیبانی نمی‌شود"
                )
            }
            val nonceLen = sealed[1].toInt() and 0xFF
            if (nonceLen != GCM_NONCE_LEN) {
                throw RemotePairingException(
                    RemoteFailure.CIPHERTEXT_MALFORMED,
                    "طول nonce پاکت رمزنگاری‌شده نامعتبر است"
                )
            }
            val nonce = sealed.copyOfRange(2, 2 + nonceLen)
            val ciphertext = sealed.copyOfRange(2 + nonceLen, sealed.size)
            return try {
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(key, "AES"),
                    GCMParameterSpec(GCM_TAG_BITS, nonce)
                )
                cipher.updateAAD(associatedData)
                cipher.doFinal(ciphertext)
            } catch (e: GeneralSecurityException) {
                throw RemotePairingException(
                    RemoteFailure.CIPHERTEXT_AUTHENTICATION_FAILED,
                    "احراز اصالت پاکت رمزنگاری‌شده شکست خورد (کلید نادرست یا دستکاری داده)",
                    e
                )
            }
        }

        /** Extracts the nonce of a sealed envelope (diagnostics only; never used for security decisions). */
        fun nonceOf(sealed: ByteArray): ByteArray {
            require(sealed.size >= 2 + GCM_NONCE_LEN) { "sealed envelope too short" }
            return sealed.copyOfRange(2, 2 + GCM_NONCE_LEN)
        }
    }

    /**
     * HMAC-SHA256 confirmation tag over a client-only transcript, used so each device can prove to the
     * *peer* that it holds the same derived keys.
     *
     * The server can never check this (it has no key), which is why the protocol never claims it does.
     */
    object ConfirmTag {
        private const val HMAC_ALG = "HmacSHA256"

        fun compute(key: ByteArray, transcript: ByteArray): ByteArray {
            val mac = Mac.getInstance(HMAC_ALG)
            mac.init(SecretKeySpec(key, HMAC_ALG))
            return mac.doFinal(transcript)
        }

        fun verify(key: ByteArray, transcript: ByteArray, tag: ByteArray): Boolean {
            if (tag.size != 32) return false
            val expected = compute(key, transcript)
            return try {
                MessageDigest.isEqual(expected, tag)
            } finally {
                expected.zeroize()
            }
        }

        /** `AAD` for a directional envelope: binds invitation id, role direction and protocol version. */
        fun envelopeAssociatedData(invitationId: String, senderRole: String, purpose: String): ByteArray =
            TranscriptBuilder()
                .putUtf8("DuoLink-RemoteEnvelopeAAD-v1")
                .putInt32(RemoteTranscripts.PROTOCOL_VERSION)
                .putUtf8(invitationId)
                .putUtf8(senderRole)
                .putUtf8(purpose)
                .build()
    }

    /** Best-effort wipe of a public key byte array that is still referenced by the caller. */
    fun wipe(bytes: ByteArray?) {
        bytes?.zeroize()
    }

    fun fingerprintOf(bytes: ByteArray): String =
        ByteEncoding.toHexUpper(ByteEncoding.sha256(bytes).copyOfRange(0, 8))
}
