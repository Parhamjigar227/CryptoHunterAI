package com.duolink.app.remote

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.KeyValueByteStore
import com.duolink.app.crypto.RawStoreRead
import com.duolink.app.crypto.StorageSealer
import com.duolink.app.crypto.zeroize
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.SecureRandom

/**
 * Crash-safe, encrypted storage for *in-flight* remote pairing state.
 *
 * Why this exists: remote pairing spans several user interactions (show code → peer redeems → compare
 * 60 digits → approve → wait for quorum → persist → confirm receipt). An Android process can be
 * killed at any of those points. Without durable pending state the user would be forced to start over
 * — and, worse, could end up with a half-finished flow whose derived keys were never cleaned up.
 *
 * Security properties:
 *  1. The whole record is sealed with `MSK` (`AES-256-GCM`) under a distinct AAD, so it is
 *     confidential and integrity-protected at rest, and cannot be swapped with any other record type.
 *  2. Schema is length-explicit and version-tagged; truncated, extended or reordered bytes are
 *     rejected, never "repaired".
 *  3. Every embedded public key / digest is re-validated on load: a corrupted record that happens to
 *     authenticate (e.g. an attacker with `MSK`) still cannot smuggle in a malformed key.
 *  4. Corruption fails closed: [read] returns [PendingSessionRead.Corrupted] and the coordinator
 *     blocks the flow instead of silently starting fresh, because "start fresh" on corrupt state is
 *     indistinguishable from a downgrade attack.
 *  5. Any secret bytes that were decrypted into this object are wiped by [StoredPendingSession.destroy]
 *     as soon as the coordinator is done with them (best effort — see the JVM memory notes in the
 *     architecture document).
 */
class RemotePendingSessionStore(
    private val store: KeyValueByteStore,
    private val sealer: StorageSealer
) {

    sealed class PendingSessionRead {
        data object None : PendingSessionRead()
        data class Present(val session: StoredPendingSession) : PendingSessionRead()
        data class Corrupted(val reason: String) : PendingSessionRead()
    }

    @Synchronized
    fun read(): PendingSessionRead {
        return when (val raw = store.readState(KEY_PENDING)) {
            is RawStoreRead.Missing -> PendingSessionRead.None
            is RawStoreRead.CorruptedIo -> PendingSessionRead.Corrupted(raw.detail)
            is RawStoreRead.Present -> {
                val plain = try {
                    sealer.unseal(raw.bytes, AAD_PENDING)
                } catch (e: Exception) {
                    return PendingSessionRead.Corrupted(
                        "Pending remote session failed AEAD authentication: ${e.javaClass.simpleName}"
                    )
                }
                try {
                    PendingSessionRead.Present(decode(plain))
                } catch (e: Exception) {
                    PendingSessionRead.Corrupted(
                        "Pending remote session failed schema/key validation: ${e.message ?: e.javaClass.simpleName}"
                    )
                } finally {
                    plain.zeroize()
                }
            }
        }
    }

    @Synchronized
    fun write(session: StoredPendingSession) {
        val plaintext = encode(session)
        try {
            store.write(KEY_PENDING, sealer.seal(plaintext, AAD_PENDING))
        } finally {
            plaintext.zeroize()
        }
    }

    @Synchronized
    fun clear() {
        store.delete(KEY_PENDING)
    }

    @Synchronized
    fun exists(): Boolean = store.readState(KEY_PENDING) is RawStoreRead.Present

    private fun encode(session: StoredPendingSession): ByteArray {
        val invitationIdBytes = session.invitationId.toByteArray(StandardCharsets.UTF_8)
        val exchangeToken = session.exchangeToken ?: ByteArray(0)
        val safetyBytes = session.safetyNumber?.toByteArray(StandardCharsets.UTF_8) ?: ByteArray(0)
        val commitCertificate = session.commitCertificate ?: ByteArray(0)
        val buffer = ByteBuffer.allocate(
            1 +
                4 + invitationIdBytes.size +
                4 + session.serverBaseUrl.toByteArray(StandardCharsets.UTF_8).size +
                1 +
                4 + exchangeToken.size +
                16 + 16 +
                4 + session.ownerIdentitySpki.size +
                4 + session.ownerSpkSpki.size +
                4 + session.ownerEphemeralSpki.size +
                4 + session.ownerNonce.size +
                4 + session.recipientIdentitySpki.size +
                4 + session.recipientSpkSpki.size +
                4 + session.recipientEphemeralSpki.size +
                4 + session.recipientNonce.size +
                4 + session.recipientIdentitySignature.size +
                8 +
                4 + safetyBytes.size +
                8 +
                1 +
                4 + commitCertificate.size +
                1
        )
        buffer.put(SCHEMA_VERSION)
        putString(buffer, session.invitationId)
        putString(buffer, session.serverBaseUrl)
        buffer.put(session.role.wireValue.toByteArray(StandardCharsets.UTF_8)[0])
        putBytes(buffer, exchangeToken)
        buffer.put(session.ownerDeviceId)
        buffer.put(session.recipientDeviceId)
        putBytes(buffer, session.ownerIdentitySpki)
        putBytes(buffer, session.ownerSpkSpki)
        putBytes(buffer, session.ownerEphemeralSpki)
        putBytes(buffer, session.ownerNonce)
        putBytes(buffer, session.recipientIdentitySpki)
        putBytes(buffer, session.recipientSpkSpki)
        putBytes(buffer, session.recipientEphemeralSpki)
        putBytes(buffer, session.recipientNonce)
        putBytes(buffer, session.recipientIdentitySignature)
        buffer.putLong(session.invitationExpiresAtEpochSec)
        putBytes(buffer, safetyBytes)
        buffer.putLong(session.safetyNumberVerifiedAtEpochSec ?: 0L)
        buffer.put(if (session.safetyNumberVerifiedAtEpochSec != null) 1 else 0)
        putBytes(buffer, commitCertificate)
        buffer.put(if (session.commitSubmitted) 1 else 0)
        return buffer.array()
    }

    private fun decode(plain: ByteArray): StoredPendingSession {
        val buffer = ByteBuffer.wrap(plain)
        require(buffer.remaining() >= 1) { "pending session header truncated" }
        val version = buffer.get()
        require(version == SCHEMA_VERSION) { "unsupported pending session schema: $version" }
        val invitationId = readString(buffer)
        val serverBaseUrl = readString(buffer)
        require(buffer.remaining() >= 1) { "pending session role truncated" }
        val role = when (buffer.get().toInt().toChar()) {
            'o' -> RemoteRole.OWNER
            'r' -> RemoteRole.RECIPIENT
            else -> throw IllegalArgumentException("unknown role byte")
        }
        val exchangeToken = readBytes(buffer).takeIf { it.isNotEmpty() }
        val ownerDeviceId = ByteArray(16).also { buffer.get(it) }
        val recipientDeviceId = ByteArray(16).also { buffer.get(it) }
        val ownerIdentitySpki = readBytes(buffer)
        val ownerSpkSpki = readBytes(buffer)
        val ownerEphemeralSpki = readBytes(buffer)
        val ownerNonce = readBytes(buffer)
        val recipientIdentitySpki = readBytes(buffer)
        val recipientSpkSpki = readBytes(buffer)
        val recipientEphemeralSpki = readBytes(buffer)
        val recipientNonce = readBytes(buffer)
        val recipientIdentitySignature = readBytes(buffer)
        val expires = buffer.long
        val safetyBytes = readBytes(buffer)
        val verifiedAt = buffer.long
        val verifiedFlag = buffer.get().toInt()
        val commitCertificate = readBytes(buffer)
        val commitSubmitted = buffer.get().toInt() == 1
        require(!buffer.hasRemaining()) { "unexpected trailing bytes in pending session" }
        require(verifiedFlag == 0 || verifiedFlag == 1) { "invalid verification flag" }
        require(commitCertificate.isEmpty() || commitCertificate.size in 65..96) {
            "invalid commit certificate length"
        }

        // Structural validation: a record that authenticates under MSK must still be well formed.
        com.duolink.app.crypto.EcP256Crypto.decodeAndValidateP256PublicKey(ownerIdentitySpki)
        com.duolink.app.crypto.EcP256Crypto.decodeAndValidateP256PublicKey(recipientIdentitySpki)
        com.duolink.app.crypto.EcP256Crypto.decodeAndValidateP256PublicKey(ownerSpkSpki)
        com.duolink.app.crypto.EcP256Crypto.decodeAndValidateP256PublicKey(recipientSpkSpki)
        com.duolink.app.crypto.EcP256Crypto.decodeAndValidateP256PublicKey(ownerEphemeralSpki)
        com.duolink.app.crypto.EcP256Crypto.decodeAndValidateP256PublicKey(recipientEphemeralSpki)
        require(ownerNonce.size == NONCE_BYTES && recipientNonce.size == NONCE_BYTES) {
            "invalid nonce length"
        }
        require(recipientIdentitySignature.size in 64..80) { "invalid identity signature length" }

        return StoredPendingSession(
            invitationId = invitationId,
            serverBaseUrl = serverBaseUrl,
            role = role,
            exchangeToken = exchangeToken,
            ownerDeviceId = ownerDeviceId,
            recipientDeviceId = recipientDeviceId,
            ownerIdentitySpki = ownerIdentitySpki,
            ownerSpkSpki = ownerSpkSpki,
            ownerEphemeralSpki = ownerEphemeralSpki,
            ownerNonce = ownerNonce,
            recipientIdentitySpki = recipientIdentitySpki,
            recipientSpkSpki = recipientSpkSpki,
            recipientEphemeralSpki = recipientEphemeralSpki,
            recipientNonce = recipientNonce,
            recipientIdentitySignature = recipientIdentitySignature,
            invitationExpiresAtEpochSec = expires,
            safetyNumber = if (safetyBytes.isEmpty()) null else String(safetyBytes, StandardCharsets.UTF_8),
            safetyNumberVerifiedAtEpochSec = if (verifiedFlag == 1) verifiedAt else null,
            commitCertificate = commitCertificate.takeIf { it.isNotEmpty() },
            commitSubmitted = commitSubmitted
        )
    }

    private fun putBytes(buffer: ByteBuffer, bytes: ByteArray) {
        buffer.putInt(bytes.size)
        buffer.put(bytes)
    }

    private fun putString(buffer: ByteBuffer, value: String) =
        putBytes(buffer, value.toByteArray(StandardCharsets.UTF_8))

    private fun readBytes(buffer: ByteBuffer): ByteArray {
        require(buffer.remaining() >= 4) { "length prefix truncated" }
        val length = buffer.int
        require(length in 0..MAX_FIELD_BYTES) { "field length out of range: $length" }
        require(buffer.remaining() >= length) { "field body truncated" }
        return ByteArray(length).also { buffer.get(it) }
    }

    private fun readString(buffer: ByteBuffer): String =
        String(readBytes(buffer), StandardCharsets.UTF_8)

    companion object {
        const val KEY_PENDING = "remote_pending_v1"
        private const val SCHEMA_VERSION: Byte = 1
        private const val NONCE_BYTES = 16
        private const val MAX_FIELD_BYTES = 4096
        private val AAD_PENDING = "duolink:remote:pending_session:v1".toByteArray(StandardCharsets.UTF_8)

        fun randomNonce(secureRandom: SecureRandom = SecureRandom()): ByteArray =
            ByteArray(NONCE_BYTES).also { secureRandom.nextBytes(it) }
    }
}

/**
 * The durable half of an in-flight remote pairing.
 *
 * NOTE: this record deliberately contains **no private keys**. The ephemeral private key and the
 * derived key set live only in memory for the duration of one operation; if the process dies they are
 * gone, which is the intended forward-secrecy behaviour. On resume the device re-derives keys from the
 * re-fetched public material and the (still-in-memory-only) ephemeral key, or restarts the attempt.
 */
data class StoredPendingSession(
    val invitationId: String,
    val serverBaseUrl: String,
    val role: RemoteRole,
    val exchangeToken: ByteArray?,
    val ownerDeviceId: ByteArray,
    val recipientDeviceId: ByteArray,
    val ownerIdentitySpki: ByteArray,
    val ownerSpkSpki: ByteArray,
    val ownerEphemeralSpki: ByteArray,
    val ownerNonce: ByteArray,
    val recipientIdentitySpki: ByteArray,
    val recipientSpkSpki: ByteArray,
    val recipientEphemeralSpki: ByteArray,
    val recipientNonce: ByteArray,
    val recipientIdentitySignature: ByteArray,
    val invitationExpiresAtEpochSec: Long,
    val safetyNumber: String?,
    val safetyNumberVerifiedAtEpochSec: Long?,
    val commitCertificate: ByteArray?,
    val commitSubmitted: Boolean
) {
    val ownerDeviceIdHex: String get() = ByteEncoding.toHexLower(ownerDeviceId)
    val recipientDeviceIdHex: String get() = ByteEncoding.toHexLower(recipientDeviceId)
    val peerDeviceId: ByteArray get() = if (role == RemoteRole.OWNER) recipientDeviceId else ownerDeviceId

    fun destroy() {
        exchangeToken?.zeroize()
    }

    /** Reconstructs the exact handshake binding both devices must agree on. */
    fun binding(): RemoteKeySchedule.HandshakeBinding = RemoteKeySchedule.HandshakeBinding(
        protocolVersion = RemoteTranscripts.PROTOCOL_VERSION,
        invitationId = invitationId,
        ownerDeviceId = ownerDeviceId,
        recipientDeviceId = recipientDeviceId,
        ownerIdentitySpki = ownerIdentitySpki,
        recipientIdentitySpki = recipientIdentitySpki,
        ownerSpkSpki = ownerSpkSpki,
        recipientSpkSpki = recipientSpkSpki,
        ownerEphemeralSpki = ownerEphemeralSpki,
        recipientEphemeralSpki = recipientEphemeralSpki,
        ownerNonce = ownerNonce,
        recipientNonce = recipientNonce,
        recipientIdentitySignature = recipientIdentitySignature
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is StoredPendingSession) return false
        return invitationId == other.invitationId &&
            serverBaseUrl == other.serverBaseUrl &&
            role == other.role &&
            ((exchangeToken == null && other.exchangeToken == null) ||
                (exchangeToken != null && other.exchangeToken != null && exchangeToken.contentEquals(other.exchangeToken))) &&
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
            recipientIdentitySignature.contentEquals(other.recipientIdentitySignature) &&
            invitationExpiresAtEpochSec == other.invitationExpiresAtEpochSec &&
            safetyNumber == other.safetyNumber &&
            safetyNumberVerifiedAtEpochSec == other.safetyNumberVerifiedAtEpochSec &&
            ((commitCertificate == null && other.commitCertificate == null) ||
                (commitCertificate != null && other.commitCertificate != null && commitCertificate.contentEquals(other.commitCertificate))) &&
            commitSubmitted == other.commitSubmitted
    }

    override fun hashCode(): Int = invitationId.hashCode()
}
