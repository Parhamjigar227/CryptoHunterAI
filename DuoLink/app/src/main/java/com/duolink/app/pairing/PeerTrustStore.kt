package com.duolink.app.pairing

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.KeyValueByteStore
import com.duolink.app.crypto.RawStoreRead
import com.duolink.app.crypto.SignedPreKeyPublic
import com.duolink.app.crypto.StorageSealer
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest

/**
 * Identifies which security storage component failed integrity/authentication validation.
 */
enum class TrustStoreComponent {
    PINNED_PEER,
    ARCHIVED_PEER,
    REPLAY_LEDGER,
    KEY_VAULT
}

/**
 * Thrown whenever encrypted trust/replay storage fails AEAD authentication, binary schema checks,
 * embedded signature checks, or anti-deletion invariants. Callers MUST fail closed.
 */
class TrustStorageCorruptedException(
    val component: TrustStoreComponent,
    message: String,
    cause: Throwable? = null
) : GeneralSecurityException(message, cause)

/**
 * Tri-state read outcome for the active pinned peer record (`pinned_peer_v1`).
 */
sealed class PinnedPeerReadResult {
    data object None : PinnedPeerReadResult()
    data class Valid(val record: PairedPeerRecord) : PinnedPeerReadResult()
    data class Corrupted(val reason: String) : PinnedPeerReadResult()
}

/**
 * Tri-state read outcome for the archived historical peer identity (`archived_peer_v1`).
 *
 * Security rule: [Corrupted] MUST block pairing and re-pairing so an attacker or storage fault cannot
 * bypass key-change warnings (`previousPeerChanged`) by corrupting `archived_peer_v1`.
 */
sealed class ArchivedPeerReadResult {
    data object None : ArchivedPeerReadResult()
    data class Valid(val identity: PeerTrustStore.ArchivedPeerIdentity) : ArchivedPeerReadResult()
    data class Corrupted(val reason: String) : ArchivedPeerReadResult()
}

/**
 * Tri-state read outcome for the persistent QR replay ledger (`replay_ledger_v1`).
 */
sealed class ReplayLedgerReadResult {
    data object Uninitialized : ReplayLedgerReadResult()
    data class Valid(val hashes: List<ByteArray>) : ReplayLedgerReadResult()
    data class Corrupted(val reason: String) : ReplayLedgerReadResult()
}

/**
 * Aggregate health state of all trust-store records.
 */
sealed class TrustStoreHealth {
    data object Healthy : TrustStoreHealth()
    data class Corrupted(
        val component: TrustStoreComponent,
        val reason: String
    ) : TrustStoreHealth()
}

/**
 * Encrypted, authenticated persistence for:
 * 1. The single allowed peer trust record (`pinned_peer_v1`), sealed with `AES-256-GCM` + domain AAD.
 * 2. Previous peer identity history (`archived_peer_v1`) so re-pairing with a changed key triggers an
 *    explicit key-change warning; corruption fails closed instead of returning `None`.
 * 3. Persistent replay ledger (`replay_ledger_v1`) of consumed QR session/nonce digests so replayed QR
 *    codes are rejected even across app restarts; corruption or deletion fails closed.
 */
class PeerTrustStore(
    private val store: KeyValueByteStore,
    private val sealer: StorageSealer
) {

    /**
     * Evaluates integrity and cryptographic authenticity across `pinned_peer_v1`, `archived_peer_v1`,
     * and `replay_ledger_v1`, including anti-deletion cross-checks.
     */
    @Synchronized
    fun inspectHealth(): TrustStoreHealth {
        val pinned = readPinnedPeer()
        if (pinned is PinnedPeerReadResult.Corrupted) {
            return TrustStoreHealth.Corrupted(TrustStoreComponent.PINNED_PEER, pinned.reason)
        }
        val archived = readArchivedPreviousPeer()
        if (archived is ArchivedPeerReadResult.Corrupted) {
            return TrustStoreHealth.Corrupted(TrustStoreComponent.ARCHIVED_PEER, archived.reason)
        }
        val replay = readReplayLedger()
        if (replay is ReplayLedgerReadResult.Corrupted) {
            return TrustStoreHealth.Corrupted(TrustStoreComponent.REPLAY_LEDGER, replay.reason)
        }
        if ((pinned is PinnedPeerReadResult.Valid || archived is ArchivedPeerReadResult.Valid) &&
            replay is ReplayLedgerReadResult.Uninitialized
        ) {
            return TrustStoreHealth.Corrupted(
                TrustStoreComponent.REPLAY_LEDGER,
                "Replay ledger missing alongside active or archived trust state"
            )
        }
        return TrustStoreHealth.Healthy
    }

    @Synchronized
    fun ensureHealthyOrThrow() {
        when (val health = inspectHealth()) {
            is TrustStoreHealth.Healthy -> return
            is TrustStoreHealth.Corrupted -> throw TrustStorageCorruptedException(
                component = health.component,
                message = health.reason
            )
        }
    }

    @Synchronized
    fun readPinnedPeer(): PinnedPeerReadResult {
        return when (val raw = store.readState(KEY_PINNED_PEER)) {
            is RawStoreRead.Missing -> PinnedPeerReadResult.None
            is RawStoreRead.CorruptedIo -> PinnedPeerReadResult.Corrupted(raw.detail)
            is RawStoreRead.Present -> {
                val plain = try {
                    sealer.unseal(raw.bytes, AAD_PINNED_PEER)
                } catch (e: Exception) {
                    return PinnedPeerReadResult.Corrupted(
                        "Pinned peer record failed AEAD authentication: ${e.javaClass.simpleName}"
                    )
                }
                try {
                    PinnedPeerReadResult.Valid(deserializePeerRecordStrict(plain))
                } catch (e: Exception) {
                    PinnedPeerReadResult.Corrupted(
                        "Pinned peer record failed schema/key validation: ${e.message ?: e.javaClass.simpleName}"
                    )
                }
            }
        }
    }

    @Synchronized
    fun readArchivedPreviousPeer(): ArchivedPeerReadResult {
        return when (val raw = store.readState(KEY_ARCHIVED_PEER)) {
            is RawStoreRead.Missing -> ArchivedPeerReadResult.None
            is RawStoreRead.CorruptedIo -> ArchivedPeerReadResult.Corrupted(raw.detail)
            is RawStoreRead.Present -> {
                val plain = try {
                    sealer.unseal(raw.bytes, AAD_ARCHIVED_PEER)
                } catch (e: Exception) {
                    return ArchivedPeerReadResult.Corrupted(
                        "Archived peer record failed AEAD authentication: ${e.javaClass.simpleName}"
                    )
                }
                try {
                    ArchivedPeerReadResult.Valid(deserializeArchivedPeerStrict(plain))
                } catch (e: Exception) {
                    ArchivedPeerReadResult.Corrupted(
                        "Archived peer record failed schema/key validation: ${e.message ?: e.javaClass.simpleName}"
                    )
                }
            }
        }
    }

    @Synchronized
    fun readReplayLedger(): ReplayLedgerReadResult {
        return when (val raw = store.readState(KEY_REPLAY_LEDGER)) {
            is RawStoreRead.Missing -> ReplayLedgerReadResult.Uninitialized
            is RawStoreRead.CorruptedIo -> ReplayLedgerReadResult.Corrupted(raw.detail)
            is RawStoreRead.Present -> {
                val plain = try {
                    sealer.unseal(raw.bytes, AAD_REPLAY_LEDGER)
                } catch (e: Exception) {
                    return ReplayLedgerReadResult.Corrupted(
                        "Replay ledger failed AEAD authentication: ${e.javaClass.simpleName}"
                    )
                }
                try {
                    ReplayLedgerReadResult.Valid(deserializeReplayEntriesStrict(plain))
                } catch (e: Exception) {
                    ReplayLedgerReadResult.Corrupted(
                        "Replay ledger failed schema validation: ${e.message ?: e.javaClass.simpleName}"
                    )
                }
            }
        }
    }

    @Synchronized
    fun savePinnedPeer(record: PairedPeerRecord) {
        ensureHealthyOrThrow()
        ensureReplayLedgerInitializedInternal()
        val plaintext = serializePeerRecord(record)
        val sealed = sealer.seal(plaintext, AAD_PINNED_PEER)
        store.write(KEY_PINNED_PEER, sealed)
    }

    /**
     * Archives the currently pinned peer identity (so subsequent re-pairing detects key changes)
     * BEFORE deleting the active pinned peer record.
     *
     * Fails closed with [TrustStorageCorruptedException] if ANY trust-store component (`pinned_peer_v1`,
     * `archived_peer_v1`, or `replay_ledger_v1`) is corrupted, never wiping corrupted records silently.
     */
    @Synchronized
    fun archiveAndClearPinnedPeer() {
        ensureHealthyOrThrow()
        ensureReplayLedgerInitializedInternal()
        when (val current = readPinnedPeer()) {
            is PinnedPeerReadResult.Corrupted -> throw TrustStorageCorruptedException(
                TrustStoreComponent.PINNED_PEER,
                current.reason
            )
            is PinnedPeerReadResult.Valid -> {
                val archivedPlain = serializeArchivedPeer(
                    current.record.peerDeviceId,
                    current.record.peerIkSigSpki
                )
                // Persist archived identity FIRST before deleting active pinned peer (crash-safe ordering).
                store.write(KEY_ARCHIVED_PEER, sealer.seal(archivedPlain, AAD_ARCHIVED_PEER))
                store.delete(KEY_PINNED_PEER)
            }
            is PinnedPeerReadResult.None -> {
                // Keep any existing valid archived_peer_v1 intact across repeated unpair calls.
            }
        }
    }

    @Synchronized
    fun hasSeenReplayToken(token: ByteArray): Boolean {
        ensureHealthyOrThrow()
        val targetHash = sha256(token)
        val entries = when (val replay = readReplayLedger()) {
            is ReplayLedgerReadResult.Uninitialized -> emptyList()
            is ReplayLedgerReadResult.Valid -> replay.hashes
            is ReplayLedgerReadResult.Corrupted -> throw TrustStorageCorruptedException(
                TrustStoreComponent.REPLAY_LEDGER,
                replay.reason
            )
        }
        return entries.any { ByteEncoding.constantTimeEquals(it, targetHash) }
    }

    @Synchronized
    fun recordReplayToken(token: ByteArray) {
        ensureHealthyOrThrow()
        val targetHash = sha256(token)
        val current = when (val replay = readReplayLedger()) {
            is ReplayLedgerReadResult.Uninitialized -> ArrayList()
            is ReplayLedgerReadResult.Valid -> ArrayList(replay.hashes)
            is ReplayLedgerReadResult.Corrupted -> throw TrustStorageCorruptedException(
                TrustStoreComponent.REPLAY_LEDGER,
                replay.reason
            )
        }
        if (current.any { ByteEncoding.constantTimeEquals(it, targetHash) }) return
        current.add(targetHash)
        while (current.size > MAX_REPLAY_ENTRIES) {
            current.removeAt(0)
        }
        writeReplayEntriesInternal(current)
    }

    /**
     * Explicit destructive recovery procedure invoked ONLY after explicit user authorization when
     * security storage has been flagged as corrupted. Purges corrupted files and writes a fresh
     * authenticated empty replay ledger under `MSK`.
     */
    @Synchronized
    fun purgeCorruptedTrustStateForRecovery() {
        store.delete(KEY_PINNED_PEER)
        store.delete(KEY_ARCHIVED_PEER)
        store.delete(KEY_REPLAY_LEDGER)
        writeReplayEntriesInternal(emptyList())
    }

    private fun ensureReplayLedgerInitializedInternal() {
        when (val replay = readReplayLedger()) {
            is ReplayLedgerReadResult.Uninitialized -> writeReplayEntriesInternal(emptyList())
            is ReplayLedgerReadResult.Valid -> return
            is ReplayLedgerReadResult.Corrupted -> throw TrustStorageCorruptedException(
                TrustStoreComponent.REPLAY_LEDGER,
                replay.reason
            )
        }
    }

    private fun writeReplayEntriesInternal(entries: List<ByteArray>) {
        val buf = ByteBuffer.allocate(1 + 4 + entries.size * 32)
        buf.put(RECORD_SCHEMA_VERSION)
        buf.putInt(entries.size)
        entries.forEach { hash ->
            require(hash.size == 32) { "Replay digest must be 32 bytes" }
            buf.put(hash)
        }
        store.write(KEY_REPLAY_LEDGER, sealer.seal(buf.array(), AAD_REPLAY_LEDGER))
    }

    private fun deserializeReplayEntriesStrict(plain: ByteArray): List<ByteArray> {
        val buf = ByteBuffer.wrap(plain)
        require(buf.remaining() >= 5) { "Replay ledger header truncated" }
        val ver = buf.get()
        require(ver == RECORD_SCHEMA_VERSION) { "Unsupported replay ledger schema: $ver" }
        val count = buf.int
        require(count in 0..MAX_REPLAY_ENTRIES) { "Invalid replay entry count: $count" }
        require(buf.remaining() == count * 32) { "Replay ledger body length mismatch" }
        return List(count) {
            ByteArray(32).also { buf.get(it) }
        }
    }

    private fun sha256(input: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(input)

    private fun serializePeerRecord(r: PairedPeerRecord): ByteArray {
        val snBytes = r.safetyNumber.toByteArray(StandardCharsets.UTF_8)
        val total =
            1 +
                16 +
                4 + r.peerIkSigSpki.size +
                4 +
                8 +
                4 + r.peerSpkPubSpki.size +
                4 + r.peerSpkSignature.size +
                32 +
                4 + snBytes.size +
                8 +
                1
        val buf = ByteBuffer.allocate(total)
        buf.put(RECORD_SCHEMA_VERSION)
        buf.put(r.peerDeviceId)
        buf.putInt(r.peerIkSigSpki.size)
        buf.put(r.peerIkSigSpki)
        buf.putInt(r.peerSpkId)
        buf.putLong(r.peerSpkCreatedAtEpochSec)
        buf.putInt(r.peerSpkPubSpki.size)
        buf.put(r.peerSpkPubSpki)
        buf.putInt(r.peerSpkSignature.size)
        buf.put(r.peerSpkSignature)
        buf.put(r.rootPairingKey)
        buf.putInt(snBytes.size)
        buf.put(snBytes)
        buf.putLong(r.pairedAtEpochSec)
        buf.put(if (r.safetyNumberVerified) 1.toByte() else 0.toByte())
        return buf.array()
    }

    private fun deserializePeerRecordStrict(bytes: ByteArray): PairedPeerRecord {
        val buf = ByteBuffer.wrap(bytes)
        val version = buf.get()
        require(version == RECORD_SCHEMA_VERSION) { "Unsupported peer record schema: $version" }
        val peerDeviceId = ByteArray(16).also { buf.get(it) }
        val ikLen = buf.int
        require(ikLen == 91 && buf.remaining() >= ikLen + 4) { "Invalid peer IK length" }
        val peerIkSpki = ByteArray(ikLen).also { buf.get(it) }
        val expectedDeviceId = EcP256Crypto.computeDeviceId(peerIkSpki)
        require(ByteEncoding.constantTimeEquals(peerDeviceId, expectedDeviceId)) {
            "Pinned peer deviceId does not match peer IK_sig"
        }

        val peerSpkId = buf.int
        val peerSpkCreatedAt = buf.long
        val spkLen = buf.int
        require(spkLen == 91 && buf.remaining() >= spkLen + 4) { "Invalid peer SPK length" }
        val peerSpkSpki = ByteArray(spkLen).also { buf.get(it) }
        val sigLen = buf.int
        require(sigLen in 1..80 && buf.remaining() >= sigLen + 32 + 4) { "Invalid peer SPK signature length" }
        val peerSpkSig = ByteArray(sigLen).also { buf.get(it) }
        require(
            EcP256Crypto.verifySignedPreKey(
                deviceId = peerDeviceId,
                identitySigningPublicKeySpki = peerIkSpki,
                spk = SignedPreKeyPublic(peerSpkId, peerSpkSpki, peerSpkSig, peerSpkCreatedAt)
            )
        ) { "Pinned peer SPK signature verification failed" }

        val rootKey = ByteArray(32).also { buf.get(it) }
        val snLen = buf.int
        require(snLen in 60..128 && buf.remaining() >= snLen + 9) { "Invalid safety number length" }
        val snBytes = ByteArray(snLen).also { buf.get(it) }
        val pairedAt = buf.long
        val verifiedFlag = buf.get().toInt()
        require(verifiedFlag == 0 || verifiedFlag == 1) { "Invalid verified flag: $verifiedFlag" }
        require(!buf.hasRemaining()) { "Unexpected trailing bytes in pinned peer record" }

        return PairedPeerRecord(
            peerDeviceId = peerDeviceId,
            peerIkSigSpki = peerIkSpki,
            peerSpkId = peerSpkId,
            peerSpkPubSpki = peerSpkSpki,
            peerSpkSignature = peerSpkSig,
            peerSpkCreatedAtEpochSec = peerSpkCreatedAt,
            rootPairingKey = rootKey,
            safetyNumber = String(snBytes, StandardCharsets.UTF_8),
            pairedAtEpochSec = pairedAt,
            safetyNumberVerified = verifiedFlag == 1
        )
    }

    private fun serializeArchivedPeer(deviceId: ByteArray, ikSpki: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(1 + 16 + 4 + ikSpki.size)
        buf.put(RECORD_SCHEMA_VERSION)
        buf.put(deviceId)
        buf.putInt(ikSpki.size)
        buf.put(ikSpki)
        return buf.array()
    }

    private fun deserializeArchivedPeerStrict(bytes: ByteArray): ArchivedPeerIdentity {
        val buf = ByteBuffer.wrap(bytes)
        val version = buf.get()
        require(version == RECORD_SCHEMA_VERSION) { "Unsupported archived peer schema: $version" }
        require(buf.remaining() >= 20) { "Truncated archived peer header" }
        val deviceId = ByteArray(16).also { buf.get(it) }
        val ikLen = buf.int
        require(ikLen == 91 && buf.remaining() == ikLen) { "Invalid archived peer IK length" }
        val ikSpki = ByteArray(ikLen).also { buf.get(it) }
        val expectedDeviceId = EcP256Crypto.computeDeviceId(ikSpki)
        require(ByteEncoding.constantTimeEquals(deviceId, expectedDeviceId)) {
            "Archived peer deviceId does not match archived IK_sig"
        }
        return ArchivedPeerIdentity(deviceId, ikSpki)
    }

    data class ArchivedPeerIdentity(
        val peerDeviceId: ByteArray,
        val peerIkSigSpki: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ArchivedPeerIdentity) return false
            return peerDeviceId.contentEquals(other.peerDeviceId) &&
                peerIkSigSpki.contentEquals(other.peerIkSigSpki)
        }

        override fun hashCode(): Int =
            31 * peerDeviceId.contentHashCode() + peerIkSigSpki.contentHashCode()
    }

    companion object {
        private const val RECORD_SCHEMA_VERSION: Byte = 1
        private const val MAX_REPLAY_ENTRIES = 256
        const val KEY_PINNED_PEER = "pinned_peer_v1"
        const val KEY_ARCHIVED_PEER = "archived_peer_v1"
        const val KEY_REPLAY_LEDGER = "replay_ledger_v1"

        private val AAD_PINNED_PEER = "duolink:trust:pinned_peer:v1".toByteArray(StandardCharsets.UTF_8)
        private val AAD_ARCHIVED_PEER = "duolink:trust:archived_peer:v1".toByteArray(StandardCharsets.UTF_8)
        private val AAD_REPLAY_LEDGER = "duolink:trust:replay_ledger:v1".toByteArray(StandardCharsets.UTF_8)
    }
}
