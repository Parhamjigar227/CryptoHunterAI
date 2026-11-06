package com.duolink.app.pairing

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.StorageSealer
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * Minimal key-value byte storage interface so PeerTrustStore runs identically against
 * app-private files on Android and in-memory maps in deterministic unit tests.
 */
interface KeyValueByteStore {
    fun read(key: String): ByteArray?
    fun write(key: String, bytes: ByteArray)
    fun delete(key: String)
}

class InMemoryByteStore : KeyValueByteStore {
    private val map = HashMap<String, ByteArray>()
    override fun read(key: String): ByteArray? = map[key]?.copyOf()
    override fun write(key: String, bytes: ByteArray) {
        map[key] = bytes.copyOf()
    }
    override fun delete(key: String) {
        map.remove(key)
    }
}

class DirectoryFileByteStore(private val directory: File) : KeyValueByteStore {
    init {
        if (!directory.exists()) {
            directory.mkdirs()
        }
    }

    private fun fileFor(key: String): File {
        val safeName = key.replace(Regex("[^a-zA-Z0-9._-]"), "_") + ".bin"
        return File(directory, safeName)
    }

    override fun read(key: String): ByteArray? {
        val f = fileFor(key)
        return if (f.exists() && f.isFile) f.readBytes() else null
    }

    override fun write(key: String, bytes: ByteArray) {
        val target = fileFor(key)
        val tmp = File(directory, target.name + ".tmp")
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(target)) {
            target.writeBytes(bytes)
            tmp.delete()
        }
    }

    override fun delete(key: String) {
        fileFor(key).delete()
    }
}

/**
 * Encrypted persistent store for:
 * 1. The single pinned peer identity & derived RootPairingKey (enforcing max 1 peer = 2 devices total).
 * 2. Historical previous peer identity (to surface KeyChangeAlert during re-pairing if peer key changed).
 * 3. Bounded persistent replay-nonce ledger (prevents QR replay even across app restarts).
 */
class PeerTrustStore(
    private val byteStore: KeyValueByteStore,
    private val sealer: StorageSealer
) {
    data class ArchivedPeerIdentity(
        val peerDeviceId: String,
        val peerIkSigSpki: ByteArray,
        val safetyNumber: String
    )

    @Synchronized
    fun loadPinnedPeer(): PairedPeerRecord? {
        val sealed = byteStore.read(KEY_PINNED_PEER) ?: return null
        val plain = sealer.unseal(sealed, AAD_PINNED_PEER)
        return deserializePeerRecord(plain)
    }

    @Synchronized
    fun savePinnedPeer(record: PairedPeerRecord) {
        val plain = serializePeerRecord(record)
        val sealed = sealer.seal(plain, AAD_PINNED_PEER)
        byteStore.write(KEY_PINNED_PEER, sealed)
        // Clear archived previous identity once new peer is explicitly confirmed
        byteStore.delete(KEY_ARCHIVED_PEER)
    }

    /**
     * Unpairs the current peer and archives its public identity fingerprint so a subsequent
     * re-pairing explicitly warns if the peer's identity key has changed.
     */
    @Synchronized
    fun archiveAndClearPinnedPeer() {
        val current = try {
            loadPinnedPeer()
        } catch (_: Exception) {
            null
        }
        if (current != null) {
            val archivedPlain = serializeArchivedPeer(
                ArchivedPeerIdentity(
                    peerDeviceId = current.peerDeviceId,
                    peerIkSigSpki = current.peerIkSigSpki,
                    safetyNumber = current.safetyNumber
                )
            )
            byteStore.write(KEY_ARCHIVED_PEER, sealer.seal(archivedPlain, AAD_ARCHIVED_PEER))
        }
        byteStore.delete(KEY_PINNED_PEER)
    }

    @Synchronized
    fun loadArchivedPreviousPeer(): ArchivedPeerIdentity? {
        val sealed = byteStore.read(KEY_ARCHIVED_PEER) ?: return null
        return try {
            deserializeArchivedPeer(sealer.unseal(sealed, AAD_ARCHIVED_PEER))
        } catch (_: Exception) {
            null
        }
    }

    @Synchronized
    fun hasSeenReplayToken(replayTokenHash: ByteArray): Boolean {
        require(replayTokenHash.size == 32)
        val entries = loadReplayEntriesInternal()
        return entries.any { ByteEncoding.constantTimeEquals(it, replayTokenHash) }
    }

    @Synchronized
    fun recordReplayToken(replayTokenHash: ByteArray) {
        require(replayTokenHash.size == 32)
        val entries = loadReplayEntriesInternal().toMutableList()
        if (entries.any { ByteEncoding.constantTimeEquals(it, replayTokenHash) }) return
        entries.add(replayTokenHash.copyOf())
        while (entries.size > MAX_REPLAY_ENTRIES) {
            entries.removeAt(0)
        }
        val out = ByteArrayOutputStream(4 + entries.size * 32)
        out.write(ByteBuffer.allocate(4).putInt(entries.size).array())
        for (item in entries) {
            out.write(item)
        }
        byteStore.write(KEY_REPLAY_LEDGER, sealer.seal(out.toByteArray(), AAD_REPLAY_LEDGER))
    }

    private fun loadReplayEntriesInternal(): List<ByteArray> {
        val sealed = byteStore.read(KEY_REPLAY_LEDGER) ?: return emptyList()
        val plain = sealer.unseal(sealed, AAD_REPLAY_LEDGER)
        val buf = ByteBuffer.wrap(plain)
        val count = buf.int
        if (count < 0 || count > MAX_REPLAY_ENTRIES || buf.remaining() != count * 32) {
            throw SecurityException("Corrupted replay ledger")
        }
        return List(count) {
            ByteArray(32).also { buf.get(it) }
        }
    }

    private fun serializePeerRecord(r: PairedPeerRecord): ByteArray {
        val out = ByteArrayOutputStream(384)
        writeUtf8(out, r.peerDeviceId)
        writeChunk(out, r.peerIkSigSpki)
        out.write(ByteBuffer.allocate(4).putInt(r.peerSpkId).array())
        writeChunk(out, r.peerSpkDhSpki)
        out.write(ByteBuffer.allocate(8).putLong(r.peerSpkIssuedAtSec).array())
        out.write(ByteBuffer.allocate(8).putLong(r.peerSpkExpiresAtSec).array())
        writeChunk(out, r.peerSpkSignature)
        writeUtf8(out, r.safetyNumber)
        writeChunk(out, r.rootPairingKey)
        out.write(ByteBuffer.allocate(8).putLong(r.pairedAtEpochSec).array())
        return out.toByteArray()
    }

    private fun deserializePeerRecord(bytes: ByteArray): PairedPeerRecord {
        val buf = ByteBuffer.wrap(bytes)
        val peerDeviceId = readUtf8(buf)
        val peerIkSigSpki = readChunk(buf)
        val peerSpkId = buf.int
        val peerSpkDhSpki = readChunk(buf)
        val peerSpkIssuedAt = buf.long
        val peerSpkExpiresAt = buf.long
        val peerSpkSig = readChunk(buf)
        val safetyNumber = readUtf8(buf)
        val rootKey = readChunk(buf)
        val pairedAt = buf.long
        require(!buf.hasRemaining()) { "Trailing bytes in peer record" }
        return PairedPeerRecord(
            peerDeviceId = peerDeviceId,
            peerIkSigSpki = peerIkSigSpki,
            peerSpkId = peerSpkId,
            peerSpkDhSpki = peerSpkDhSpki,
            peerSpkIssuedAtSec = peerSpkIssuedAt,
            peerSpkExpiresAtSec = peerSpkExpiresAt,
            peerSpkSignature = peerSpkSig,
            safetyNumber = safetyNumber,
            rootPairingKey = rootKey,
            pairedAtEpochSec = pairedAt
        )
    }

    private fun serializeArchivedPeer(a: ArchivedPeerIdentity): ByteArray {
        val out = ByteArrayOutputStream(192)
        writeUtf8(out, a.peerDeviceId)
        writeChunk(out, a.peerIkSigSpki)
        writeUtf8(out, a.safetyNumber)
        return out.toByteArray()
    }

    private fun deserializeArchivedPeer(bytes: ByteArray): ArchivedPeerIdentity {
        val buf = ByteBuffer.wrap(bytes)
        val id = readUtf8(buf)
        val ik = readChunk(buf)
        val sn = readUtf8(buf)
        require(!buf.hasRemaining())
        return ArchivedPeerIdentity(id, ik, sn)
    }

    private fun writeUtf8(out: ByteArrayOutputStream, s: String) =
        writeChunk(out, s.toByteArray(StandardCharsets.UTF_8))

    private fun writeChunk(out: ByteArrayOutputStream, b: ByteArray) {
        out.write(ByteBuffer.allocate(4).putInt(b.size).array())
        out.write(b)
    }

    private fun readUtf8(buf: ByteBuffer): String =
        String(readChunk(buf), StandardCharsets.UTF_8)

    private fun readChunk(buf: ByteBuffer): ByteArray {
        val len = buf.int
        require(len in 0..16384 && buf.remaining() >= len) { "Invalid chunk length" }
        return ByteArray(len).also { buf.get(it) }
    }

    companion object {
        private const val KEY_PINNED_PEER = "pinned_peer_v1"
        private const val KEY_ARCHIVED_PEER = "archived_peer_v1"
        private const val KEY_REPLAY_LEDGER = "replay_ledger_v1"
        private const val MAX_REPLAY_ENTRIES = 512

        private val AAD_PINNED_PEER = "duolink:trust_store:pinned_peer:v1".toByteArray(StandardCharsets.UTF_8)
        private val AAD_ARCHIVED_PEER = "duolink:trust_store:archived_peer:v1".toByteArray(StandardCharsets.UTF_8)
        private val AAD_REPLAY_LEDGER = "duolink:trust_store:replay_ledger:v1".toByteArray(StandardCharsets.UTF_8)
    }
}
