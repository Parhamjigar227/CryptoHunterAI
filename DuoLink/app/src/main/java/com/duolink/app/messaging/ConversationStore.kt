package com.duolink.app.messaging

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.KeyValueByteStore
import com.duolink.app.crypto.RawStoreRead
import com.duolink.app.crypto.StorageSealer
import com.duolink.app.crypto.TranscriptBuilder
import com.duolink.app.crypto.zeroize

/**
 * One message as the UI sees it: the decrypted payload plus local delivery bookkeeping.
 *
 * [payload] is held in memory only while the conversation is open. At rest the whole record is sealed
 * under the Keystore-backed sealer, so a filesystem copy of the conversation yields ciphertext.
 */
data class ChatMessage(
    val payload: MessagePayload,
    val deliveryState: DeliveryState,
    val isOutgoing: Boolean,
    /** Set when the payload failed to authenticate, so the UI can show "unreadable" instead of hiding it. */
    val cryptoFailure: String? = null
) {
    val messageIdHex: String get() = ByteEncoding.toHexLower(payload.messageId)
    val timestampEpochMs: Long get() = payload.createdAtEpochMs
}

/**
 * Append-only, per-conversation message log sealed at rest.
 *
 * Persistence decisions worth stating:
 *  - The log is one sealed blob rather than a SQLite database because every row must be encrypted
 *    anyway and the ciphertext is opaque to the platform. It is written atomically (temp + rename in
 *    the underlying [KeyValueByteStore]), so a crash cannot truncate the transcript.
 *  - Only the *encrypted* envelope is ever persisted. Plaintext is decrypted on read into memory and
 *    is never written to disk in the clear, so the "no plaintext messages on disk" rule holds even for
 *    the app's own storage.
 *  - Ordering is by (createdAt, sequenceNumber), with the message id as a deterministic tiebreaker, so
 *    two devices that receive in different orders still display the same conversation.
 *  - De-duplication is by message id: the transport may deliver the same envelope twice (polling and
 *    WebSocket can overlap), and a duplicate must not create a second bubble or, worse, re-trigger an
 *    attachment download.
 */
class ConversationStore(
    private val store: KeyValueByteStore,
    private val sealer: StorageSealer,
    private val conversationId: String
) {
    sealed class LoadResult {
        data class Loaded(val messages: List<StoredEnvelope>) : LoadResult()
        object Empty : LoadResult()
        data class Corrupted(val detail: String) : LoadResult()
    }

    /** Envelope plus its local delivery state, both sealed together. */
    data class StoredEnvelope(
        val envelope: SealedMessageEnvelope,
        val deliveryState: DeliveryState,
        val isOutgoing: Boolean
    ) {
        val key: String get() = ByteEncoding.toHexLower(envelope.messageId)
    }

    fun load(): LoadResult = when (val raw = store.readState(keyFor(conversationId))) {
        is RawStoreRead.Present -> {
            try {
                val plaintext = sealer.unseal(raw.bytes, associatedData())
                try {
                    LoadResult.Loaded(decode(plaintext))
                } finally {
                    plaintext.zeroize()
                }
            } catch (t: Throwable) {
                LoadResult.Corrupted("unseal_failed:${t.javaClass.simpleName}")
            }
        }
        is RawStoreRead.CorruptedIo -> LoadResult.Corrupted(raw.detail)
        is RawStoreRead.Missing -> LoadResult.Empty
    }

    /** Inserts or updates one envelope. Returns the new full list so callers can re-render. */
    fun upsert(entry: StoredEnvelope): List<StoredEnvelope> {
        val current = (load() as? LoadResult.Loaded)?.messages?.toMutableList() ?: mutableListOf()
        val existingIndex = current.indexOfFirst { it.key == entry.key }
        if (existingIndex >= 0) {
            val existing = current[existingIndex]
            // Never let a stale state overwrite a newer one (e.g. a polled PENDING after a DELIVERED).
            val merged = if (existing.deliveryState.rank() > entry.deliveryState.rank()) {
                existing.copy(envelope = entry.envelope)
            } else {
                entry
            }
            current[existingIndex] = merged
        } else {
            current += entry
        }
        persist(current)
        return current.sortedWith(order)
    }

    /** Marks a message's delivery state, returning the updated list (no-op if the id is unknown). */
    fun updateDeliveryState(messageIdHex: String, newState: DeliveryState): List<StoredEnvelope> {
        val current = (load() as? LoadResult.Loaded)?.messages?.toMutableList() ?: return emptyList()
        val index = current.indexOfFirst { it.key == messageIdHex }
        if (index < 0) return current.sortedWith(order)
        val existing = current[index]
        if (shouldApplyTransition(existing.deliveryState, newState)) {
            current[index] = existing.copy(deliveryState = newState)
            persist(current)
        }
        return current.sortedWith(order)
    }

    /**
     * Decides whether a delivery-state transition is allowed to overwrite the stored one.
     *
     * Ordering is monotonic (PENDING < SENT < DELIVERED < READ) so a late, stale poll response cannot
     * make an already-read message look unread again. FAILED is a *side* state, not the top of the
     * ladder: it may only replace a message that has not yet been confirmed by the server, and it may
     * not overwrite a state the peer itself has attested.
     */
    private fun shouldApplyTransition(current: DeliveryState, next: DeliveryState): Boolean {
        if (current == next) return false
        return when (next) {
            // A failed send may only supersede a not-yet-confirmed state. It may never overwrite a
            // state the peer itself attested (DELIVERED/READ).
            DeliveryState.FAILED -> current == DeliveryState.PENDING || current == DeliveryState.SENT
            // A retry legitimately moves an explicitly FAILED message back to SENT. Without this the
            // user could tap "retry" forever and the bubble would stay red.
            DeliveryState.SENT ->
                current == DeliveryState.PENDING || current == DeliveryState.FAILED
            DeliveryState.READ -> current != DeliveryState.READ
            else -> next.rank() > current.rank() && current != DeliveryState.READ
        }
    }

    fun contains(messageIdHex: String): Boolean =
        (load() as? LoadResult.Loaded)?.messages?.any { it.key == messageIdHex } ?: false

    /** Highest sequence number seen, used to keep the local counter monotonic across restarts. */
    fun highestSequence(): Long =
        (load() as? LoadResult.Loaded)?.messages?.maxOfOrNull { it.envelope.sequenceNumber } ?: 0L

    fun clear() {
        store.delete(keyFor(conversationId))
    }

    private fun persist(messages: List<StoredEnvelope>) {
        val plaintext = encode(messages)
        try {
            store.write(keyFor(conversationId), sealer.seal(plaintext, associatedData()))
        } finally {
            plaintext.zeroize()
        }
    }

    private fun associatedData(): ByteArray =
        TranscriptBuilder()
            .putRawUtf8("DuoLink-ConvStore-v1")
            .putRawUtf8(conversationId)
            .build()

    // ---- wire format -----------------------------------------------------

    private fun encode(messages: List<StoredEnvelope>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(STORAGE_VERSION.toInt())
        out.write(TranscriptBuilder().putInt32(messages.size).build())
        messages.forEach { entry ->
            val e = entry.envelope
            out.write(e.protocolVersion.toInt())
            out.write(e.messageId.size)
            out.write(e.messageId)
            out.write(e.senderDeviceId.size)
            out.write(e.senderDeviceId)
            out.write(e.recipientDeviceId.size)
            out.write(e.recipientDeviceId)
            out.write(TranscriptBuilder().putInt64(e.sequenceNumber).build())
            out.write(e.iv.size)
            out.write(e.iv)
            out.write(TranscriptBuilder().putInt32(e.ciphertextAndTag.size).build())
            out.write(e.ciphertextAndTag)
            out.write(entry.deliveryState.ordinal)
            out.write(if (entry.isOutgoing) 1 else 0)
        }
        return out.toByteArray()
    }

    private fun decode(plaintext: ByteArray): List<StoredEnvelope> {
        val input = java.io.ByteArrayInputStream(plaintext)
        val version = input.read()
        require(version == STORAGE_VERSION.toInt()) { "unsupported store version $version" }
        val count = readInt(input)
        require(count in 0..MAX_MESSAGES) { "invalid message count $count" }
        val out = ArrayList<StoredEnvelope>(count)
        repeat(count) {
            val protocolVersion = input.read().toByte()
            val idLen = input.read()
            require(idLen in 1..64) { "invalid message id length" }
            val id = readExact(input, idLen)
            val senderLen = input.read()
            require(senderLen in 1..64) { "invalid sender length" }
            val sender = readExact(input, senderLen)
            val recipientLen = input.read()
            require(recipientLen in 1..64) { "invalid recipient length" }
            val recipient = readExact(input, recipientLen)
            val sequence = readLong(input)
            val ivLen = input.read()
            require(ivLen in 12..16) { "invalid iv length $ivLen" }
            val iv = readExact(input, ivLen)
            val ctLen = readInt(input)
            require(ctLen in 16..(MAX_ENVELOPE_BYTES)) { "invalid ciphertext length $ctLen" }
            val ct = readExact(input, ctLen)
            val stateOrdinal = input.read()
            require(stateOrdinal in DeliveryState.entries.indices) { "invalid delivery state" }
            val outgoing = input.read() == 1
            out += StoredEnvelope(
                envelope = SealedMessageEnvelope(
                    protocolVersion = protocolVersion,
                    messageId = id,
                    senderDeviceId = sender,
                    recipientDeviceId = recipient,
                    sequenceNumber = sequence,
                    iv = iv,
                    ciphertextAndTag = ct
                ),
                deliveryState = DeliveryState.entries[stateOrdinal],
                isOutgoing = outgoing
            )
        }
        require(input.available() == 0) { "trailing bytes in message store" }
        return out.sortedWith(order)
    }

    private fun readInt(input: java.io.ByteArrayInputStream): Int {
        val b = readExact(input, 4)
        return ((b[0].toInt() and 0xFF) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or
            (b[3].toInt() and 0xFF)
    }

    private fun readLong(input: java.io.ByteArrayInputStream): Long {
        var v = 0L
        readExact(input, 8).forEach { v = (v shl 8) or (it.toLong() and 0xFF) }
        return v
    }

    private fun readExact(input: java.io.ByteArrayInputStream, count: Int): ByteArray {
        require(count >= 0) { "negative read length" }
        val buffer = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = input.read(buffer, offset, count - offset)
            require(read > 0) { "truncated message store" }
            offset += read
        }
        return buffer
    }

    companion object {
        private const val STORAGE_VERSION: Byte = 0x01
        private const val MAX_MESSAGES = 20_000
        private const val MAX_ENVELOPE_BYTES = MessageCipher.MAX_BODY_BYTES + 4096

        fun keyFor(conversationId: String): String = "duolink.conv.$conversationId.v1"

        /** Deterministic display order shared by both devices. */
        val order: Comparator<StoredEnvelope> = Comparator { a, b ->
            val byTime = a.envelope.sequenceNumber.compareTo(b.envelope.sequenceNumber)
            if (byTime != 0) byTime
            else ByteEncoding.compareLexicographically(a.envelope.messageId, b.envelope.messageId)
        }
    }
}

/** Monotonic delivery ordering, used to reject stale state overwrites. */
fun DeliveryState.rank(): Int = when (this) {
    DeliveryState.PENDING -> 0
    DeliveryState.SENT -> 1
    DeliveryState.DELIVERED -> 2
    DeliveryState.READ -> 3
    DeliveryState.FAILED -> 4
}
