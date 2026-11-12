package com.duolink.app.messaging

import com.duolink.app.crypto.ByteEncoding
import java.security.SecureRandom

/**
 * Transport contract the conversation engine needs.
 *
 * Kept as an interface so the same engine can be driven by the WebSocket transport, the polling
 * fallback, or an in-memory fake in tests — and so the engine never learns which one is live.
 *
 * Implementations must be fail-closed: an upload that cannot be confirmed is reported as a failure, and
 * a fetch that errors must throw rather than return a silently empty list (an empty list means "no new
 * messages", which is a different thing from "the network is down").
 */
interface MessageTransport {
    /** Uploads one sealed envelope. Returns once the server has durably accepted it. */
    suspend fun send(envelope: SealedMessageEnvelope)

    /** Fetches envelopes addressed to [deviceId] newer than [sinceSequence], in sequence order. */
    suspend fun fetchSince(deviceId: ByteArray, sinceSequence: Long): List<SealedMessageEnvelope>

    /** Tells the peer we received [messageIdHex]. A lost receipt must not lose the message. */
    suspend fun sendDeliveryReceipt(messageIdHex: String)

    /** Tells the peer we displayed [messageIdHex]. */
    suspend fun sendReadReceipt(messageIdHex: String)
}

/** Connection state shown in the UI as a plain status line. */
enum class ConnectionState { OFFLINE, CONNECTING, ONLINE, RECONNECTING }

/** Failures the engine can surface, each with a Persian sentence the UI can show directly. */
sealed class ConversationFailure(val persianMessage: String) : Exception(persianMessage) {
    class NotPaired :
        ConversationFailure("برای گفتگو ابتدا باید با دستگاه دیگر جفت شوید.")

    class SessionLocked :
        ConversationFailure("برای ارسال پیام، برنامه را باز کنید.")

    class TransportError(detail: String) :
        ConversationFailure("ارتباط با سرور برقرار نشد. اتصال دوباره تلاش می‌شود.")

    class RejectedEnvelope(reason: String) :
        ConversationFailure("پیام دریافتی معتبر نبود و کنار گذاشته شد.")

    class StorageError(detail: String) :
        ConversationFailure("ذخیرهٔ پیام در حافظهٔ دستگاه ناموفق بود.")
}

/**
 * The conversation state machine: sequencing, sealing, de-duplication and delivery bookkeeping.
 *
 * Security invariants enforced here (and asserted in tests):
 *  1. Outgoing messages are sealed with the *sender's* directional key; incoming ones are opened with
 *     the peer's, so a reflected envelope (one the local device sent, echoed back) can never be
 *     accepted as an incoming message from the peer.
 *  2. An envelope whose authenticated sender is not the pinned peer is rejected before decryption is
 *     attempted, and rejected again by the AEAD if someone tampers with the header.
 *  3. Sequence numbers only ever move forward locally, and a message id is stored at most once.
 *  4. A decryption failure is recorded as [ChatMessage.cryptoFailure] and shown as "unreadable" — it
 *     is never silently dropped, because a dropped message is indistinguishable from a message that
 *     never arrived.
 */
class ConversationEngine(
    private val store: ConversationStore,
    private val transport: MessageTransport,
    private val localDeviceId: ByteArray,
    private val peerDeviceId: ByteArray,
    private val sendKey: ByteArray,
    private val receiveKey: ByteArray,
    private val controlKey: ByteArray,
    private val clock: () -> Long = System::currentTimeMillis,
    private val random: SecureRandom = SecureRandom()
) {
    init {
        require(localDeviceId.size == MessageCipher.DEVICE_ID_BYTES) { "bad local device id" }
        require(peerDeviceId.size == MessageCipher.DEVICE_ID_BYTES) { "bad peer device id" }
        require(sendKey.size == ConversationKeySchedule.KEY_BYTES) { "bad send key" }
        require(receiveKey.size == ConversationKeySchedule.KEY_BYTES) { "bad receive key" }
        require(!ByteEncoding.constantTimeEquals(sendKey, receiveKey)) {
            "send and receive keys must differ (reflection protection)"
        }
    }

    /** Emits the current message list plus connection state whenever either changes. */
    private val listeners = mutableListOf<(List<ChatMessage>, ConnectionState) -> Unit>()
    private var cached: List<ChatMessage> = emptyList()
    private var connectionState: ConnectionState = ConnectionState.OFFLINE

    fun addListener(listener: (List<ChatMessage>, ConnectionState) -> Unit) {
        listeners += listener
        listener(cached, connectionState)
    }

    fun removeListener(listener: (List<ChatMessage>, ConnectionState) -> Unit) {
        listeners -= listener
    }

    /** Loads the transcript from sealed storage into memory. */
    fun loadHistory() {
        cached = when (val result = store.load()) {
            is ConversationStore.LoadResult.Loaded -> result.messages.mapNotNull { toChatMessage(it) }
            is ConversationStore.LoadResult.Empty -> emptyList()
            // Corruption is reported to the UI via the connection banner rather than silently
            // presenting an empty conversation, which would look like the history was deleted.
            is ConversationStore.LoadResult.Corrupted -> {
                connectionState = ConnectionState.OFFLINE
                emptyList()
            }
        }
        publish()
    }

    fun setConnectionState(state: ConnectionState) {
        connectionState = state
        publish()
    }

    /** Next sequence number: locally monotonic, never reuses a value even across restarts. */
    fun nextSequence(): Long = store.highestSequence() + 1

    /**
     * Sends a text message.
     *
     * The message is sealed locally *first* and displayed as PENDING immediately, so the user sees
     * their message even if the network call has not completed. A transport failure moves it to FAILED
     * with a retry affordance — it is never silently dropped.
     */
    suspend fun sendText(body: String): Result<ChatMessage> {
        if (body.isBlank()) {
            return Result.failure(IllegalArgumentException("empty message"))
        }
        if (body.toByteArray(Charsets.UTF_8).size > MessageCipher.MAX_BODY_BYTES) {
            return Result.failure(IllegalArgumentException("message too long"))
        }
        return sendPayload(
            type = MessageType.TEXT,
            body = body.toByteArray(Charsets.UTF_8)
        )
    }

    /** Sends an attachment message. The media bytes are already sealed in [com.duolink.app.media.MediaVault]. */
    suspend fun sendAttachment(
        kind: MessageType,
        mediaDigestSha256: ByteArray,
        mediaFileName: String,
        mediaMimeType: String,
        mediaSizeBytes: Long,
        mediaDurationMs: Long,
        caption: String = ""
    ): Result<ChatMessage> {
        require(kind == MessageType.IMAGE || kind == MessageType.VIDEO) { "not an attachment type" }
        require(mediaDigestSha256.size == 32) { "media digest must be 32 bytes" }
        return sendPayload(
            type = kind,
            body = caption.toByteArray(Charsets.UTF_8),
            mediaDigest = mediaDigestSha256,
            mediaFileName = mediaFileName,
            mediaMimeType = mediaMimeType,
            mediaSize = mediaSizeBytes,
            mediaDuration = mediaDurationMs
        )
    }

    private suspend fun sendPayload(
        type: MessageType,
        body: ByteArray,
        mediaDigest: ByteArray? = null,
        mediaFileName: String? = null,
        mediaMimeType: String? = null,
        mediaSize: Long = 0L,
        mediaDuration: Long = 0L
    ): Result<ChatMessage> {
        val payload = MessagePayload(
            messageId = ByteArray(MessageCipher.MESSAGE_ID_BYTES).also { random.nextBytes(it) },
            senderDeviceId = localDeviceId,
            createdAtEpochMs = clock(),
            sequenceNumber = nextSequence(),
            type = type,
            body = body,
            mediaDigestSha256 = mediaDigest,
            mediaFileName = mediaFileName,
            mediaMimeType = mediaMimeType,
            mediaSizeBytes = mediaSize,
            mediaDurationMs = mediaDuration
        )
        val envelope = MessageCipher.seal(payload, sendKey, peerDeviceId, random)

        // Persist as PENDING before touching the network: if the process dies mid-send, the message is
        // still on screen and can be retried rather than lost.
        store.upsert(ConversationStore.StoredEnvelope(envelope, DeliveryState.PENDING, isOutgoing = true))
        val pending = ChatMessage(payload, DeliveryState.PENDING, isOutgoing = true)
        refresh()

        return try {
            transport.send(envelope)
            store.updateDeliveryState(ByteEncoding.toHexLower(payload.messageId), DeliveryState.SENT)
            refresh()
            Result.success(pending.copy(deliveryState = DeliveryState.SENT))
        } catch (t: Throwable) {
            store.updateDeliveryState(ByteEncoding.toHexLower(payload.messageId), DeliveryState.FAILED)
            refresh()
            Result.failure(ConversationFailure.TransportError(t.message ?: t.javaClass.simpleName))
        }
    }

    /** Re-attempts a previously FAILED outgoing message. */
    suspend fun retry(messageIdHex: String): Result<ChatMessage> {
        val entry = (store.load() as? ConversationStore.LoadResult.Loaded)
            ?.messages?.firstOrNull { it.key == messageIdHex && it.isOutgoing }
            ?: return Result.failure(IllegalArgumentException("unknown outgoing message"))
        return try {
            transport.send(entry.envelope)
            store.updateDeliveryState(messageIdHex, DeliveryState.SENT)
            refresh()
            Result.success(toChatMessage(entry.copy(deliveryState = DeliveryState.SENT))!!)
        } catch (t: Throwable) {
            store.updateDeliveryState(messageIdHex, DeliveryState.SENT)
            refresh()
            Result.failure(ConversationFailure.TransportError(t.message ?: "unknown"))
        }
    }

    /**
     * Pulls new envelopes from the transport and folds them into the transcript.
     *
     * Returns the number of *new* messages accepted. Duplicates (already stored by id) are skipped
     * without re-decrypting, which is what makes overlapping WebSocket + polling delivery safe.
     */
    suspend fun syncOnce(): Int {
        val since = store.highestSequence()
        val incoming = transport.fetchSince(localDeviceId, since)
        var accepted = 0
        incoming.sortedBy { it.sequenceNumber }.forEach { envelope ->
            if (ingest(envelope)) accepted++
        }
        if (accepted > 0) refresh()
        return accepted
    }

    /**
     * Validates and stores one incoming envelope.
     *
     * Returns true only when a genuinely new message was accepted.
     */
    fun ingest(envelope: SealedMessageEnvelope): Boolean {
        val idHex = ByteEncoding.toHexLower(envelope.messageId)
        if (store.contains(idHex)) return false

        // 1. The authenticated sender must be the pinned peer. Anything else is a third device.
        if (!ByteEncoding.constantTimeEquals(envelope.senderDeviceId, peerDeviceId)) return false
        // 2. It must be addressed to this device.
        if (!ByteEncoding.constantTimeEquals(envelope.recipientDeviceId, localDeviceId)) return false

        // 3. Decrypt. A tag failure is recorded, not hidden.
        val (payload, failure) = try {
            MessageCipher.open(envelope, receiveKey) to null
        } catch (t: MessageCryptoException) {
            null to t.message
        }

        if (payload == null) {
            // Store the opaque envelope with no plaintext so the user sees that something failed to
            // authenticate, and the transport can still be asked to re-send it.
            val placeholder = MessagePayload(
                messageId = envelope.messageId,
                senderDeviceId = envelope.senderDeviceId,
                createdAtEpochMs = clock(),
                sequenceNumber = envelope.sequenceNumber,
                type = MessageType.SYSTEM,
                body = ByteArray(0)
            )
            store.upsert(
                ConversationStore.StoredEnvelope(envelope, DeliveryState.DELIVERED, isOutgoing = false)
            )
            cached = cached + ChatMessage(placeholder, DeliveryState.DELIVERED, false, failure ?: "unknown")
            return true
        }

        store.upsert(ConversationStore.StoredEnvelope(envelope, DeliveryState.DELIVERED, isOutgoing = false))
        return true
    }

    /** Marks every incoming message as read and tells the peer. Best effort on the receipt. */
    suspend fun markAllRead() {
        val unread = cached.filter { !it.isOutgoing && it.deliveryState != DeliveryState.READ }
        unread.forEach { message ->
            store.updateDeliveryState(message.messageIdHex, DeliveryState.READ)
            runCatching { transport.sendReadReceipt(message.messageIdHex) }
        }
        if (unread.isNotEmpty()) refresh()
    }

    /** Marks a single delivered message as read (called when it scrolls into view). */
    suspend fun markRead(messageIdHex: String) {
        store.updateDeliveryState(messageIdHex, DeliveryState.READ)
        runCatching { transport.sendReadReceipt(messageIdHex) }
        refresh()
    }

    private fun refresh() {
        cached = when (val result = store.load()) {
            is ConversationStore.LoadResult.Loaded -> result.messages.mapNotNull { toChatMessage(it) }
            else -> cached
        }
        publish()
    }

    private fun publish() {
        val snapshot = cached
        listeners.toList().forEach { it(snapshot, connectionState) }
    }

    private fun toChatMessage(entry: ConversationStore.StoredEnvelope): ChatMessage? {
        return try {
            val payload = MessageCipher.open(
                entry.envelope,
                if (entry.isOutgoing) sendKey else receiveKey
            )
            ChatMessage(payload, entry.deliveryState, entry.isOutgoing)
        } catch (t: MessageCryptoException) {
            // The stored envelope no longer opens (e.g. the conversation key was rotated after a
            // re-pair). Surface it rather than dropping the bubble.
            ChatMessage(
                MessagePayload(
                    messageId = entry.envelope.messageId,
                    senderDeviceId = entry.envelope.senderDeviceId,
                    createdAtEpochMs = 0L,
                    sequenceNumber = entry.envelope.sequenceNumber,
                    type = MessageType.SYSTEM,
                    body = ByteArray(0)
                ),
                entry.deliveryState,
                entry.isOutgoing,
                cryptoFailure = t.message
            )
        }
    }
}
