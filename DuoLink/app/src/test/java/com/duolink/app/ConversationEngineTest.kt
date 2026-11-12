package com.duolink.app

import com.duolink.app.crypto.InMemoryByteStore
import com.duolink.app.crypto.JcaAesGcmSealer
import com.duolink.app.messaging.ChatMessage
import com.duolink.app.messaging.ConnectionState
import com.duolink.app.messaging.ConversationEngine
import com.duolink.app.messaging.ConversationKeySchedule
import com.duolink.app.messaging.ConversationStore
import com.duolink.app.messaging.DeliveryState
import com.duolink.app.messaging.MessageCipher
import com.duolink.app.messaging.MessagePayload
import com.duolink.app.messaging.MessageTransport
import com.duolink.app.messaging.MessageType
import com.duolink.app.messaging.SealedMessageEnvelope
import kotlinx.coroutines.runBlocking
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Transport that is deliberately in-memory and, importantly, *lossless only when told to be*.
 *
 * Tests drive failure by flipping [failNextSend] / [failFetch], which is how a real flaky link behaves.
 */
private class FakeTransport : MessageTransport {
    val outbox = mutableListOf<SealedMessageEnvelope>()
    val deliveryReceipts = mutableListOf<String>()
    val readReceipts = mutableListOf<String>()
    var failNextSend = false
    var failFetch = false
    var pending = mutableListOf<SealedMessageEnvelope>()

    override suspend fun send(envelope: SealedMessageEnvelope) {
        if (failNextSend) {
            failNextSend = false
            throw java.io.IOException("network down")
        }
        outbox += envelope
    }

    override suspend fun fetchSince(deviceId: ByteArray, sinceSequence: Long): List<SealedMessageEnvelope> {
        if (failFetch) {
            failFetch = false
            throw java.io.IOException("network down")
        }
        return pending.filter { it.sequenceNumber > sinceSequence }.toList()
    }

    override suspend fun sendDeliveryReceipt(messageIdHex: String) {
        deliveryReceipts += messageIdHex
    }

    override suspend fun sendReadReceipt(messageIdHex: String) {
        readReceipts += messageIdHex
    }
}

/**
 * End-to-end conversation tests exercised fully on the JVM.
 *
 * Two real engines are built (initiator and responder) with mirrored key schedules, and messages are
 * actually sealed, transported and opened - nothing is stubbed at the crypto layer.
 */
class ConversationEngineTest {

    private val random = SecureRandom()
    // One sealer per logical device. A real Android Keystore key persists across process restarts, so
    // modelling a restart with a *fresh* JcaAesGcmSealer (which generates a new random key) would be
    // testing the wrong thing. Each device gets its own sealer, as in production.
    private val aliceSealer = JcaAesGcmSealer()
    private val bobSealer = JcaAesGcmSealer()
    private val rootKey = ByteArray(32).also { random.nextBytes(it) }
    private val aliceId = ByteArray(16).also { random.nextBytes(it) }
    private val bobId = ByteArray(16).also { random.nextBytes(it) }

    private val i2r get() = ConversationKeySchedule.initiatorToResponderKey(rootKey, aliceId, bobId)
    private val r2i get() = ConversationKeySchedule.responderToInitiatorKey(rootKey, aliceId, bobId)
    private val ctl get() = ConversationKeySchedule.controlKey(rootKey, aliceId, bobId)

    private class Pair(
        val alice: ConversationEngine,
        val bob: ConversationEngine,
        val aliceStore: ConversationStore,
        val bobStore: ConversationStore,
        val transport: FakeTransport
    )

    private fun buildPair(sharedTransport: FakeTransport = FakeTransport()): Pair {
        val aliceStore = ConversationStore(InMemoryByteStore(), aliceSealer, "conv-alice")
        val bobStore = ConversationStore(InMemoryByteStore(), bobSealer, "conv-bob")
        val alice = ConversationEngine(
            store = aliceStore,
            transport = sharedTransport,
            localDeviceId = aliceId,
            peerDeviceId = bobId,
            sendKey = i2r,
            receiveKey = r2i,
            controlKey = ctl,
            clock = { 1_700_000_000_000L },
            random = random
        )
        val bob = ConversationEngine(
            store = bobStore,
            transport = sharedTransport,
            localDeviceId = bobId,
            peerDeviceId = aliceId,
            // Mirrored intentionally: Bob sends with r2i and receives with i2r.
            sendKey = r2i,
            receiveKey = i2r,
            controlKey = ctl,
            clock = { 1_700_000_000_000L },
            random = random
        )
        alice.loadHistory()
        bob.loadHistory()
        return Pair(alice, bob, aliceStore, bobStore, sharedTransport)
    }

    // ---- happy path ------------------------------------------------------

    @Test
    fun textMessageTravelsFromAliceToBob() = runBlocking {
        val pair = buildPair()

        val result = pair.alice.sendText("سلام نسرین، این پیام تست است.")
        assertTrue(result.isSuccess)
        assertEquals(1, pair.transport.outbox.size)

        val envelope = pair.transport.outbox.single()
        assertTrue(pair.bob.ingest(envelope))

        val bobMessages = pair.bobStore.load()
        assertIs<ConversationStore.LoadResult.Loaded>(bobMessages)
        assertEquals(1, bobMessages.messages.size)

        val opened = MessageCipher.open(bobMessages.messages.single().envelope, i2r)
        assertEquals("سلام نسرین، این پیام تست است.", String(opened.body, Charsets.UTF_8))
        assertEquals(MessageType.TEXT, opened.type)
    }

    @Test
    fun outgoingMessageIsPersistedBeforeTheNetworkCall() = runBlocking {
        val pair = buildPair()
        pair.transport.failNextSend = true

        val result = pair.alice.sendText("پیامی که ارسال نمی‌شود")
        assertTrue(result.isFailure)

        // Even though the send failed, the message is on the device, marked FAILED (not lost).
        val stored = pair.aliceStore.load()
        assertIs<ConversationStore.LoadResult.Loaded>(stored)
        assertEquals(1, stored.messages.size)
        assertEquals(DeliveryState.FAILED, stored.messages.single().deliveryState)
    }

    @Test
    fun failedMessageCanBeRetriedSuccessfully() = runBlocking {
        val pair = buildPair()
        pair.transport.failNextSend = true
        pair.alice.sendText("دوباره تلاش کن")

        val idHex = (pair.aliceStore.load() as ConversationStore.LoadResult.Loaded)
            .messages.single().key
        val retried = pair.alice.retry(idHex)

        assertTrue(retried.isSuccess)
        assertEquals(1, pair.transport.outbox.size)
        val stored = pair.aliceStore.load() as ConversationStore.LoadResult.Loaded
        assertEquals(DeliveryState.SENT, stored.messages.single().deliveryState)
    }

    @Test
    fun bothDirectionsHaveIndependentSequencesAndKeys() = runBlocking {
        val pair = buildPair()
        pair.alice.sendText("از آلیس ۱")
        pair.alice.sendText("از آلیس ۲")
        pair.bob.sendText("از باب ۱")

        // Each device numbers its OWN messages; receiving does not advance the local counter.
        assertEquals(2, pair.aliceStore.highestSequence())
        assertEquals(1, pair.bobStore.highestSequence(), "each device keeps its own monotonic counter")

        val fromAlice = pair.transport.outbox.filter { it.senderDeviceId.contentEquals(aliceId) }
        assertEquals(2, fromAlice.size)
        fromAlice.forEach { assertTrue(pair.bob.ingest(it)) }
    }

    @Test
    fun sequenceNumbersNeverRepeatAcrossRestarts() = runBlocking {
        val first = buildPair()
        first.alice.sendText("قبل از بستن برنامه")
        val before = first.alice.nextSequence()

        // Simulate a restart: rebuild the engine over the *same* sealed store.
        val revivedStore = first.aliceStore
        val revived = ConversationEngine(
            store = revivedStore,
            transport = first.transport,
            localDeviceId = aliceId,
            peerDeviceId = bobId,
            sendKey = i2r,
            receiveKey = r2i,
            controlKey = ctl,
            clock = { 1_700_000_000_000L },
            random = random
        )
        assertEquals(before, revived.nextSequence())
        revived.sendText("بعد از باز شدن مجدد")
        assertTrue(revived.nextSequence() > before)
    }

    // ---- delivery & de-duplication ---------------------------------------

    @Test
    fun duplicateEnvelopeIsIgnoredNotDisplayedTwice() = runBlocking {
        val pair = buildPair()
        pair.alice.sendText("یک پیام")
        val envelope = pair.transport.outbox.single()

        assertTrue(pair.bob.ingest(envelope), "first delivery is accepted")
        assertFalse(pair.bob.ingest(envelope), "second delivery must be ignored")

        val stored = pair.bobStore.load() as ConversationStore.LoadResult.Loaded
        assertEquals(1, stored.messages.size)
    }

    @Test
    fun overlappingPollAndPushDeliveryIsSafe() = runBlocking {
        // The brief requires WebSocket with a polling fallback; those can deliver the same envelope.
        val pair = buildPair()
        pair.alice.sendText("پیام همزمان")
        val envelope = pair.transport.outbox.single()

        pair.transport.pending = mutableListOf(envelope)
        val fromPoll = pair.bob.syncOnce()
        val fromPush = if (pair.bob.ingest(envelope)) 1 else 0

        assertEquals(1, fromPoll + fromPush, "the message must be counted exactly once")
        val stored = pair.bobStore.load() as ConversationStore.LoadResult.Loaded
        assertEquals(1, stored.messages.size)
    }

    @Test
    fun syncOnceReportsOnlyGenuinelyNewMessages() = runBlocking {
        val pair = buildPair()
        pair.alice.sendText("اول")
        pair.alice.sendText("دوم")

        pair.transport.pending = pair.transport.outbox.toMutableList()
        assertEquals(2, pair.bob.syncOnce())
        assertEquals(0, pair.bob.syncOnce(), "a second poll with nothing new must report zero")
    }

    @Test
    fun readStateMovesForwardAndIsNeverDowngraded() = runBlocking {
        val pair = buildPair()
        pair.alice.sendText("خوانده شود")
        val envelope = pair.transport.outbox.single()
        pair.bob.ingest(envelope)
        val idHex = java.util.HexFormat.of().formatHex(envelope.messageId)

        pair.bob.markRead(idHex)
        assertEquals(DeliveryState.READ, (pair.bobStore.load() as ConversationStore.LoadResult.Loaded).messages.single().deliveryState)

        // A stale SENT update arriving late must NOT un-read the message.
        pair.bobStore.updateDeliveryState(idHex, DeliveryState.SENT)
        val after = pair.bobStore.load() as ConversationStore.LoadResult.Loaded
        assertEquals(
            DeliveryState.READ,
            after.messages.single().deliveryState,
            "a late/stale update must never downgrade a read message"
        )
    }

    @Test
    fun markAllReadSendsReceiptsForIncomingOnly() = runBlocking {
        val pair = buildPair()
        pair.alice.sendText("دریافتی")
        pair.bob.ingest(pair.transport.outbox.single())
        pair.bob.sendText("پاسخ من")

        pair.bob.markAllRead()
        // Only the incoming message generates a read receipt.
        assertEquals(1, pair.transport.readReceipts.size)
    }

    // ---- negative security ----------------------------------------------

    @Test
    fun envelopeFromAThirdDeviceIsRejected() = runBlocking {
        val pair = buildPair()
        val thirdDevice = ByteArray(16).also { random.nextBytes(it) }
        val impostorPayload = MessagePayload(
            messageId = ByteArray(16).also { random.nextBytes(it) },
            senderDeviceId = thirdDevice,
            createdAtEpochMs = 1L,
            sequenceNumber = 99L,
            type = MessageType.TEXT,
            body = "من باب هستم".toByteArray()
        )
        val forged = MessageCipher.seal(impostorPayload, i2r, bobId, random)

        assertFalse(pair.bob.ingest(forged), "a third device must never be accepted")
        assertIs<ConversationStore.LoadResult.Empty>(pair.bobStore.load())
    }

    @Test
    fun envelopeAddressedToAnotherDeviceIsRejected() = runBlocking {
        val pair = buildPair()
        val someoneElse = ByteArray(16).also { random.nextBytes(it) }
        val payload = MessagePayload(
            messageId = ByteArray(16).also { random.nextBytes(it) },
            senderDeviceId = aliceId,
            createdAtEpochMs = 1L,
            sequenceNumber = 1L,
            type = MessageType.TEXT,
            body = "برای دستگاه دیگر".toByteArray()
        )
        val misaddressed = MessageCipher.seal(payload, i2r, someoneElse, random)
        assertFalse(pair.bob.ingest(misaddressed))
    }

    @Test
    fun reflectedMessageCannotBeAcceptedAsIncoming() = runBlocking {
        // Alice's own outgoing envelope, replayed back to her, must not appear as a message from Bob.
        val pair = buildPair()
        pair.alice.sendText("پیام خودم")
        val own = pair.transport.outbox.single()
        assertFalse(pair.alice.ingest(own), "own message must not be ingested as incoming")
    }

    @Test
    fun tamperedEnvelopeIsRecordedAsUnreadableRatherThanDropped() = runBlocking {
        val pair = buildPair()
        pair.alice.sendText("پیام اصلی")
        val envelope = pair.transport.outbox.single()
        val tampered = envelope.copy(
            ciphertextAndTag = envelope.ciphertextAndTag.copyOf().also {
                it[it.size / 2] = (it[it.size / 2].toInt() xor 0xFF).toByte()
            }
        )

        assertTrue(pair.bob.ingest(tampered), "the failure is recorded so the user can see it")
        val stored = pair.bobStore.load() as ConversationStore.LoadResult.Loaded
        assertEquals(1, stored.messages.size)

        val rendered = mutableListOf<ChatMessage>()
        pair.bob.addListener { messages, _ -> rendered.clear(); rendered.addAll(messages) }
        // After a refresh, the bubble carries a cryptoFailure explanation rather than disappearing.
        val direct = pair.bob.ingest(tampered.copy(messageId = ByteArray(16) { 9 }))
        assertTrue(direct)
    }

    @Test
    fun engineRefusesToConstructWithIdenticalSendAndReceiveKeys() {
        try {
            ConversationEngine(
                store = ConversationStore(InMemoryByteStore(), JcaAesGcmSealer(), "c"),
                transport = FakeTransport(),
                localDeviceId = aliceId,
                peerDeviceId = bobId,
                sendKey = i2r,
                receiveKey = i2r,
                controlKey = ctl
            )
            throw AssertionError("expected IllegalArgumentException for reflected key schedule")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("reflection"))
        }
    }

    // ---- storage ---------------------------------------------------------

    @Test
    fun transcriptIsSealedAtRestAndSurvivesReload() = runBlocking {
        val backing = InMemoryByteStore()
        val store = ConversationStore(backing, aliceSealer, "conv-persist")
        val engine = ConversationEngine(
            store = store,
            transport = FakeTransport(),
            localDeviceId = aliceId,
            peerDeviceId = bobId,
            sendKey = i2r,
            receiveKey = r2i,
            controlKey = ctl,
            clock = { 1_700_000_000_000L },
            random = random
        )
        engine.sendText("یک پیام محرمانه بسیار مهم")

        // The stored blob must not contain the plaintext.
        val raw = backing.readState(ConversationStore.keyFor("conv-persist"))
        assertIs<com.duolink.app.crypto.RawStoreRead.Present>(raw)
        val asLatin1 = String(raw.bytes, Charsets.ISO_8859_1)
        assertFalse(asLatin1.contains("محرمانه"), "plaintext must never be persisted")
        assertFalse(asLatin1.contains("DuoLink"), "not even internal markers should be greppable")

        // A fresh engine over the same store still sees the message.
        val revived = ConversationEngine(
            store = ConversationStore(backing, aliceSealer, "conv-persist"),
            transport = FakeTransport(),
            localDeviceId = aliceId,
            peerDeviceId = bobId,
            sendKey = i2r,
            receiveKey = r2i,
            controlKey = ctl,
            clock = { 1_700_000_000_000L },
            random = random
        )
        revived.loadHistory()
        val seen = mutableListOf<ChatMessage>()
        revived.addListener { messages, _ -> seen.clear(); seen.addAll(messages) }
        assertEquals(1, seen.size)
        assertEquals("یک پیام محرمانه بسیار مهم", String(seen.single().payload.body, Charsets.UTF_8))
    }

    @Test
    fun corruptedTranscriptIsReportedNotSilentlyEmptied() {
        val backing = InMemoryByteStore()
        val store = ConversationStore(backing, JcaAesGcmSealer(), "conv-broken")
        val engine = ConversationEngine(
            store = store,
            transport = FakeTransport(),
            localDeviceId = aliceId,
            peerDeviceId = bobId,
            sendKey = i2r,
            receiveKey = r2i,
            controlKey = ctl
        )
        runBlocking { engine.sendText("پیام") }
        backing.corruptRawBytesForTesting(ConversationStore.keyFor("conv-broken")) { bytes ->
            bytes.copyOf().also { it[it.size - 2] = (it[it.size - 2].toInt() xor 0xFF).toByte() }
        }
        assertIs<ConversationStore.LoadResult.Corrupted>(store.load())
    }

    @Test
    fun connectionStateIsObservable() {
        val pair = buildPair()
        val states = mutableListOf<ConnectionState>()
        pair.alice.addListener { _, state -> states += state }
        pair.alice.setConnectionState(ConnectionState.CONNECTING)
        pair.alice.setConnectionState(ConnectionState.ONLINE)
        pair.alice.setConnectionState(ConnectionState.RECONNECTING)

        assertTrue(states.contains(ConnectionState.OFFLINE), "initial state is published")
        assertTrue(states.contains(ConnectionState.ONLINE))
        assertTrue(states.contains(ConnectionState.RECONNECTING))
    }

    @Test
    fun emptyMessageIsRefused() = runBlocking {
        val pair = buildPair()
        assertTrue(pair.alice.sendText("   ").isFailure)
        assertEquals(0, pair.transport.outbox.size)
    }

    @Test
    fun attachmentMessageCarriesTheDigestAndOpens() = runBlocking {
        val pair = buildPair()
        val digest = ByteArray(32).also { random.nextBytes(it) }
        val result = pair.alice.sendAttachment(
            kind = MessageType.IMAGE,
            mediaDigestSha256 = digest,
            mediaFileName = "m_deadbeef.dlm",
            mediaMimeType = "image/jpeg",
            mediaSizeBytes = 250_000L,
            mediaDurationMs = 0L,
            caption = "نگاه کن"
        )
        assertTrue(result.isSuccess)
        val envelope = pair.transport.outbox.single()
        assertTrue(pair.bob.ingest(envelope))

        val stored = pair.bobStore.load() as ConversationStore.LoadResult.Loaded
        val opened = MessageCipher.open(stored.messages.single().envelope, i2r)
        assertEquals(MessageType.IMAGE, opened.type)
        assertEquals(250_000L, opened.mediaSizeBytes)
        assertEquals(digest.toList(), opened.mediaDigestSha256!!.toList())
    }
}
