package com.duolink.app

import com.duolink.app.messaging.ConversationKeySchedule
import com.duolink.app.messaging.MessageCipher
import com.duolink.app.messaging.MessageCryptoException
import com.duolink.app.messaging.MessagePayload
import com.duolink.app.messaging.MessageType
import com.duolink.app.messaging.SealedMessageEnvelope
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for the conversation crypto core.
 *
 * These run on the JVM (no Android framework), so they are enforced on every CI build. Everything here
 * is deterministic except the values marked as randomised.
 */
class MessagingCryptoTest {

    private val random = SecureRandom()
    private val initiatorId = ByteArray(16).also { random.nextBytes(it) }
    private val responderId = ByteArray(16).also { random.nextBytes(it) }
    private val rootKey = ByteArray(32).also { random.nextBytes(it) }

    private fun payload(
        type: MessageType = MessageType.TEXT,
        body: String = "سلام نسرین! این پیام رمزنگاری‌شده است.",
        sequence: Long = 1L,
        mediaDigest: ByteArray? = null
    ): MessagePayload = MessagePayload(
        messageId = ByteArray(16).also { random.nextBytes(it) },
        senderDeviceId = initiatorId,
        createdAtEpochMs = 1_767_225_600_000L,
        sequenceNumber = sequence,
        type = type,
        body = body.toByteArray(Charsets.UTF_8),
        mediaDigestSha256 = mediaDigest,
        mediaFileName = if (mediaDigest != null) "photo.dlmedia" else null,
        mediaMimeType = if (mediaDigest != null) "image/jpeg" else null,
        mediaSizeBytes = if (mediaDigest != null) 123_456L else 0L
    )

    // ---- key schedule -------------------------------------------------------

    @Test
    fun directionalKeysAreDistinctAndDeterministic() {
        val i2r = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val r2i = ConversationKeySchedule.responderToInitiatorKey(rootKey, initiatorId, responderId)
        val ctl = ConversationKeySchedule.controlKey(rootKey, initiatorId, responderId)

        // Deterministic: both devices derive identical keys from the same inputs.
        assertContentEquals(
            i2r,
            ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        )
        // Purpose separation: the three keys must never collide.
        assertNotEquals(i2r.toList(), r2i.toList())
        assertNotEquals(i2r.toList(), ctl.toList())
        assertNotEquals(r2i.toList(), ctl.toList())
        // Size is AES-256.
        assertEquals(32, i2r.size)
    }

    @Test
    fun keyScheduleIsBoundToBothDeviceIdentities() {
        val base = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val otherInitiator = ByteArray(16).also { random.nextBytes(it) }
        val swapped = ConversationKeySchedule.initiatorToResponderKey(rootKey, otherInitiator, responderId)
        val reversed = ConversationKeySchedule.initiatorToResponderKey(rootKey, responderId, initiatorId)

        assertNotEquals(base.toList(), swapped.toList())
        // Swapping the roles must not produce the same key: order is part of the transcript.
        assertNotEquals(base.toList(), reversed.toList())
    }

    @Test
    fun differentRootKeysProduceDifferentConversationKeys() {
        val otherRoot = ByteArray(32).also { random.nextBytes(it) }
        assertNotEquals(
            ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId).toList(),
            ConversationKeySchedule.initiatorToResponderKey(otherRoot, initiatorId, responderId).toList()
        )
    }

    // ---- round trip ---------------------------------------------------------

    @Test
    fun sealedMessageRoundTripsBetweenTheTwoDevices() {
        val i2r = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val r2i = ConversationKeySchedule.responderToInitiatorKey(rootKey, initiatorId, responderId)
        val original = payload(body = "پیام آزمایشی ۱۲۳")

        // Initiator seals with i2r; responder opens with the same key.
        val envelope = MessageCipher.seal(original, i2r, responderId, random)
        val opened = MessageCipher.open(envelope, i2r)

        assertEquals(original.messageId.toList(), opened.messageId.toList())
        assertEquals(original.sequenceNumber, opened.sequenceNumber)
        assertEquals(MessageType.TEXT, opened.type)
        assertContentEquals(original.body, opened.body)
        assertNull(opened.mediaDigestSha256)
        // The reverse key must not open it.
        assertFailsWith<MessageCryptoException.TagMismatch> { MessageCipher.open(envelope, r2i) }
    }

    @Test
    fun everyEnvelopeUsesAFreshIv() {
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val msg = payload()
        val first = MessageCipher.seal(msg, key, responderId, random)
        val second = MessageCipher.seal(msg, key, responderId, random)
        // Same plaintext, different IV => different ciphertext. This is what makes GCM safe across messages.
        assertNotEquals(first.iv.toList(), second.iv.toList())
        assertNotEquals(first.ciphertextAndTag.toList(), second.ciphertextAndTag.toList())
    }

    @Test
    fun gcmCiphertextHidesThePlaintext() {
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val secret = "این یک راز است"
        val envelope = MessageCipher.seal(payload(body = secret), key, responderId, random)
        val haystack = String(envelope.ciphertextAndTag, Charsets.ISO_8859_1)
        assertFalse(haystack.contains(secret), "plaintext must never appear in the ciphertext")
    }

    // ---- negative security --------------------------------------------------

    @Test
    fun flippedCiphertextByteIsRejected() {
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val envelope = MessageCipher.seal(payload(), key, responderId, random)
        val tampered = envelope.copy(ciphertextAndTag = envelope.ciphertextAndTag.copyOf().also {
            it[it.size / 2] = (it[it.size / 2].toInt() xor 0x01).toByte()
        })
        assertFailsWith<MessageCryptoException.TagMismatch> { MessageCipher.open(tampered, key) }
    }

    @Test
    fun truncatedCiphertextIsRejected() {
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val envelope = MessageCipher.seal(payload(), key, responderId, random)
        val truncated = envelope.copy(ciphertextAndTag = envelope.ciphertextAndTag.copyOf(envelope.ciphertextAndTag.size - 4))
        assertFailsWith<MessageCryptoException.TagMismatch> { MessageCipher.open(truncated, key) }
    }

    @Test
    fun tamperedSequenceNumberFailsBecauseItIsInTheAssociatedData() {
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val envelope = MessageCipher.seal(payload(sequence = 5), key, responderId, random)

        // Bumping the sequence (a replay/reorder attack) must invalidate the GCM tag.
        val reordered = envelope.copy(sequenceNumber = envelope.sequenceNumber + 1)
        assertFailsWith<MessageCryptoException.TagMismatch> { MessageCipher.open(reordered, key) }
    }

    @Test
    fun tamperedRecipientFailsBecauseItIsInTheAssociatedData() {
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val envelope = MessageCipher.seal(payload(), key, responderId, random)

        // Redirecting the envelope to a third device must break authentication.
        val thirdDevice = ByteArray(16).also { random.nextBytes(it) }
        val redirected = envelope.copy(recipientDeviceId = thirdDevice)
        assertFailsWith<MessageCryptoException.TagMismatch> { MessageCipher.open(redirected, key) }
    }

    @Test
    fun ciphertextCannotBeReboundToADifferentMessageId() {
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val envelope = MessageCipher.seal(payload(), key, responderId, random)
        val newId = ByteArray(16).also { random.nextBytes(it) }
        assertFailsWith<MessageCryptoException.TagMismatch> {
            MessageCipher.open(envelope.copy(messageId = newId), key)
        }
    }

    @Test
    fun envelopeFromOneConversationCannotBeOpenedInAnother() {
        val keyA = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val otherRoot = ByteArray(32).also { random.nextBytes(it) }
        val keyB = ConversationKeySchedule.initiatorToResponderKey(otherRoot, initiatorId, responderId)
        val envelope = MessageCipher.seal(payload(), keyA, responderId, random)
        assertFailsWith<MessageCryptoException.TagMismatch> { MessageCipher.open(envelope, keyB) }
    }

    @Test
    fun unsupportedEnvelopeVersionIsRejectedBeforeDecryption() {
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val envelope = MessageCipher.seal(payload(), key, responderId, random)
        assertFailsWith<IllegalArgumentException> {
            MessageCipher.open(envelope.copy(protocolVersion = 0x02), key)
        }
    }

    // ---- attachments --------------------------------------------------------

    @Test
    fun imageMessageCarriesADigestButNotTheMediaBytes() {
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val digest = ByteArray(32).also { random.nextBytes(it) }
        val original = payload(type = MessageType.IMAGE, body = "", mediaDigest = digest)

        val envelope = MessageCipher.seal(original, key, responderId, random)
        val opened = MessageCipher.open(envelope, key)

        assertEquals(MessageType.IMAGE, opened.type)
        assertContentEquals(digest, opened.mediaDigestSha256)
        assertEquals("image/jpeg", opened.mediaMimeType)
        assertEquals(123_456L, opened.mediaSizeBytes)
        // The media bytes are not in the envelope: only the digest and file handle travel.
        assertTrue(envelope.ciphertextAndTag.size < 1_000)
    }

    @Test
    fun messageTypeIsAuthenticatedNotJustHinted() {
        // TYPE_TEXT and TYPE_IMAGE payloads differ, so an attacker cannot relabel one as the other and
        // still have the tag verify: flipping the type byte changes the decrypted structure.
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val envelope = MessageCipher.seal(payload(type = MessageType.TEXT, body = "hello"), key, responderId, random)
        val raw = envelope.ciphertextAndTag.copyOf()

        // Flip a byte inside the sealed body region (past the 16-byte tag at the end).
        raw[raw.size - 20] = (raw[raw.size - 20].toInt() xor 0x40).toByte()
        assertFailsWith<MessageCryptoException.TagMismatch> {
            MessageCipher.open(envelope.copy(ciphertextAndTag = raw), key)
        }
    }

    @Test
    fun associatedDataIsStableAcrossCalls() {
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val envelope = MessageCipher.seal(payload(), key, responderId, random)
        // Both devices must compute identical AD from the same header, byte for byte.
        assertContentEquals(envelope.associatedData(), envelope.associatedData())
        assertTrue(
            String(envelope.associatedData(), Charsets.ISO_8859_1)
                .startsWith(SealedMessageEnvelope.AD_PREFIX)
        )
    }

    @Test
    fun oversizedBodyIsRefusedRatherThanSilentlyTruncated() {
        val key = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val huge = payload(body = "x".repeat(MessageCipher.MAX_BODY_BYTES + 1))
        assertFailsWith<IllegalArgumentException> { MessageCipher.seal(huge, key, responderId, random) }
    }
}
