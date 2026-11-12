package com.duolink.app.messaging

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.HkdfSha256
import com.duolink.app.crypto.TranscriptBuilder
import com.duolink.app.crypto.zeroize
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * What a conversation bubble can contain.
 *
 * The type is authenticated, not just hinted: [MessageType] is fed into the AEAD associated data, so
 * flipping a TYPE_TEXT envelope into TYPE_IMAGE causes authentication to fail rather than silently
 * rendering a text body as an image (or vice-versa).
 */
enum class MessageType(val wireCode: Byte) {
    TEXT(0x01),
    IMAGE(0x02),
    VIDEO(0x03),
    /** Local-only marker used after an attachment was saved/removed. Never sent over the wire. */
    SYSTEM(0x7F);

    companion object {
        fun fromWire(code: Byte): MessageType? = entries.firstOrNull { it.wireCode == code }
    }
}

/** Delivery state of an outgoing message, from the local user's point of view. */
enum class DeliveryState {
    /** Created and sealed locally; not yet acknowledged by the transport. */
    PENDING,
    /** The signaling server accepted and stored the ciphertext. */
    SENT,
    /** The peer device fetched and acknowledged the ciphertext. */
    DELIVERED,
    /** The peer explicitly confirmed it decrypted the message. */
    READ,
    /** The transport reported a permanent failure. */
    FAILED
}

/**
 * Identity of one conversation participant, as pinned at pairing time.
 *
 * Derived from the pairing record so a message can never be attributed to a device other than the one
 * the user compared a Safety Number with.
 */
data class ParticipantRef(
    val deviceId: ByteArray,
    val identitySpki: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ParticipantRef) return false
        return ByteEncoding.constantTimeEquals(deviceId, other.deviceId) &&
            ByteEncoding.constantTimeEquals(identitySpki, other.identitySpki)
    }

    override fun hashCode(): Int = 31 * deviceId.contentHashCode() + identitySpki.contentHashCode()
}

/**
 * Derives the long-lived conversation key from the pairing root key.
 *
 * `rootPairingKey` is the ECDH-derived secret both devices already hold after a successful Method A or
 * Method B pairing. We never encrypt messages directly with it: HKDF expands it into purpose-separated
 * subkeys so that (a) the message key is cryptographically independent of the Safety Number display key
 * and (b) each direction gets its own key, which prevents a reflected-ciphertext confusion between the
 * two participants.
 *
 * The `info` strings are domain separators. They are part of the frozen protocol: changing them without
 * changing both devices would silently break interop, so they are versioned (`v1`).
 */
object ConversationKeySchedule {
    private const val VERSION = "v1"

    /** Key for messages sent by the initiator (the device that displayed the first QR). */
    fun initiatorToResponderKey(
        rootPairingKey: ByteArray,
        initiatorDeviceId: ByteArray,
        responderDeviceId: ByteArray
    ): ByteArray = derive(rootPairingKey, "i2r", initiatorDeviceId, responderDeviceId)

    /** Key for messages sent by the responder. */
    fun responderToInitiatorKey(
        rootPairingKey: ByteArray,
        initiatorDeviceId: ByteArray,
        responderDeviceId: ByteArray
    ): ByteArray = derive(rootPairingKey, "r2i", initiatorDeviceId, responderDeviceId)

    /**
     * Key used to authenticate a *control* frame (delivery receipt, read receipt, typing indicator).
     * Separate from the message keys so a receipt frame can never be replayed as a message body.
     */
    fun controlKey(
        rootPairingKey: ByteArray,
        initiatorDeviceId: ByteArray,
        responderDeviceId: ByteArray
    ): ByteArray = derive(rootPairingKey, "ctl", initiatorDeviceId, responderDeviceId)

    private fun derive(
        rootPairingKey: ByteArray,
        direction: String,
        initiatorDeviceId: ByteArray,
        responderDeviceId: ByteArray
    ): ByteArray {
        require(rootPairingKey.isNotEmpty()) { "root pairing key must not be empty" }
        val info = TranscriptBuilder()
            .putRawUtf8("DuoLink-MsgKey-$VERSION")
            .putRawUtf8(direction)
            .putBytes(initiatorDeviceId)
            .putBytes(responderDeviceId)
            .build()
        return HkdfSha256.deriveKey(
            ikm = rootPairingKey,
            salt = null,
            info = info,
            outputLength = KEY_BYTES
        )
    }

    const val KEY_BYTES = 32
}

/**
 * Plaintext payload of a message, before sealing.
 *
 * [body] holds UTF-8 text for [MessageType.TEXT], or the *local file name* of the attachment for
 * image/video types. Media bytes are never carried inside the envelope: they are sealed separately to
 * disk so a 40 MB video does not have to fit in one JSON frame, and so the server never sees them at
 * all in the default (device-to-device over paired transport) path.
 */
data class MessagePayload(
    val messageId: ByteArray,
    val senderDeviceId: ByteArray,
    val createdAtEpochMs: Long,
    val sequenceNumber: Long,
    val type: MessageType,
    val body: ByteArray,
    val mediaDigestSha256: ByteArray? = null,
    val mediaFileName: String? = null,
    val mediaMimeType: String? = null,
    val mediaSizeBytes: Long = 0L,
    val mediaDurationMs: Long = 0L,
    val replyToMessageId: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MessagePayload) return false
        return ByteEncoding.constantTimeEquals(messageId, other.messageId) &&
            ByteEncoding.constantTimeEquals(senderDeviceId, other.senderDeviceId) &&
            createdAtEpochMs == other.createdAtEpochMs &&
            sequenceNumber == other.sequenceNumber &&
            type == other.type &&
            ByteEncoding.constantTimeEquals(body, other.body) &&
            mediaDigestMatches(other)
    }

    private fun mediaDigestMatches(other: MessagePayload): Boolean {
        val a = mediaDigestSha256 ?: return other.mediaDigestSha256 == null
        val b = other.mediaDigestSha256 ?: return false
        return ByteEncoding.constantTimeEquals(a, b)
    }

    override fun hashCode(): Int {
        var result = messageId.contentHashCode()
        result = 31 * result + senderDeviceId.contentHashCode()
        result = 31 * result + createdAtEpochMs.hashCode()
        result = 31 * result + sequenceNumber.hashCode()
        result = 31 * result + type.hashCode()
        result = 31 * result + body.contentHashCode()
        result = 31 * result + (mediaDigestSha256?.contentHashCode() ?: 0)
        return result
    }
}

/**
 * A sealed message as it travels and as it is stored on the server.
 *
 * The server sees exactly this: an opaque IV + AES-256-GCM ciphertext and a bounded set of routing
 * fields. It has no key material, no plaintext, and no ability to forge a message that either device
 * will accept, because the associated data binds the ciphertext to the two device identities and the
 * sequence number.
 */
data class SealedMessageEnvelope(
    val protocolVersion: Byte,
    val messageId: ByteArray,
    val senderDeviceId: ByteArray,
    val recipientDeviceId: ByteArray,
    val sequenceNumber: Long,
    val iv: ByteArray,
    val ciphertextAndTag: ByteArray
) {
    /** Canonical associated data — must match byte-for-byte on both devices. */
    fun associatedData(): ByteArray =
        TranscriptBuilder()
            .putRawUtf8(AD_PREFIX)
            .putInt32(protocolVersion.toInt() and 0xFF)
            .putBytes(messageId)
            .putBytes(senderDeviceId)
            .putBytes(recipientDeviceId)
            .putInt64(sequenceNumber)
            .build()

    companion object {
        const val AD_PREFIX = "DuoLink-MsgAD-v1"
        const val PROTOCOL_VERSION: Byte = 0x01
    }
}

/**
 * Seals and opens message envelopes with AES-256-GCM.
 *
 * Using the JDK's `Cipher` directly (not the Android Keystore sealer) is correct here: these keys are
 * *conversation* keys derived from the pairing, not device-bound keys. They must be identical on both
 * devices, so they cannot live in the Keystore. They are protected at rest by [MessageStore] sealing the
 * conversation key itself under the Keystore-backed storage sealer.
 */
object MessageCipher {
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128

    /** Seals [payload] for [recipientDeviceId] using [sendKey]. */
    fun seal(
        payload: MessagePayload,
        sendKey: ByteArray,
        recipientDeviceId: ByteArray,
        random: SecureRandom = SecureRandom()
    ): SealedMessageEnvelope {
        require(sendKey.size == ConversationKeySchedule.KEY_BYTES) {
            "message key must be ${ConversationKeySchedule.KEY_BYTES} bytes"
        }
        val iv = ByteArray(IV_BYTES).also { random.nextBytes(it) }
        val plaintext = encodePayload(payload)
        val envelope = SealedMessageEnvelope(
            protocolVersion = SealedMessageEnvelope.PROTOCOL_VERSION,
            messageId = payload.messageId,
            senderDeviceId = payload.senderDeviceId,
            recipientDeviceId = recipientDeviceId,
            sequenceNumber = payload.sequenceNumber,
            iv = iv,
            ciphertextAndTag = ByteArray(0)
        )
        val cipher = javax.crypto.Cipher.getInstance(TRANSFORMATION).apply {
            init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(sendKey, "AES"),
                javax.crypto.spec.GCMParameterSpec(TAG_BITS, iv)
            )
            updateAAD(envelope.associatedData())
        }
        return try {
            envelope.copy(ciphertextAndTag = cipher.doFinal(plaintext))
        } finally {
            plaintext.zeroizeLocal()
        }
    }

    /**
     * Opens [envelope] with [receiveKey].
     *
     * Every rejection is a hard failure — there is no "best effort" path and no partial plaintext is
     * ever returned. A GCM tag mismatch (tampered ciphertext, wrong key, mismatched associated data)
     * surfaces as [MessageCryptoException.TagMismatch]; callers must treat it as hostile input.
     */
    fun open(
        envelope: SealedMessageEnvelope,
        receiveKey: ByteArray
    ): MessagePayload {
        require(envelope.protocolVersion == SealedMessageEnvelope.PROTOCOL_VERSION) {
            "unsupported envelope version ${envelope.protocolVersion}"
        }
        require(envelope.iv.size == IV_BYTES) { "unexpected IV length ${envelope.iv.size}" }
        val cipher = javax.crypto.Cipher.getInstance(TRANSFORMATION).apply {
            init(
                javax.crypto.Cipher.DECRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(receiveKey, "AES"),
                javax.crypto.spec.GCMParameterSpec(TAG_BITS, envelope.iv)
            )
            updateAAD(envelope.associatedData())
        }
        val plaintext = try {
            cipher.doFinal(envelope.ciphertextAndTag)
        } catch (e: javax.crypto.AEADBadTagException) {
            throw MessageCryptoException.TagMismatch(
                "ciphertext failed authentication (tampered, truncated, or wrong key)"
            )
        } catch (e: java.security.GeneralSecurityException) {
            throw MessageCryptoException.TagMismatch("decryption failed: ${e.javaClass.simpleName}")
        }
        return try {
            decodePayload(plaintext, envelope)
        } finally {
            plaintext.zeroizeLocal()
        }
    }

    // ---- payload wire format -------------------------------------------------

    private fun encodePayload(payload: MessagePayload): ByteArray {
        require(payload.body.size <= MAX_BODY_BYTES) { "body too large" }
        val out = java.io.ByteArrayOutputStream()
        out.write(PAYLOAD_VERSION.toInt())
        out.write(payload.type.wireCode.toInt())
        out.writeBytes(payload.messageId)
        out.writeBytes(payload.senderDeviceId)
        writeLong(out, payload.createdAtEpochMs)
        writeLong(out, payload.sequenceNumber)
        writeInt(out, payload.body.size)
        out.write(payload.body)
        val mediaDigest = payload.mediaDigestSha256
        out.write(if (mediaDigest != null) 1 else 0)
        if (mediaDigest != null) {
            out.writeBytes(mediaDigest)
            writeString(out, payload.mediaFileName ?: "")
            writeString(out, payload.mediaMimeType ?: "")
            writeLong(out, payload.mediaSizeBytes)
            writeLong(out, payload.mediaDurationMs)
        }
        val replyTo = payload.replyToMessageId
        out.write(if (replyTo != null) 1 else 0)
        if (replyTo != null) out.writeBytes(replyTo)
        return out.toByteArray()
    }

    private fun decodePayload(plaintext: ByteArray, envelope: SealedMessageEnvelope): MessagePayload {
        val input = java.io.ByteArrayInputStream(plaintext)
        val version = input.read()
        require(version == PAYLOAD_VERSION.toInt()) { "unsupported payload version $version" }
        val typeCode = input.read().toByte()
        val type = MessageType.fromWire(typeCode)
            ?: throw MessageCryptoException.MalformedPayload("unknown message type $typeCode")
        val messageId = readExact(input, MESSAGE_ID_BYTES)
        val senderDeviceId = readExact(input, DEVICE_ID_BYTES)
        // Cross-check: the payload must agree with the authenticated envelope header. Because the header
        // is in the associated data, a mismatch here means someone built a payload for a different
        // message and encrypted it under this session — reject rather than trust either copy.
        if (!MessageDigest.isEqual(messageId, envelope.messageId)) {
            throw MessageCryptoException.MalformedPayload("payload messageId disagrees with envelope")
        }
        if (!MessageDigest.isEqual(senderDeviceId, envelope.senderDeviceId)) {
            throw MessageCryptoException.MalformedPayload("payload sender disagrees with envelope")
        }
        val createdAt = readLong(input)
        val sequence = readLong(input)
        if (sequence != envelope.sequenceNumber) {
            throw MessageCryptoException.MalformedPayload("payload sequence disagrees with envelope")
        }
        val bodyLen = readInt(input)
        require(bodyLen in 0..MAX_BODY_BYTES) { "invalid body length $bodyLen" }
        val body = readExact(input, bodyLen)
        val hasMedia = input.read()
        var mediaDigest: ByteArray? = null
        var mediaFileName: String? = null
        var mediaMime: String? = null
        var mediaSize = 0L
        var mediaDuration = 0L
        if (hasMedia == 1) {
            mediaDigest = readExact(input, 32)
            mediaFileName = readString(input)
            mediaMime = readString(input)
            mediaSize = readLong(input)
            mediaDuration = readLong(input)
        } else {
            require(hasMedia == 0) { "invalid media flag $hasMedia" }
        }
        val hasReply = input.read()
        val replyTo = if (hasReply == 1) readExact(input, MESSAGE_ID_BYTES) else null
        require(hasReply == 0 || hasReply == 1) { "invalid reply flag $hasReply" }
        require(input.available() == 0) { "trailing bytes in payload" }
        return MessagePayload(
            messageId = messageId,
            senderDeviceId = senderDeviceId,
            createdAtEpochMs = createdAt,
            sequenceNumber = sequence,
            type = type,
            body = body,
            mediaDigestSha256 = mediaDigest,
            mediaFileName = mediaFileName,
            mediaMimeType = mediaMime,
            mediaSizeBytes = mediaSize,
            mediaDurationMs = mediaDuration,
            replyToMessageId = replyTo
        )
    }

    private fun writeString(out: java.io.ByteArrayOutputStream, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        writeInt(out, bytes.size)
        out.write(bytes)
    }

    private fun writeInt(out: java.io.ByteArrayOutputStream, value: Int) {
        out.write(byteArrayOf(
            (value ushr 24).toByte(),
            (value ushr 16).toByte(),
            (value ushr 8).toByte(),
            value.toByte()
        ))
    }

    private fun writeLong(out: java.io.ByteArrayOutputStream, value: Long) {
        out.write(ByteArray(8) { i -> (value ushr (56 - 8 * i)).toByte() })
    }

    private fun readString(input: java.io.ByteArrayInputStream): String {
        val len = readInt(input)
        require(len in 0..MAX_STRING_BYTES) { "invalid string length $len" }
        return String(readExact(input, len), Charsets.UTF_8)
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
            require(read > 0) { "truncated payload" }
            offset += read
        }
        return buffer
    }

    private fun ByteArray.zeroizeLocal() = zeroize()

    private const val PAYLOAD_VERSION: Byte = 0x01
    const val MESSAGE_ID_BYTES = 16
    const val DEVICE_ID_BYTES = 16

    /** 64 KiB of UTF-8 text per message; larger content must be an attachment. */
    const val MAX_BODY_BYTES = 64 * 1024
    const val MAX_STRING_BYTES = 512
}

/** Typed failures so the UI can show a precise Persian message and never a generic "error". */
sealed class MessageCryptoException(message: String) : Exception(message) {
    class TagMismatch(message: String) : MessageCryptoException(message)
    class MalformedPayload(message: String) : MessageCryptoException(message)
}
