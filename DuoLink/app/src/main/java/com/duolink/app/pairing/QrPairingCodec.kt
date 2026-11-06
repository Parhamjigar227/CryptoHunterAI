package com.duolink.app.pairing

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.SignedPreKeyPublic
import com.duolink.app.crypto.TranscriptBuilder
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * Deterministic, zero-reflection binary wire codec for DuoLink QR pairing payloads:
 * URI format: duolink://pair/v1?p=<canonical-base64url>
 */
object QrPairingCodec {
    const val URI_PREFIX = "duolink://pair/v1?p="
    const val PROTOCOL_VERSION: Byte = 1
    const val TYPE_OFFER: Byte = 1
    const val TYPE_ACCEPT: Byte = 2

    const val SESSION_ID_BYTES = 16
    const val NONCE_BYTES = 32
    const val SHA256_BYTES = 32
    const val MAX_QR_TEXT_LENGTH = 2048
    private const val MAX_BLOB_BYTES = 1024

    sealed class DecodedQrPacket {
        abstract val sessionId: String
        abstract val senderDeviceId: String
        abstract val senderIkSigSpki: ByteArray
        abstract val senderSpk: SignedPreKeyPublic
        abstract val nonce: ByteArray
        abstract val issuedAtEpochSec: Long
        abstract val expiresAtEpochSec: Long
        abstract val signature: ByteArray
        abstract val signedTranscript: ByteArray

        data class Offer(
            override val sessionId: String,
            override val senderDeviceId: String,
            override val senderIkSigSpki: ByteArray,
            override val senderSpk: SignedPreKeyPublic,
            override val nonce: ByteArray,
            override val issuedAtEpochSec: Long,
            override val expiresAtEpochSec: Long,
            override val signature: ByteArray,
            override val signedTranscript: ByteArray
        ) : DecodedQrPacket()

        data class Accept(
            override val sessionId: String,
            val targetPeerDeviceId: String,
            val offerTranscriptDigest: ByteArray,
            override val senderDeviceId: String,
            override val senderIkSigSpki: ByteArray,
            override val senderSpk: SignedPreKeyPublic,
            override val nonce: ByteArray,
            override val issuedAtEpochSec: Long,
            override val expiresAtEpochSec: Long,
            override val signature: ByteArray,
            override val signedTranscript: ByteArray
        ) : DecodedQrPacket()
    }

    sealed class CodecResult {
        data class Ok(val packet: DecodedQrPacket) : CodecResult()
        data class Err(val reason: PairingRejectionReason) : CodecResult()
    }

    fun buildOfferSigningTranscript(
        sessionId: String,
        senderDeviceId: String,
        senderIkSigSpki: ByteArray,
        senderSpk: SignedPreKeyPublic,
        nonce: ByteArray,
        issuedAtEpochSec: Long,
        expiresAtEpochSec: Long
    ): ByteArray = TranscriptBuilder()
        .putUtf8("DUOLINK-QR-OFFER-V1")
        .putUtf8(sessionId)
        .putUtf8(senderDeviceId)
        .putBytes(senderIkSigSpki)
        .putInt32(senderSpk.spkId)
        .putInt64(senderSpk.issuedAtEpochSec)
        .putInt64(senderSpk.expiresAtEpochSec)
        .putBytes(senderSpk.publicKeySpki)
        .putBytes(senderSpk.signature)
        .putBytes(nonce)
        .putInt64(issuedAtEpochSec)
        .putInt64(expiresAtEpochSec)
        .build()

    fun buildAcceptSigningTranscript(
        sessionId: String,
        targetPeerDeviceId: String,
        offerTranscriptDigest: ByteArray,
        senderDeviceId: String,
        senderIkSigSpki: ByteArray,
        senderSpk: SignedPreKeyPublic,
        nonce: ByteArray,
        issuedAtEpochSec: Long,
        expiresAtEpochSec: Long
    ): ByteArray = TranscriptBuilder()
        .putUtf8("DUOLINK-QR-ACCEPT-V1")
        .putUtf8(sessionId)
        .putUtf8(targetPeerDeviceId)
        .putBytes(offerTranscriptDigest)
        .putUtf8(senderDeviceId)
        .putBytes(senderIkSigSpki)
        .putInt32(senderSpk.spkId)
        .putInt64(senderSpk.issuedAtEpochSec)
        .putInt64(senderSpk.expiresAtEpochSec)
        .putBytes(senderSpk.publicKeySpki)
        .putBytes(senderSpk.signature)
        .putBytes(nonce)
        .putInt64(issuedAtEpochSec)
        .putInt64(expiresAtEpochSec)
        .build()

    fun encodeOfferUri(
        sessionId: String,
        senderDeviceId: String,
        senderIkSigSpki: ByteArray,
        senderSpk: SignedPreKeyPublic,
        nonce: ByteArray,
        issuedAtEpochSec: Long,
        expiresAtEpochSec: Long,
        signature: ByteArray
    ): String {
        val sessionBytes = ByteEncoding.fromHexStrict(sessionId)
        val deviceBytes = ByteEncoding.fromHexStrict(senderDeviceId)
        require(sessionBytes.size == SESSION_ID_BYTES)
        require(deviceBytes.size == 16)
        require(nonce.size == NONCE_BYTES)

        val out = ByteArrayOutputStream(480)
        out.write(PROTOCOL_VERSION.toInt())
        out.write(TYPE_OFFER.toInt())
        out.write(sessionBytes)
        out.write(deviceBytes)
        writeShortChunk(out, senderIkSigSpki)
        writeInt(out, senderSpk.spkId)
        writeLong(out, senderSpk.issuedAtEpochSec)
        writeLong(out, senderSpk.expiresAtEpochSec)
        writeShortChunk(out, senderSpk.publicKeySpki)
        writeShortChunk(out, senderSpk.signature)
        out.write(nonce)
        writeLong(out, issuedAtEpochSec)
        writeLong(out, expiresAtEpochSec)
        writeShortChunk(out, signature)

        return URI_PREFIX + ByteEncoding.encodeBase64Url(out.toByteArray())
    }

    fun encodeAcceptUri(
        sessionId: String,
        targetPeerDeviceId: String,
        offerTranscriptDigest: ByteArray,
        senderDeviceId: String,
        senderIkSigSpki: ByteArray,
        senderSpk: SignedPreKeyPublic,
        nonce: ByteArray,
        issuedAtEpochSec: Long,
        expiresAtEpochSec: Long,
        signature: ByteArray
    ): String {
        val sessionBytes = ByteEncoding.fromHexStrict(sessionId)
        val targetDeviceBytes = ByteEncoding.fromHexStrict(targetPeerDeviceId)
        val senderDeviceBytes = ByteEncoding.fromHexStrict(senderDeviceId)
        require(sessionBytes.size == SESSION_ID_BYTES)
        require(targetDeviceBytes.size == 16)
        require(offerTranscriptDigest.size == SHA256_BYTES)
        require(senderDeviceBytes.size == 16)
        require(nonce.size == NONCE_BYTES)

        val out = ByteArrayOutputStream(540)
        out.write(PROTOCOL_VERSION.toInt())
        out.write(TYPE_ACCEPT.toInt())
        out.write(sessionBytes)
        out.write(targetDeviceBytes)
        out.write(offerTranscriptDigest)
        out.write(senderDeviceBytes)
        writeShortChunk(out, senderIkSigSpki)
        writeInt(out, senderSpk.spkId)
        writeLong(out, senderSpk.issuedAtEpochSec)
        writeLong(out, senderSpk.expiresAtEpochSec)
        writeShortChunk(out, senderSpk.publicKeySpki)
        writeShortChunk(out, senderSpk.signature)
        out.write(nonce)
        writeLong(out, issuedAtEpochSec)
        writeLong(out, expiresAtEpochSec)
        writeShortChunk(out, signature)

        return URI_PREFIX + ByteEncoding.encodeBase64Url(out.toByteArray())
    }

    fun decodeUri(rawInput: String): CodecResult {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty() || trimmed.length > MAX_QR_TEXT_LENGTH || !trimmed.startsWith(URI_PREFIX)) {
            return CodecResult.Err(PairingRejectionReason.INVALID_FORMAT)
        }
        val b64Part = trimmed.substring(URI_PREFIX.length)
        val bytes = try {
            ByteEncoding.decodeBase64UrlStrict(b64Part)
        } catch (_: Exception) {
            return CodecResult.Err(PairingRejectionReason.INVALID_FORMAT)
        }
        if (bytes.size < 64 || bytes.size > MAX_BLOB_BYTES) {
            return CodecResult.Err(PairingRejectionReason.INVALID_FORMAT)
        }

        val buf = ByteBuffer.wrap(bytes)
        val version = buf.get()
        if (version != PROTOCOL_VERSION) {
            return CodecResult.Err(PairingRejectionReason.UNSUPPORTED_VERSION)
        }
        val packetType = buf.get()

        return try {
            when (packetType) {
                TYPE_OFFER -> decodeOfferBody(buf)
                TYPE_ACCEPT -> decodeAcceptBody(buf)
                else -> CodecResult.Err(PairingRejectionReason.INVALID_FORMAT)
            }
        } catch (_: Exception) {
            CodecResult.Err(PairingRejectionReason.INVALID_FORMAT)
        }
    }

    private fun decodeOfferBody(buf: ByteBuffer): CodecResult {
        val sessionId = ByteEncoding.toHexLower(readFixed(buf, SESSION_ID_BYTES))
        val senderDeviceId = ByteEncoding.toHexLower(readFixed(buf, 16))
        val senderIkSigSpki = readShortChunk(buf, 88, 96)
        val spkId = buf.int
        val spkIssuedAt = buf.long
        val spkExpiresAt = buf.long
        val spkDhSpki = readShortChunk(buf, 88, 96)
        val spkSig = readShortChunk(buf, 64, 80)
        val nonce = readFixed(buf, NONCE_BYTES)
        val iat = buf.long
        val exp = buf.long
        val sig = readShortChunk(buf, 64, 80)
        if (buf.hasRemaining()) {
            return CodecResult.Err(PairingRejectionReason.INVALID_FORMAT)
        }

        val spk = SignedPreKeyPublic(
            spkId = spkId,
            publicKeySpki = spkDhSpki,
            issuedAtEpochSec = spkIssuedAt,
            expiresAtEpochSec = spkExpiresAt,
            signature = spkSig
        )
        val transcript = buildOfferSigningTranscript(
            sessionId = sessionId,
            senderDeviceId = senderDeviceId,
            senderIkSigSpki = senderIkSigSpki,
            senderSpk = spk,
            nonce = nonce,
            issuedAtEpochSec = iat,
            expiresAtEpochSec = exp
        )
        return CodecResult.Ok(
            DecodedQrPacket.Offer(
                sessionId = sessionId,
                senderDeviceId = senderDeviceId,
                senderIkSigSpki = senderIkSigSpki,
                senderSpk = spk,
                nonce = nonce,
                issuedAtEpochSec = iat,
                expiresAtEpochSec = exp,
                signature = sig,
                signedTranscript = transcript
            )
        )
    }

    private fun decodeAcceptBody(buf: ByteBuffer): CodecResult {
        val sessionId = ByteEncoding.toHexLower(readFixed(buf, SESSION_ID_BYTES))
        val targetPeerDeviceId = ByteEncoding.toHexLower(readFixed(buf, 16))
        val offerDigest = readFixed(buf, SHA256_BYTES)
        val senderDeviceId = ByteEncoding.toHexLower(readFixed(buf, 16))
        val senderIkSigSpki = readShortChunk(buf, 88, 96)
        val spkId = buf.int
        val spkIssuedAt = buf.long
        val spkExpiresAt = buf.long
        val spkDhSpki = readShortChunk(buf, 88, 96)
        val spkSig = readShortChunk(buf, 64, 80)
        val nonce = readFixed(buf, NONCE_BYTES)
        val iat = buf.long
        val exp = buf.long
        val sig = readShortChunk(buf, 64, 80)
        if (buf.hasRemaining()) {
            return CodecResult.Err(PairingRejectionReason.INVALID_FORMAT)
        }

        val spk = SignedPreKeyPublic(
            spkId = spkId,
            publicKeySpki = spkDhSpki,
            issuedAtEpochSec = spkIssuedAt,
            expiresAtEpochSec = spkExpiresAt,
            signature = spkSig
        )
        val transcript = buildAcceptSigningTranscript(
            sessionId = sessionId,
            targetPeerDeviceId = targetPeerDeviceId,
            offerTranscriptDigest = offerDigest,
            senderDeviceId = senderDeviceId,
            senderIkSigSpki = senderIkSigSpki,
            senderSpk = spk,
            nonce = nonce,
            issuedAtEpochSec = iat,
            expiresAtEpochSec = exp
        )
        return CodecResult.Ok(
            DecodedQrPacket.Accept(
                sessionId = sessionId,
                targetPeerDeviceId = targetPeerDeviceId,
                offerTranscriptDigest = offerDigest,
                senderDeviceId = senderDeviceId,
                senderIkSigSpki = senderIkSigSpki,
                senderSpk = spk,
                nonce = nonce,
                issuedAtEpochSec = iat,
                expiresAtEpochSec = exp,
                signature = sig,
                signedTranscript = transcript
            )
        )
    }

    private fun writeShortChunk(out: ByteArrayOutputStream, bytes: ByteArray) {
        require(bytes.size in 1..65535)
        out.write((bytes.size ushr 8) and 0xFF)
        out.write(bytes.size and 0xFF)
        out.write(bytes)
    }

    private fun writeInt(out: ByteArrayOutputStream, v: Int) {
        out.write(ByteBuffer.allocate(4).putInt(v).array())
    }

    private fun writeLong(out: ByteArrayOutputStream, v: Long) {
        out.write(ByteBuffer.allocate(8).putLong(v).array())
    }

    private fun readFixed(buf: ByteBuffer, len: Int): ByteArray {
        if (buf.remaining() < len) throw IllegalArgumentException("Buffer underflow")
        return ByteArray(len).also { buf.get(it) }
    }

    private fun readShortChunk(buf: ByteBuffer, minLen: Int, maxLen: Int): ByteArray {
        if (buf.remaining() < 2) throw IllegalArgumentException("Missing chunk length")
        val len = ((buf.get().toInt() and 0xFF) shl 8) or (buf.get().toInt() and 0xFF)
        if (len !in minLen..maxLen || buf.remaining() < len) {
            throw IllegalArgumentException("Invalid chunk length: $len")
        }
        return ByteArray(len).also { buf.get(it) }
    }
}
