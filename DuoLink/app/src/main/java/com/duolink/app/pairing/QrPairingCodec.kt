package com.duolink.app.pairing

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.DeviceKeyVault
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.LocalIdentityPublic
import com.duolink.app.crypto.SignedPreKeyPublic
import com.duolink.app.crypto.TranscriptBuilder
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * Deterministic, zero-reflection binary wire codec & signature verifier for DuoLink QR pairing payloads:
 * URI format: `duolink://pair/v1?p=<canonical-base64url>`
 */
object QrPairingCodec {
    const val URI_PREFIX = "duolink://pair/v1?p="
    const val PROTOCOL_VERSION: Byte = 1

    const val SESSION_ID_BYTES = 16
    const val NONCE_BYTES = 32
    const val SHA256_BYTES = 32
    const val MAX_QR_TEXT_LENGTH = 2048
    private const val MAX_BLOB_BYTES = 1024

    fun encodeSignedPacket(
        role: QrPacketRole,
        sessionId: ByteArray,
        issuedAtEpochSec: Long,
        expiresAtEpochSec: Long,
        localIdentity: LocalIdentityPublic,
        senderNonce: ByteArray,
        targetInitiatorDeviceId: ByteArray?,
        boundOfferDigest: ByteArray?,
        keyVault: DeviceKeyVault
    ): String {
        require(sessionId.size == SESSION_ID_BYTES) { "sessionId must be 16 bytes" }
        require(localIdentity.deviceId.size == 16) { "deviceId must be 16 bytes" }
        require(senderNonce.size == NONCE_BYTES) { "senderNonce must be 32 bytes" }

        val spk = localIdentity.currentSignedPreKey
        val transcript = buildSigningTranscript(
            role = role,
            sessionId = sessionId,
            issuedAtEpochSec = issuedAtEpochSec,
            expiresAtEpochSec = expiresAtEpochSec,
            senderDeviceId = localIdentity.deviceId,
            senderIkSigSpki = localIdentity.identitySigningPublicKeySpki,
            senderSpk = spk,
            senderNonce = senderNonce,
            targetInitiatorDeviceId = targetInitiatorDeviceId,
            boundOfferDigest = boundOfferDigest
        )
        val packetSig = keyVault.signWithIdentityKey(transcript)

        val out = ByteArrayOutputStream(520)
        out.write(PROTOCOL_VERSION.toInt())
        out.write(role.wireCode.toInt())
        out.write(sessionId)
        writeLong(out, issuedAtEpochSec)
        writeLong(out, expiresAtEpochSec)
        out.write(localIdentity.deviceId)
        writeShortChunk(out, localIdentity.identitySigningPublicKeySpki)
        writeInt(out, spk.spkId)
        writeLong(out, spk.createdAtEpochSec)
        writeShortChunk(out, spk.publicKeySpki)
        writeShortChunk(out, spk.signatureByIdentityKey)
        out.write(senderNonce)
        if (role == QrPacketRole.ACCEPT) {
            val targetId = requireNotNull(targetInitiatorDeviceId) { "ACCEPT requires targetInitiatorDeviceId" }
            val offerDigest = requireNotNull(boundOfferDigest) { "ACCEPT requires boundOfferDigest" }
            require(targetId.size == 16) { "targetInitiatorDeviceId must be 16 bytes" }
            require(offerDigest.size == SHA256_BYTES) { "boundOfferDigest must be 32 bytes" }
            out.write(targetId)
            out.write(offerDigest)
        }
        writeShortChunk(out, packetSig)

        return URI_PREFIX + ByteEncoding.encodeBase64Url(out.toByteArray())
    }

    /**
     * Decodes a QR URI string and strictly verifies:
     * 1. Canonical Base64URL encoding, protocol version, and exact binary bounds (no trailing bytes).
     * 2. Uncompressed NIST P-256 SPKI validity for both `IK_sig` and `SPK_dh`.
     * 3. `senderDeviceId == computeDeviceId(senderIkSigSpki)`.
     * 4. `IK_sig` signature over `SPK_dh` (`verifySignedPreKey`).
     * 5. `IK_sig` packet signature over the full domain-separated QR handshake transcript.
     */
    fun decodeAndVerifySignatures(rawInput: String): PairingQrPacket {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty() || trimmed.length > MAX_QR_TEXT_LENGTH || !trimmed.startsWith(URI_PREFIX)) {
            throw PairingValidationException(
                PairingRejectionReason.MALFORMED_PAYLOAD,
                PairingRejectionReason.MALFORMED_PAYLOAD.persianMessage
            )
        }
        val b64Part = trimmed.substring(URI_PREFIX.length)
        val bytes = try {
            ByteEncoding.decodeBase64UrlStrict(b64Part)
        } catch (e: Exception) {
            throw PairingValidationException(
                PairingRejectionReason.MALFORMED_PAYLOAD,
                PairingRejectionReason.MALFORMED_PAYLOAD.persianMessage,
                e
            )
        }
        if (bytes.size < 64 || bytes.size > MAX_BLOB_BYTES) {
            throw PairingValidationException(
                PairingRejectionReason.MALFORMED_PAYLOAD,
                PairingRejectionReason.MALFORMED_PAYLOAD.persianMessage
            )
        }

        val buf = ByteBuffer.wrap(bytes)
        val version = buf.get()
        if (version != PROTOCOL_VERSION) {
            throw PairingValidationException(
                PairingRejectionReason.UNSUPPORTED_VERSION,
                PairingRejectionReason.UNSUPPORTED_VERSION.persianMessage
            )
        }
        val role = QrPacketRole.fromWireCode(buf.get())

        val sessionId: ByteArray
        val issuedAt: Long
        val expiresAt: Long
        val senderDeviceId: ByteArray
        val senderIkSpki: ByteArray
        val spk: SignedPreKeyPublic
        val senderNonce: ByteArray
        val targetInitId: ByteArray?
        val boundOfferDigest: ByteArray?
        val packetSig: ByteArray

        try {
            sessionId = readFixed(buf, SESSION_ID_BYTES)
            issuedAt = buf.long
            expiresAt = buf.long
            senderDeviceId = readFixed(buf, 16)
            senderIkSpki = readShortChunk(buf, 91, 91)
            val spkId = buf.int
            val spkCreatedAt = buf.long
            val spkSpki = readShortChunk(buf, 91, 91)
            val spkSig = readShortChunk(buf, 64, 80)
            spk = SignedPreKeyPublic(
                spkId = spkId,
                publicKeySpki = spkSpki,
                signatureByIdentityKey = spkSig,
                createdAtEpochSec = spkCreatedAt
            )
            senderNonce = readFixed(buf, NONCE_BYTES)
            if (role == QrPacketRole.ACCEPT) {
                targetInitId = readFixed(buf, 16)
                boundOfferDigest = readFixed(buf, SHA256_BYTES)
            } else {
                targetInitId = null
                boundOfferDigest = null
            }
            packetSig = readShortChunk(buf, 64, 80)
            if (buf.hasRemaining()) {
                throw IllegalArgumentException("Trailing bytes in QR packet")
            }
        } catch (e: PairingValidationException) {
            throw e
        } catch (e: Exception) {
            throw PairingValidationException(
                PairingRejectionReason.MALFORMED_PAYLOAD,
                PairingRejectionReason.MALFORMED_PAYLOAD.persianMessage,
                e
            )
        }

        // Validate public keys & deviceId derivation
        val expectedDeviceId = try {
            EcP256Crypto.decodeAndValidateP256PublicKey(senderIkSpki)
            EcP256Crypto.decodeAndValidateP256PublicKey(spk.publicKeySpki)
            EcP256Crypto.computeDeviceId(senderIkSpki)
        } catch (e: Exception) {
            throw PairingValidationException(
                PairingRejectionReason.INVALID_PUBLIC_KEY,
                PairingRejectionReason.INVALID_PUBLIC_KEY.persianMessage,
                e
            )
        }
        if (!ByteEncoding.constantTimeEquals(senderDeviceId, expectedDeviceId)) {
            throw PairingValidationException(
                PairingRejectionReason.INVALID_PUBLIC_KEY,
                PairingRejectionReason.INVALID_PUBLIC_KEY.persianMessage
            )
        }

        // Verify signed pre-key binding
        if (!EcP256Crypto.verifySignedPreKey(senderDeviceId, senderIkSpki, spk)) {
            throw PairingValidationException(
                PairingRejectionReason.INVALID_SPK_SIGNATURE,
                PairingRejectionReason.INVALID_SPK_SIGNATURE.persianMessage
            )
        }

        // Verify packet signature over canonical transcript
        val transcript = buildSigningTranscript(
            role = role,
            sessionId = sessionId,
            issuedAtEpochSec = issuedAt,
            expiresAtEpochSec = expiresAt,
            senderDeviceId = senderDeviceId,
            senderIkSigSpki = senderIkSpki,
            senderSpk = spk,
            senderNonce = senderNonce,
            targetInitiatorDeviceId = targetInitId,
            boundOfferDigest = boundOfferDigest
        )
        if (!EcP256Crypto.verifySha256Ecdsa(senderIkSpki, transcript, packetSig)) {
            throw PairingValidationException(
                PairingRejectionReason.INVALID_IDENTITY_SIGNATURE,
                PairingRejectionReason.INVALID_IDENTITY_SIGNATURE.persianMessage
            )
        }

        return PairingQrPacket(
            protocolVersion = version,
            role = role,
            sessionId = sessionId,
            issuedAtEpochSec = issuedAt,
            expiresAtEpochSec = expiresAt,
            senderDeviceId = senderDeviceId,
            senderIkSigSpki = senderIkSpki,
            senderSpk = spk,
            senderNonce = senderNonce,
            targetInitiatorDeviceId = targetInitId,
            boundOfferDigest = boundOfferDigest,
            packetSignature = packetSig,
            rawTranscriptDigestSha256 = ByteEncoding.sha256(transcript)
        )
    }

    private fun buildSigningTranscript(
        role: QrPacketRole,
        sessionId: ByteArray,
        issuedAtEpochSec: Long,
        expiresAtEpochSec: Long,
        senderDeviceId: ByteArray,
        senderIkSigSpki: ByteArray,
        senderSpk: SignedPreKeyPublic,
        senderNonce: ByteArray,
        targetInitiatorDeviceId: ByteArray?,
        boundOfferDigest: ByteArray?
    ): ByteArray {
        val tb = TranscriptBuilder()
            .putUtf8(if (role == QrPacketRole.OFFER) "DUOLINK-QR-OFFER-V1" else "DUOLINK-QR-ACCEPT-V1")
            .putBytes(sessionId)
            .putInt64(issuedAtEpochSec)
            .putInt64(expiresAtEpochSec)
            .putBytes(senderDeviceId)
            .putBytes(senderIkSigSpki)
            .putInt32(senderSpk.spkId)
            .putInt64(senderSpk.createdAtEpochSec)
            .putBytes(senderSpk.publicKeySpki)
            .putBytes(senderSpk.signatureByIdentityKey)
            .putBytes(senderNonce)
        if (role == QrPacketRole.ACCEPT) {
            tb.putBytes(requireNotNull(targetInitiatorDeviceId))
            tb.putBytes(requireNotNull(boundOfferDigest))
        }
        return tb.build()
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
