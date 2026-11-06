package com.duolink.app.pairing

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.SignedPreKeyPublic

/**
 * Role of a QR pairing frame in DuoLink's mutual two-step authenticated handshake:
 * - Step 1 (`OFFER`): Device A displays an `OFFER` QR signed by `IK_sig_A`.
 * - Step 2 (`ACCEPT`): Device B scans `OFFER`, verifies signatures/expiry/replay, computes
 *   `K_pair_root` + 60-digit Safety Number, and displays a cryptographically bound `ACCEPT` QR
 *   signed by `IK_sig_B` (containing `offerDigest`, `initiatorDeviceId`, `sessionId`, and `acceptNonce`).
 * - Step 3: Device A scans `ACCEPT`, verifies `offerDigest` + signatures + expiry, derives the
 *   identical `K_pair_root` + 60-digit Safety Number, and BOTH users MUST compare the complete
 *   60-digit Safety Number through an independent trusted channel before pinning the peer.
 */
enum class QrPacketRole(val wireCode: Byte) {
    OFFER(0x01),
    ACCEPT(0x02);

    companion object {
        fun fromWireCode(code: Byte): QrPacketRole =
            entries.firstOrNull { it.wireCode == code }
                ?: throw PairingValidationException(
                    PairingRejectionReason.MALFORMED_PAYLOAD,
                    "Unknown QR packet role: $code"
                )
    }
}

enum class PairingRejectionReason(val persianMessage: String) {
    MALFORMED_PAYLOAD("ساختار کد QR نامعتبر یا دستکاری‌شده است"),
    UNSUPPORTED_VERSION("نسخه پروتکل کد QR پشتیبانی نمی‌شود"),
    INVALID_PUBLIC_KEY("کلید عمومی دستگاه نامعتبر است"),
    INVALID_IDENTITY_SIGNATURE("امضای دیجیتال کد QR نامعتبر است (احتمال جعل یا دستکاری)"),
    INVALID_SPK_SIGNATURE("امضای پیش‌کلید امنیتی نامعتبر است"),
    EXPIRED_QR("مهلت زمانی این کد QR منقضی شده است؛ کد جدید بسازید"),
    FUTURE_TIMESTAMP_SKEW("زمان کد QR با ساعت دستگاه هم‌خوانی ندارد"),
    REPLAYED_SESSION("این کد QR قبلاً استفاده شده است (جلوگیری از حمله بازپخش)"),
    SELF_PAIRING_FORBIDDEN("جفت‌سازی دستگاه با خودش مجاز نیست"),
    UNEXPECTED_PACKET_ROLE("مرحله کد QR اسکن‌شده با وضعیت فعلی جفت‌سازی مطابقت ندارد"),
    SESSION_MISMATCH("پاسخ اسکن‌شده مربوط به درخواست جفت‌سازی فعلی این دستگاه نیست"),
    THIRD_DEVICE_BLOCKED("این برنامه قبلاً با یک مخاطب مجاز جفت شده است؛ دستگاه سوم مجاز نیست"),
    TRUST_STORAGE_CORRUPTED("ذخیره‌سازی امن اعتماد یا پیش‌کلید آسیب دیده یا دستکاری شده است؛ جفت‌سازی تا زمان اجرای بازیابی صریح مسدود است")
}

class PairingValidationException(
    val reason: PairingRejectionReason,
    override val message: String,
    cause: Throwable? = null
) : Exception(message, cause)

/**
 * Decoded, signature-verified QR pairing packet.
 */
data class PairingQrPacket(
    val protocolVersion: Byte,
    val role: QrPacketRole,
    val sessionId: ByteArray,
    val issuedAtEpochSec: Long,
    val expiresAtEpochSec: Long,
    val senderDeviceId: ByteArray,
    val senderIkSigSpki: ByteArray,
    val senderSpk: SignedPreKeyPublic,
    val senderNonce: ByteArray,
    val targetInitiatorDeviceId: ByteArray?,
    val boundOfferDigest: ByteArray?,
    val packetSignature: ByteArray,
    val rawTranscriptDigestSha256: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PairingQrPacket) return false
        return protocolVersion == other.protocolVersion &&
            role == other.role &&
            sessionId.contentEquals(other.sessionId) &&
            issuedAtEpochSec == other.issuedAtEpochSec &&
            expiresAtEpochSec == other.expiresAtEpochSec &&
            senderDeviceId.contentEquals(other.senderDeviceId) &&
            senderIkSigSpki.contentEquals(other.senderIkSigSpki) &&
            senderSpk == other.senderSpk &&
            senderNonce.contentEquals(other.senderNonce) &&
            ((targetInitiatorDeviceId == null && other.targetInitiatorDeviceId == null) ||
                (targetInitiatorDeviceId != null && other.targetInitiatorDeviceId != null &&
                    targetInitiatorDeviceId.contentEquals(other.targetInitiatorDeviceId))) &&
            ((boundOfferDigest == null && other.boundOfferDigest == null) ||
                (boundOfferDigest != null && other.boundOfferDigest != null &&
                    boundOfferDigest.contentEquals(other.boundOfferDigest))) &&
            packetSignature.contentEquals(other.packetSignature) &&
            rawTranscriptDigestSha256.contentEquals(other.rawTranscriptDigestSha256)
    }

    override fun hashCode(): Int = sessionId.contentHashCode()
}

/**
 * Persisted record of the single authorized paired peer.
 * Only written to encrypted local storage AFTER explicit out-of-band confirmation of the complete
 * 60-digit Safety Number on this device.
 */
data class PairedPeerRecord(
    val peerDeviceId: ByteArray,
    val peerIkSigSpki: ByteArray,
    val peerSpkId: Int,
    val peerSpkPubSpki: ByteArray,
    val peerSpkSignature: ByteArray,
    val peerSpkCreatedAtEpochSec: Long,
    val rootPairingKey: ByteArray,
    val safetyNumber: String,
    val pairedAtEpochSec: Long,
    val safetyNumberVerified: Boolean
) {
    val peerDeviceIdHex: String get() = ByteEncoding.toHexLower(peerDeviceId)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PairedPeerRecord) return false
        return peerDeviceId.contentEquals(other.peerDeviceId) &&
            peerIkSigSpki.contentEquals(other.peerIkSigSpki) &&
            peerSpkId == other.peerSpkId &&
            peerSpkPubSpki.contentEquals(other.peerSpkPubSpki) &&
            peerSpkSignature.contentEquals(other.peerSpkSignature) &&
            peerSpkCreatedAtEpochSec == other.peerSpkCreatedAtEpochSec &&
            rootPairingKey.contentEquals(other.rootPairingKey) &&
            safetyNumber == other.safetyNumber &&
            pairedAtEpochSec == other.pairedAtEpochSec &&
            safetyNumberVerified == other.safetyNumberVerified
    }

    override fun hashCode(): Int = peerDeviceId.contentHashCode()
}

/**
 * Staged handshake awaiting explicit user verification of the complete 60-digit Safety Number.
 *
 * Note: [publicHandshakeTranscriptId] is a non-secret 12-hex diagnostic string derived from public
 * QR fields; [safetyNumber] is the full 60-digit Safety Number that MUST be compared out-of-band.
 */
data class PendingPairingConfirmation(
    val sessionId: ByteArray,
    val peerDeviceId: ByteArray,
    val peerIkSigSpki: ByteArray,
    val peerSpk: SignedPreKeyPublic,
    val derivedRootPairingKey: ByteArray,
    val safetyNumber: String,
    val publicHandshakeTranscriptId: String,
    val responseQrStringForPeer: String?,
    val previousPeerChanged: Boolean,
    val previousPeerDeviceIdHex: String?
)

sealed class PairingStateSnapshot {
    data object UnpairedIdle : PairingStateSnapshot()

    data class TrustStorageCorrupted(
        val component: TrustStoreComponent,
        val technicalReason: String
    ) : PairingStateSnapshot()

    data class InitiatorOfferReady(
        val offerQrPayload: String,
        val sessionIdHex: String,
        val expiresAtEpochSec: Long
    ) : PairingStateSnapshot()

    data class AwaitingUserConfirmation(
        val peerDeviceIdHex: String,
        val safetyNumber: String,
        val publicHandshakeTranscriptId: String,
        val responseAcceptQrPayload: String?,
        val previousPeerChanged: Boolean,
        val previousPeerDeviceIdHex: String?
    ) : PairingStateSnapshot()

    data class PairedActive(
        val peerRecord: PairedPeerRecord
    ) : PairingStateSnapshot()
}
