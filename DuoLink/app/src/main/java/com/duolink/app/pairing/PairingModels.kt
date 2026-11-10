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
    /** Phone A -> B: opening request. Carries the initiator's identity + signed pre-key. */
    OFFER(0x01),

    /** Phone B -> A: acceptance. Binds the exact OFFER it answers (device id + transcript digest). */
    ACCEPT(0x02),

    /**
     * Phone A -> B: "I have compared the Safety Number and locked my side".
     *
     * This third step exists because the OFFER/ACCEPT QR exchange carries no return path. Without it the
     * responder never learns that the initiator finished, so the two devices end in different states and
     * the initiator could show "connected" while the responder still waits — a false success.
     *
     * The payload is signed by A's identity key and carries the digest of B's ACCEPT packet, so B can
     * prove this confirmation answers *its own* session and nothing else. It is not a secret: it contains
     * no key material, and it only ever confirms a pairing that B itself initiated by scanning.
     */
    CONFIRM(0x03);

    /** True when the packet closes a pairing session from the peer's point of view. */
    val isClosingStep: Boolean get() = this == CONFIRM

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
    PEER_CONFIRMATION_MISSING("دستگاه مقابل هنوز تأیید نهایی را نفرستاده است؛ جفت‌سازی ناقص است"),
    PEER_CONFIRMATION_INVALID("تأیید نهایی دستگاه مقابل با این جلسه جفت‌سازی مطابقت ندارد"),
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
    val previousPeerDeviceIdHex: String?,
    /**
     * Set on the initiator after its ACCEPT is verified: the signed CONFIRM packet it must show the
     * responder. `null` on the responder, whose confirmation arrives by scanning.
     */
    val confirmQrStringForPeer: String? = null,
    /** True once the *peer's* explicit confirmation has been verified in this session. */
    val peerConfirmationVerified: Boolean = false,
    /** This device's own user confirmed the 60 digits (does not imply the peer did). */
    val localApproved: Boolean = false,
    val localApprovedAtEpochSec: Long? = null,
    /**
     * Digest of the ACCEPT packet this device issued (responder only).
     *
     * The initiator's CONFIRM binds this value, which is what proves the confirmation answers *our*
     * session rather than a replayed or substituted one.
     */
    val ourAcceptTranscriptDigest: ByteArray? = null
)

/** Which side of the handshake this device is playing, used to explain what is still missing. */
enum class PairingRole { INITIATOR, RESPONDER }

/**
 * Thrown when this device approved but the peer's confirmation has not been verified yet.
 *
 * Callers MUST NOT treat this as a pairing failure: the handshake is still in progress and completes as
 * soon as the peer's confirmation arrives. Treating it as success is exactly the defect this class exists
 * to prevent; treating it as failure would be wrong too, because nothing has gone wrong.
 */
class PeerConfirmationPendingException(
    val role: PairingRole,
    val confirmQrStringForPeer: String?
) : Exception(
    if (role == PairingRole.INITIATOR) {
        "این دستگاه تأیید شد؛ برای تکمیل، کد تأیید را به گوشی مقابل نشان دهید"
    } else {
        "این دستگاه تأیید شد؛ در انتظار تأیید نهایی گوشی مقابل"
    }
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
        val previousPeerDeviceIdHex: String?,
        /** This device's own user has checked the 60 digits and pressed confirm. */
        val localApproved: Boolean = false,
        /** The peer's explicit confirmation for this exact session has been verified. */
        val peerConfirmed: Boolean = false,
        /**
         * Initiator only: the signed CONFIRM packet to show the responder after local approval.
         * Displaying it is what lets the responder finish, so this is the return path of the handshake.
         */
        val confirmQrPayloadForPeer: String? = null
    ) : PairingStateSnapshot()

    /**
     * True only when BOTH sides have confirmed. The UI must use this — and only this — to show a
     * successful connection. `PairedActive` cannot appear before it is true.
     */
    val isMutualSuccess: Boolean
        get() = this is PairedActive

    data class PairedActive(
        val peerRecord: PairedPeerRecord
    ) : PairingStateSnapshot()
}
