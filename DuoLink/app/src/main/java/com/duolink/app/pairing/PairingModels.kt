package com.duolink.app.pairing

enum class PairingRejectionReason(val persianTitle: String, val persianDetail: String) {
    INVALID_FORMAT(
        "فرمت کد QR نامعتبر است",
        "این کد متعلق به پروتکل جفت‌سازی امن DuoLink نیست یا ناقص اسکن شده است."
    ),
    UNSUPPORTED_VERSION(
        "نسخه پروتکل پشتیبانی نمی‌شود",
        "نسخه بسته جفت‌سازی با این نسخه از DuoLink سازگار نیست."
    ),
    TAMPERED_SIGNATURE(
        "دستکاری یا امضای نامعتبر شناسایی شد",
        "امضای دیجیتال کد QR معتبر نیست. ممکن است کد تغییر یافته یا جعلی باشد."
    ),
    IDENTITY_SUBSTITUTION(
        "عدم تطابق شناسه و کلید عمومی",
        "شناسه دستگاه ادعاشده با کلید عمومی امضا هم‌خوانی رمزنگاری ندارد."
    ),
    EXPIRED_PAYLOAD(
        "کد QR منقضی شده است",
        "مهلت ۵ دقیقه‌ای این کد به پایان رسیده یا ساعت یکی از دو گوشی تنظیم نیست."
    ),
    REPLAYED_NONCE(
        "حمله تکرار (Replay) مسدود شد",
        "این کد جفت‌سازی قبلاً یک‌بار مصرف شده و دیگر قابل استفاده نیست."
    ),
    SELF_PAIRING_ATTEMPT(
        "اسکن کد همین گوشی مجاز نیست",
        "کد نمایش‌داده‌شده مربوط به همین دستگاه است؛ لطفاً کد گوشی مقابل را اسکن کنید."
    ),
    WRONG_PEER_TARGET(
        "پاسخ متعلق به دستگاه دیگری است",
        "این کد پاسخ برای گوشی دیگری صادر شده و با درخواست فعلی شما مطابقت ندارد."
    ),
    OFFER_DIGEST_MISMATCH(
        "عدم تطابق نشست جفت‌سازی (احتمال حمله مرد میانی)",
        "هش درخواست اولیه در پاسخ دریافتی با درخواست صادرشده توسط این گوشی مطابقت ندارد."
    ),
    NO_ACTIVE_OFFER_SESSION(
        "درخواست جفت‌سازی فعالی وجود ندارد",
        "شما کد پاسخ (مرحله دوم) را اسکن کردید، اما در این گوشی درخواست اولیه‌ای باز نیست."
    ),
    THIRD_DEVICE_BLOCKED(
        "دستگاه سوم مسدود شد",
        "DuoLink منحصراً برای دو نفر طراحی شده و این گوشی هم‌اکنون با یک مخاطب جفت شده است."
    ),
    PEER_KEY_CHANGED_WARNING(
        "هشدار امنیتی: کلید هویت مخاطب تغییر کرده است!",
        "کلید عمومی ارائه‌شده با کلید ثبت‌شده قبلی متفاوت است. ممکن است مخاطب برنامه را دوباره نصب کرده باشد یا شخص ثالثی قصد جعل هویت داشته باشد."
    )
}

data class KeyChangeAlert(
    val previousDeviceId: String,
    val previousSafetyNumber: String,
    val newDeviceId: String,
    val newSafetyNumber: String
)

data class PairedPeerRecord(
    val peerDeviceId: String,
    val peerIkSigSpki: ByteArray,
    val peerSpkId: Int,
    val peerSpkDhSpki: ByteArray,
    val peerSpkIssuedAtSec: Long,
    val peerSpkExpiresAtSec: Long,
    val peerSpkSignature: ByteArray,
    val safetyNumber: String,
    val rootPairingKey: ByteArray,
    val pairedAtEpochSec: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PairedPeerRecord) return false
        return peerDeviceId == other.peerDeviceId &&
            peerSpkId == other.peerSpkId &&
            peerSpkIssuedAtSec == other.peerSpkIssuedAtSec &&
            peerSpkExpiresAtSec == other.peerSpkExpiresAtSec &&
            safetyNumber == other.safetyNumber &&
            pairedAtEpochSec == other.pairedAtEpochSec &&
            peerIkSigSpki.contentEquals(other.peerIkSigSpki) &&
            peerSpkDhSpki.contentEquals(other.peerSpkDhSpki) &&
            peerSpkSignature.contentEquals(other.peerSpkSignature) &&
            rootPairingKey.contentEquals(other.rootPairingKey)
    }

    override fun hashCode(): Int {
        var result = peerDeviceId.hashCode()
        result = 31 * result + peerIkSigSpki.contentHashCode()
        result = 31 * result + peerSpkId
        result = 31 * result + safetyNumber.hashCode()
        return result
    }
}

sealed class QrProcessResult {
    data class ResponderReadyToConfirm(
        val acceptQrUri: String,
        val peerDeviceId: String,
        val safetyNumber: String,
        val sessionVerificationCode: String,
        val expiresAtEpochSec: Long,
        val keyChangeFromPreviousPeer: KeyChangeAlert? = null
    ) : QrProcessResult()

    data class InitiatorReadyToConfirm(
        val peerDeviceId: String,
        val safetyNumber: String,
        val sessionVerificationCode: String,
        val keyChangeFromPreviousPeer: KeyChangeAlert? = null
    ) : QrProcessResult()

    data class ExistingPeerVerified(
        val peerDeviceId: String,
        val safetyNumber: String,
        val preKeyUpdated: Boolean
    ) : QrProcessResult()

    data class Rejected(
        val reason: PairingRejectionReason,
        val keyChangeAlert: KeyChangeAlert? = null
    ) : QrProcessResult()
}

sealed class PairingStateSnapshot {
    data object Unpaired : PairingStateSnapshot()

    data class OfferCreated(
        val sessionId: String,
        val offerQrUri: String,
        val expiresAtEpochSec: Long
    ) : PairingStateSnapshot()

    data class AwaitingUserConfirmation(
        val role: Role,
        val acceptQrUri: String?,
        val peerDeviceId: String,
        val safetyNumber: String,
        val sessionVerificationCode: String,
        val expiresAtEpochSec: Long,
        val keyChangeAlert: KeyChangeAlert?
    ) : PairingStateSnapshot() {
        enum class Role { INITIATOR, RESPONDER }
    }

    data class Paired(
        val peerDeviceId: String,
        val safetyNumber: String,
        val pairedAtEpochSec: Long,
        val peerSpkId: Int
    ) : PairingStateSnapshot()
}
