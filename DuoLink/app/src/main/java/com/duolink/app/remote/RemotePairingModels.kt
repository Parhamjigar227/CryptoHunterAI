package com.duolink.app.remote

/**
 * Every distinguishable failure of the Method B flow, with a Persian message a non-technical user can
 * act on. Grouping (rather than string munging) is what lets the UI decide between:
 *
 *  - retry is safe (network/timeout);
 *  - the peer/user must act (rejected, cancelled, mismatch);
 *  - the local state is suspect and the flow must stop hard (corruption, tampering).
 *
 * There is deliberately **no** generic `SOMETHING_WENT_WRONG` fallback: an unmapped condition is a
 * programming error, and tests assert that every reachable branch maps to a specific value.
 */
enum class RemoteFailure(val persianMessage: String, val isRetryable: Boolean, val isSecurityAlarming: Boolean) {
    NETWORK_UNAVAILABLE("اتصال به سرور واسط برقرار نشد؛ اینترنت یا آدرس سرور را بررسی کنید", true, false),
    SERVER_UNREACHABLE("سرور واسط پاسخ نداد یا در دسترس نیست", true, false),
    SERVER_REJECTED_REQUEST("سرور واسط درخواست را نپذیرفت", false, false),
    INVITATION_NOT_FOUND("این دعوت یافت نشد یا منقضی شده است", false, false),
    INVITATION_EXPIRED("مهلت این دعوت به پایان رسیده است؛ باید دعوت تازه ساخته شود", false, false),
    INVITATION_ALREADY_REDEEMED("این دعوت قبلاً توسط دستگاه دیگری پذیرفته شده است", false, true),
    INVITATION_REVOKED("دعوت توسط دستگاه میزبان لغو شده است", false, false),
    INVITATION_REJECTED("دعوت توسط دستگاه مقابل رد شده است", false, false),
    RATE_LIMITED("تعداد درخواست‌ها بیش از حد مجاز است؛ چند لحظه بعد دوباره تلاش کنید", true, false),

    ACTIVATION_CODE_MALFORMED("ساختار کد فعال‌سازی نامعتبر است", false, false),
    ACTIVATION_CODE_REJECTED("کد فعال‌سازی پذیرفته نشد", false, false),
    INVITATION_QR_MALFORMED("کد QR دعوت خوانده‌شده متعلق به دوولینک نیست یا آسیب دیده است", false, false),
    SERVER_MISMATCH("دستگاه مقابل به سرور واسط متفاوتی متصل است؛ آدرس سرور هر دو دستگاه باید یکسان باشد", false, false),

    INVALID_PEER_PUBLIC_KEY("کلید عمومی دستگاه مقابل نامعتبر است", false, true),
    INVALID_PEER_IDENTITY_SIGNATURE("امضای هویت دستگاه مقابل نامعتبر است (احتمال جعل یا دستکاری)", false, true),
    TRANSCRIPT_MISMATCH("اطلاعات دست‌دادن دو دستگاه با هم مطابقت ندارد (احتمال دستکاری در میانه)", false, true),
    DEVICE_ID_MISMATCH("شناسه دستگاه مقابل با کلید هویت او هم‌خوانی ندارد", false, true),
    SELF_PAIRING_FORBIDDEN("جفت‌سازی دستگاه با خودش مجاز نیست", false, false),
    PROTOCOL_VERSION_UNSUPPORTED("نسخه پروتکل دستگاه مقابل پشتیبانی نمی‌شود", false, false),

    COMMIT_NOT_YET_SENT("هنوز تأیید رمزنگاری‌شده این دستگاه ارسال نشده است", false, false),
    PEER_COMMIT_NOT_YET_AVAILABLE("تأیید دستگاه مقابل هنوز آماده نیست؛ منتظر بمانید", true, false),
    CIPHERTEXT_MALFORMED("ساختار داده رمزنگاری‌شده نامعتبر است", false, true),
    CIPHERTEXT_AUTHENTICATION_FAILED("احراز اصالت داده رمزنگاری‌شده شکست خورد (کلید نادرست یا دستکاری)", false, true),
    CONFIRMATION_HMAC_INVALID("امضای تأیید (HMAC) دستگاه مقابل معتبر نیست (احتمال جعل)", false, true),
    ACK_SIGNATURE_INVALID("امضای دیجیتال تأیید نهایی دستگاه مقابل معتبر نیست", false, true),
    RECEIPT_SIGNATURE_INVALID("رسید سرور واسط معتبر نیست", false, false),

    SAFETY_NUMBER_NOT_COMPARED("مقایسه کامل ۶۰ رقم کد امنیتی الزامی است", false, false),
    SAFETY_NUMBER_INCOMPLETE("کد امنیتی نمایش‌داده‌شده کامل نیست؛ مقایسه را متوقف کنید", false, true),
    KEY_CHANGE_NOT_ACKNOWLEDGED("تغییر کلید هویت مخاطب شناسایی شده و نیازمند تأیید آگاهانه است", false, false),
    USER_DECLINED("تأیید شما ثبت نشد", false, false),

    PEER_ALREADY_PINNED("این دستگاه از قبل با یک مخاطب مورد اعتماد جفت شده است؛ دستگاه سوم مجاز نیست", false, false),
    TRUST_STORAGE_CORRUPTED("ذخیره‌سازی امن اعتماد آسیب دیده است؛ تا بازیابی صریح، جفت‌سازی مسدود است", false, true),
    PENDING_STORAGE_CORRUPTED("ذخیره‌سازی جفت‌سازی ناتمام آسیب دیده است؛ از نو آغاز کنید", false, true),
    KEY_VAULT_UNAVAILABLE("دسترسی به کلیدهای امنیتی دستگاه ممکن نشد", false, true),

    LOCAL_PERSISTENCE_FAILED("ذخیره‌سازی محلی اعتماد شکست خورد؛ این جفت‌سازی کامل نشده است", true, true),
    PEER_ACK_MISSING("تأیید نهایی دستگاه مقابل هنوز دریافت نشده است", true, false),
    MUTUAL_RECEIPT_NOT_CONFIRMED("تأیید نهایی دوطرفه هنوز کامل نشده است", true, false),
    CANCELLED_BY_LOCAL_USER("فرآیند توسط شما لغو شد", false, false),
    ALREADY_TERMINAL("این جفت‌سازی در وضعیت پایانی است و تغییر نمی‌کند", false, false),
    INVALID_STATE_TRANSITION("وضعیت جفت‌سازی اجازه این عملیات را نمی‌دهد", false, false)
}

/**
 * Thrown by the Method B engine. Always carries a [RemoteFailure]; callers must map it to UI text
 * rather than displaying [message] directly (which may contain internal detail useful only in logs —
 * and even there, never key material).
 */
class RemotePairingException(
    val failure: RemoteFailure,
    override val message: String = failure.persianMessage,
    cause: Throwable? = null
) : Exception(message, cause)

/**
 * The five distributed-persistence states required by the specification, plus the two terminal/idle
 * states the UI needs. The ordering of [ordinal] is meaningful: a flow may only move forward, and the
 * coordinator enforces that.
 *
 * Honest naming: `LOCAL_TRUST_PERSISTED` explicitly says *local*. There is no state called "paired"
 * until [MUTUAL_RECEIPT_CONFIRMED], because only then has each device learned that the *other* device
 * also persisted.
 */
enum class RemotePairingPhase(val ordinalIndex: Int) {
    /** Nothing in progress. */
    IDLE(0),

    /** Owner created an invitation and is showing the activation code / QR. */
    INVITATION_CREATED(1),

    /** Recipient accepted the code and the two devices exchanged public key material. */
    INVITATION_REDEEMED(2),

    /** Both users are comparing the 60-digit Safety Number; nothing is trusted yet. */
    AWAITING_SAFETY_NUMBER_COMPARISON(3),

    /** This device's user approved, and this device's encrypted commit exists locally. */
    LOCAL_USER_APPROVED(4),

    /** Server confirmed both commits exist (serialisation barrier passed). */
    COMMIT_QUORUM_REACHED(5),

    /** Peer commit retrieved, decrypted, HMAC/ECDSA-verified and digest-matched. */
    PEER_COMMIT_VERIFIED(6),

    /** Trust record written to this device's encrypted storage. Local only. */
    LOCAL_TRUST_PERSISTED(7),

    /** Both authenticated persistence ACKs recorded by the server. */
    MUTUAL_RECEIPT_CONFIRMED(8),

    /** Aborted before any local trust was written; nothing to undo. */
    CANCELLED(90),

    /** Aborted; a locally persisted trust record (if any) is intentionally kept. */
    CANCELLED_AFTER_LOCAL_TRUST(91),

    /** Server-side invitation is terminal (expired/revoked/rejected). */
    TERMINAL(92),

    /** Fail-closed: the flow may not continue without explicit recovery. */
    BLOCKED(99);

    val isTerminal: Boolean get() = ordinalIndex >= 90

    companion object {
        /** The five states the specification names, in order, for the progress UI. */
        val FIVE_REQUIRED_STATES: List<RemotePairingPhase> = listOf(
            LOCAL_USER_APPROVED,
            COMMIT_QUORUM_REACHED,
            PEER_COMMIT_VERIFIED,
            LOCAL_TRUST_PERSISTED,
            MUTUAL_RECEIPT_CONFIRMED
        )
    }
}

/** Which side of an invitation this device is. Mirrors the server's role strings. */
enum class RemoteRole(val wireValue: String, val persianLabel: String) {
    OWNER(RemoteTranscripts.Role.OWNER, "میزبان (سازنده دعوت)"),
    RECIPIENT(RemoteTranscripts.Role.RECIPIENT, "مهمان (پذیرنده دعوت)");

    val peerRole: RemoteRole get() = if (this == OWNER) RECIPIENT else OWNER

    companion object {
        fun fromWire(value: String?): RemoteRole? = entries.firstOrNull { it.wireValue == value }
    }
}
