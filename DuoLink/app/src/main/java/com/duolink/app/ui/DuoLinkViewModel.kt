package com.duolink.app.ui

import android.app.Application
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.duolink.app.android.AndroidKeystoreSealer
import com.duolink.app.android.AndroidKeystoreVault
import com.duolink.app.android.QrBitmapCodec
import com.duolink.app.pairing.DirectoryFileByteStore
import com.duolink.app.pairing.KeyChangeAlert
import com.duolink.app.pairing.PairingCoordinator
import com.duolink.app.pairing.PairingStateSnapshot
import com.duolink.app.pairing.PeerTrustStore
import com.duolink.app.pairing.QrProcessResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

enum class BannerTone { INFO, SUCCESS, WARNING, ERROR }

data class UiBanner(
    val title: String,
    val detail: String,
    val tone: BannerTone
)

data class DuoLinkUiState(
    val localDeviceId: String = "",
    val localIdentityDigits: String = "",
    val isHardwareBacked: Boolean = false,
    val hardwareDescription: String = "",
    val currentSpkId: Int = 1,
    val pairingSnapshot: PairingStateSnapshot = PairingStateSnapshot.Unpaired,
    val activeQrBitmap: ImageBitmap? = null,
    val activeQrUri: String? = null,
    val remainingSeconds: Long = 0L,
    val banner: UiBanner? = null,
    val blockingKeyChangeAlert: KeyChangeAlert? = null
)

class DuoLinkViewModel(application: Application) : AndroidViewModel(application) {

    private val sealer = AndroidKeystoreSealer(application.applicationContext)
    private val keyVault = AndroidKeystoreVault(application.applicationContext, sealer)
    private val trustStore = PeerTrustStore(
        byteStore = DirectoryFileByteStore(File(application.filesDir, "duolink_trust_store")),
        sealer = sealer
    )
    private val coordinator = PairingCoordinator(
        keyVault = keyVault,
        trustStore = trustStore
    )

    private val _uiState = MutableStateFlow(DuoLinkUiState())
    val uiState: StateFlow<DuoLinkUiState> = _uiState.asStateFlow()

    init {
        refreshFromCoordinator()
        startExpiryTicker()
    }

    fun startInitiatorOffer() {
        val result = coordinator.startInitiatorOffer()
        result.fold(
            onSuccess = {
                _uiState.update { s -> s.copy(banner = null, blockingKeyChangeAlert = null) }
                refreshFromCoordinator()
            },
            onFailure = { err ->
                _uiState.update { s ->
                    s.copy(
                        banner = UiBanner(
                            title = "امکان ایجاد کد جفت‌سازی جدید نیست",
                            detail = err.message ?: "خطای وضعیت جفت‌سازی",
                            tone = BannerTone.ERROR
                        )
                    )
                }
            }
        )
    }

    fun processScannedQr(rawQrText: String, verifyExistingPeerMode: Boolean = false) {
        when (val res = coordinator.processScannedQr(rawQrText, verifyExistingPeerMode = verifyExistingPeerMode)) {
            is QrProcessResult.ResponderReadyToConfirm -> {
                _uiState.update {
                    it.copy(
                        banner = UiBanner(
                            title = "کد درخواست دریافت و امضای آن تأیید شد",
                            detail = "اکنون کد پاسخ زیر را با گوشی اول اسکن کنید و سپس کد امنیتی ۱۲ بخشی را در هر دو گوشی مقایسه و تأیید نمایید.",
                            tone = BannerTone.INFO
                        ),
                        blockingKeyChangeAlert = res.keyChangeFromPreviousPeer
                    )
                }
                refreshFromCoordinator()
            }
            is QrProcessResult.InitiatorReadyToConfirm -> {
                _uiState.update {
                    it.copy(
                        banner = UiBanner(
                            title = "پاسخ گوشی مقابل با موفقیت تأیید شد",
                            detail = "لطفاً کد امنیتی ۱۲ بخشی را در هر دو گوشی مقایسه کنید و در صورت تطابق کامل، دکمه تأیید نهایی را بزنید.",
                            tone = BannerTone.INFO
                        ),
                        blockingKeyChangeAlert = res.keyChangeFromPreviousPeer
                    )
                }
                refreshFromCoordinator()
            }
            is QrProcessResult.ExistingPeerVerified -> {
                val extra = if (res.preKeyUpdated) " (کلید پیش‌امضاشده جدید مخاطب نیز به‌روز شد)" else ""
                _uiState.update {
                    it.copy(
                        banner = UiBanner(
                            title = "هویت مخاطب کاملاً منطبق و معتبر است",
                            detail = "کلید عمومی با هویت ثبت‌شده قبلی مطابقت دارد$extra.",
                            tone = BannerTone.SUCCESS
                        ),
                        blockingKeyChangeAlert = null
                    )
                }
                refreshFromCoordinator()
            }
            is QrProcessResult.Rejected -> {
                _uiState.update {
                    it.copy(
                        banner = UiBanner(
                            title = res.reason.persianTitle,
                            detail = res.reason.persianDetail,
                            tone = BannerTone.ERROR
                        ),
                        blockingKeyChangeAlert = res.keyChangeAlert
                    )
                }
                refreshFromCoordinator()
            }
        }
    }

    fun confirmSafetyFingerprint(acknowledgeKeyChange: Boolean) {
        val res = coordinator.confirmSafetyFingerprint(acknowledgeKeyChange = acknowledgeKeyChange)
        res.fold(
            onSuccess = {
                _uiState.update {
                    it.copy(
                        banner = UiBanner(
                            title = "جفت‌سازی امن در این گوشی نهایی شد",
                            detail = "مطمئن شوید تأیید نهایی روی گوشی دوم نیز انجام شده است.",
                            tone = BannerTone.SUCCESS
                        ),
                        blockingKeyChangeAlert = null
                    )
                }
                refreshFromCoordinator()
            },
            onFailure = { err ->
                _uiState.update {
                    it.copy(
                        banner = UiBanner(
                            title = "تأیید انجام نشد",
                            detail = err.message ?: "نشست معتبر نیست.",
                            tone = BannerTone.ERROR
                        )
                    )
                }
                refreshFromCoordinator()
            }
        )
    }

    fun cancelPendingPairing() {
        coordinator.cancelPendingSession()
        _uiState.update { it.copy(banner = null, blockingKeyChangeAlert = null) }
        refreshFromCoordinator()
    }

    fun rotateLocalSignedPreKey() {
        val spk = coordinator.rotateSignedPreKey()
        _uiState.update {
            it.copy(
                currentSpkId = spk.spkId,
                banner = UiBanner(
                    title = "کلید پیش‌امضاشده چرخش یافت",
                    detail = "کلید تبادل جدید با شناسه #${spk.spkId} تولید و با کلید هویت امضا شد.",
                    tone = BannerTone.SUCCESS
                )
            )
        }
    }

    fun resetPairingForSecureRePair(regenerateDeviceIdentity: Boolean) {
        coordinator.unpairForSecureRePairing(regenerateDeviceIdentity = regenerateDeviceIdentity)
        _uiState.update {
            it.copy(
                banner = UiBanner(
                    title = "جفت‌سازی قبلی بازنشانی شد",
                    detail = if (regenerateDeviceIdentity) {
                        "کلید هویت جدیدی برای این گوشی تولید شد. اکنون می‌توانید جفت‌سازی دوطرفه جدیدی انجام دهید."
                    } else {
                        "همتای قبلی لغو شد و اثرانگشت قبلی برای تشخیص تغییر کلید بایگانی گردید."
                    },
                    tone = BannerTone.WARNING
                ),
                blockingKeyChangeAlert = null
            )
        }
        refreshFromCoordinator()
    }

    fun dismissBanner() {
        _uiState.update { it.copy(banner = null) }
    }

    fun dismissBlockingKeyChangeAlert() {
        _uiState.update { it.copy(blockingKeyChangeAlert = null) }
    }

    private fun refreshFromCoordinator() {
        val now = System.currentTimeMillis() / 1000L
        val snapshot = coordinator.currentStateSnapshot(now)
        val qrUriToRender = when (snapshot) {
            is PairingStateSnapshot.OfferCreated -> snapshot.offerQrUri
            is PairingStateSnapshot.AwaitingUserConfirmation -> snapshot.acceptQrUri
            else -> null
        }
        val expSec = when (snapshot) {
            is PairingStateSnapshot.OfferCreated -> snapshot.expiresAtEpochSec
            is PairingStateSnapshot.AwaitingUserConfirmation -> snapshot.expiresAtEpochSec
            else -> 0L
        }
        val remaining = if (expSec > now) expSec - now else 0L

        val previousUri = _uiState.value.activeQrUri
        _uiState.update { prev ->
            prev.copy(
                localDeviceId = coordinator.getLocalDeviceId(),
                localIdentityDigits = coordinator.getLocalIdentityDigits(),
                isHardwareBacked = coordinator.isHardwareKeyBacked(),
                hardwareDescription = coordinator.getHardwareKeyDescription(),
                currentSpkId = coordinator.getCurrentSignedPreKey(now).spkId,
                pairingSnapshot = snapshot,
                activeQrUri = qrUriToRender,
                activeQrBitmap = if (qrUriToRender == previousUri) prev.activeQrBitmap else null,
                remainingSeconds = remaining
            )
        }

        if (qrUriToRender != null && qrUriToRender != previousUri) {
            viewModelScope.launch {
                val bmp = withContext(Dispatchers.Default) {
                    runCatching { QrBitmapCodec.renderQrBitmap(qrUriToRender, 720).asImageBitmap() }.getOrNull()
                }
                _uiState.update { state ->
                    if (state.activeQrUri == qrUriToRender) state.copy(activeQrBitmap = bmp) else state
                }
            }
        }
    }

    private fun startExpiryTicker() {
        viewModelScope.launch {
            while (isActive) {
                delay(1000L)
                val snap = _uiState.value.pairingSnapshot
                val exp = when (snap) {
                    is PairingStateSnapshot.OfferCreated -> snap.expiresAtEpochSec
                    is PairingStateSnapshot.AwaitingUserConfirmation -> snap.expiresAtEpochSec
                    else -> 0L
                }
                if (exp > 0L) {
                    val now = System.currentTimeMillis() / 1000L
                    if (now > exp) {
                        refreshFromCoordinator()
                    } else {
                        _uiState.update { it.copy(remainingSeconds = (exp - now).coerceAtLeast(0L)) }
                    }
                }
            }
        }
    }
}
