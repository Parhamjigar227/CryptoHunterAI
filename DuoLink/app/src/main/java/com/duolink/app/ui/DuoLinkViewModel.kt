package com.duolink.app.ui

import android.app.Application
import android.graphics.Bitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.duolink.app.android.AndroidKeystoreSealer
import com.duolink.app.android.AndroidKeystoreVault
import com.duolink.app.android.QrBitmapCodec
import com.duolink.app.crypto.DirectoryFileByteStore
import com.duolink.app.crypto.KeyProtectionReport
import com.duolink.app.pairing.PairingCoordinator
import com.duolink.app.pairing.PairingStateSnapshot
import com.duolink.app.pairing.PeerTrustStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

data class DuoLinkUiState(
    val initialized: Boolean = false,
    val localDeviceIdHex: String = "",
    val localSpkId: Int = 0,
    val keyProtectionReport: KeyProtectionReport? = null,
    val pairingState: PairingStateSnapshot = PairingStateSnapshot.UnpairedIdle,
    val qrBitmap: Bitmap? = null,
    val cameraScannerOpen: Boolean = false,
    val statusBannerPersian: String? = null,
    val isErrorBanner: Boolean = false
)

class DuoLinkViewModel(application: Application) : AndroidViewModel(application) {

    private val trustDir = File(application.filesDir, "duolink_trust_v1")
    private val byteStore = DirectoryFileByteStore(trustDir)
    private val sealer = AndroidKeystoreSealer()
    private val keyVault = AndroidKeystoreVault(
        packageManager = application.packageManager,
        sealer = sealer,
        byteStore = byteStore
    )
    private val trustStore = PeerTrustStore(store = byteStore, sealer = sealer)
    private val coordinator = PairingCoordinator(keyVault = keyVault, trustStore = trustStore)

    private val _uiState = MutableStateFlow(DuoLinkUiState())
    val uiState: StateFlow<DuoLinkUiState> = _uiState.asStateFlow()

    init {
        refreshIdentityAndState()
    }

    fun refreshIdentityAndState() {
        viewModelScope.launch {
            val updated = withContext(Dispatchers.IO) {
                val now = PairingCoordinator.currentEpochSec()
                val snap = coordinator.currentStateSnapshot(now)
                if (snap is PairingStateSnapshot.TrustStorageCorrupted) {
                    return@withContext DuoLinkUiState(
                        initialized = true,
                        localDeviceIdHex = "",
                        localSpkId = 0,
                        keyProtectionReport = null,
                        pairingState = snap,
                        qrBitmap = null,
                        cameraScannerOpen = false,
                        statusBannerPersian = "هشدار امنیتی: ذخیره‌سازی امن دچار آسیب یا دستکاری شده و عملیات جفت‌سازی مسدود است.",
                        isErrorBanner = true
                    )
                }

                try {
                    val localId = keyVault.getOrCreateLocalIdentity(now)
                    val report = keyVault.getKeyProtectionReport(now)
                    val qrContent = when (snap) {
                        is PairingStateSnapshot.InitiatorOfferReady -> snap.offerQrPayload
                        is PairingStateSnapshot.AwaitingUserConfirmation -> snap.responseAcceptQrPayload
                        else -> null
                    }
                    val bmp = qrContent?.let { QrBitmapCodec.renderQrBitmap(it, 680) }
                    DuoLinkUiState(
                        initialized = true,
                        localDeviceIdHex = localId.deviceIdHex,
                        localSpkId = localId.currentSignedPreKey.spkId,
                        keyProtectionReport = report,
                        pairingState = snap,
                        qrBitmap = bmp,
                        cameraScannerOpen = _uiState.value.cameraScannerOpen,
                        statusBannerPersian = _uiState.value.statusBannerPersian,
                        isErrorBanner = _uiState.value.isErrorBanner
                    )
                } catch (e: Exception) {
                    val corruptedSnap = coordinator.currentStateSnapshot(now)
                    DuoLinkUiState(
                        initialized = true,
                        pairingState = corruptedSnap,
                        statusBannerPersian = e.message ?: "خطای امنیتی در بررسی ذخیره‌سازی کلیدها",
                        isErrorBanner = true
                    )
                }
            }
            _uiState.value = updated
        }
    }

    fun generateInitiatorOfferQr() {
        viewModelScope.launch {
            val res = withContext(Dispatchers.IO) {
                coordinator.startInitiatorOffer()
            }
            res.fold(
                onSuccess = {
                    _uiState.update {
                        it.copy(
                            cameraScannerOpen = false,
                            statusBannerPersian = "کد درخواست جفت‌سازی ساخته شد. از مخاطب بخواهید آن را اسکن کند و سپس کد پاسخ او را اسکن کنید.",
                            isErrorBanner = false
                        )
                    }
                    refreshIdentityAndState()
                },
                onFailure = { err ->
                    _uiState.update {
                        it.copy(
                            statusBannerPersian = err.message ?: "ساخت کد درخواست ممکن نیست",
                            isErrorBanner = true
                        )
                    }
                    refreshIdentityAndState()
                }
            )
        }
    }

    fun setScannerOpen(open: Boolean) {
        _uiState.update { it.copy(cameraScannerOpen = open) }
    }

    fun onQrPayloadScanned(rawQrText: String) {
        val trimmed = rawQrText.trim()
        if (trimmed.isEmpty()) return
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                coordinator.processScannedQr(trimmed)
            }
            when (outcome) {
                is PairingCoordinator.QrProcessResult.ResponderReadyToConfirm -> {
                    _uiState.update {
                        it.copy(
                            cameraScannerOpen = false,
                            statusBannerPersian = "کد پذیرفته شد. اکنون هر ۶۰ رقم کد امنیتی را با گوشی مقابل مقایسه کنید.",
                            isErrorBanner = false
                        )
                    }
                }
                is PairingCoordinator.QrProcessResult.InitiatorReadyToConfirm -> {
                    _uiState.update {
                        it.copy(
                            cameraScannerOpen = false,
                            statusBannerPersian = "کد پاسخ پذیرفته شد. اکنون هر ۶۰ رقم کد امنیتی را با گوشی مقابل مقایسه کنید.",
                            isErrorBanner = false
                        )
                    }
                }
                is PairingCoordinator.QrProcessResult.PeerConfirmationVerified -> {
                    _uiState.update {
                        it.copy(
                            cameraScannerOpen = false,
                            statusBannerPersian = "گوشی مقابل این اتصال را تأیید کرد.",
                            isErrorBanner = false
                        )
                    }
                }
                is PairingCoordinator.QrProcessResult.Rejected -> {
                    _uiState.update {
                        it.copy(
                            cameraScannerOpen = false,
                            statusBannerPersian = outcome.detail,
                            isErrorBanner = true
                        )
                    }
                }
            }
            refreshIdentityAndState()
        }
    }

    fun confirmSafetyNumberAndPair(
        fullSafetyNumberComparedViaTrustedChannel: Boolean,
        acknowledgeKeyChange: Boolean
    ) {
        viewModelScope.launch {
            val res = withContext(Dispatchers.IO) {
                coordinator.confirmSafetyFingerprint(
                    fullSafetyNumberComparedViaTrustedChannel = fullSafetyNumberComparedViaTrustedChannel,
                    acknowledgeKeyChange = acknowledgeKeyChange
                )
            }
            res.fold(
                onSuccess = {
                    _uiState.update {
                        it.copy(
                            statusBannerPersian = "اتصال با موفقیت برقرار شد و کلید امنیتی گوشی مقابل ذخیره شد.",
                            isErrorBanner = false
                        )
                    }
                    refreshIdentityAndState()
                },
                onFailure = { err ->
                    _uiState.update {
                        it.copy(
                            statusBannerPersian = err.message ?: "خطا در ثبت جفت‌سازی",
                            isErrorBanner = true
                        )
                    }
                    refreshIdentityAndState()
                }
            )
        }
    }

    fun cancelPendingHandshake() {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                coordinator.cancelPendingPairing()
            }
            _uiState.update {
                it.copy(
                    cameraScannerOpen = false,
                    statusBannerPersian = "فرآیند جفت‌سازی موقت لغو شد.",
                    isErrorBanner = false
                )
            }
            refreshIdentityAndState()
        }
    }

    fun unpairAndPrepareRePairing(rotateDeviceIdentity: Boolean) {
        viewModelScope.launch {
            val res = withContext(Dispatchers.IO) {
                coordinator.unpairForSecureRePairing(rotateDeviceIdentity = rotateDeviceIdentity)
            }
            res.fold(
                onSuccess = {
                    _uiState.update {
                        it.copy(
                            cameraScannerOpen = false,
                            statusBannerPersian = if (rotateDeviceIdentity) {
                                "جفت‌سازی قبلی لغو و کلید هویت جدید ساخته شد. آماده جفت‌سازی مجدد هستید."
                            } else {
                                "جفت‌سازی قبلی لغو و پیش‌کلید تازه شد. آماده جفت‌سازی مجدد امن هستید."
                            },
                            isErrorBanner = false
                        )
                    }
                },
                onFailure = { err ->
                    _uiState.update {
                        it.copy(
                            cameraScannerOpen = false,
                            statusBannerPersian = err.message ?: "لغو جفت‌سازی به علت خطای ذخیره‌سازی امن مسدود شد",
                            isErrorBanner = true
                        )
                    }
                }
            )
            refreshIdentityAndState()
        }
    }

    fun recoverFromCorruptedStorage(confirmDestructiveRecovery: Boolean) {
        viewModelScope.launch {
            val res = withContext(Dispatchers.IO) {
                coordinator.recoverFromCorruptedStorage(
                    confirmDestructiveRecovery = confirmDestructiveRecovery
                )
            }
            res.fold(
                onSuccess = {
                    _uiState.update {
                        it.copy(
                            cameraScannerOpen = false,
                            statusBannerPersian = "بازیابی امن انجام شد: رکوردهای آسیب‌دیده پاک‌سازی و هویت رمزنگاری جدید صادر شد. جفت‌سازی حضوری/تأییدشده جدید الزامی است.",
                            isErrorBanner = false
                        )
                    }
                },
                onFailure = { err ->
                    _uiState.update {
                        it.copy(
                            statusBannerPersian = err.message ?: "اجرای بازیابی امن ممکن نشد",
                            isErrorBanner = true
                        )
                    }
                }
            )
            refreshIdentityAndState()
        }
    }

    fun dismissBanner() {
        _uiState.update { it.copy(statusBannerPersian = null) }
    }
}
