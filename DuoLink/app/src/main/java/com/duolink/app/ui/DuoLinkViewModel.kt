package com.duolink.app.ui

import android.app.Application
import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.lock.AppLockPolicy
import com.duolink.app.lock.AppLockRecord
import com.duolink.app.lock.AppLockVerifier
import com.duolink.app.lock.PinDerivation
import com.duolink.app.lock.PinRules
import com.duolink.app.lock.SealedAppLockStore
import com.duolink.app.media.MediaKeyManager
import com.duolink.app.media.MediaVault
import com.duolink.app.messaging.ChatMessage
import com.duolink.app.pairing.PairedPeerRecord
import com.duolink.app.messaging.ConnectionState
import com.duolink.app.messaging.ConversationEngine
import com.duolink.app.messaging.ConversationKeySchedule
import com.duolink.app.messaging.ConversationStore
import com.duolink.app.messaging.HttpRelayClient
import com.duolink.app.messaging.MessageType
import com.duolink.app.messaging.RelayMessageTransport
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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

/**
 * What the lock screen must show.
 *
 * [isUnlocked] is the only thing the navigation graph checks. Everything else is presentation.
 * [storageCorrupted] is a distinct, loud state: it means the lock record exists but cannot be
 * authenticated, so the app must not pretend "there is no lock" and let the user in.
 */
data class AppLockUiState(
    val isConfigured: Boolean = false,
    val isUnlocked: Boolean = false,
    val storageCorrupted: Boolean = false,
    val errorPersian: String? = null,
    val lockoutRemainingSeconds: Long = 0L,
    val biometricAvailable: Boolean = false,
    val isCreating: Boolean = false,
    val awaitingConfirmation: Boolean = false
)

/** State of the full-screen attachment viewer, including the explicit Gallery-export dialog. */
data class AttachmentViewerUiState(
    val messageIdHex: String = "",
    val isLoading: Boolean = false,
    val plaintext: ByteArray? = null,
    val mimeType: String = "application/octet-stream",
    val digestHex: String = "",
    val isVideo: Boolean = false,
    val errorPersian: String? = null,
    val exportDialogVisible: Boolean = false,
    val isExporting: Boolean = false,
    val exportResultPersian: String? = null
)

/** Everything the chat screen needs. */
data class ConversationUiState(
    val messages: List<ChatMessage> = emptyList(),
    val connectionState: ConnectionState = ConnectionState.OFFLINE,
    val peerDisplayName: String = "طرف مقابل",
    val isSending: Boolean = false,
    val errorPersian: String? = null
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

    /** App-lock gate. The record is stored only as an AES-256-GCM sealed blob. */
    private val appLockStore = SealedAppLockStore(byteStore, sealer)

    /** Encrypted attachment storage, created lazily once the media master key is available. */
    private val mediaKeyManager = MediaKeyManager(byteStore, sealer)
    val mediaVault: MediaVault? by lazy {
        when (val state = mediaKeyManager.obtainOrCreate()) {
            is MediaKeyManager.KeyState.Ready ->
                MediaVault(File(application.filesDir, "duolink_media_v1"), state.masterKey)
            // A corrupted media key is not silently replaced: doing so would orphan every attachment.
            else -> null
        }
    }

    private val relayHttp = HttpRelayClient()

    /** The live conversation engine, present only while paired and unlocked. */
    private var conversationEngine: ConversationEngine? = null
    private var relayTransport: RelayMessageTransport? = null

    private val _lockState = MutableStateFlow(AppLockUiState())
    val lockState: StateFlow<AppLockUiState> = _lockState.asStateFlow()

    private val _viewer = MutableStateFlow(AttachmentViewerUiState())
    val viewerState: StateFlow<AttachmentViewerUiState> = _viewer.asStateFlow()

    private val _conversation = MutableStateFlow(ConversationUiState())
    val conversation: StateFlow<ConversationUiState> = _conversation.asStateFlow()

    /** Wall-clock of the last successful unlock, used for auto-lock. */
    private var lastUnlockAtMs: Long = 0L
    private var pendingNewPin: String? = null

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

    // =====================================================================================
    // App lock
    // =====================================================================================

    /** Reads the lock configuration and decides whether the gate must be shown. */
    fun refreshLockState(biometricAvailable: Boolean) {
        viewModelScope.launch {
            val loaded = withContext(Dispatchers.IO) { appLockStore.read() }
            _lockState.value = when (loaded) {
                is SealedAppLockStore.LockRead.Absent ->
                    // No lock yet: the user is asked to create one before any conversation exists.
                    AppLockUiState(
                        isConfigured = false,
                        isUnlocked = false,
                        isCreating = false,
                        biometricAvailable = biometricAvailable
                    )
                is SealedAppLockStore.LockRead.Configured -> {
                    val lockedOut = AppLockPolicy.isLockedOut(loaded.record, System.currentTimeMillis())
                    _lockState.value.copy(
                        isConfigured = true,
                        storageCorrupted = false,
                        biometricAvailable = biometricAvailable,
                        lockoutRemainingSeconds = if (lockedOut) {
                            AppLockPolicy.remainingLockoutMs(loaded.record, System.currentTimeMillis()) / 1000
                        } else {
                            0L
                        }
                    )
                }
                is SealedAppLockStore.LockRead.Corrupted ->
                    // Fail closed: never treat a damaged record as "no lock configured".
                    _lockState.value.copy(
                        isConfigured = true,
                        isUnlocked = false,
                        storageCorrupted = true,
                        errorPersian = "پروندهٔ قفل برنامه آسیب دیده است. برای بازگردانی، برنامه را دوباره نصب کنید یا از بازیابی استفاده کنید."
                    )
            }
        }
    }

    /** Submits a PIN for unlock, or collects the two-step creation flow. */
    fun submitPin(pin: String) {
        val state = _lockState.value
        if (state.isCreating || !state.isConfigured) {
            handlePinCreation(pin)
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { attemptUnlock(pin) }
            _lockState.value = result
        }
    }

    private fun attemptUnlock(pin: String): AppLockUiState {
        val loaded = appLockStore.read()
        val current = _lockState.value
        when (loaded) {
            is SealedAppLockStore.LockRead.Absent -> return current.copy(isUnlocked = true)
            is SealedAppLockStore.LockRead.Corrupted ->
                return current.copy(isUnlocked = false, storageCorrupted = true)
            is SealedAppLockStore.LockRead.Configured -> {
                val now = System.currentTimeMillis()
                if (AppLockPolicy.isLockedOut(loaded.record, now)) {
                    return current.copy(
                        errorPersian = null,
                        lockoutRemainingSeconds = AppLockPolicy.remainingLockoutMs(loaded.record, now) / 1000
                    )
                }
                return if (AppLockVerifier.verify(pin, loaded.record)) {
                    // Clear the failure counter on success, and persist the cleared counter.
                    appLockStore.write(AppLockPolicy.registerSuccess(loaded.record))
                    lastUnlockAtMs = now
                    current.copy(
                        isUnlocked = true,
                        errorPersian = null,
                        lockoutRemainingSeconds = 0L
                    ).also { onUnlocked() }
                } else {
                    val updated = AppLockPolicy.registerFailure(loaded.record, now)
                    appLockStore.write(updated)
                    val remaining = AppLockPolicy.remainingLockoutMs(updated, now) / 1000
                    current.copy(
                        isUnlocked = false,
                        errorPersian = "رمز اشتباه است.",
                        lockoutRemainingSeconds = remaining
                    )
                }
            }
        }
    }

    /** Starts the two-step "choose a PIN" flow. */
    fun beginPinCreation() {
        _lockState.value = _lockState.value.copy(
            isCreating = true,
            awaitingConfirmation = false,
            errorPersian = null
        )
    }

    private fun handlePinCreation(pin: String) {
        val pending = pendingNewPin
        if (pending == null) {
            val rejection = PinRules.rejectionReason(pin)
            if (rejection != null) {
                _lockState.value = _lockState.value.copy(errorPersian = rejection)
                return
            }
            pendingNewPin = pin
            _lockState.value = _lockState.value.copy(
                isCreating = true,
                awaitingConfirmation = true,
                errorPersian = null
            )
            return
        }
        if (pending != pin) {
            pendingNewPin = null
            _lockState.value = _lockState.value.copy(
                isCreating = true,
                awaitingConfirmation = false,
                errorPersian = "رمزها یکسان نبودند. دوباره تلاش کنید."
            )
            return
        }
        viewModelScope.launch {
            val record = withContext(Dispatchers.IO) {
                AppLockVerifier.createRecord(pin, System.currentTimeMillis())
            }
            withContext(Dispatchers.IO) { appLockStore.write(record) }
            pendingNewPin = null
            lastUnlockAtMs = System.currentTimeMillis()
            _lockState.value = _lockState.value.copy(
                isConfigured = true,
                isUnlocked = true,
                isCreating = false,
                awaitingConfirmation = false,
                errorPersian = null,
                storageCorrupted = false
            )
            withContext(Dispatchers.Main) { onUnlocked() }
        }
    }

    /**
     * Called after a biometric success reported by the platform.
     *
     * This does NOT re-verify the PIN: the OS already proved the user is the enrolled biometric holder
     * and released the auth-bound Keystore key. It also does not weaken the PIN gate — the PIN still
     * guards a cold start and a biometric failure falls back to it.
     */
    fun onBiometricUnlocked() {
        lastUnlockAtMs = System.currentTimeMillis()
        _lockState.value = _lockState.value.copy(
            isUnlocked = true,
            errorPersian = null,
            lockoutRemainingSeconds = 0L
        )
        onUnlocked()
    }

    /** Re-arms the gate. Called on a lifecycle stop and when no PIN has been entered for a while. */
    fun lockNow() {
        if (!_lockState.value.isConfigured) return
        conversationEngine?.setConnectionState(ConnectionState.OFFLINE)
        relayTransport?.disconnectSocket()
        _lockState.value = _lockState.value.copy(isUnlocked = false)
    }

    fun autoLockIfIdle(idleThresholdMs: Long = AppLockPolicy.AUTO_LOCK_AFTER_MS) {
        if (!_lockState.value.isUnlocked) return
        if (System.currentTimeMillis() - lastUnlockAtMs >= idleThresholdMs) lockNow()
    }

    fun updateLockoutCountdown(seconds: Long) {
        if (_lockState.value.lockoutRemainingSeconds == seconds) return
        _lockState.value = _lockState.value.copy(lockoutRemainingSeconds = seconds)
    }

    fun clearLockError() {
        if (_lockState.value.errorPersian == null) return
        _lockState.value = _lockState.value.copy(errorPersian = null)
    }

    // =====================================================================================
    // Conversation
    // =====================================================================================

    /**
     * Builds (or rebuilds) the conversation engine for the current paired peer.
     *
     * Called only after the app is unlocked and a peer is paired, so key material is never derived
     * while the gate is closed.
     */
    fun openConversation(serverBaseUrl: String) {
        val paired = _uiState.value.pairingState as? PairingStateSnapshot.PairedActive ?: run {
            _conversation.value = _conversation.value.copy(
                errorPersian = "برای گفتگو ابتدا باید با دستگاه دیگر جفت شوید."
            )
            return
        }
        val localIdHex = _uiState.value.localDeviceIdHex
        if (localIdHex.isBlank()) {
            _conversation.value = _conversation.value.copy(
                errorPersian = "هویت دستگاه در دسترس نیست."
            )
            return
        }
        viewModelScope.launch {
            val engine = withContext(Dispatchers.IO) {
                buildEngine(paired.peerRecord, serverBaseUrl)
            }
            if (engine == null) {
                _conversation.value = _conversation.value.copy(
                    errorPersian = "کلید گفتگو در دسترس نیست. لطفاً دوباره جفت شوید."
                )
                return@launch
            }
            engine.addListener { messages, state ->
                _conversation.value = _conversation.value.copy(
                    messages = messages,
                    connectionState = state
                )
            }
            withContext(Dispatchers.IO) {
                engine.loadHistory()
                runCatching { engine.syncOnce() }
            }
            engine.setConnectionState(
                if (relayTransport?.socketConnected == true) ConnectionState.ONLINE
                else ConnectionState.CONNECTING
            )
        }
    }

    private fun buildEngine(peer: PairedPeerRecord, serverBaseUrl: String): ConversationEngine? {
        val localIdHex = _uiState.value.localDeviceIdHex
        val localDeviceId = runCatching { ByteEncoding.fromHexStrict(localIdHex) }.getOrNull()
            ?: return null
        val peerDeviceId = peer.peerDeviceId
        val rootKey = peer.rootPairingKey

        // Both devices must agree on which id is the "initiator" so the directional keys line up.
        val initiatorId: ByteArray
        val responderId: ByteArray
        val localIsInitiator =
            ByteEncoding.compareLexicographically(localDeviceId, peerDeviceId) < 0
        if (localIsInitiator) {
            initiatorId = localDeviceId
            responderId = peerDeviceId
        } else {
            initiatorId = peerDeviceId
            responderId = localDeviceId
        }

        val i2r = ConversationKeySchedule.initiatorToResponderKey(rootKey, initiatorId, responderId)
        val r2i = ConversationKeySchedule.responderToInitiatorKey(rootKey, initiatorId, responderId)
        val ctl = ConversationKeySchedule.controlKey(rootKey, initiatorId, responderId)

        val store = ConversationStore(byteStore, sealer, ByteEncoding.toHexLower(peerDeviceId))
        val transport = RelayMessageTransport(serverBaseUrl, localDeviceId, relayHttp)
        relayTransport = transport
        val engine = ConversationEngine(
            store = store,
            transport = transport,
            localDeviceId = localDeviceId,
            peerDeviceId = peerDeviceId,
            sendKey = if (localIsInitiator) i2r else r2i,
            receiveKey = if (localIsInitiator) r2i else i2r,
            controlKey = ctl
        )
        conversationEngine = engine
        return engine
    }

    fun sendMessage(text: String) {
        val engine = conversationEngine ?: return
        if (!_lockState.value.isUnlocked) return
        viewModelScope.launch {
            _conversation.value = _conversation.value.copy(isSending = true, errorPersian = null)
            val result = withContext(Dispatchers.IO) { engine.sendText(text) }
            _conversation.value = _conversation.value.copy(
                isSending = false,
                errorPersian = result.exceptionOrNull()?.let { "پیام ارسال نشد. دوباره تلاش کنید." }
            )
        }
    }

    fun retryMessage(messageIdHex: String) {
        val engine = conversationEngine ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) { engine.retry(messageIdHex) }
        }
    }

    fun markConversationRead() {
        val engine = conversationEngine ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                runCatching { engine.markAllRead() }
                runCatching { engine.syncOnce() }
            }
        }
    }

    /** One polling tick for the fallback path. The socket, when live, pushes instead. */
    fun syncConversation() {
        val engine = conversationEngine ?: return
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { runCatching { engine.syncOnce() } }
            if (result.isFailure) {
                val current = _conversation.value.connectionState
                if (current != ConnectionState.OFFLINE) {
                    engine.setConnectionState(ConnectionState.RECONNECTING)
                }
            } else if (relayTransport?.socketConnected != true) {
                engine.setConnectionState(ConnectionState.ONLINE)
            }
        }
    }

    fun closeConversation() {
        relayTransport?.disconnectSocket()
        conversationEngine?.setConnectionState(ConnectionState.OFFLINE)
        conversationEngine = null
        relayTransport = null
    }

    /** Runs once the gate opens, so nothing heavy happens while the lock screen is up. */
    private fun onUnlocked() {
        refreshIdentityAndState()
    }


    // =====================================================================================
    // Attachments
    // =====================================================================================

    /**
     * Seals a picked image/video into the private vault and sends the message that references it.
     *
     * The media bytes never travel inside the message envelope: only the digest, MIME type, size and
     * duration do. The sealed blob stays on this device, so the transport never carries plaintext media.
     */
    fun attachPickedMedia(uri: android.net.Uri) {
        val vault = mediaVault ?: run {
            _conversation.value = _conversation.value.copy(
                errorPersian = "حافظهٔ امن رسانه در دسترس نیست. برنامه را دوباره باز کنید."
            )
            return
        }
        val engine = conversationEngine ?: return
        val app = getApplication<Application>()

        viewModelScope.launch {
            _conversation.value = _conversation.value.copy(isSending = true, errorPersian = null)
            val outcome = withContext(Dispatchers.IO) {
                com.duolink.app.ui.AttachmentIngest.ingest(app, uri, vault)
            }
            when (outcome) {
                is com.duolink.app.ui.AttachmentIngest.Result.Rejected -> {
                    _conversation.value = _conversation.value.copy(
                        isSending = false,
                        errorPersian = outcome.persianMessage
                    )
                }
                is com.duolink.app.ui.AttachmentIngest.Result.Stored -> {
                    val ref = outcome.ref
                    val result = withContext(Dispatchers.IO) {
                        engine.sendAttachment(
                            kind = if (ref.kind.isVideo) MessageType.VIDEO else MessageType.IMAGE,
                            mediaDigestSha256 = ref.sha256,
                            mediaFileName = ref.sealedFileName,
                            mediaMimeType = ref.mimeType,
                            mediaSizeBytes = ref.sizeBytes,
                            mediaDurationMs = ref.durationMs
                        )
                    }
                    _conversation.value = _conversation.value.copy(
                        isSending = false,
                        errorPersian = result.exceptionOrNull()?.let { "ارسال پیوست ناموفق بود." }
                    )
                }
            }
        }
    }

    /** Loads one attachment's sealed bytes into the viewer. */
    fun openAttachment(messageIdHex: String) {
        val vault = mediaVault
        val message = _conversation.value.messages.firstOrNull { it.messageIdHex == messageIdHex }
        val digest = message?.payload?.mediaDigestSha256
        if (vault == null || message == null || digest == null) {
            _viewer.value = AttachmentViewerUiState(
                messageIdHex = messageIdHex,
                isLoading = false,
                errorPersian = "این پیوست در دسترس نیست."
            )
            return
        }
        _viewer.value = AttachmentViewerUiState(
            messageIdHex = messageIdHex,
            isLoading = true,
            mimeType = message.payload.mediaMimeType ?: "application/octet-stream",
            digestHex = com.duolink.app.crypto.ByteEncoding.toHexLower(digest),
            isVideo = message.payload.type == MessageType.VIDEO
        )
        viewModelScope.launch {
            val bytes = withContext(Dispatchers.IO) {
                runCatching { vault.open(digest, kindOf(message)) }.getOrNull()
            }
            _viewer.value = _viewer.value.copy(
                isLoading = false,
                plaintext = bytes,
                errorPersian = when {
                    bytes != null -> null
                    // A missing blob and a failed integrity check are different problems and are
                    // reported differently, so the user can tell "not synced" from "tampered".
                    !vault.contains(digest) -> "این پیوست روی این دستگاه ذخیره نشده است."
                    else -> "این پیوست قابل اعتماد نیست و باز نشد."
                }
            )
        }
    }

    private fun kindOf(message: ChatMessage): com.duolink.app.media.MediaKind =
        if (message.payload.type == MessageType.VIDEO) {
            com.duolink.app.media.MediaKind.VIDEO
        } else {
            com.duolink.app.media.MediaKind.IMAGE
        }

    fun closeAttachmentViewer() {
        _viewer.value = AttachmentViewerUiState()
    }

    fun requestGalleryExport() {
        if (_viewer.value.plaintext == null) return
        _viewer.value = _viewer.value.copy(exportDialogVisible = true, exportResultPersian = null)
    }

    fun dismissGalleryExportDialog() {
        _viewer.value = _viewer.value.copy(exportDialogVisible = false)
    }

    /**
     * Performs the explicit, confirmed Gallery export for exactly one attachment.
     *
     * This is the only place in the app that writes to shared storage, and it only runs from this
     * user-confirmed path. The sealed private copy is left in place.
     */
    fun confirmGalleryExport() {
        val state = _viewer.value
        val plaintext = state.plaintext ?: return
        val message = _conversation.value.messages.firstOrNull { it.messageIdHex == state.messageIdHex }
        val mime = state.mimeType
        val app = getApplication<Application>()
        val exporter = com.duolink.app.media.MediaExporter(app)
        val kind = if (state.isVideo) com.duolink.app.media.MediaKind.VIDEO
        else com.duolink.app.media.MediaKind.IMAGE

        _viewer.value = state.copy(exportDialogVisible = false, isExporting = true)
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                exporter.exportToGallery(
                    plaintext = plaintext,
                    kind = kind,
                    mimeType = mime,
                    displayName = message?.payload?.mediaFileName ?: "duolink-export",
                    takenAtEpochSec = (message?.payload?.createdAtEpochMs ?: System.currentTimeMillis()) / 1000
                )
            }
            _viewer.value = _viewer.value.copy(
                isExporting = false,
                exportResultPersian = when (result) {
                    is com.duolink.app.media.MediaExporter.Result.Saved -> "در گالری ذخیره شد."
                    is com.duolink.app.media.MediaExporter.Result.Failed -> result.persianMessage
                }
            )
        }
    }

    /**
     * Deletes this device's sealed copy of an attachment.
     *
     * Deliberately local-only: it does not ask the peer to delete anything, and the message bubble
     * remains so the conversation history is not silently rewritten.
     */
    fun removeAttachmentFromDevice() {
        val vault = mediaVault ?: return
        val state = _viewer.value
        if (state.digestHex.isEmpty()) return
        viewModelScope.launch {
            val digest = com.duolink.app.crypto.ByteEncoding.fromHexStrict(state.digestHex)
            withContext(Dispatchers.IO) { vault.delete(digest) }
            _viewer.value = _viewer.value.copy(
                plaintext = null,
                errorPersian = "این پیوست از این دستگاه حذف شد."
            )
        }
    }

    fun reportAttachmentError(message: String) {
        _viewer.value = _viewer.value.copy(errorPersian = message)
    }

}
