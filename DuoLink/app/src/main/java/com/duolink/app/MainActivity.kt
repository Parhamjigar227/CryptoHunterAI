package com.duolink.app

import android.os.Bundle
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.duolink.app.pairing.PairingStateSnapshot
import com.duolink.app.ui.DuoLinkTheme
import com.duolink.app.ui.DuoLinkUiState
import com.duolink.app.ui.DuoLinkViewModel
import com.duolink.app.ui.ErrorCrimson
import com.duolink.app.ui.GoldMuted
import com.duolink.app.ui.GoldPrimary
import com.duolink.app.ui.ObsidianBackground
import com.duolink.app.ui.PairingScreen
import com.duolink.app.ui.SecurityIdentityScreen
import com.duolink.app.ui.SuccessEmerald
import com.duolink.app.ui.SurfaceCharcoal
import com.duolink.app.ui.SurfaceElevated
import com.duolink.app.ui.TextIvory
import com.duolink.app.ui.TextMuted
import com.duolink.app.ui.WarningAmber
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.duolink.app.lock.BiometricUnlockGate
import com.duolink.app.ui.AppLockScreen
import com.duolink.app.ui.AppLockUiState
import com.duolink.app.ui.ConversationScreen
import com.duolink.app.ui.LockScreenMode

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Global Privacy Mode enabled by default: block OS screenshots & Recents previews.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        setContent {
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                DuoLinkTheme {
                    DuoLinkAppRoot()
                }
            }
        }
    }
}

@Composable
fun DuoLinkAppRoot(duoViewModel: DuoLinkViewModel = viewModel()) {
    val navController = rememberNavController()
    val uiState by duoViewModel.uiState.collectAsState()
    val lockState by duoViewModel.lockState.collectAsState()
    val conversation by duoViewModel.conversation.collectAsState()
    val activity = LocalContext.current as? FragmentActivity

    // The lock gate is installed the first time the app runs and re-armed on every cold start.
    LaunchedEffect(Unit) {
        val biometricAvailable = activity
            ?.let { BiometricUnlockGate(it).availability() is BiometricUnlockGate.Availability.Available }
            ?: false
        duoViewModel.refreshLockState(biometricAvailable)
    }

    // Re-arm when the app goes to the background, so switching apps does not leave it open.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                duoViewModel.lockNow()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // While locked, nothing else in the graph is reachable.
    val showLockGate = lockState.isConfigured.let { configured ->
        configured && !lockState.isUnlocked
    } || (!lockState.isConfigured && !lockState.isUnlocked && !lockState.storageCorrupted)

    if (showLockGate) {
        AppLockGate(
            lockState = lockState,
            activity = activity,
            onPinSubmitted = duoViewModel::submitPin,
            onBiometricUnlocked = duoViewModel::onBiometricUnlocked
        )
        return
    }

    NavHost(navController = navController, startDestination = "home") {
        composable("home") {
            HomeScreen(
                uiState = uiState,
                onOpenPairing = { navController.navigate("pairing") },
                onOpenSecurity = { navController.navigate("security") },
                onOpenAbout = { navController.navigate("about") }
            )
        }
        composable("pairing") {
            PairingScreen(
                uiState = uiState,
                onBack = {
                    duoViewModel.setScannerOpen(false)
                    navController.popBackStack()
                },
                onCreateOfferQr = duoViewModel::generateInitiatorOfferQr,
                onOpenScanner = duoViewModel::setScannerOpen,
                onQrScanned = duoViewModel::onQrPayloadScanned,
                onConfirmPairing = duoViewModel::confirmSafetyNumberAndPair,
                onCancelHandshake = duoViewModel::cancelPendingHandshake,
                onOpenSecurityDetails = { navController.navigate("security") },
                onRecoverCorruptedStorage = duoViewModel::recoverFromCorruptedStorage,
                onDismissBanner = duoViewModel::dismissBanner
            )
        }
        composable("security") {
            SecurityIdentityScreen(
                uiState = uiState,
                onBack = { navController.popBackStack() },
                onUnpairKeepIdentity = { duoViewModel.unpairAndPrepareRePairing(rotateDeviceIdentity = false) },
                onUnpairRotateIdentity = { duoViewModel.unpairAndPrepareRePairing(rotateDeviceIdentity = true) },
                onRecoverCorruptedStorage = duoViewModel::recoverFromCorruptedStorage,
                onGoToPairing = {
                    navController.navigate("pairing") {
                        launchSingleTop = true
                    }
                }
            )
        }
        composable("conversation") {
            LaunchedEffect(Unit) {
                duoViewModel.openConversation(DEFAULT_RELAY_BASE_URL)
                duoViewModel.markConversationRead()
            }
            // Polling fallback: the WebSocket pushes when available, this guarantees progress when it
            // is not. Harmless when the socket is live because the engine de-duplicates by message id.
            LaunchedEffect(Unit) {
                while (true) {
                    kotlinx.coroutines.delay(CONVERSATION_POLL_INTERVAL_MS)
                    duoViewModel.syncConversation()
                }
            }
            // System picker: one-item grant, no media permission requested at all.
            val pickers = rememberAttachmentPickers(
                onPicked = { uri -> duoViewModel.attachPickedMedia(uri) },
                onCancelled = { /* user backed out; nothing to report */ }
            )

            ConversationScreen(
                messages = conversation.messages,
                connectionState = conversation.connectionState,
                peerDisplayName = conversation.peerDisplayName,
                isSending = conversation.isSending,
                onBack = {
                    duoViewModel.closeConversation()
                    navController.popBackStack()
                },
                onSendText = duoViewModel::sendMessage,
                onPickImage = pickers.pickImage,
                onPickVideo = pickers.pickVideo,
                onOpenAttachment = { message ->
                    duoViewModel.openAttachment(message.messageIdHex)
                    navController.navigate("attachment")
                },
                onRetry = { message -> duoViewModel.retryMessage(message.messageIdHex) }
            )
        }
        composable("attachment") {
            val viewer by duoViewModel.viewerState.collectAsState()
            AttachmentViewerScreen(
                state = viewer,
                onBack = {
                    duoViewModel.closeAttachmentViewer()
                    navController.popBackStack()
                },
                onRequestExport = duoViewModel::requestGalleryExport,
                onConfirmExport = { duoViewModel.confirmGalleryExport() },
                onDismissExportDialog = duoViewModel::dismissGalleryExportDialog,
                exportDialogVisible = viewer.exportDialogVisible,
                exportResultPersian = viewer.exportResultPersian,
                onRemoveFromDevice = duoViewModel::removeAttachmentFromDevice,
                videoContent = {
                    PrivateVideoPlayer(
                        plaintext = viewer.plaintext,
                        mimeType = viewer.mimeType,
                        onError = { duoViewModel.reportAttachmentError(it) }
                    )
                }
            )
        }
        composable("about") {
            AboutScreen(onBack = { navController.popBackStack() })
        }
    }
}

/**
 * Main screen — deliberately minimal.
 *
 * The user asked for a private messenger, not a configuration tool. Only four things are here: the
 * portrait/logo, one plain-language status line, one primary action, and a small settings entry.
 * Cryptography, key ids, device fingerprints and storage diagnostics live behind [onOpenSecurity],
 * which is the "small settings option" — they are never shown on this screen.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeScreen(
    uiState: DuoLinkUiState,
    onOpenPairing: () -> Unit,
    onOpenSecurity: () -> Unit,
    onOpenAbout: () -> Unit
) {
    val paired = uiState.pairingState as? PairingStateSnapshot.PairedActive
    val corrupted = uiState.pairingState is PairingStateSnapshot.TrustStorageCorrupted
    val inProgress = when (val snap = uiState.pairingState) {
        is PairingStateSnapshot.AwaitingUserConfirmation -> !snap.localApproved
        is PairingStateSnapshot.InitiatorOfferReady -> true
        else -> false
    }

    Scaffold(
        containerColor = ObsidianBackground,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Image(
                            painter = painterResource(id = R.drawable.duolink_logo),
                            contentDescription = null,
                            modifier = Modifier.size(32.dp).clip(CircleShape),
                            contentScale = ContentScale.Crop
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text("دوولینک", fontWeight = FontWeight.Bold)
                    }
                },
                actions = {
                    // The only secondary entry point: one small settings icon.
                    IconButton(onClick = onOpenSecurity) {
                        Icon(
                            Icons.Default.Settings,
                            contentDescription = "تنظیمات و امنیت",
                            tint = if (corrupted) ErrorCrimson else GoldPrimary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = ObsidianBackground,
                    titleContentColor = GoldPrimary
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 24.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(28.dp))

            Image(
                painter = painterResource(id = R.drawable.nasrin_portrait),
                contentDescription = "نسرین خانم",
                modifier = Modifier
                    .size(132.dp)
                    .clip(CircleShape)
                    .border(2.dp, GoldPrimary, CircleShape),
                contentScale = ContentScale.Crop
            )
            Spacer(modifier = Modifier.height(18.dp))
            Text(
                text = "نسرین خانم",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = TextIvory
            )

            Spacer(modifier = Modifier.height(28.dp))

            // Plain-language status. No device ids, no key names, no server addresses.
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(
                            when {
                                corrupted -> ErrorCrimson
                                paired != null -> SuccessEmerald
                                inProgress -> WarningAmber
                                else -> TextMuted
                            }
                        )
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = when {
                        corrupted -> "نیازمند بررسی امنیتی"
                        paired != null -> "متصل به گوشی مقابل"
                        inProgress -> "در حال اتصال…"
                        else -> "متصل نیست"
                    },
                    fontSize = 17.sp,
                    color = when {
                        corrupted -> ErrorCrimson
                        paired != null -> SuccessEmerald
                        inProgress -> WarningAmber
                        else -> TextMuted
                    }
                )
            }

            Spacer(modifier = Modifier.height(36.dp))

            Button(
                onClick = { if (corrupted) onOpenSecurity() else onOpenPairing() },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (corrupted) ErrorCrimson else GoldPrimary,
                    contentColor = if (corrupted) Color.White else Color.Black
                )
            ) {
                Icon(Icons.Default.QrCodeScanner, contentDescription = null)
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = when {
                        corrupted -> "بررسی و بازیابی"
                        paired != null -> "مشاهده اتصال"
                        else -> "اتصال به گوشی دیگر"
                    },
                    fontSize = 17.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }

            if (paired != null) {
                Spacer(modifier = Modifier.height(14.dp))
                OutlinedButton(
                    onClick = onOpenSecurity,
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = GoldPrimary)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("گفتگوی خصوصی", color = GoldPrimary)
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            TextButton(onClick = onOpenAbout) {
                Text("درباره", color = TextMuted, fontSize = 13.sp)
            }
            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AboutScreen(onBack: () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("درباره برنامه") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "بازگشت")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = SurfaceCharcoal,
                    titleContentColor = GoldPrimary,
                    navigationIconContentColor = GoldPrimary
                )
            )
        },
        containerColor = ObsidianBackground
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(24.dp))
                    .background(SurfaceCharcoal)
                    .border(1.dp, GoldMuted, RoundedCornerShape(24.dp))
                    .padding(28.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Image(
                    painter = painterResource(id = R.drawable.nasrin_portrait),
                    contentDescription = "نسرین خانم",
                    modifier = Modifier
                        .size(148.dp)
                        .clip(CircleShape)
                        .border(2.5.dp, GoldPrimary, CircleShape),
                    contentScale = ContentScale.Crop
                )
                Spacer(modifier = Modifier.height(22.dp))
                Text(
                    text = "نسرین خانم",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = GoldPrimary,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "این برنامه مخصوص شما ساخته شده است.",
                    fontSize = 16.sp,
                    color = TextIvory,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "یک ارتباط خصوصی، برای دو نفر",
                    fontSize = 14.sp,
                    color = GoldPrimary,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}

/** Default relay base URL. Loopback is allowed for adb-reverse development; a real deployment is wss. */
private const val DEFAULT_RELAY_BASE_URL = "https://relay.duolink.invalid"

/** How often the fallback poll runs while the chat screen is open. */
private const val CONVERSATION_POLL_INTERVAL_MS = 5_000L

/**
 * Hosts the lock screen and performs the platform biometric prompt.
 *
 * The gate is a *screen-level* decision, not an overlay: while locked, the NavHost is never composed,
 * so a screenshot or a deep link cannot reach the conversation.
 */
@Composable
private fun AppLockGate(
    lockState: AppLockUiState,
    activity: FragmentActivity?,
    onPinSubmitted: (String) -> Unit,
    onBiometricUnlocked: () -> Unit
) {
    var biometricError by remember { mutableStateOf<String?>(null) }
    val mode = when {
        lockState.isCreating && lockState.awaitingConfirmation -> LockScreenMode.CONFIRM
        lockState.isCreating -> LockScreenMode.CREATE
        !lockState.isConfigured -> LockScreenMode.CREATE
        else -> LockScreenMode.UNLOCK
    }

    // Ticks the cooling-off countdown so the number on screen actually decreases.
    var remaining by remember { mutableStateOf(lockState.lockoutRemainingSeconds) }
    LaunchedEffect(lockState.lockoutRemainingSeconds) {
        remaining = lockState.lockoutRemainingSeconds
        while (remaining > 0) {
            kotlinx.coroutines.delay(1000)
            remaining = (remaining - 1).coerceAtLeast(0)
        }
    }

    AppLockScreen(
        mode = mode,
        errorMessage = biometricError ?: lockState.errorPersian,
        lockoutRemainingSeconds = remaining,
        biometricAvailable = lockState.biometricAvailable && mode == LockScreenMode.UNLOCK,
        onPinSubmitted = { pin ->
            biometricError = null
            onPinSubmitted(pin)
        },
        onBiometricRequested = {
            val host = activity
            if (host == null) {
                biometricError = "ورود بیومتریک در این دستگاه در دسترس نیست."
                return@AppLockScreen
            }
            BiometricUnlockGate(host).authenticate(
                activity = host,
                title = "باز کردن دوولینک",
                subtitle = "برای ورود، هویت خود را تأیید کنید.",
                negativeButton = "استفاده از رمز",
                onSuccess = {
                    biometricError = null
                    onBiometricUnlocked()
                },
                onFailure = { reason -> biometricError = reason }
            )
        }
    )
}
