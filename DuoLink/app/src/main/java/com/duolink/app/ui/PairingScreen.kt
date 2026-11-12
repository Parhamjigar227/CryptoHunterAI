package com.duolink.app.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.duolink.app.pairing.PairingStateSnapshot
import com.duolink.app.pairing.TrustStoreComponent

/**
 * Pairing screen — two steps, plain language.
 *
 * The whole handshake is presented as: scan/generate a code, then confirm. OFFER/ACCEPT packet names,
 * session ids, transcript digests and key ids are *not* shown; they are reachable on purpose under
 * «جزئیات فنی» for debugging, and they never gate the flow.
 *
 * The security gate is unchanged and still mandatory: the user must attest to comparing all 60 digits of
 * the Safety Number through an independent trusted channel before either device persists a pairing.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairingScreen(
    uiState: DuoLinkUiState,
    onBack: () -> Unit,
    onCreateOfferQr: () -> Unit,
    onOpenScanner: (Boolean) -> Unit,
    onQrScanned: (String) -> Unit,
    onConfirmPairing: (fullSafetyNumberCompared: Boolean, acknowledgeKeyChange: Boolean) -> Unit,
    onCancelHandshake: () -> Unit,
    onOpenSecurityDetails: () -> Unit,
    onRecoverCorruptedStorage: (Boolean) -> Unit,
    onDismissBanner: () -> Unit
) {
    val context = LocalContext.current
    var manualPayloadInput by remember { mutableStateOf("") }
    var showManualInput by remember { mutableStateOf(false) }
    var showTechnicalDetails by remember { mutableStateOf(false) }
    var fullSafetyNumberChecked by remember(uiState.pairingState) { mutableStateOf(false) }
    var acknowledgeKeyChange by remember(uiState.pairingState) { mutableStateOf(false) }
    var confirmDestructiveRecovery by remember(uiState.pairingState) { mutableStateOf(false) }

    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) onOpenScanner(true)
    }

    fun requestCameraAndOpenScanner() {
        val granted = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED
        if (granted) onOpenScanner(true) else cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("اتصال به گوشی دیگر") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "بازگشت")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = ObsidianBackground,
                    titleContentColor = GoldPrimary,
                    navigationIconContentColor = GoldPrimary
                )
            )
        },
        containerColor = ObsidianBackground
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            uiState.statusBannerPersian?.let { msg ->
                StatusBannerCard(message = msg, isError = uiState.isErrorBanner, onDismiss = onDismissBanner)
            }

            when (val snap = uiState.pairingState) {
                is PairingStateSnapshot.TrustStorageCorrupted -> {
                    CorruptedStorageRecoveryCard(
                        component = snap.component,
                        technicalReason = snap.technicalReason,
                        confirmChecked = confirmDestructiveRecovery,
                        onConfirmCheckedChange = { confirmDestructiveRecovery = it },
                        onExecuteRecovery = { onRecoverCorruptedStorage(confirmDestructiveRecovery) }
                    )
                }

                is PairingStateSnapshot.UnpairedIdle -> {
                    StepCard(step = "گام ۱ از ۲") {
                        Text(
                            text = "کدام کار را انجام می‌دهید؟",
                            fontSize = 19.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextIvory
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "یکی از دو گوشی کد می‌سازد و گوشی دیگر آن را اسکن می‌کند. " +
                                "این انتخاب فقط یک بار لازم است.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextMuted
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(
                            onClick = onCreateOfferQr,
                            modifier = Modifier.fillMaxWidth().height(54.dp),
                            shape = RoundedCornerShape(14.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = GoldPrimary,
                                contentColor = Color.Black
                            )
                        ) {
                            Icon(Icons.Default.QrCode2, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("نمایش کد QR در این گوشی", fontWeight = FontWeight.SemiBold)
                        }
                        Spacer(modifier = Modifier.height(10.dp))
                        OutlinedButton(
                            onClick = ::requestCameraAndOpenScanner,
                            modifier = Modifier.fillMaxWidth().height(54.dp),
                            shape = RoundedCornerShape(14.dp)
                        ) {
                            Icon(Icons.Default.CameraAlt, contentDescription = null, tint = GoldPrimary)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("اسکن کد QR گوشی مقابل", color = GoldPrimary)
                        }
                    }
                }

                is PairingStateSnapshot.InitiatorOfferReady -> {
                    StepCard(step = "گام ۱ از ۲") {
                        Text(
                            text = "این کد را با گوشی مقابل اسکن کنید",
                            fontSize = 19.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextIvory
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        uiState.qrBitmap?.let { bmp ->
                            Image(
                                bitmap = bmp.asImageBitmap(),
                                contentDescription = "کد QR اتصال",
                                modifier = Modifier
                                    .size(240.dp)
                                    .clip(RoundedCornerShape(14.dp))
                                    .background(Color.White)
                                    .padding(10.dp)
                                    .align(Alignment.CenterHorizontally)
                            )
                        }
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = "پس از اسکن، گوشی مقابل یک کد پاسخ نشان می‌دهد؛ آن را با همین گوشی اسکن کنید.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMuted
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Button(
                            onClick = ::requestCameraAndOpenScanner,
                            modifier = Modifier.fillMaxWidth().height(54.dp),
                            shape = RoundedCornerShape(14.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = GoldPrimary,
                                contentColor = Color.Black
                            )
                        ) {
                            Icon(Icons.Default.CameraAlt, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("گام ۲: اسکن کد پاسخ", fontWeight = FontWeight.SemiBold)
                        }
                        Spacer(modifier = Modifier.height(10.dp))
                        TextButton(
                            onClick = onCancelHandshake,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("لغو", color = TextMuted)
                        }
                    }
                }

                is PairingStateSnapshot.AwaitingUserConfirmation -> {
                    StepCard(step = "گام ۲ از ۲") {
                        Text(
                            text = "تأیید اتصال",
                            fontSize = 19.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextIvory
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "این کد باید در هر دو گوشی دقیقاً یکسان باشد. " +
                                "آن را با صدای بلند یا حضوری، رقم به رقم مقایسه کنید.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextMuted
                        )
                        Spacer(modifier = Modifier.height(14.dp))
                        SafetyNumberBox(safetyNumber = snap.safetyNumber)

                        if (snap.previousPeerChanged) {
                            Spacer(modifier = Modifier.height(12.dp))
                            KeyChangeWarningBox(previousDeviceIdHex = snap.previousPeerDeviceIdHex)
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(
                                    checked = acknowledgeKeyChange,
                                    onCheckedChange = { acknowledgeKeyChange = it },
                                    colors = CheckboxDefaults.colors(checkedColor = GoldPrimary)
                                )
                                Text(
                                    text = "تغییر کلید مخاطب را بررسی و تأیید می‌کنم.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = WarningAmber
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(12.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = fullSafetyNumberChecked,
                                onCheckedChange = { fullSafetyNumberChecked = it },
                                colors = CheckboxDefaults.colors(checkedColor = GoldPrimary)
                            )
                            Text(
                                text = "هر ۶۰ رقم را در دو گوشی یکسان دیدم.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = TextIvory
                            )
                        }

                        val canConfirm = fullSafetyNumberChecked &&
                            (!snap.previousPeerChanged || acknowledgeKeyChange)
                        Spacer(modifier = Modifier.height(12.dp))
                        Button(
                            onClick = { onConfirmPairing(fullSafetyNumberChecked, acknowledgeKeyChange) },
                            enabled = canConfirm,
                            modifier = Modifier.fillMaxWidth().height(54.dp),
                            shape = RoundedCornerShape(14.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (snap.localApproved) SuccessEmerald else GoldPrimary,
                                contentColor = Color.Black
                            )
                        ) {
                            Icon(Icons.Default.CheckCircle, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = if (snap.localApproved) "تأیید شد" else "تأیید اتصال",
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                        Spacer(modifier = Modifier.height(10.dp))
                        TextButton(onClick = onCancelHandshake, modifier = Modifier.fillMaxWidth()) {
                            Text("لغو", color = TextMuted)
                        }
                    }
                }

                is PairingStateSnapshot.PairedActive -> {
                    StepCard(step = null) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = SuccessEmerald)
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = "اتصال با موفقیت برقرار شد",
                                fontSize = 19.sp,
                                fontWeight = FontWeight.Bold,
                                color = SuccessEmerald
                            )
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "هر دو گوشی همین اتصال را تأیید کرده‌اند.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextIvory
                        )
                        Spacer(modifier = Modifier.height(14.dp))
                        SafetyNumberBox(safetyNumber = snap.peerRecord.safetyNumber)
                        Spacer(modifier = Modifier.height(14.dp))
                        OutlinedButton(
                            onClick = onOpenSecurityDetails,
                            modifier = Modifier.fillMaxWidth().height(50.dp),
                            shape = RoundedCornerShape(14.dp)
                        ) {
                            Text("جزئیات امنیتی", color = GoldPrimary)
                        }
                    }
                }
            }

            if (uiState.pairingState !is PairingStateSnapshot.TrustStorageCorrupted) {
                TechnicalDetailsSection(
                    expanded = showTechnicalDetails,
                    onToggle = { showTechnicalDetails = !showTechnicalDetails },
                    uiState = uiState,
                    manualPayloadInput = manualPayloadInput,
                    onManualPayloadChange = { manualPayloadInput = it },
                    showManualInput = showManualInput,
                    onToggleManualInput = { showManualInput = !showManualInput },
                    onQrScanned = onQrScanned
                )
            }
        }
    }
}

/** A single, quiet card wrapper so every step looks the same. */
@Composable
private fun StepCard(step: String?, content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = SurfaceElevated),
        shape = RoundedCornerShape(18.dp)
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            if (step != null) {
                Text(
                    text = step,
                    style = MaterialTheme.typography.labelMedium,
                    color = GoldSoft
                )
                Spacer(modifier = Modifier.height(8.dp))
            }
            content()
        }
    }
}

/**
 * Everything a normal user should never need: device id, key-protection report, transcript id and the
 * manual QR entry fallback. Collapsed by default; available for debugging on request.
 */
@Composable
private fun TechnicalDetailsSection(
    expanded: Boolean,
    onToggle: () -> Unit,
    uiState: DuoLinkUiState,
    manualPayloadInput: String,
    onManualPayloadChange: (String) -> Unit,
    showManualInput: Boolean,
    onToggleManualInput: () -> Unit,
    onQrScanned: (String) -> Unit
) {
    TextButton(onClick = onToggle, modifier = Modifier.fillMaxWidth()) {
        Text(
            text = if (expanded) "بستن جزئیات فنی" else "جزئیات فنی (برای عیب‌یابی)",
            style = MaterialTheme.typography.bodySmall,
            color = TextMuted
        )
    }
    if (!expanded) return

    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        if (uiState.localDeviceIdHex.isNotEmpty()) {
            Text(
                text = "شناسه دستگاه این گوشی: ${uiState.localDeviceIdHex}",
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    textDirection = TextDirection.Ltr
                ),
                color = GoldSoft
            )
        }
        uiState.keyProtectionReport?.let { report ->
            Text(
                text = "کلید امضا: ${report.identitySigningKey.persianDescription}",
                style = MaterialTheme.typography.bodySmall,
                color = TextMuted
            )
            Text(
                text = "پیش‌کلید: ${report.activeSignedPreKey.persianDescription}",
                style = MaterialTheme.typography.bodySmall,
                color = TextMuted
            )
        }
        (uiState.pairingState as? PairingStateSnapshot.AwaitingUserConfirmation)?.let { snap ->
            Text(
                text = "شناسه فنی گفت‌وگو: ${snap.publicHandshakeTranscriptId}",
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = TextMuted
            )
        }
        if (uiState.pairingState !is PairingStateSnapshot.PairedActive) {
            TextButton(onClick = onToggleManualInput) {
                Text(
                    text = if (showManualInput) "بستن ورود دستی" else "ورود دستی کد (بدون دوربین)",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMuted
                )
            }
            if (showManualInput) {
                OutlinedTextField(
                    value = manualPayloadInput,
                    onValueChange = onManualPayloadChange,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("رشته کد جفت‌سازی") },
                    singleLine = true
                )
                Button(
                    onClick = { onQrScanned(manualPayloadInput); onManualPayloadChange("") },
                    enabled = manualPayloadInput.isNotBlank(),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("بررسی کد")
                }
            }
        }
    }
}

@Composable
fun CorruptedStorageRecoveryCard(
    component: TrustStoreComponent,
    technicalReason: String,
    confirmChecked: Boolean,
    onConfirmCheckedChange: (Boolean) -> Unit,
    onExecuteRecovery: () -> Unit
) {
    val componentNamePersian = when (component) {
        TrustStoreComponent.PINNED_PEER -> "رکورد همتای پین‌شده (pinned_peer)"
        TrustStoreComponent.ARCHIVED_PEER -> "بایگانی هویت قبلی همتا (archived_peer)"
        TrustStoreComponent.REPLAY_LEDGER -> "دفتر ضدبازپخش جلسات QR (replay_ledger)"
        TrustStoreComponent.KEY_VAULT -> "متادیتا یا پیش‌کلید امضاشده دستگاه (spk_entries / Keystore)"
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.5.dp, ErrorCrimson, RoundedCornerShape(16.dp)),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF2B1215)),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Warning, contentDescription = null, tint = ErrorCrimson)
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "مسدودسازی امنیتی (Fail-Closed): خرابی یا دستکاری ذخیره‌سازی امن",
                    fontWeight = FontWeight.Bold,
                    color = ErrorCrimson
                )
            }
            Text(
                text = "بخش آسیب‌دیده: $componentNamePersian\n" +
                    "برنامه به‌منظور جلوگیری از دور زدن هشدار تغییر کلید یا بازپخش کدهای قدیمی، تمام عملیات جفت‌سازی و بازجفت‌سازی را مسدود کرده است.",
                style = MaterialTheme.typography.bodySmall,
                color = TextIvory,
                lineHeight = 20.sp
            )
            Text(
                text = "جزئیات فنی: $technicalReason",
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    textDirection = TextDirection.Ltr
                ),
                color = WarningAmber
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Checkbox(
                    checked = confirmChecked,
                    onCheckedChange = onConfirmCheckedChange,
                    colors = CheckboxDefaults.colors(checkedColor = ErrorCrimson)
                )
                Text(
                    text = "آگاهم که بازیابی امن تمام رکوردهای اعتماد آسیب‌دیده و کلیدهای قبلی را حذف و هویت رمزنگاری جدید صادر می‌کند و پس از آن باید جفت‌سازی حضوری ۶۰ رقمی را از نو انجام دهم.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextIvory,
                    lineHeight = 20.sp
                )
            }
            Button(
                onClick = onExecuteRecovery,
                enabled = confirmChecked,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = ErrorCrimson,
                    contentColor = Color.White
                )
            ) {
                Text("اجرای بازیابی صریح و بازنشانی کامل هویت امنیتی")
            }
        }
    }
}

@Composable
fun SafetyNumberBox(safetyNumber: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(ObsidianBackground)
            .border(1.dp, GoldMuted, RoundedCornerShape(12.dp))
            .padding(14.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = safetyNumber,
            style = MaterialTheme.typography.bodyLarge.copy(
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.4.sp,
                lineHeight = 26.sp,
                textDirection = TextDirection.Ltr
            ),
            color = GoldPrimary,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
internal fun KeyChangeWarningBox(previousDeviceIdHex: String?) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(Color(0xFF2B1C10))
            .border(1.dp, WarningAmber, RoundedCornerShape(12.dp))
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Warning, contentDescription = null, tint = WarningAmber)
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "هشدار تغییر کلید امنیتی مخاطب!",
                fontWeight = FontWeight.Bold,
                color = WarningAmber
            )
        }
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = "کلید هویت جدید با کلید قبلی ذخیره‌شده تفاوت دارد" +
                (previousDeviceIdHex?.let { " (شناسه قبلی: $it)" } ?: "") +
                ". تنها در صورتی ادامه دهید که از تعویض گوشی یا نصب مجدد برنامه توسط خود نسرین خانم مطمئن هستید.",
            style = MaterialTheme.typography.bodySmall,
            color = TextIvory
        )
    }
}

@Composable
private fun StatusBannerCard(
    message: String,
    isError: Boolean,
    onDismiss: () -> Unit
) {
    val borderCol = if (isError) ErrorCrimson else GoldPrimary
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, borderCol, RoundedCornerShape(12.dp)),
        colors = CardDefaults.cardColors(containerColor = SurfaceCharcoal),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = message,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodySmall,
                color = if (isError) ErrorCrimson else TextIvory
            )
            OutlinedButton(onClick = onDismiss) {
                Text("بستن", style = MaterialTheme.typography.labelSmall, color = GoldPrimary)
            }
        }
    }
}
