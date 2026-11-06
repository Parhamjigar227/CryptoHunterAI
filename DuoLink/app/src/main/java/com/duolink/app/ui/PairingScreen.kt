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
    var fullSafetyNumberChecked by remember(uiState.pairingState) { mutableStateOf(false) }
    var acknowledgeKeyChange by remember(uiState.pairingState) { mutableStateOf(false) }
    var confirmDestructiveRecovery by remember(uiState.pairingState) { mutableStateOf(false) }

    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            onOpenScanner(true)
        }
    }

    fun requestCameraAndOpenScanner() {
        val granted = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED
        if (granted) {
            onOpenScanner(true)
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("جفت‌سازی امن دوطرفه (QR)") },
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            uiState.statusBannerPersian?.let { msg ->
                StatusBannerCard(
                    message = msg,
                    isError = uiState.isErrorBanner,
                    onDismiss = onDismissBanner
                )
            }

            // Local device identity card with separate per-key protection summary
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = SurfaceCharcoal),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Security, contentDescription = null, tint = GoldPrimary)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "هویت رمزنگاری این دستگاه",
                            fontWeight = FontWeight.Bold,
                            color = TextIvory
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = if (uiState.localDeviceIdHex.isNotEmpty()) {
                            "شناسه دستگاه: ${uiState.localDeviceIdHex}"
                        } else {
                            "شناسه دستگاه: غیرفعال تا رفع خطای ذخیره‌سازی امن"
                        },
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            textDirection = TextDirection.Ltr
                        ),
                        color = GoldSoft
                    )
                    uiState.keyProtectionReport?.let { report ->
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "• امضای هویت (IK_sig): ${report.identitySigningKey.persianDescription}",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMuted
                        )
                        Text(
                            text = "• کلید پوششی (MSK): ${report.storageWrappingKey.persianDescription}",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMuted
                        )
                        Text(
                            text = "• پیش‌کلید (SPK_dh): ${report.activeSignedPreKey.persianDescription}",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMuted
                        )
                    }
                }
            }

            if (uiState.cameraScannerOpen && uiState.pairingState !is PairingStateSnapshot.TrustStorageCorrupted) {
                CameraQrScannerBox(
                    promptText = "دوربین را مقابل کد QR گوشی مقابل بگیرید",
                    onQrDecoded = onQrScanned,
                    onClose = { onOpenScanner(false) }
                )
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
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = SurfaceElevated),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Text(
                                text = "مراحل جفت‌سازی اختصاصی دو نفره",
                                fontWeight = FontWeight.Bold,
                                color = GoldPrimary
                            )
                            Text(
                                text = "۱. یکی از دو گوشی گزینه «ساخت کد QR درخواست» را می‌زند.\n" +
                                    "۲. گوشی دوم آن کد را اسکن می‌کند تا «کد QR پاسخ» تولید شود.\n" +
                                    "۳. گوشی اول کد پاسخ را اسکن می‌کند.\n" +
                                    "۴. هر دو نفر تمام ۶۰ رقم کد امنیتی را از طریق یک کانال مستقل و مورد اعتماد (حضوری یا تماس صوتی مستقیم) مقایسه و تأیید می‌کنند.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = TextIvory,
                                lineHeight = 24.sp
                            )
                            Button(
                                onClick = onCreateOfferQr,
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = GoldPrimary,
                                    contentColor = Color.Black
                                )
                            ) {
                                Icon(Icons.Default.QrCode2, contentDescription = null)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("گام ۱: ساخت کد QR درخواست (دستگاه شروع‌کننده)")
                            }
                            OutlinedButton(
                                onClick = ::requestCameraAndOpenScanner,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Icon(Icons.Default.CameraAlt, contentDescription = null, tint = GoldPrimary)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("اسکن کد QR درخواست از گوشی مقابل", color = GoldPrimary)
                            }
                        }
                    }
                }

                is PairingStateSnapshot.InitiatorOfferReady -> {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = SurfaceElevated),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Text(
                                text = "کد QR درخواست جفت‌سازی (گام ۱ از ۲)",
                                fontWeight = FontWeight.Bold,
                                color = GoldPrimary
                            )
                            Text(
                                text = "از نسرین خانم بخواهید این کد را اسکن کند؛ سپس دکمه «اسکن کد پاسخ» را بزنید.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = TextIvory,
                                textAlign = TextAlign.Center
                            )
                            uiState.qrBitmap?.let { bmp ->
                                Image(
                                    bitmap = bmp.asImageBitmap(),
                                    contentDescription = "کد QR درخواست جفت‌سازی",
                                    modifier = Modifier
                                        .size(250.dp)
                                        .clip(RoundedCornerShape(12.dp))
                                        .background(Color.White)
                                        .padding(8.dp)
                                )
                            }
                            Button(
                                onClick = ::requestCameraAndOpenScanner,
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = GoldPrimary,
                                    contentColor = Color.Black
                                )
                            ) {
                                Icon(Icons.Default.CameraAlt, contentDescription = null)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("گام ۲: اسکن کد QR پاسخ از گوشی مقابل")
                            }
                            OutlinedButton(
                                onClick = onCancelHandshake,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("لغو این درخواست", color = TextMuted)
                            }
                        }
                    }
                }

                is PairingStateSnapshot.AwaitingUserConfirmation -> {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = SurfaceElevated),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            if (snap.responseAcceptQrPayload != null && uiState.qrBitmap != null) {
                                Text(
                                    text = "کد QR پاسخ (به گوشی شروع‌کننده نشان دهید)",
                                    fontWeight = FontWeight.Bold,
                                    color = GoldPrimary
                                )
                                Image(
                                    bitmap = uiState.qrBitmap.asImageBitmap(),
                                    contentDescription = "کد QR پاسخ جفت‌سازی",
                                    modifier = Modifier
                                        .size(240.dp)
                                        .clip(RoundedCornerShape(12.dp))
                                        .background(Color.White)
                                        .padding(8.dp)
                                )
                            }

                            if (snap.previousPeerChanged) {
                                KeyChangeWarningBox(previousDeviceIdHex = snap.previousPeerDeviceIdHex)
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Checkbox(
                                        checked = acknowledgeKeyChange,
                                        onCheckedChange = { acknowledgeKeyChange = it },
                                        colors = CheckboxDefaults.colors(checkedColor = GoldPrimary)
                                    )
                                    Text(
                                        text = "تغییر کلید امنیتی مخاطب را حضوری یا با تماس صوتی مستقیم بررسی و تأیید می‌کنم.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = WarningAmber
                                    )
                                }
                            }

                            Text(
                                text = "کد امنیتی کامل ۶۰ رقمی (مقایسه کامل الزامی است)",
                                fontWeight = FontWeight.Bold,
                                color = GoldPrimary
                            )
                            SafetyNumberBox(safetyNumber = snap.safetyNumber)

                            Text(
                                text = "شناسه تشخیصی عمومی بسته QR (محاسبه از داده‌های علنی؛ رمز یا جایگزین مقایسه ۶۰ رقم کد امنیتی نیست): ${snap.publicHandshakeTranscriptId}",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextMuted,
                                textAlign = TextAlign.Center
                            )

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Checkbox(
                                    checked = fullSafetyNumberChecked,
                                    onCheckedChange = { fullSafetyNumberChecked = it },
                                    colors = CheckboxDefaults.colors(checkedColor = GoldPrimary)
                                )
                                Text(
                                    text = "تمام ۶۰ رقم کد امنیتی بالا (هر ۱۲ گروه پنج‌رقمی) را از طریق یک کانال مستقل و مورد اعتماد (حضوری یا تماس صوتی مستقیم) رقم‌به‌رقم مقایسه کردم و یکسان بودن کامل آن را تأیید می‌کنم.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = TextIvory,
                                    lineHeight = 20.sp
                                )
                            }

                            val canConfirm = fullSafetyNumberChecked &&
                                (!snap.previousPeerChanged || acknowledgeKeyChange)

                            Button(
                                onClick = {
                                    onConfirmPairing(fullSafetyNumberChecked, acknowledgeKeyChange)
                                },
                                enabled = canConfirm,
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = GoldPrimary,
                                    contentColor = Color.Black
                                )
                            ) {
                                Icon(Icons.Default.CheckCircle, contentDescription = null)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("تأیید نهایی ۶۰ رقم و قفل جفت‌سازی روبرو")
                            }
                            OutlinedButton(
                                onClick = onCancelHandshake,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("رد و لغو جفت‌سازی", color = ErrorCrimson)
                            }
                        }
                    }
                }

                is PairingStateSnapshot.PairedActive -> {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = SurfaceElevated),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.CheckCircle, contentDescription = null, tint = SuccessEmerald)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "جفت‌سازی امن فعال و پین‌شده است",
                                    fontWeight = FontWeight.Bold,
                                    color = SuccessEmerald
                                )
                            }
                            Text(
                                text = "شناسه دستگاه مخاطب: ${snap.peerRecord.peerDeviceIdHex}",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    textDirection = TextDirection.Ltr
                                ),
                                color = GoldSoft
                            )
                            Text(
                                text = "هرگونه درخواست جفت‌سازی از دستگاه سوم به‌طور خودکار رد می‌شود.",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextMuted
                            )
                            SafetyNumberBox(safetyNumber = snap.peerRecord.safetyNumber)
                            Button(
                                onClick = onOpenSecurityDetails,
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = GoldPrimary,
                                    contentColor = Color.Black
                                )
                            ) {
                                Text("مدیریت اثرانگشت امنیتی و جفت‌سازی مجدد")
                            }
                        }
                    }
                }
            }

            if (uiState.pairingState !is PairingStateSnapshot.PairedActive &&
                uiState.pairingState !is PairingStateSnapshot.TrustStorageCorrupted
            ) {
                OutlinedButton(
                    onClick = { showManualInput = !showManualInput },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = if (showManualInput) "بستن ورود متنی کد جفت‌سازی" else "ورود دستی رشته QR (در صورت نبود دوربین)",
                        color = TextMuted
                    )
                }
                if (showManualInput) {
                    OutlinedTextField(
                        value = manualPayloadInput,
                        onValueChange = { manualPayloadInput = it },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("رشته dlpair://v1/...") },
                        singleLine = true
                    )
                    Button(
                        onClick = {
                            onQrScanned(manualPayloadInput)
                            manualPayloadInput = ""
                        },
                        enabled = manualPayloadInput.isNotBlank(),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("بررسی و اعتبارسنجی رشته جفت‌سازی")
                    }
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
private fun KeyChangeWarningBox(previousDeviceIdHex: String?) {
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
