package com.duolink.app.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import com.duolink.app.R
import com.duolink.app.crypto.SafetyFingerprint
import com.duolink.app.pairing.KeyChangeAlert
import com.duolink.app.pairing.PairingStateSnapshot

@Composable
fun PairingScreen(
    uiState: DuoLinkUiState,
    onStartOffer: () -> Unit,
    onScanQrPayload: (rawQr: String, verifyExistingPeer: Boolean) -> Unit,
    onConfirmFingerprint: (acknowledgeKeyChange: Boolean) -> Unit,
    onCancelPending: () -> Unit,
    onNavigateToSecurity: () -> Unit,
    onDismissBanner: () -> Unit,
    onBack: () -> Unit
) {
    var scannerOpen by remember { mutableStateOf(false) }
    var scannerVerifyMode by remember { mutableStateOf(false) }
    var manualEntryExpanded by remember { mutableStateOf(false) }
    var manualInput by remember { mutableStateOf("") }
    var confirmedComparison by remember(uiState.pairingSnapshot) { mutableStateOf(false) }
    var confirmedKeyChange by remember(uiState.pairingSnapshot) { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DuoLinkColors.Ink)
    ) {
        DuoLinkTopBar(title = "جفت‌سازی امن دو گوشی", onBack = onBack)

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            uiState.banner?.let { banner ->
                FeedbackBannerCard(banner = banner, onDismiss = onDismissBanner)
            }

            uiState.blockingKeyChangeAlert?.let { alert ->
                KeyChangeWarningCard(
                    alert = alert,
                    onGoToSecurityReset = onNavigateToSecurity
                )
            }

            if (scannerOpen) {
                CameraQrScannerBox(
                    promptText = if (scannerVerifyMode) {
                        "اسکن کد برای بررسی مطابقت کلید مخاطب"
                    } else {
                        "دوربین را مقابل کد QR گوشی مقابل بگیرید"
                    },
                    onQrDecoded = { raw ->
                        scannerOpen = false
                        onScanQrPayload(raw, scannerVerifyMode)
                    },
                    onClose = { scannerOpen = false }
                )
            }

            when (val snapshot = uiState.pairingSnapshot) {
                is PairingStateSnapshot.Unpaired -> {
                    UnpairedIntroSection(
                        onCreateOffer = {
                            scannerOpen = false
                            onStartOffer()
                        },
                        onOpenScanner = {
                            scannerVerifyMode = false
                            scannerOpen = true
                        }
                    )
                }

                is PairingStateSnapshot.OfferCreated -> {
                    InitiatorOfferSection(
                        qrBitmap = uiState.activeQrBitmap,
                        qrUri = snapshot.offerQrUri,
                        remainingSeconds = uiState.remainingSeconds,
                        onScanAcceptQr = {
                            scannerVerifyMode = false
                            scannerOpen = true
                        },
                        onCopySignedUri = {
                            clipboard.setText(AnnotatedString(snapshot.offerQrUri))
                        },
                        onCancel = onCancelPending
                    )
                }

                is PairingStateSnapshot.AwaitingUserConfirmation -> {
                    MutualConfirmationSection(
                        snapshot = snapshot,
                        acceptQrBitmap = uiState.activeQrBitmap,
                        remainingSeconds = uiState.remainingSeconds,
                        confirmedComparison = confirmedComparison,
                        onConfirmedComparisonChange = { confirmedComparison = it },
                        confirmedKeyChange = confirmedKeyChange,
                        onConfirmedKeyChange = { confirmedKeyChange = it },
                        onCopyAcceptUri = { uri ->
                            clipboard.setText(AnnotatedString(uri))
                        },
                        onConfirmFinal = {
                            onConfirmFingerprint(confirmedKeyChange)
                        },
                        onCancel = onCancelPending
                    )
                }

                is PairingStateSnapshot.Paired -> {
                    AlreadyPairedSection(
                        snapshot = snapshot,
                        onVerifyPeerQr = {
                            scannerVerifyMode = true
                            scannerOpen = true
                        },
                        onOpenSecuritySettings = onNavigateToSecurity
                    )
                }
            }

            // Camera-free / emulator fallback using strictly signed public URI (never private keys)
            HorizontalDivider(color = DuoLinkColors.Divider)
            TextButton(
                onClick = { manualEntryExpanded = !manualEntryExpanded },
                modifier = Modifier.align(Alignment.CenterHorizontally)
            ) {
                Text(
                    text = if (manualEntryExpanded) {
                        "بستن بخش ورود دستی کد امضاشده"
                    } else {
                        "دوربین کار نمی‌کند؟ ورود دستی کد عمومی امضاشده"
                    },
                    color = DuoLinkColors.Muted,
                    fontSize = 12.sp
                )
            }

            if (manualEntryExpanded) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = DuoLinkColors.Panel),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Text(
                            text = "ورود دستی بسته عمومی امضاشده (بدون کلید خصوصی)",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = DuoLinkColors.Gold
                        )
                        Text(
                            text = "این رشته فقط شامل کلید عمومی و امضای دیجیتال موقت است؛ کلیدهای خصوصی در Android Keystore باقی می‌مانند و هرگز صادر نمی‌شوند.",
                            color = DuoLinkColors.Muted,
                            fontSize = 12.sp,
                            lineHeight = 20.sp
                        )
                        CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                            OutlinedTextField(
                                value = manualInput,
                                onValueChange = { manualInput = it },
                                modifier = Modifier.fillMaxWidth(),
                                placeholder = { Text("duolink://pair/v1?p=...") },
                                maxLines = 4
                            )
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            Button(
                                onClick = {
                                    if (manualInput.isNotBlank()) {
                                        val isPaired = uiState.pairingSnapshot is PairingStateSnapshot.Paired
                                        onScanQrPayload(manualInput.trim(), isPaired)
                                        manualInput = ""
                                    }
                                },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = DuoLinkColors.Gold,
                                    contentColor = DuoLinkColors.Ink
                                )
                            ) {
                                Text("بررسی و پردازش کد", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun UnpairedIntroSection(
    onCreateOffer: () -> Unit,
    onOpenScanner: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = DuoLinkColors.Panel),
        shape = RoundedCornerShape(22.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            AsyncImage(
                model = R.drawable.nasrin_portrait,
                contentDescription = "نسرین خانم",
                modifier = Modifier
                    .size(78.dp)
                    .clip(CircleShape)
            )
            Text(
                text = "احراز هویت متقابل با نسرین خانم",
                fontWeight = FontWeight.Bold,
                fontSize = 18.sp,
                textAlign = TextAlign.Center
            )
            Text(
                text = "برای جلوگیری کامل از حمله مرد میانی (MITM)، جفت‌سازی در سه گام کوتاه انجام می‌شود: ۱) نمایش کد درخواست در گوشی اول، ۲) اسکن و نمایش کد پاسخ در گوشی دوم، ۳) مقایسه و تأیید کد امنیتی ۱۲ بخشی روی هر دو گوشی.",
                color = DuoLinkColors.Muted,
                fontSize = 13.sp,
                lineHeight = 22.sp,
                textAlign = TextAlign.Center
            )

            Button(
                onClick = onCreateOffer,
                colors = ButtonDefaults.buttonColors(
                    containerColor = DuoLinkColors.Gold,
                    contentColor = DuoLinkColors.Ink
                ),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.QrCode, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("گوشی اول: ساخت و نمایش کد QR من", fontWeight = FontWeight.Bold)
            }

            OutlinedButton(
                onClick = onOpenScanner,
                border = BorderStroke(1.dp, DuoLinkColors.Gold),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.QrCodeScanner, contentDescription = null, tint = DuoLinkColors.Gold)
                Spacer(Modifier.width(8.dp))
                Text("گوشی دوم: اسکن کد QR گوشی مقابل", color = Color.White, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun InitiatorOfferSection(
    qrBitmap: androidx.compose.ui.graphics.ImageBitmap?,
    qrUri: String,
    remainingSeconds: Long,
    onScanAcceptQr: () -> Unit,
    onCopySignedUri: () -> Unit,
    onCancel: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = DuoLinkColors.Panel),
        shape = RoundedCornerShape(22.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Text(
                text = "گام ۱ از ۲: این کد را با گوشی نسرین خانم اسکن کنید",
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
                color = DuoLinkColors.Gold,
                textAlign = TextAlign.Center
            )
            Text(
                text = "زمان اعتبار باقی‌مانده: ${formatCountdown(remainingSeconds)}",
                color = DuoLinkColors.Muted,
                fontSize = 13.sp
            )

            QrImageFrame(qrBitmap = qrBitmap)

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onCopySignedUri) {
                    Icon(Icons.Default.ContentCopy, contentDescription = null, tint = DuoLinkColors.Gold, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("کپی کد عمومی امضاشده", color = DuoLinkColors.Gold, fontSize = 12.sp)
                }
            }

            Text(
                text = "پس از اسکن در گوشی دوم، یک کد QR پاسخ روی صفحه گوشی دوم ظاهر می‌شود. دکمه زیر را بزنید تا آن را اسکن کنید.",
                color = DuoLinkColors.Muted,
                fontSize = 13.sp,
                lineHeight = 22.sp,
                textAlign = TextAlign.Center
            )

            Button(
                onClick = onScanAcceptQr,
                colors = ButtonDefaults.buttonColors(
                    containerColor = DuoLinkColors.Gold,
                    contentColor = DuoLinkColors.Ink
                ),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.QrCodeScanner, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("گام ۲: اسکن کد پاسخ گوشی مقابل", fontWeight = FontWeight.Bold)
            }

            OutlinedButton(
                onClick = onCancel,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp)
            ) {
                Text("لغو این نشست جفت‌سازی", color = DuoLinkColors.Muted)
            }
        }
    }
}

@Composable
private fun MutualConfirmationSection(
    snapshot: PairingStateSnapshot.AwaitingUserConfirmation,
    acceptQrBitmap: androidx.compose.ui.graphics.ImageBitmap?,
    remainingSeconds: Long,
    confirmedComparison: Boolean,
    onConfirmedComparisonChange: (Boolean) -> Unit,
    confirmedKeyChange: Boolean,
    onConfirmedKeyChange: (Boolean) -> Unit,
    onCopyAcceptUri: (String) -> Unit,
    onConfirmFinal: () -> Unit,
    onCancel: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = DuoLinkColors.Panel),
        shape = RoundedCornerShape(22.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            if (snapshot.role == PairingStateSnapshot.AwaitingUserConfirmation.Role.RESPONDER &&
                snapshot.acceptQrUri != null
            ) {
                Text(
                    text = "ابتدا این کد پاسخ را با گوشی اول اسکن کنید",
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                    color = DuoLinkColors.Gold,
                    textAlign = TextAlign.Center
                )
                Text(
                    text = "اعتبار باقی‌مانده: ${formatCountdown(remainingSeconds)}",
                    color = DuoLinkColors.Muted,
                    fontSize = 12.sp
                )
                QrImageFrame(qrBitmap = acceptQrBitmap)
                TextButton(onClick = { onCopyAcceptUri(snapshot.acceptQrUri) }) {
                    Icon(Icons.Default.ContentCopy, contentDescription = null, tint = DuoLinkColors.Gold, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("کپی کد پاسخ امضاشده", color = DuoLinkColors.Gold, fontSize = 12.sp)
                }
                HorizontalDivider(color = DuoLinkColors.Divider)
            }

            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = null,
                tint = DuoLinkColors.Gold,
                modifier = Modifier.size(36.dp)
            )
            Text(
                text = "مقایسه کد امنیتی (Safety Fingerprint)",
                fontWeight = FontWeight.Bold,
                fontSize = 17.sp,
                textAlign = TextAlign.Center
            )
            Text(
                text = "هر ۱۲ گروه پنج‌رقمی زیر باید در هر دو گوشی دقیقاً یکسان باشند. اگر حتی یک رقم متفاوت است، جفت‌سازی را لغو کنید.",
                color = DuoLinkColors.Muted,
                fontSize = 13.sp,
                lineHeight = 22.sp,
                textAlign = TextAlign.Center
            )

            SafetyNumberBox(
                safetyNumber = snapshot.safetyNumber,
                sessionCode = snapshot.sessionVerificationCode
            )

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Checkbox(
                    checked = confirmedComparison,
                    onCheckedChange = onConfirmedComparisonChange,
                    colors = CheckboxDefaults.colors(checkedColor = DuoLinkColors.Gold)
                )
                Text(
                    text = "کد امنیتی ۱۲ بخشی و کد نشست را حضوری یا تلفنی در هر دو گوشی مقایسه کردم و کاملاً یکسان هستند.",
                    fontSize = 13.sp,
                    lineHeight = 21.sp,
                    modifier = Modifier.weight(1f)
                )
            }

            if (snapshot.keyChangeAlert != null) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(DuoLinkColors.WarningBg, RoundedCornerShape(12.dp))
                        .padding(10.dp)
                ) {
                    Checkbox(
                        checked = confirmedKeyChange,
                        onCheckedChange = onConfirmedKeyChange,
                        colors = CheckboxDefaults.colors(checkedColor = DuoLinkColors.Warning)
                    )
                    Text(
                        text = "می‌دانم کلید امنیتی مخاطب نسبت به جفت‌سازی قبلی تغییر کرده است و هویت گوشی جدید نسرین خانم را حضوری تأیید کرده‌ام.",
                        fontSize = 12.sp,
                        color = DuoLinkColors.Warning,
                        lineHeight = 20.sp,
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            val canConfirm = confirmedComparison && (snapshot.keyChangeAlert == null || confirmedKeyChange)

            Button(
                onClick = onConfirmFinal,
                enabled = canConfirm,
                colors = ButtonDefaults.buttonColors(
                    containerColor = DuoLinkColors.Gold,
                    contentColor = DuoLinkColors.Ink
                ),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.CheckCircle, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("تأیید نهایی هویت در این گوشی", fontWeight = FontWeight.Bold)
            }

            OutlinedButton(
                onClick = onCancel,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("انصراف و لغو", color = DuoLinkColors.Muted)
            }
        }
    }
}

@Composable
private fun AlreadyPairedSection(
    snapshot: PairingStateSnapshot.Paired,
    onVerifyPeerQr: () -> Unit,
    onOpenSecuritySettings: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = DuoLinkColors.Panel),
        shape = RoundedCornerShape(22.dp),
        border = BorderStroke(1.dp, DuoLinkColors.Success),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            AsyncImage(
                model = R.drawable.nasrin_portrait,
                contentDescription = "نسرین خانم",
                modifier = Modifier
                    .size(80.dp)
                    .clip(CircleShape)
            )
            Text(
                text = "جفت‌سازی امن با نسرین خانم فعال است",
                fontWeight = FontWeight.Bold,
                fontSize = 17.sp,
                color = DuoLinkColors.Success,
                textAlign = TextAlign.Center
            )
            Text(
                text = "ظرفیت دو نفره قفل شده است؛ هیچ دستگاه سومی مجاز به پیوستن نیست.",
                color = DuoLinkColors.Muted,
                fontSize = 13.sp,
                textAlign = TextAlign.Center
            )

            SafetyNumberBox(safetyNumber = snapshot.safetyNumber, sessionCode = null)

            OutlinedButton(
                onClick = onVerifyPeerQr,
                border = BorderStroke(1.dp, DuoLinkColors.Gold),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.QrCodeScanner, contentDescription = null, tint = DuoLinkColors.Gold)
                Spacer(Modifier.width(8.dp))
                Text("بررسی مجدد کلید هویت مخاطب با اسکن QR", color = Color.White)
            }

            TextButton(onClick = onOpenSecuritySettings) {
                Text("مدیریت کلیدها یا بازنشانی امن جفت‌سازی", color = DuoLinkColors.Gold)
            }
        }
    }
}

@Composable
fun SafetyNumberBox(
    safetyNumber: String,
    sessionCode: String?
) {
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        Surface(
            color = DuoLinkColors.Ink,
            shape = RoundedCornerShape(14.dp),
            border = BorderStroke(1.dp, DuoLinkColors.Divider),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = SafetyFingerprint.formatMultiline(safetyNumber),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    color = DuoLinkColors.Gold,
                    lineHeight = 26.sp,
                    textAlign = TextAlign.Center
                )
                if (sessionCode != null) {
                    HorizontalDivider(color = DuoLinkColors.Divider)
                    Text(
                        text = "SESSION: $sessionCode",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        color = DuoLinkColors.Muted
                    )
                }
            }
        }
    }
}

@Composable
private fun QrImageFrame(qrBitmap: androidx.compose.ui.graphics.ImageBitmap?) {
    Surface(
        color = Color.White,
        shape = RoundedCornerShape(18.dp),
        modifier = Modifier.size(250.dp)
    ) {
        Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
            if (qrBitmap != null) {
                Image(
                    bitmap = qrBitmap,
                    contentDescription = "کد QR جفت‌سازی امن",
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(10.dp)
                )
            } else {
                Text("در حال تولید QR...", color = Color.Black, fontSize = 13.sp)
            }
        }
    }
}

@Composable
fun KeyChangeWarningCard(
    alert: KeyChangeAlert,
    onGoToSecurityReset: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = DuoLinkColors.DangerBg),
        border = BorderStroke(1.5.dp, DuoLinkColors.Danger),
        shape = RoundedCornerShape(18.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Warning, contentDescription = null, tint = DuoLinkColors.Danger)
                Spacer(Modifier.width(8.dp))
                Text(
                    text = "هشدار امنیتی مهم: تغییر کلید هویت مخاطب!",
                    fontWeight = FontWeight.Bold,
                    color = DuoLinkColors.Danger,
                    fontSize = 15.sp
                )
            }
            Text(
                text = "کلید عمومی اسکن‌شده با کلید ثبت‌شده قبلی مطابقت ندارد. DuoLink به‌طور خودکار کلید قبلی را جایگزین نمی‌کند. اگر نسرین خانم گوشی خود را عوض کرده یا برنامه را دوباره نصب کرده است، ابتدا حضوری اطمینان حاصل کنید و سپس از بخش امنیت، جفت‌سازی را بازنشانی نمایید.",
                fontSize = 13.sp,
                lineHeight = 22.sp,
                color = Color.White
            )
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = "Old: ${alert.previousSafetyNumber.take(23)}...",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = DuoLinkColors.Muted
                    )
                    Text(
                        text = "New: ${alert.newSafetyNumber.take(23)}...",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = DuoLinkColors.Warning
                    )
                }
            }
            OutlinedButton(
                onClick = onGoToSecurityReset,
                border = BorderStroke(1.dp, DuoLinkColors.Danger)
            ) {
                Text("رفتن به بخش امنیت و بازنشانی امن", color = Color.White, fontSize = 12.sp)
            }
        }
    }
}

@Composable
fun FeedbackBannerCard(
    banner: UiBanner,
    onDismiss: () -> Unit
) {
    val (bg, borderCol) = when (banner.tone) {
        BannerTone.SUCCESS -> DuoLinkColors.SuccessBg to DuoLinkColors.Success
        BannerTone.WARNING -> DuoLinkColors.WarningBg to DuoLinkColors.Warning
        BannerTone.ERROR -> DuoLinkColors.DangerBg to DuoLinkColors.Danger
        BannerTone.INFO -> DuoLinkColors.PanelElevated to DuoLinkColors.Gold
    }
    Surface(
        color = bg,
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, borderCol),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.Top
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(banner.title, fontWeight = FontWeight.Bold, fontSize = 14.sp, color = borderCol)
                Text(banner.detail, fontSize = 12.sp, color = Color.White, lineHeight = 20.sp)
            }
            IconButton(onClick = onDismiss, modifier = Modifier.size(28.dp)) {
                Text("×", color = DuoLinkColors.Muted, fontSize = 18.sp)
            }
        }
    }
}

private fun formatCountdown(seconds: Long): String {
    val m = seconds / 60L
    val s = seconds % 60L
    return String.format("%02d:%02d", m, s)
}
