package com.duolink.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Dialpad
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.duolink.app.remote.RemotePairingController

/**
 * Remote pairing by numeric invitation code — "اتصال از راه دور با کد".
 *
 * This file renders ONLY. Every decision about when to say "connected" lives in
 * [RemotePairingController], which is unit-tested without Compose. That split exists because Compose
 * cannot be compiled or tested in the JVM harness: anything decided in this file is effectively
 * untested, so nothing security-relevant is decided here.
 *
 * The screens are RTL-first. Persian text is right-aligned by the layout direction rather than by
 * hard-coded `TextAlign.Right`, so the numbers and the code itself still read left-to-right inside an
 * RTL paragraph - which is what an Iranian user expects when reading a digit string aloud.
 */

/** Entry point offering the two connection methods required by the brief. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectMethodPickerScreen(
    onBack: () -> Unit,
    onChooseQr: () -> Unit,
    onChooseNumeric: () -> Unit
) {
    Scaffold(
        topBar = { RemoteTopBar(title = "اتصال به گوشی دیگر", onBack = onBack) },
        containerColor = ObsidianBackground
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "چگونه می‌خواهید دو گوشی را به هم متصل کنید؟",
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                color = TextIvory
            )
            Text(
                text = "هر دو روش امن هستند و کلیدها فقط روی همین دو گوشی می‌مانند.",
                style = MaterialTheme.typography.bodyMedium,
                color = TextMuted
            )

            MethodCard(
                title = "اتصال با QR",
                description = "گوشی مقابل را روبه‌روی دوربین بگیرید. سریع‌ترین روش، بدون تایپ کردن.",
                icon = { Icon(Icons.Default.QrCode2, contentDescription = null, tint = GoldPrimary) },
                onClick = onChooseQr
            )

            MethodCard(
                title = "اتصال از راه دور با کد",
                description = "وقتی هر دو گوشی در یک مکان نیستند. یک کد ۱۰ رقمی ساخته می‌شود و شما آن را " +
                    "با تماس تلفنی یا پیام برای طرف مقابل می‌فرستید.",
                icon = { Icon(Icons.Default.Dialpad, contentDescription = null, tint = GoldPrimary) },
                onClick = onChooseNumeric
            )

            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "در هر دو روش، پس از اتصال یک «کد امنیتی ۶۰ رقمی» روی هر دو گوشی نمایش داده می‌شود " +
                    "و باید آن را با هم مقایسه و تأیید کنید.",
                style = MaterialTheme.typography.bodySmall,
                color = TextMuted
            )
        }
    }
}

@Composable
internal fun MethodCard(
    title: String,
    description: String,
    icon: @Composable () -> Unit,
    onClick: () -> Unit
) {
    Button(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = SurfaceCharcoal,
            contentColor = TextIvory
        ),
        contentPadding = PaddingValues(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            icon()
            Spacer(modifier = Modifier.width(14.dp))
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(text = title, fontSize = 17.sp, fontWeight = FontWeight.Bold, color = TextIvory)
                Spacer(modifier = Modifier.height(4.dp))
                Text(text = description, style = MaterialTheme.typography.bodySmall, color = TextMuted)
            }
        }
    }
}

/**
 * Owner screen: shows the 10-digit code, a countdown, and the three required actions.
 *
 * The countdown is rendered from [secondsRemaining], which the controller derives from the SERVER's
 * expiry. This screen never computes time itself - a phone with a skewed clock would otherwise display a
 * countdown that disagrees with the server and either cancel a live code or bless a dead one.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NumericCodeOwnerScreen(
    state: RemotePairingController.RemotePairingState,
    onCopyCode: () -> Unit,
    onCancel: () -> Unit,
    onGenerateNew: () -> Unit,
    onDismissFailure: () -> Unit,
    onBack: () -> Unit
) {
    val clipboard = LocalClipboardManager.current
    var showSecurityDetails by remember { mutableStateOf(false) }

    Scaffold(
        topBar = { RemoteTopBar(title = "ایجاد کد اتصال", onBack = onBack) },
        containerColor = ObsidianBackground
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            state.failurePersian?.let { message ->
                FailureCard(
                    message = message,
                    isSecurityAlarming = state.failureIsSecurityAlarming,
                    onDismiss = onDismissFailure
                )
            }

            when {
                state.step == RemotePairingController.Step.COMPLETED -> {
                    SuccessCard(state.safetyNumber)
                }

                state.isExpired || state.step == RemotePairingController.Step.CLOSED -> {
                    RemoteStepCard(step = null) {
                        Icon(
                            Icons.Default.Timer,
                            contentDescription = null,
                            tint = WarningAmber,
                            modifier = Modifier.size(32.dp)
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = "کد منقضی شده است",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextIvory
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "کدهای اتصال فقط ۱۰ دقیقه معتبر هستند و فقط یک بار قابل استفاده‌اند. " +
                                "برای ادامه یک کد تازه بسازید.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMuted
                        )
                        Spacer(modifier = Modifier.height(14.dp))
                        PrimaryButton(label = "ساخت کد جدید", icon = Icons.Default.Refresh, onClick = onGenerateNew)
                    }
                }

                state.codeDisplay != null -> {
                    RemoteStepCard(step = "گام ۱ از ۳") {
                        Text(
                            text = "ایجاد کد اتصال",
                            fontSize = 19.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextIvory
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "کد را برای طرف مقابل بفرستید",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextMuted
                        )
                        Spacer(modifier = Modifier.height(18.dp))

                        // The code itself, direction-isolated so the digits stay readable inside an RTL
                        // paragraph and are not reordered by the bidi algorithm.
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(14.dp))
                                .background(SurfaceElevated)
                                .border(1.dp, GoldMuted, RoundedCornerShape(14.dp))
                                .padding(vertical = 20.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = state.codeDisplay,
                                fontSize = 32.sp,
                                fontWeight = FontWeight.Bold,
                                color = GoldSoft,
                                letterSpacing = 3.sp,
                                textAlign = TextAlign.Center
                            )
                        }

                        Spacer(modifier = Modifier.height(12.dp))
                        CountdownRow(state.secondsRemaining, state.isExpired)

                        Spacer(modifier = Modifier.height(16.dp))
                        PrimaryButton(
                            label = "کپی کد",
                            icon = Icons.Default.ContentCopy,
                            onClick = {
                                state.codeDisplay?.let { clipboard.setText(AnnotatedString(it)) }
                                onCopyCode()
                            }
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        OutlinedButton(
                            onClick = onCancel,
                            modifier = Modifier.fillMaxWidth().height(52.dp),
                            shape = RoundedCornerShape(14.dp)
                        ) {
                            Text("لغو اتصال", color = ErrorCrimson)
                        }
                        Spacer(modifier = Modifier.height(10.dp))
                        TextButton(
                            onClick = onGenerateNew,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Refresh, contentDescription = null, tint = GoldPrimary)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("ساخت کد جدید", color = GoldPrimary)
                        }

                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "کد را فقط به همان شخصی بدهید که می‌خواهید متصل شوید. هر کس این کد را " +
                                "داشته باشد می‌تواند درخواست اتصال بدهد.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMuted
                        )
                    }
                }

                else -> {
                    RemoteStepCard(step = null) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = GoldPrimary,
                                strokeWidth = 2.dp
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = "در حال برقراری ارتباط امن",
                                fontSize = 17.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextIvory
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "منتظر پذیرش کد توسط گوشی مقابل بمانید.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMuted
                        )
                    }
                }
            }

            // Technical terms are hidden behind this section, per the brief. The summary line is
            // deliberately plain so a non-technical user is not alarmed by words like "HMAC".
            if (state.technicalDetail != null || state.safetyNumber != null) {
                TextButton(onClick = { showSecurityDetails = !showSecurityDetails }) {
                    Icon(Icons.Default.Shield, contentDescription = null, tint = GoldMuted, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (showSecurityDetails) "بستن جزئیات امنیتی" else "جزئیات امنیتی",
                        color = GoldMuted
                    )
                }
                if (showSecurityDetails) {
                    TechnicalDetailsCard(state)
                }
            }
        }
    }

}

/** Joiner screen: numeric entry, with the same failure vocabulary as the owner screen. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NumericCodeJoinScreen(
    state: RemotePairingController.RemotePairingState,
    onCodeChanged: (String) -> Unit,
    onSubmit: (String) -> Unit,
    onRetry: () -> Unit,
    onCancel: () -> Unit,
    onBack: () -> Unit
) {
    var typed by remember { mutableStateOf("") }

    Scaffold(
        topBar = { RemoteTopBar(title = "ورود کد دعوت", onBack = onBack) },
        containerColor = ObsidianBackground
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            state.failurePersian?.let { message ->
                FailureCard(
                    message = message,
                    isSecurityAlarming = state.failureIsSecurityAlarming,
                    onDismiss = onRetry
                )
            }

            if (state.step == RemotePairingController.Step.COMPLETED) {
                SuccessCard(state.safetyNumber)
                return@Column
            }

            if (state.step == RemotePairingController.Step.CLOSED) {
                RemoteStepCard(step = null) {
                    Icon(Icons.Default.ErrorOutline, contentDescription = null, tint = WarningAmber, modifier = Modifier.size(30.dp))
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = "این دعوت دیگر قابل استفاده نیست",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextIvory
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "ممکن است کد منقضی شده باشد یا پیش‌تر استفاده شده باشد. از طرف مقابل بخواهید " +
                            "یک کد تازه بسازد.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMuted
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                    PrimaryButton(label = "تلاش دوباره", icon = Icons.Default.Refresh, onClick = onRetry)
                }
                return@Column
            }

            if (state.step == RemotePairingController.Step.JOINER_CONNECTING ||
                state.step == RemotePairingController.Step.HANDSHAKE_IN_PROGRESS
            ) {
                RemoteStepCard(step = "گام ۲ از ۳") {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = GoldPrimary,
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(
                            text = "در حال برقراری ارتباط امن",
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextIvory
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "این مرحله چند ثانیه طول می‌کشد. برنامه را نبندید.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMuted
                    )
                }
                return@Column
            }

            RemoteStepCard(step = "گام ۱ از ۳") {
                Text(
                    text = "ورود کد دعوت",
                    fontSize = 19.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextIvory
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "۱۰ رقم کدی را که طرف مقابل برایتان فرستاده وارد کنید.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextMuted
                )
                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = typed,
                    onValueChange = { input ->
                        // Accept digits, spaces, dots and dashes only; cap at a sane length so a paste of
                        // a whole message cannot produce a confusing field. The parser is lenient about
                        // separators but strict about the digit count, so nothing is silently truncated.
                        val filtered = input.filter { it.isDigit() || it == '-' || it == ' ' || it == '.' }
                        if (filtered.length <= 20) {
                            typed = filtered
                            onCodeChanged(filtered)
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("کد دعوت") },
                    placeholder = { Text("مثلاً 482-913-7462") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    textStyle = MaterialTheme.typography.headlineSmall.copy(
                        letterSpacing = 2.sp,
                        textAlign = TextAlign.Center
                    )
                )

                Spacer(modifier = Modifier.height(16.dp))
                PrimaryButton(
                    label = "اتصال",
                    icon = Icons.Default.Lock,
                    enabled = typed.count { it.isDigit() } == 10,
                    onClick = { onSubmit(typed) }
                )
                Spacer(modifier = Modifier.height(10.dp))
                OutlinedButton(
                    onClick = onCancel,
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Text("انصراف", color = TextMuted)
                }
            }

            Text(
                text = "پس از اتصال، یک کد امنیتی ۶۰ رقمی روی هر دو گوشی نمایش داده می‌شود؛ باید آن را با " +
                    "طرف مقابل مقایسه و تأیید کنید.",
                style = MaterialTheme.typography.bodySmall,
                color = TextMuted
            )
        }
    }
}

/**
 * The mutual-approval screen shown on BOTH phones.
 *
 * It is deliberately impossible to reach [RemotePairingController.Step.COMPLETED] from here without the
 * full 60-digit comparison: the confirm button is disabled until the checkbox is ticked, and the
 * checkbox's own label states that all 60 digits must match. The controller independently refuses a
 * `false` value, so a UI bug cannot bypass it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemoteApprovalScreen(
    state: RemotePairingController.RemotePairingState,
    onApprove: (Boolean, Boolean) -> Unit,
    onCancel: () -> Unit,
    onBack: () -> Unit
) {
    var compared by remember { mutableStateOf(false) }
    var keyChangeAcknowledged by remember { mutableStateOf(false) }
    var showConfirmDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = { RemoteTopBar(title = "تأیید هویت دستگاه مقابل", onBack = onBack) },
        containerColor = ObsidianBackground
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            state.failurePersian?.let { message ->
                FailureCard(
                    message = message,
                    isSecurityAlarming = state.failureIsSecurityAlarming,
                    onDismiss = {}
                )
            }

            if (state.step == RemotePairingController.Step.COMPLETED) {
                SuccessCard(state.safetyNumber)
                return@Column
            }

            RemoteStepCard(step = "گام ۳ از ۳") {
                Text(
                    text = "تأیید هویت دستگاه مقابل",
                    fontSize = 19.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextIvory
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "این ۶۰ رقم را با طرف مقابل مقایسه کنید. هر دو گوشی باید دقیقاً همین ارقام را " +
                        "نشان دهند. اگر حتی یک رقم متفاوت بود، اتصال را لغو کنید.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextMuted
                )
                Spacer(modifier = Modifier.height(16.dp))

                state.safetyNumber?.let { SafetyNumberBox(it) }
                    ?: Text(
                        text = "کد امنیتی هنوز آماده نیست…",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMuted
                    )

                if (state.previousPeerChanged) {
                    Spacer(modifier = Modifier.height(12.dp))
                    // Reuse the QR flow's warning so both methods say exactly the same thing. A divergence
                    // here would be a security-UX bug: one flow subtly understating a key change is worse
                    // than either flow wording it badly.
                    KeyChangeWarningBox(state.previousPeerDeviceIdHex)
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Checkbox(
                    checked = compared,
                    onCheckedChange = { compared = it },
                    colors = CheckboxDefaults.colors(checkedColor = GoldPrimary)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "هر ۶۰ رقم را با طرف مقابل مقایسه کردم و کاملاً یکسان بود.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextIvory
                )
            }

            if (state.previousPeerChanged) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Checkbox(
                        checked = keyChangeAcknowledged,
                        onCheckedChange = { keyChangeAcknowledged = it },
                        colors = CheckboxDefaults.colors(checkedColor = WarningAmber)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "می‌دانم که کلید هویت دستگاه مقابل تغییر کرده است و با آن موافقم.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextIvory
                    )
                }
            }

            PrimaryButton(
                label = "تأیید و اتصال",
                icon = Icons.Default.CheckCircle,
                enabled = compared && (!state.previousPeerChanged || keyChangeAcknowledged),
                onClick = { showConfirmDialog = true }
            )

            OutlinedButton(
                onClick = onCancel,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                shape = RoundedCornerShape(14.dp)
            ) {
                Text("لغو اتصال", color = ErrorCrimson)
            }
        }
    }

    if (showConfirmDialog) {
        AlertDialog(
            onDismissRequest = { showConfirmDialog = false },
            title = { Text("تأیید نهایی") },
            text = {
                Text(
                    "با تأیید، این دو گوشی به هم متصل می‌شوند و می‌توانید پیام امن رد و بدل کنید. " +
                        "این کار فقط با موافقت هر دو طرف انجام می‌شود."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showConfirmDialog = false
                    onApprove(compared, keyChangeAcknowledged)
                }) { Text("تأیید می‌کنم", color = GoldPrimary) }
            },
            dismissButton = {
                TextButton(onClick = { showConfirmDialog = false }) { Text("انصراف", color = TextMuted) }
            },
            containerColor = SurfaceElevated
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Shared small components
// ---------------------------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun RemoteTopBar(title: String, onBack: () -> Unit) {
    TopAppBar(
        title = { Text(title) },
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
}

@Composable
internal fun PrimaryButton(
    label: String,
    icon: ImageVector,
    enabled: Boolean = true,
    onClick: () -> Unit
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().height(54.dp),
        shape = RoundedCornerShape(14.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = GoldPrimary,
            contentColor = Color.Black,
            disabledContainerColor = SurfaceElevated,
            disabledContentColor = TextMuted
        )
    ) {
        Icon(icon, contentDescription = null)
        Spacer(modifier = Modifier.width(8.dp))
        Text(label, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
internal fun CountdownRow(secondsRemaining: Long, isExpired: Boolean) {
    val minutes = secondsRemaining / 60
    val seconds = secondsRemaining % 60
    val label = when {
        isExpired -> "کد منقضی شده است"
        else -> "اعتبار کد: %d:%02d".format(minutes, seconds)
    }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Default.Timer,
            contentDescription = null,
            tint = if (isExpired) ErrorCrimson else if (secondsRemaining <= 60) WarningAmber else TextMuted,
            modifier = Modifier.size(18.dp)
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = if (isExpired) ErrorCrimson else if (secondsRemaining <= 60) WarningAmber else TextMuted
        )
    }
}

@Composable
internal fun FailureCard(message: String, isSecurityAlarming: Boolean, onDismiss: () -> Unit) {
    val accent = if (isSecurityAlarming) ErrorCrimson else WarningAmber
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(if (isSecurityAlarming) DuoLinkColors.DangerBg else DuoLinkColors.WarningBg)
            .border(1.dp, accent.copy(alpha = 0.4f), RoundedCornerShape(14.dp))
            .padding(14.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                if (isSecurityAlarming) Icons.Default.Shield else Icons.Default.ErrorOutline,
                contentDescription = null,
                tint = accent,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                color = TextIvory,
                modifier = Modifier.weight(1f)
            )
        }
        TextButton(onClick = onDismiss, modifier = Modifier.align(Alignment.End)) {
            Text("بستن", color = accent)
        }
    }
}

@Composable
internal fun SuccessCard(safetyNumber: String?) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(DuoLinkColors.SuccessBg)
            .border(1.dp, SuccessEmerald.copy(alpha = 0.5f), RoundedCornerShape(16.dp))
            .padding(18.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            Icons.Default.CheckCircle,
            contentDescription = null,
            tint = SuccessEmerald,
            modifier = Modifier.size(44.dp)
        )
        Spacer(modifier = Modifier.height(10.dp))
        Text(
            text = "اتصال با موفقیت برقرار شد",
            fontSize = 19.sp,
            fontWeight = FontWeight.Bold,
            color = TextIvory
        )
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = "از این پس پیام‌های شما رمزنگاری‌شده و خصوصی هستند.",
            style = MaterialTheme.typography.bodySmall,
            color = TextMuted,
            textAlign = TextAlign.Center
        )
        if (safetyNumber != null) {
            Spacer(modifier = Modifier.height(14.dp))
            Text(
                text = "کد امنیتی مشترک شما (برای مقایسه‌های بعدی):",
                style = MaterialTheme.typography.bodySmall,
                color = TextMuted
            )
            Spacer(modifier = Modifier.height(6.dp))
            SafetyNumberBox(safetyNumber)
        }
    }
}

@Composable
private fun TechnicalDetailsCard(state: RemotePairingController.RemotePairingState) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(SurfaceCharcoal)
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text(
            text = "این بخش برای کاربران فنی است و برای استفاده روزمره لازم نیست.",
            style = MaterialTheme.typography.bodySmall,
            color = TextMuted
        )
        state.technicalDetail?.let {
            Text(text = "وضعیت: $it", style = MaterialTheme.typography.bodySmall, color = TextMuted)
        }
        state.peerDeviceIdHex?.let {
            Text(text = "شناسه دستگاه مقابل: $it", style = MaterialTheme.typography.bodySmall, color = TextMuted)
        }
        Text(
            text = "سرور واسط فقط کلیدهای عمومی و رمزنگاری‌شده را می‌بیند؛ کلید خصوصی و متن پیام هرگز " +
                "از گوشی خارج نمی‌شود.",
            style = MaterialTheme.typography.bodySmall,
            color = TextMuted
        )
    }
}

@Composable
internal fun RemoteStepCard(step: String?, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(SurfaceCharcoal)
            .padding(18.dp)
    ) {
        step?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.labelMedium,
                color = GoldMuted
            )
            Spacer(modifier = Modifier.height(8.dp))
        }
        content()
    }
}

/**
 * Role chooser for the numeric flow: does THIS phone create the code, or enter one?
 *
 * Kept separate from [ConnectMethodPickerScreen] because they answer different questions. That screen
 * answers "QR or code?"; this one answers "creator or joiner?". Merging them into a single four-way choice
 * would make the common path (one obvious action) harder to find.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemoteRoleChooserScreen(
    onBack: () -> Unit,
    onGenerate: () -> Unit,
    onEnterCode: () -> Unit
) {
    Scaffold(
        topBar = { RemoteTopBar(title = "اتصال از راه دور با کد", onBack = onBack) },
        containerColor = ObsidianBackground
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "کدام گوشی کد را می‌سازد؟",
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                color = TextIvory
            )
            Text(
                text = "یکی از دو گوشی کد ۱۰ رقمی می‌سازد، گوشی دیگر همان کد را وارد می‌کند. " +
                    "فرقی نمی‌کند کدام گوشی کد را بسازد.",
                style = MaterialTheme.typography.bodyMedium,
                color = TextMuted
            )

            MethodCard(
                title = "ایجاد کد اتصال",
                description = "یک کد ۱۰ رقمی در این گوشی ساخته می‌شود و شما آن را برای طرف مقابل می‌فرستید.",
                icon = { Icon(Icons.Default.Dialpad, contentDescription = null, tint = GoldPrimary) },
                onClick = onGenerate
            )

            MethodCard(
                title = "ورود کد دعوت",
                description = "طرف مقابل یک کد برای شما فرستاده است؛ آن را اینجا وارد کنید.",
                icon = { Icon(Icons.Default.Lock, contentDescription = null, tint = GoldPrimary) },
                onClick = onEnterCode
            )

            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "این کد فقط ۱۰ دقیقه و فقط یک بار قابل استفاده است. هرگز آن را در شبکه‌های اجتماعی " +
                    "عمومی یا گروه‌های چت منتشر نکنید.",
                style = MaterialTheme.typography.bodySmall,
                color = TextMuted
            )
        }
    }
}
