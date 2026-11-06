package com.duolink.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.LockReset
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.AlertDialog
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import com.duolink.app.crypto.SingleKeyProtectionStatus
import com.duolink.app.pairing.PairingStateSnapshot

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityIdentityScreen(
    uiState: DuoLinkUiState,
    onBack: () -> Unit,
    onUnpairKeepIdentity: () -> Unit,
    onUnpairRotateIdentity: () -> Unit,
    onRecoverCorruptedStorage: (Boolean) -> Unit,
    onGoToPairing: () -> Unit
) {
    var confirmDialogMode by remember { mutableStateOf<UnpairMode?>(null) }
    var confirmDestructiveRecovery by remember(uiState.pairingState) { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("کد امنیتی و بررسی کلیدها") },
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
            if (uiState.pairingState is PairingStateSnapshot.TrustStorageCorrupted) {
                CorruptedStorageRecoveryCard(
                    component = uiState.pairingState.component,
                    technicalReason = uiState.pairingState.technicalReason,
                    confirmChecked = confirmDestructiveRecovery,
                    onConfirmCheckedChange = { confirmDestructiveRecovery = it },
                    onExecuteRecovery = { onRecoverCorruptedStorage(confirmDestructiveRecovery) }
                )
            }

            // Separate per-key protection card
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = SurfaceCharcoal),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Key, contentDescription = null, tint = GoldPrimary)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "وضعیت تفکیکی حفاظت کلیدهای این دستگاه",
                            fontWeight = FontWeight.Bold,
                            color = TextIvory
                        )
                    }
                    Text(
                        text = if (uiState.localDeviceIdHex.isNotEmpty()) {
                            "شناسه عمومی دستگاه (Device ID):\n${uiState.localDeviceIdHex}"
                        } else {
                            "شناسه عمومی دستگاه: غیرفعال تا اجرای بازیابی امن"
                        },
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            textDirection = TextDirection.Ltr
                        ),
                        color = GoldSoft
                    )
                    Text(
                        text = "نسخه پیش‌کلید امضاشده فعال (SPK): #${uiState.localSpkId}",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMuted
                    )

                    uiState.keyProtectionReport?.let { report ->
                        KeyProtectionStatusRow(report.identitySigningKey)
                        KeyProtectionStatusRow(report.storageWrappingKey)
                        KeyProtectionStatusRow(report.activeSignedPreKey)
                    }
                }
            }

            val paired = uiState.pairingState as? PairingStateSnapshot.PairedActive
            if (paired != null) {
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
                            Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = SuccessEmerald)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "اثرانگشت امنیتی ۶۰ رقمی با نسرین خانم",
                                fontWeight = FontWeight.Bold,
                                color = GoldPrimary
                            )
                        }
                        Text(
                            text = "شناسه دستگاه مخاطب:\n${paired.peerRecord.peerDeviceIdHex}",
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace,
                                textDirection = TextDirection.Ltr
                            ),
                            color = GoldSoft
                        )
                        SafetyNumberBox(safetyNumber = paired.peerRecord.safetyNumber)
                        Text(
                            text = "اگر تمام ۶۰ رقم کد بالا روی هر دو گوشی دقیقاً یکسان باشد، کانال در برابر حمله مرد میانی (MITM) تأیید شده است.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMuted
                        )
                    }
                }

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = SurfaceCharcoal),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.LockReset, contentDescription = null, tint = WarningAmber)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("جفت‌سازی مجدد امن", fontWeight = FontWeight.Bold, color = WarningAmber)
                        }
                        Text(
                            text = "در صورت تعویض گوشی مخاطب یا نیاز به جفت‌سازی مجدد، ابتدا جفت‌سازی فعلی را لغو کنید تا هویت قبلی بایگانی شده و امکان تشخیص تغییر کلید حفظ شود.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextIvory
                        )
                        OutlinedButton(
                            onClick = { confirmDialogMode = UnpairMode.KEEP_IDENTITY },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("لغو جفت‌سازی فعلی (با حفظ کلید هویت این گوشی)", color = GoldPrimary)
                        }
                        OutlinedButton(
                            onClick = { confirmDialogMode = UnpairMode.ROTATE_IDENTITY },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("لغو جفت‌سازی + ساخت کلید هویت کاملاً جدید", color = ErrorCrimson)
                        }
                    }
                }
            } else if (uiState.pairingState !is PairingStateSnapshot.TrustStorageCorrupted) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = SurfaceElevated),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Text(
                            text = "هنوز هیچ مخاطبی جفت نشده است",
                            fontWeight = FontWeight.Bold,
                            color = WarningAmber
                        )
                        Text(
                            text = "برای برقراری ارتباط خصوصی دو نفره، ابتدا از صفحه جفت‌سازی کد QR را تبادل و هر ۶۰ رقم کد امنیتی را از طریق کانال مستقل مقایسه و تأیید کنید.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextIvory
                        )
                        Button(
                            onClick = onGoToPairing,
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = GoldPrimary)
                        ) {
                            Text("رفتن به صفحه جفت‌سازی امن")
                        }
                    }
                }
            }
        }
    }

    confirmDialogMode?.let { mode ->
        AlertDialog(
            onDismissRequest = { confirmDialogMode = null },
            title = { Text("تأیید لغو جفت‌سازی") },
            text = {
                Text(
                    if (mode == UnpairMode.ROTATE_IDENTITY) {
                        "آیا مطمئن هستید؟ ارتباط با مخاطب فعلی قطع شده و کلید هویت این دستگاه بازتولید می‌شود (کد امنیتی ۶۰ رقمی در جفت‌سازی بعدی تغییر خواهد کرد)."
                    } else {
                        "آیا مطمئن هستید؟ جفت‌سازی فعلی پاک شده و دستگاه آماده جفت‌سازی مجدد امن می‌شود."
                    }
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val chosen = mode
                        confirmDialogMode = null
                        if (chosen == UnpairMode.ROTATE_IDENTITY) {
                            onUnpairRotateIdentity()
                        } else {
                            onUnpairKeepIdentity()
                        }
                        onGoToPairing()
                    }
                ) {
                    Text("بله، انجام شود", color = ErrorCrimson)
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmDialogMode = null }) {
                    Text("انصراف", color = GoldPrimary)
                }
            }
        )
    }
}

@Composable
private fun KeyProtectionStatusRow(status: SingleKeyProtectionStatus) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = "${status.keyRolePersian} — ${status.algorithm}",
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
            color = GoldPrimary
        )
        Text(
            text = status.persianDescription,
            style = MaterialTheme.typography.bodySmall,
            color = TextIvory
        )
        Spacer(modifier = Modifier.height(4.dp))
    }
}

private enum class UnpairMode {
    KEEP_IDENTITY,
    ROTATE_IDENTITY
}
