package com.duolink.app.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
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
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.duolink.app.pairing.PairingStateSnapshot

@Composable
fun SecurityIdentityScreen(
    uiState: DuoLinkUiState,
    onRotatePreKey: () -> Unit,
    onResetPairing: (regenerateDeviceIdentity: Boolean) -> Unit,
    onOpenPairing: () -> Unit,
    onDismissBanner: () -> Unit,
    onBack: () -> Unit
) {
    var confirmResetDialog by remember { mutableStateOf(false) }
    var regenerateIdentityOnReset by remember { mutableStateOf(false) }

    if (confirmResetDialog) {
        AlertDialog(
            onDismissRequest = { confirmResetDialog = false },
            containerColor = DuoLinkColors.Panel,
            titleContentColor = DuoLinkColors.Danger,
            textContentColor = Color.White,
            title = { Text("بازنشانی امن جفت‌سازی؟", fontWeight = FontWeight.Bold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "با این کار ارتباط جفت‌شده فعلی در این گوشی لغو می‌شود و برای ارتباط مجدد باید فرآیند دوجانبه اسکن QR و تأیید کد امنیتی از نو انجام شود. اثرانگشت قبلی برای هشدار تغییر کلید بایگانی خواهد شد.",
                        fontSize = 13.sp,
                        lineHeight = 22.sp
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = regenerateIdentityOnReset,
                            onCheckedChange = { regenerateIdentityOnReset = it }
                        )
                        Text(
                            text = "حذف و تولید مجدد کلید هویت این گوشی در Android Keystore",
                            fontSize = 12.sp,
                            color = DuoLinkColors.Muted
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        confirmResetDialog = false
                        onResetPairing(regenerateIdentityOnReset)
                        regenerateIdentityOnReset = false
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = DuoLinkColors.Danger,
                        contentColor = Color.White
                    )
                ) {
                    Text("تأیید و بازنشانی", fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmResetDialog = false }) {
                    Text("انصراف", color = DuoLinkColors.Muted)
                }
            }
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DuoLinkColors.Ink)
    ) {
        DuoLinkTopBar(title = "امنیت و هویت دستگاه", onBack = onBack)

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            uiState.banner?.let { banner ->
                FeedbackBannerCard(banner = banner, onDismiss = onDismissBanner)
            }

            // Local device cryptographic identity card
            Card(
                colors = CardDefaults.cardColors(containerColor = DuoLinkColors.Panel),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Security, contentDescription = null, tint = DuoLinkColors.Gold)
                        Spacer(Modifier.width(8.dp))
                        Text("هویت رمزنگاری این دستگاه", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    }
                    Text(
                        text = "محل کلید خصوصی امضا: ${uiState.hardwareDescription}",
                        fontSize = 13.sp,
                        color = if (uiState.isHardwareBacked) DuoLinkColors.Success else DuoLinkColors.Gold
                    )
                    Text(
                        text = "الگوریتم هویت: ECDSA P-256 (غیرقابل استخراج) • تبادل کلید: ECDH P-256 + HKDF-SHA256",
                        fontSize = 12.sp,
                        color = DuoLinkColors.Muted,
                        lineHeight = 20.sp
                    )
                    HorizontalDivider(color = DuoLinkColors.Divider)
                    Text("شناسه یکتای دستگاه (مشتق از کلید عمومی):", fontSize = 12.sp, color = DuoLinkColors.Muted)
                    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                        Text(
                            text = uiState.localDeviceId,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 13.sp,
                            color = DuoLinkColors.Gold
                        )
                    }
                    Text("اثرانگشت ۳۰ رقمی کلید این گوشی:", fontSize = 12.sp, color = DuoLinkColors.Muted)
                    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                        Text(
                            text = uiState.localIdentityDigits,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 14.sp,
                            color = Color.White
                        )
                    }
                    HorizontalDivider(color = DuoLinkColors.Divider)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Key, contentDescription = null, tint = DuoLinkColors.Gold)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = "کلید پیش‌امضاشده فعال (SPK): #${uiState.currentSpkId}",
                            fontSize = 13.sp,
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedButton(
                            onClick = onRotatePreKey,
                            border = BorderStroke(1.dp, DuoLinkColors.Gold)
                        ) {
                            Icon(Icons.Default.Refresh, contentDescription = null, tint = DuoLinkColors.Gold)
                            Spacer(Modifier.width(4.dp))
                            Text("چرخش کلید", color = Color.White, fontSize = 12.sp)
                        }
                    }
                }
            }

            // Peer trust status card
            Card(
                colors = CardDefaults.cardColors(containerColor = DuoLinkColors.Panel),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text("وضعیت همتای جفت‌شده (نسرین خانم)", fontWeight = FontWeight.Bold, fontSize = 16.sp, color = DuoLinkColors.Gold)
                    when (val snap = uiState.pairingSnapshot) {
                        is PairingStateSnapshot.Paired -> {
                            Text(
                                text = "وضعیت: جفت‌شده و تأییدشده دوجانبه",
                                color = DuoLinkColors.Success,
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp
                            )
                            Text("شناسه دستگاه مخاطب:", fontSize = 12.sp, color = DuoLinkColors.Muted)
                            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                                Text(
                                    text = snap.peerDeviceId,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 13.sp,
                                    color = Color.White
                                )
                            }
                            Text("کد امنیتی ۶۰ رقمی مشترک:", fontSize = 12.sp, color = DuoLinkColors.Muted)
                            SafetyNumberBox(safetyNumber = snap.safetyNumber, sessionCode = null)

                            OutlinedButton(
                                onClick = { confirmResetDialog = true },
                                border = BorderStroke(1.dp, DuoLinkColors.Danger),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Icon(Icons.Default.Warning, contentDescription = null, tint = DuoLinkColors.Danger)
                                Spacer(Modifier.width(8.dp))
                                Text("لغو جفت‌سازی و بازنشانی امن", color = DuoLinkColors.Danger)
                            }
                        }
                        else -> {
                            Text(
                                text = "هنوز هیچ دستگاهی به‌طور نهایی تأیید نشده است.",
                                color = DuoLinkColors.Muted,
                                fontSize = 13.sp
                            )
                            Button(
                                onClick = onOpenPairing,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = DuoLinkColors.Gold,
                                    contentColor = DuoLinkColors.Ink
                                ),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("شروع جفت‌سازی امن با QR", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}
