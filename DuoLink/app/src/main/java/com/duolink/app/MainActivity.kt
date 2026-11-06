package com.duolink.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ChevronRight
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import coil.compose.AsyncImage
import com.duolink.app.pairing.PairingStateSnapshot
import com.duolink.app.ui.DuoLinkColors
import com.duolink.app.ui.DuoLinkTopBar
import com.duolink.app.ui.DuoLinkUiState
import com.duolink.app.ui.DuoLinkViewModel
import com.duolink.app.ui.PairingScreen
import com.duolink.app.ui.SafetyNumberBox
import com.duolink.app.ui.SecurityIdentityScreen

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Global Privacy Mode enabled unconditionally by default across the entire application:
        // Discourages screenshots, Recents screen thumbnails, and standard screen recording.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        setContent {
            DuoLinkApp()
        }
    }
}

@Composable
fun DuoLinkApp(vm: DuoLinkViewModel = viewModel()) {
    val nav = rememberNavController()
    val uiState by vm.uiState.collectAsState()

    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
        MaterialTheme(
            colorScheme = darkColorScheme(
                primary = DuoLinkColors.Gold,
                background = DuoLinkColors.Ink,
                surface = DuoLinkColors.Panel,
                onBackground = Color.White,
                onSurface = Color.White
            )
        ) {
            NavHost(navController = nav, startDestination = "home") {
                composable("home") {
                    HomeScreen(
                        uiState = uiState,
                        onOpenChat = { nav.navigate("chat") },
                        onOpenProfile = { nav.navigate("profile") },
                        onOpenPairing = { nav.navigate("pairing") },
                        onOpenSecurity = { nav.navigate("security") },
                        onOpenSettings = { nav.navigate("settings") },
                        onOpenAbout = { nav.navigate("about") }
                    )
                }
                composable("pairing") {
                    PairingScreen(
                        uiState = uiState,
                        onStartOffer = vm::startInitiatorOffer,
                        onScanQrPayload = vm::processScannedQr,
                        onConfirmFingerprint = vm::confirmSafetyFingerprint,
                        onCancelPending = vm::cancelPendingPairing,
                        onNavigateToSecurity = { nav.navigate("security") },
                        onDismissBanner = vm::dismissBanner,
                        onBack = { nav.popBackStack() }
                    )
                }
                composable("security") {
                    SecurityIdentityScreen(
                        uiState = uiState,
                        onRotatePreKey = vm::rotateLocalSignedPreKey,
                        onResetPairing = vm::resetPairingForSecureRePair,
                        onOpenPairing = { nav.navigate("pairing") },
                        onDismissBanner = vm::dismissBanner,
                        onBack = { nav.popBackStack() }
                    )
                }
                composable("profile") {
                    NasrinProfileScreen(
                        uiState = uiState,
                        onOpenPairing = { nav.navigate("pairing") },
                        onOpenChat = { nav.navigate("chat") },
                        onBack = { nav.popBackStack() }
                    )
                }
                composable("chat") {
                    ChatScreen(
                        uiState = uiState,
                        onOpenPairing = { nav.navigate("pairing") },
                        onOpenProfile = { nav.navigate("profile") },
                        onBack = { nav.popBackStack() }
                    )
                }
                composable("about") {
                    AboutScreen(onBack = { nav.popBackStack() })
                }
                composable("settings") {
                    SettingsScreen(
                        uiState = uiState,
                        onOpenSecurity = { nav.navigate("security") },
                        onBack = { nav.popBackStack() }
                    )
                }
            }
        }
    }
}

@Composable
fun HomeScreen(
    uiState: DuoLinkUiState,
    onOpenChat: () -> Unit,
    onOpenProfile: () -> Unit,
    onOpenPairing: () -> Unit,
    onOpenSecurity: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenAbout: () -> Unit
) {
    val isPaired = uiState.pairingSnapshot is PairingStateSnapshot.Paired

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DuoLinkColors.Ink)
    ) {
        DuoLinkTopBar(title = "DuoLink", onBack = null)

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "ارتباط خصوصی، برای دو نفر",
                color = DuoLinkColors.Muted,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Center
            )

            // Dedicated Nasrin contact card
            Card(
                onClick = onOpenChat,
                colors = CardDefaults.cardColors(containerColor = DuoLinkColors.Panel),
                shape = RoundedCornerShape(24.dp),
                border = if (isPaired) BorderStroke(1.dp, DuoLinkColors.GoldDim) else null,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    AsyncImage(
                        model = R.drawable.nasrin_portrait,
                        contentDescription = "عکس مخاطب نسرین خانم",
                        modifier = Modifier
                            .size(76.dp)
                            .clip(CircleShape)
                            .clickable(onClick = onOpenProfile)
                    )
                    Spacer(Modifier.width(16.dp))
                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("نسرین خانم", fontSize = 20.sp, fontWeight = FontWeight.Bold)
                        Text(
                            text = if (isPaired) {
                                "هویت دستگاه با QR تأیید شده است"
                            } else {
                                "جفت‌سازی نشده — برای جفت‌سازی امن لمس کنید"
                            },
                            color = if (isPaired) DuoLinkColors.Success else DuoLinkColors.Gold,
                            fontSize = 12.sp
                        )
                    }
                    Icon(Icons.AutoMirrored.Filled.ChevronRight, contentDescription = null, tint = DuoLinkColors.Gold)
                }
            }

            if (!isPaired) {
                Button(
                    onClick = onOpenPairing,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = DuoLinkColors.Gold,
                        contentColor = DuoLinkColors.Ink
                    ),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.QrCodeScanner, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("جفت‌سازی امن دو گوشی با کد QR", fontWeight = FontWeight.Bold)
                }
            }

            NavigationTile(
                icon = Icons.Default.QrCodeScanner,
                label = if (isPaired) "وضعیت جفت‌سازی و کد امنیتی" else "جفت‌سازی امن دو گوشی (QR)",
                onClick = onOpenPairing
            )
            NavigationTile(
                icon = Icons.Default.Security,
                label = "امنیت و هویت دستگاه",
                onClick = onOpenSecurity
            )
            NavigationTile(
                icon = Icons.Default.Settings,
                label = "تنظیمات و حریم خصوصی سراسری",
                onClick = onOpenSettings
            )
            NavigationTile(
                icon = Icons.Default.Info,
                label = "درباره برنامه",
                onClick = onOpenAbout
            )

            Spacer(Modifier.height(8.dp))
            Text(
                text = "DuoLink • نسخه 0.2.0 (فاز جفت‌سازی امن)",
                color = DuoLinkColors.Muted,
                fontSize = 12.sp,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
private fun NavigationTile(icon: ImageVector, label: String, onClick: () -> Unit) {
    Card(
        onClick = onClick,
        colors = CardDefaults.cardColors(containerColor = DuoLinkColors.Panel),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(17.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(icon, contentDescription = null, tint = DuoLinkColors.Gold)
            Spacer(Modifier.width(12.dp))
            Text(label, modifier = Modifier.weight(1f))
            Icon(Icons.AutoMirrored.Filled.ChevronRight, contentDescription = null, tint = DuoLinkColors.Muted)
        }
    }
}

@Composable
fun NasrinProfileScreen(
    uiState: DuoLinkUiState,
    onOpenPairing: () -> Unit,
    onOpenChat: () -> Unit,
    onBack: () -> Unit
) {
    val paired = uiState.pairingSnapshot as? PairingStateSnapshot.Paired

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DuoLinkColors.Ink)
    ) {
        DuoLinkTopBar(title = "پروفایل مخاطب", onBack = onBack)

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            AsyncImage(
                model = R.drawable.nasrin_portrait,
                contentDescription = "نسرین خانم",
                modifier = Modifier
                    .size(136.dp)
                    .clip(CircleShape)
            )
            Text("نسرین خانم", fontSize = 24.sp, fontWeight = FontWeight.Bold)
            Text("مخاطب انحصاری DuoLink", color = DuoLinkColors.Gold, fontSize = 13.sp)

            Card(
                colors = CardDefaults.cardColors(containerColor = DuoLinkColors.Panel),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    if (paired != null) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = DuoLinkColors.Success)
                            Spacer(Modifier.width(8.dp))
                            Text("هویت کلید عمومی تأیید و قفل شده است", color = DuoLinkColors.Success, fontWeight = FontWeight.Bold)
                        }
                        SafetyNumberBox(safetyNumber = paired.safetyNumber, sessionCode = null)
                    } else {
                        Text(
                            text = "این مخاطب هنوز با کد QR جفت‌سازی نشده است.",
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
                            Text("انجام جفت‌سازی امن دو گوشی", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            OutlinedButton(
                onClick = onOpenChat,
                border = BorderStroke(1.dp, DuoLinkColors.Gold),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("مشاهده صفحه گفتگو", color = Color.White)
            }
        }
    }
}

@Composable
fun AboutScreen(onBack: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DuoLinkColors.Ink)
    ) {
        DuoLinkTopBar(title = "درباره برنامه", onBack = onBack)
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            AsyncImage(
                model = R.drawable.duolink_logo,
                contentDescription = "لوگوی DuoLink",
                modifier = Modifier
                    .size(132.dp)
                    .clip(CircleShape)
            )
            Spacer(Modifier.height(22.dp))
            Text("DuoLink", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = DuoLinkColors.Gold)
            Spacer(Modifier.height(26.dp))
            // Exact required Persian dedication copy — preserved verbatim
            Text(
                text = "نسرین خانم",
                fontSize = 25.sp,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            )
            Spacer(Modifier.height(10.dp))
            Text(
                text = "این برنامه مخصوص شما ساخته شده است.",
                fontSize = 18.sp,
                textAlign = TextAlign.Center,
                lineHeight = 30.sp
            )
            Spacer(Modifier.height(18.dp))
            Text(
                text = "یک ارتباط خصوصی، برای دو نفر",
                color = DuoLinkColors.Muted,
                fontSize = 14.sp
            )
            Spacer(Modifier.height(32.dp))
            Text(
                text = "نسخه 0.2.0 • مرحله جفت‌سازی امن پیاده‌سازی شد",
                color = DuoLinkColors.Muted,
                fontSize = 12.sp,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
fun ChatScreen(
    uiState: DuoLinkUiState,
    onOpenPairing: () -> Unit,
    onOpenProfile: () -> Unit,
    onBack: () -> Unit
) {
    val isPaired = uiState.pairingSnapshot is PairingStateSnapshot.Paired

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DuoLinkColors.Ink)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "بازگشت")
            }
            AsyncImage(
                model = R.drawable.nasrin_portrait,
                contentDescription = "نسرین خانم",
                modifier = Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .clickable(onClick = onOpenProfile)
            )
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("نسرین خانم", fontWeight = FontWeight.Bold)
                Text(
                    text = if (isPaired) "جفت‌شده • انتقال شبکه در مایل‌استون ۳" else "جفت‌سازی‌نشده",
                    color = if (isPaired) DuoLinkColors.Gold else DuoLinkColors.Muted,
                    fontSize = 11.sp
                )
            }
            IconButton(onClick = {}, enabled = false) {
                Icon(Icons.Default.Call, contentDescription = "تماس صوتی (غیرفعال تا مایل‌استون ۵)", tint = DuoLinkColors.Divider)
            }
            IconButton(onClick = {}, enabled = false) {
                Icon(Icons.Default.Videocam, contentDescription = "تماس تصویری (غیرفعال تا مایل‌استون ۶)", tint = DuoLinkColors.Divider)
            }
        }
        HorizontalDivider(color = DuoLinkColors.Divider)

        // Honest Milestone 2 status card — no simulated or fake delivered messages
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Surface(
                color = DuoLinkColors.Panel,
                shape = RoundedCornerShape(20.dp),
                border = BorderStroke(1.dp, DuoLinkColors.Divider),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Lock,
                        contentDescription = null,
                        tint = DuoLinkColors.Gold,
                        modifier = Modifier.size(34.dp)
                    )
                    if (!isPaired) {
                        Text(
                            text = "ابتدا دو گوشی را با کد QR جفت‌سازی کنید",
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp,
                            textAlign = TextAlign.Center
                        )
                        Text(
                            text = "پیش از هرگونه تبادل پیام، کلیدهای عمومی دو گوشی باید با کد QR مبادله و کد امنیتی در هر دو دستگاه تأیید شود.",
                            color = DuoLinkColors.Muted,
                            fontSize = 13.sp,
                            lineHeight = 22.sp,
                            textAlign = TextAlign.Center
                        )
                        Button(
                            onClick = onOpenPairing,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = DuoLinkColors.Gold,
                                contentColor = DuoLinkColors.Ink
                            )
                        ) {
                            Text("رفتن به صفحه جفت‌سازی امن", fontWeight = FontWeight.Bold)
                        }
                    } else {
                        Text(
                            text = "جفت‌سازی رمزنگاری و کلید ریشه مشترک آماده است",
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp,
                            color = DuoLinkColors.Success,
                            textAlign = TextAlign.Center
                        )
                        Text(
                            text = "در نسخه فعلی (مایل‌استون ۲)، فقط هویت امن و جفت‌سازی دوطرفه QR فعال شده است. ارسال واقعی پیام سرتاسر رمزنگاری‌شده، اشتراک رسانه و تماس WebRTC در مایل‌استون‌های ۳ تا ۶ فعال می‌شوند و هیچ پیام نمایشی یا تحویل ساختگی ثبت نمی‌شود.",
                            color = DuoLinkColors.Muted,
                            fontSize = 13.sp,
                            lineHeight = 22.sp,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = {}, enabled = false) {
                Icon(Icons.Default.AttachFile, contentDescription = "پیوست (مایل‌استون ۴)", tint = DuoLinkColors.Divider)
            }
            OutlinedTextField(
                value = "",
                onValueChange = {},
                enabled = false,
                modifier = Modifier.weight(1f),
                placeholder = { Text("ارسال پیام در مایل‌استون ۳ فعال می‌شود…", fontSize = 13.sp) },
                shape = RoundedCornerShape(24.dp),
                singleLine = true
            )
            IconButton(onClick = {}, enabled = false) {
                Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "ارسال", tint = DuoLinkColors.Divider)
            }
        }
    }
}

@Composable
fun SettingsScreen(
    uiState: DuoLinkUiState,
    onOpenSecurity: () -> Unit,
    onBack: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DuoLinkColors.Ink)
    ) {
        DuoLinkTopBar(title = "تنظیمات و حریم خصوصی", onBack = onBack)

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Text("حالت حریم خصوصی سراسری (فعال به‌صورت پیش‌فرض)", color = DuoLinkColors.Gold, fontWeight = FontWeight.Bold)
            Card(
                colors = CardDefaults.cardColors(containerColor = DuoLinkColors.Panel),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("• محافظت صفحه (FLAG_SECURE): فعال در کل برنامه", fontSize = 13.sp, color = DuoLinkColors.Success)
                    Text("• پشتیبان‌گیری ابری و انتقال دستگاه‌به‌دستگاه: غیرفعال", fontSize = 13.sp, color = DuoLinkColors.Success)
                    Text("• کلیدها و دفترچه اعتماد محلی: رمزنگاری‌شده با Android Keystore (AES-256-GCM)", fontSize = 13.sp, color = DuoLinkColors.Success)
                    Text("• بدون تبلیغات، بدون Firebase و بدون هرگونه SDK ردیابی", fontSize = 13.sp, color = DuoLinkColors.Success)
                    Text(
                        text = "یادآوری صادقانه امنیتی: FLAG_SECURE جلوی اسکرین‌شات و ضبط صفحه عادی سیستم‌عامل را می‌گیرد، اما هیچ برنامه‌ای نمی‌تواند مانع عکس‌برداری با دوربین فیزیکی دیگر یا دسترسی سطح روت در گوشی دستکاری‌شده شود.",
                        color = DuoLinkColors.Muted,
                        fontSize = 12.sp,
                        lineHeight = 20.sp
                    )
                }
            }

            OutlinedButton(
                onClick = onOpenSecurity,
                border = BorderStroke(1.dp, DuoLinkColors.Gold),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("مدیریت هویت دستگاه، چرخش کلید و بازنشانی جفت‌سازی", color = Color.White)
            }

            HorizontalDivider(color = DuoLinkColors.Divider)
            Text("وضعیت مراحل توسعه", color = DuoLinkColors.Gold, fontWeight = FontWeight.Bold)
            Text(
                text = "مایل‌استون ۲ (هویت رمزنگاری Android Keystore و جفت‌سازی دوجانبه QR) فعال است. پیام‌رسانی آنلاین سرتاسر رمزنگاری‌شده، انتقال خصوصی عکس و ویدیو (بدون نمایش خودکار در گالری)، تماس صوتی/تصویری WebRTC و قفل بیومتریک در مایل‌استون‌های بعدی به ترتیب اضافه می‌شوند.",
                color = DuoLinkColors.Muted,
                fontSize = 13.sp,
                lineHeight = 23.sp
            )
        }
    }
}
