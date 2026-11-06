package com.duolink.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
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
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Shield
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

class MainActivity : ComponentActivity() {
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
        composable("about") {
            AboutScreen(onBack = { navController.popBackStack() })
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeScreen(
    uiState: DuoLinkUiState,
    onOpenPairing: () -> Unit,
    onOpenSecurity: () -> Unit,
    onOpenAbout: () -> Unit
) {
    val isPaired = uiState.pairingState is PairingStateSnapshot.PairedActive
    val isCorrupted = uiState.pairingState is PairingStateSnapshot.TrustStorageCorrupted

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Image(
                            painter = painterResource(id = R.drawable.duolink_logo),
                            contentDescription = "لوگوی دوولینک",
                            modifier = Modifier
                                .size(34.dp)
                                .clip(CircleShape),
                            contentScale = ContentScale.Crop
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text("دوولینک", fontWeight = FontWeight.Bold)
                    }
                },
                actions = {
                    IconButton(onClick = onOpenSecurity) {
                        Icon(
                            Icons.Default.Shield,
                            contentDescription = "امنیت و اثرانگشت",
                            tint = if (isCorrupted) ErrorCrimson else GoldPrimary
                        )
                    }
                    IconButton(onClick = onOpenAbout) {
                        Icon(Icons.Default.Info, contentDescription = "درباره برنامه", tint = GoldPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = SurfaceCharcoal,
                    titleContentColor = GoldPrimary
                )
            )
        },
        containerColor = ObsidianBackground
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable {
                        if (isPaired) onOpenSecurity() else onOpenPairing()
                    },
                colors = CardDefaults.cardColors(containerColor = SurfaceElevated),
                shape = RoundedCornerShape(18.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Image(
                        painter = painterResource(id = R.drawable.nasrin_portrait),
                        contentDescription = "تصویر پروفایل نسرین خانم",
                        modifier = Modifier
                            .size(72.dp)
                            .clip(CircleShape)
                            .border(2.dp, GoldPrimary, CircleShape),
                        contentScale = ContentScale.Crop
                    )
                    Spacer(modifier = Modifier.width(14.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "نسرین خانم",
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextIvory
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = when {
                                isCorrupted -> "مسدودسازی امنیتی — نیازمند بازیابی ذخیره‌سازی امن"
                                isPaired -> "جفت‌سازی امن تأییدشده • آماده اتصال مستقیم"
                                else -> "در انتظار جفت‌سازی امن دوطرفه با کد QR"
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = when {
                                isCorrupted -> ErrorCrimson
                                isPaired -> SuccessEmerald
                                else -> WarningAmber
                            }
                        )
                    }
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = SurfaceCharcoal),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.Lock,
                            contentDescription = null,
                            tint = if (isCorrupted) ErrorCrimson else GoldPrimary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "حریم خصوصی سراسری فعال است",
                            fontWeight = FontWeight.SemiBold,
                            color = TextIvory
                        )
                    }
                    Text(
                        text = "کلید امضای هویت و کلید پوششی در Android Keystore نگهداری می‌شوند، اسکرین‌شات سطح سیستم غیرفعال است، پشتیبان‌گیری ابری بسته است و هیچ سروری کلید یا پیامی ذخیره نمی‌کند.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMuted,
                        lineHeight = 20.sp
                    )
                    Button(
                        onClick = onOpenPairing,
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isCorrupted) ErrorCrimson else GoldPrimary,
                            contentColor = if (isCorrupted) Color.White else Color.Black
                        )
                    ) {
                        Icon(Icons.Default.QrCodeScanner, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            when {
                                isCorrupted -> "بررسی خطای امنیتی و بازیابی صریح"
                                isPaired -> "مشاهده وضعیت جفت‌سازی"
                                else -> "شروع جفت‌سازی امن با کد QR"
                            }
                        )
                    }
                    OutlinedButton(
                        onClick = onOpenSecurity,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("بررسی کد امنیتی ۶۰ رقمی و وضعیت کلیدها", color = GoldPrimary)
                    }
                }
            }
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
