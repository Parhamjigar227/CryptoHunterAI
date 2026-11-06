package com.duolink.app.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FlashOff
import androidx.compose.material.icons.filled.FlashOn
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.duolink.app.android.QrBitmapCodec
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable
fun CameraQrScannerBox(
    promptText: String,
    onQrDecoded: (String) -> Unit,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    Surface(
        color = DuoLinkColors.Panel,
        shape = RoundedCornerShape(20.dp),
        border = BorderStroke(1.dp, DuoLinkColors.GoldDim),
        modifier = Modifier.fillMaxWidth()
    ) {
        if (!hasCameraPermission) {
            Column(
                modifier = Modifier.padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.CameraAlt,
                    contentDescription = null,
                    tint = DuoLinkColors.Gold,
                    modifier = Modifier.size(40.dp)
                )
                Text(
                    text = "دسترسی به دوربین برای اسکن کد QR لازم است",
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center
                )
                Text(
                    text = "پردازش تصویر کاملاً آفلاین و داخل همین گوشی انجام می‌شود و هیچ داده‌ای به بیرون ارسال نمی‌گردد.",
                    color = DuoLinkColors.Muted,
                    fontSize = 13.sp,
                    textAlign = TextAlign.Center,
                    lineHeight = 22.sp
                )
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button(
                        onClick = { permissionLauncher.launch(Manifest.permission.CAMERA) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = DuoLinkColors.Gold,
                            contentColor = DuoLinkColors.Ink
                        )
                    ) {
                        Text("اعطای مجوز دوربین", fontWeight = FontWeight.Bold)
                    }
                    OutlinedButton(onClick = onClose) {
                        Text("بستن", color = DuoLinkColors.Muted)
                    }
                }
            }
        } else {
            val analysisExecutor = remember { Executors.newSingleThreadExecutor() }
            val deliveredOnce = remember { AtomicBoolean(false) }
            var boundCamera by remember { mutableStateOf<Camera?>(null) }
            var torchEnabled by remember { mutableStateOf(false) }
            var cameraError by remember { mutableStateOf<String?>(null) }

            DisposableEffect(Unit) {
                onDispose {
                    analysisExecutor.shutdown()
                }
            }

            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = promptText,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = DuoLinkColors.Gold,
                        modifier = Modifier.weight(1f)
                    )
                    if (boundCamera?.cameraInfo?.hasFlashUnit() == true) {
                        IconButton(
                            onClick = {
                                val next = !torchEnabled
                                torchEnabled = next
                                boundCamera?.cameraControl?.enableTorch(next)
                            }
                        ) {
                            Icon(
                                imageVector = if (torchEnabled) Icons.Default.FlashOn else Icons.Default.FlashOff,
                                contentDescription = "چراغ قوه",
                                tint = DuoLinkColors.Gold
                            )
                        }
                    }
                    IconButton(onClick = onClose) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "بستن اسکنر",
                            tint = DuoLinkColors.Muted
                        )
                    }
                }

                Spacer(Modifier.height(8.dp))

                if (cameraError != null) {
                    Text(
                        text = cameraError ?: "",
                        color = DuoLinkColors.Danger,
                        fontSize = 13.sp,
                        modifier = Modifier.padding(12.dp)
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(270.dp)
                            .clip(RoundedCornerShape(16.dp))
                            .background(Color.Black),
                        contentAlignment = Alignment.Center
                    ) {
                        AndroidView(
                            modifier = Modifier.fillMaxSize(),
                            factory = { ctx ->
                                val previewView = PreviewView(ctx).apply {
                                    implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                                }
                                val providerFuture = ProcessCameraProvider.getInstance(ctx)
                                providerFuture.addListener(
                                    {
                                        runCatching {
                                            val cameraProvider = providerFuture.get()
                                            val preview = Preview.Builder().build().also {
                                                it.surfaceProvider = previewView.surfaceProvider
                                            }
                                            val analyzer = ImageAnalysis.Builder()
                                                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                                                .build()
                                                .also { analysis ->
                                                    analysis.setAnalyzer(analysisExecutor) { imageProxy ->
                                                        try {
                                                            if (!deliveredOnce.get()) {
                                                                val decoded = QrBitmapCodec.decodeQrFromImageProxy(imageProxy)
                                                                if (!decoded.isNullOrBlank() &&
                                                                    deliveredOnce.compareAndSet(false, true)
                                                                ) {
                                                                    ContextCompat.getMainExecutor(ctx).execute {
                                                                        onQrDecoded(decoded)
                                                                    }
                                                                }
                                                            }
                                                        } finally {
                                                            imageProxy.close()
                                                        }
                                                    }
                                                }
                                            cameraProvider.unbindAll()
                                            boundCamera = cameraProvider.bindToLifecycle(
                                                lifecycleOwner,
                                                CameraSelector.DEFAULT_BACK_CAMERA,
                                                preview,
                                                analyzer
                                            )
                                        }.onFailure {
                                            cameraError = "دوربین در دسترس نیست؛ می‌توانید از ورود دستی کد امضاشده استفاده کنید."
                                        }
                                    },
                                    ContextCompat.getMainExecutor(ctx)
                                )
                                previewView
                            }
                        )

                        // Subtle gold QR framing guide
                        Box(
                            modifier = Modifier
                                .size(190.dp)
                                .border(2.dp, DuoLinkColors.Gold, RoundedCornerShape(18.dp))
                        )
                    }
                }
            }
        }
    }
}
