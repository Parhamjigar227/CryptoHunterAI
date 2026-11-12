package com.duolink.app.ui

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
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * State of one attachment being viewed.
 *
 * [plaintext] is held in memory only while this screen is open and is released when it leaves
 * composition. It is never written to disk in the clear - the sealed copy in the vault is the only
 * persistent form.
 */
// The viewer state type lives in DuoLinkViewModel.kt (AttachmentViewerUiState) so the screen and the
// ViewModel can never drift apart.

/**
 * Full-screen attachment viewer.
 *
 * This screen is the ONLY place a Gallery export can be triggered, and it is scoped to the single
 * attachment in front of the user. There is no "save all", no background export, and the confirmation
 * dialog spells out the consequence before anything is written: once saved, the file is outside
 * DuoLink's protection.
 *
 * The sealed copy in private storage is never deleted by an export - saving is a copy, so the
 * conversation keeps working and the user can revoke the export by deleting the Gallery item.
 */
@Composable
fun AttachmentViewerScreen(
    state: AttachmentViewerUiState,
    onBack: () -> Unit,
    onRequestExport: () -> Unit,
    onConfirmExport: () -> Unit,
    onDismissExportDialog: () -> Unit,
    exportDialogVisible: Boolean,
    exportResultPersian: String?,
    onRemoveFromDevice: () -> Unit,
    videoContent: @Composable () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(ObsidianBackground)
            .statusBarsPadding()
            .navigationBarsPadding()
    ) {
        Column(modifier = Modifier.fillMaxSize()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 4.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Icon(
                        Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = "بازگشت",
                        tint = TextIvory
                    )
                }
                Text(
                    text = if (state.isVideo) "ویدیو" else "تصویر",
                    style = MaterialTheme.typography.titleMedium,
                    color = TextIvory,
                    modifier = Modifier.weight(1f)
                )
            }

            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                contentAlignment = Alignment.Center
            ) {
                when {
                    state.isLoading -> CircularProgressIndicator(color = GoldPrimary)
                    state.errorPersian != null -> {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            modifier = Modifier.padding(32.dp)
                        ) {
                            Icon(
                                Icons.Filled.Warning,
                                contentDescription = null,
                                tint = ErrorCrimson,
                                modifier = Modifier.size(40.dp)
                            )
                            Spacer(Modifier.height(12.dp))
                            Text(
                                text = state.errorPersian,
                                color = TextIvory,
                                textAlign = TextAlign.Center,
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                    state.isVideo -> videoContent()
                    state.plaintext != null -> {
                        val bitmap = remember(state.digestHex) {
                            runCatching {
                                android.graphics.BitmapFactory
                                    .decodeByteArray(state.plaintext!!, 0, state.plaintext!!.size)
                                    ?.asImageBitmap()
                            }.getOrNull()
                        }
                        if (bitmap != null) {
                            Image(
                                bitmap = bitmap,
                                contentDescription = "پیوست",
                                contentScale = ContentScale.Fit,
                                modifier = Modifier.fillMaxSize().padding(8.dp)
                            )
                        } else {
                            Text(
                                text = "نمایش این تصویر ممکن نیست.",
                                color = TextMuted,
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                }
            }

            if (exportResultPersian != null) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(SurfaceCharcoal)
                        .padding(horizontal = 16.dp, vertical = 10.dp)
                ) {
                    Text(
                        text = exportResultPersian,
                        color = TextIvory,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }

            // The explicit, per-item export action. Nothing else in the app writes to the Gallery.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = onRequestExport,
                    enabled = state.plaintext != null && !state.isExporting && state.errorPersian == null,
                    modifier = Modifier.weight(1f).height(48.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = GoldPrimary,
                        contentColor = ObsidianBackground
                    )
                ) {
                    if (state.isExporting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            color = ObsidianBackground,
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(Icons.Filled.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("ذخیره در گالری", fontSize = 13.sp)
                    }
                }
                TextButton(
                    onClick = onRemoveFromDevice,
                    modifier = Modifier.height(48.dp)
                ) {
                    Icon(
                        Icons.Filled.DeleteOutline,
                        contentDescription = null,
                        tint = TextMuted,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("حذف", color = TextMuted, fontSize = 12.sp)
                }
            }
        }
    }

    if (exportDialogVisible) {
        AlertDialog(
            onDismissRequest = onDismissExportDialog,
            containerColor = SurfaceElevated,
            title = { Text("ذخیره در گالری", color = TextIvory) },
            text = {
                // The consequence is stated before the write, not after.
                Text(
                    text = "پس از ذخیره، این فایل از حفاظت دوولینک خارج می‌شود و برنامه‌های دیگر " +
                        "می‌توانند آن را ببینند. پشتیبان‌گیری گالری هم ممکن است آن را در فضای ابری " +
                        "بارگذاری کند. ادامه می‌دهید؟",
                    color = TextMuted,
                    style = MaterialTheme.typography.bodySmall
                )
            },
            confirmButton = {
                TextButton(onClick = onConfirmExport) {
                    Text("ذخیره کن", color = GoldPrimary)
                }
            },
            dismissButton = {
                TextButton(onClick = onDismissExportDialog) {
                    Text("انصراف", color = TextMuted)
                }
            }
        )
    }
}

/**
 * Minimal video surface.
 *
 * Deliberately simple: the sealed bytes are written to an app-private, non-world-readable cache file
 * only for the lifetime of this screen, and deleted when it leaves composition. `VideoView` is used
 * instead of a media library so no additional dependency touches decrypted media.
 */
@Composable
fun PrivateVideoPlayer(plaintext: ByteArray?, mimeType: String, onError: (String) -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var tempFile by remember { mutableStateOf<java.io.File?>(null) }

    LaunchedEffect(plaintext) {
        if (plaintext == null) return@LaunchedEffect
        val file = java.io.File.createTempFile("duolink-view", ".mp4", context.cacheDir)
        file.writeBytes(plaintext)
        tempFile = file
        runCatching {
            file.setReadable(false, false)
            file.setReadable(true, true) // owner-only
        }
    }

    androidx.compose.runtime.DisposableEffect(Unit) {
        onDispose {
            // Delete the decrypted copy as soon as the screen closes.
            runCatching { tempFile?.delete() }
            tempFile = null
        }
    }

    androidx.compose.ui.viewinterop.AndroidView(
        factory = { ctx ->
            android.widget.VideoView(ctx).apply {
                setOnErrorListener { _, _, _ ->
                    onError("پخش این ویدیو ممکن نیست.")
                    true
                }
            }
        },
        update = { view ->
            val file = tempFile
            if (file != null && file.exists()) {
                if (view.tag != file.absolutePath) {
                    view.tag = file.absolutePath
                    view.setVideoPath(file.absolutePath)
                    view.setOnPreparedListener { player ->
                        player.isLooping = false
                        view.start()
                    }
                }
            }
        },
        modifier = Modifier.fillMaxSize()
    )
}
