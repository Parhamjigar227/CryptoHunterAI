package com.duolink.app.ui

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import com.duolink.app.media.MediaException
import com.duolink.app.media.MediaKind
import com.duolink.app.media.MediaRef
import com.duolink.app.media.MediaVault

/**
 * Reads a picked attachment and seals it into the private vault.
 *
 * Runs off the UI thread (callers wrap it in a coroutine), and enforces the size cap *while reading*
 * so a hostile or enormous document cannot be fully buffered into memory just to be rejected. The
 * picker itself returns a content URI; we read exactly once, seal, and never touch the file again —
 * no copy of the plaintext is kept.
 */
object AttachmentIngest {

    /** Result of ingesting a picked item. */
    sealed class Result {
        data class Stored(val ref: MediaRef) : Result()
        data class Rejected(val persianMessage: String) : Result()
    }

    fun ingest(
        context: Context,
        uri: Uri,
        vault: MediaVault
    ): Result {
        val resolver = context.contentResolver
        val mime = resolver.getType(uri)
        val kind = MediaKind.forMimeType(mime)
            ?: return Result.Rejected("این نوع فایل پشتیبانی نمی‌شود. فقط تصویر یا ویدیو قابل ارسال است.")

        val displayName = queryDisplayName(context, uri) ?: if (kind.isVideo) "video.mp4" else "image.jpg"
        val limit = if (kind.isVideo) MediaVault.MAX_VIDEO_BYTES else MediaVault.MAX_IMAGE_BYTES

        val bytes = try {
            resolver.openInputStream(uri)?.use { stream -> readCapped(stream, limit) }
                ?: return Result.Rejected("فایل انتخاب‌شده قابل خواندن نیست.")
        } catch (t: MediaException.TooLarge) {
            return Result.Rejected(
                if (kind.isVideo) {
                    "ویدیو بیش از ${MediaVault.MAX_VIDEO_BYTES / (1024 * 1024)} مگابایت است. آن را کوتاه‌تر کنید."
                } else {
                    "تصویر بیش از ${MediaVault.MAX_IMAGE_BYTES / (1024 * 1024)} مگابایت است."
                }
            )
        } catch (t: Throwable) {
            return Result.Rejected("خواندن فایل ناموفق بود (${t.javaClass.simpleName}).")
        }

        return try {
            Result.Stored(vault.store(bytes, mime, displayName))
        } catch (t: MediaException.UnsupportedType) {
            Result.Rejected("نوع فایل پشتیبانی نمی‌شود.")
        } catch (t: MediaException.Empty) {
            Result.Rejected("فایل انتخاب‌شده خالی است.")
        } catch (t: MediaException.TooLarge) {
            Result.Rejected("حجم فایل بیش از حد مجاز است.")
        } catch (t: Throwable) {
            Result.Rejected("ذخیرهٔ امن فایل ناموفق بود (${t.javaClass.simpleName}).")
        } finally {
            // Drop our copy of the plaintext as soon as it has been sealed.
            bytes.fill(0)
        }
    }

    private fun readCapped(stream: java.io.InputStream, limit: Long): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val read = stream.read(chunk)
            if (read < 0) break
            total += read
            if (total > limit) throw MediaException.TooLarge(total, limit)
            out.write(chunk, 0, read)
        }
        return out.toByteArray()
    }

    private fun queryDisplayName(context: Context, uri: Uri): String? = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            }
    }.getOrNull()
}

/**
 * Registers the two system-picker launchers (image and video) and reports the chosen URI.
 *
 * Uses [ActivityResultContracts.PickVisualMedia], which on API 33+ is the platform photo picker and on
 * older APIs falls back to the document picker. Either way the app receives a *single-item access grant*
 * and never asks for `READ_MEDIA_IMAGES` / `READ_EXTERNAL_STORAGE`: we only ever see the one file the
 * user chose, which is the smallest possible permission footprint.
 */
@Composable
fun rememberAttachmentPickers(
    onPicked: (Uri) -> Unit,
    onCancelled: () -> Unit
): AttachmentPickers {
    val imageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia()
    ) { uri ->
        if (uri != null) onPicked(uri) else onCancelled()
    }
    val videoLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia()
    ) { uri ->
        if (uri != null) onPicked(uri) else onCancelled()
    }
    return AttachmentPickers(
        pickImage = {
            imageLauncher.launch(
                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
            )
        },
        pickVideo = {
            videoLauncher.launch(
                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.VideoOnly)
            )
        }
    )
}

/** Handles to the two launchers, so the screen can trigger them from a menu item. */
class AttachmentPickers(
    val pickImage: () -> Unit,
    val pickVideo: () -> Unit
)
