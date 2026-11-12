package com.duolink.app.media

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File
import java.io.OutputStream

/**
 * The **only** code path in the app that writes an attachment into the device Gallery.
 *
 * Rules this class exists to enforce:
 *  1. It is never called automatically. Every call is triggered by the user tapping "ذخیره در گالری"
 *     on one specific attachment. There is no batch export, no "save all", and no background worker
 *     that calls this.
 *  2. It copies the **already-verified plaintext** the caller passes in, and writes it through the
 *     platform `MediaStore` API, so the app does not need `WRITE_EXTERNAL_STORAGE` on any supported API
 *     level (minSdk 26 uses `MediaStore` inserts on API 29+; on API 26–28 it writes to the public
 *     Pictures/Movies directories, which is why the manifest keeps a `maxSdkVersion=28` permission).
 *  3. It never deletes the sealed copy in private storage. Saving to the Gallery is a *copy*, so the
 *     conversation keeps working and the user can revoke the export by deleting the Gallery item
 *     themselves.
 *
 * Honest limitation surfaced in the UI: once an attachment is saved to the Gallery it is outside
 * DuoLink's protection. Other apps can read it, and a gallery backup may upload it. This is why the
 * action is per-item and explicitly labelled, never a silent background behaviour.
 */
class MediaExporter(private val context: Context) {

    /** Outcome of an export attempt, so the UI can say exactly what happened. */
    sealed class Result {
        data class Saved(val uri: Uri, val displayName: String) : Result()
        data class Failed(val persianMessage: String) : Result()
    }

    /**
     * Copies [plaintext] into the Gallery collection for [kind].
     *
     * [displayName] is sanitised: path separators and control characters are stripped so a hostile
     * peer-supplied name cannot influence where the file lands.
     */
    fun exportToGallery(
        plaintext: ByteArray,
        kind: MediaKind,
        mimeType: String,
        displayName: String,
        takenAtEpochSec: Long
    ): Result {
        val safeName = sanitiseFileName(displayName, mimeType, kind)
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                exportViaMediaStore(plaintext, kind, mimeType, safeName, takenAtEpochSec)
            } else {
                exportViaLegacyFile(plaintext, kind, safeName)
            }
        } catch (t: Throwable) {
            Result.Failed("ذخیره در گالری ناموفق بود (${t.javaClass.simpleName}).")
        }
    }

    /** API 29+: `MediaStore` with `IS_PENDING`, so half-written items are never visible. */
    private fun exportViaMediaStore(
        plaintext: ByteArray,
        kind: MediaKind,
        mimeType: String,
        displayName: String,
        takenAtEpochSec: Long
    ): Result {
        val collection = if (kind.isVideo) {
            MediaStore.Video.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
        } else {
            MediaStore.Images.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
        }
        val relativePath = if (kind.isVideo) {
            "${Environment.DIRECTORY_MOVIES}/DuoLink"
        } else {
            "${Environment.DIRECTORY_PICTURES}/DuoLink"
        }
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, displayName)
            put(MediaStore.MediaColumns.MIME_TYPE, mimeType)
            put(MediaStore.MediaColumns.RELATIVE_PATH, relativePath)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
            if (kind.isVideo) {
                put(MediaStore.Video.Media.DATE_TAKEN, takenAtEpochSec * 1000L)
            } else {
                put(MediaStore.Images.Media.DATE_TAKEN, takenAtEpochSec * 1000L)
            }
        }
        val uri = context.contentResolver.insert(collection, values)
            ?: return Result.Failed("ساخت ورودی در گالری ممکن نشد.")
        try {
            val stream: OutputStream = context.contentResolver.openOutputStream(uri)
                ?: return Result.Failed("نوشتن در گالری ممکن نشد.")
            stream.use { it.write(plaintext) }
            // Only now is the item published to other apps.
            val publish = ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }
            context.contentResolver.update(uri, publish, null, null)
            return Result.Saved(uri, displayName)
        } catch (t: Throwable) {
            // Do not leave a dangling pending row behind.
            runCatching { context.contentResolver.delete(uri, null, null) }
            throw t
        }
    }

    /**
     * API 26–28: no scoped storage, so write into the public collection directory directly.
     * Requires WRITE_EXTERNAL_STORAGE, which the manifest declares with `android:maxSdkVersion="28"`.
     */
    private fun exportViaLegacyFile(
        plaintext: ByteArray,
        kind: MediaKind,
        displayName: String
    ): Result {
        @Suppress("DEPRECATION")
        val root = Environment.getExternalStoragePublicDirectory(
            if (kind.isVideo) Environment.DIRECTORY_MOVIES else Environment.DIRECTORY_PICTURES
        )
        val dir = File(root, "DuoLink")
        if (!dir.exists() && !dir.mkdirs()) {
            return Result.Failed("ساخت پوشهٔ گالری ممکن نشد.")
        }
        val target = uniqueFile(dir, displayName)
        target.outputStream().use { it.write(plaintext) }
        // Best-effort announcement so the item shows up without a reboot.
        runCatching {
            android.media.MediaScannerConnection.scanFile(
                context, arrayOf(target.absolutePath), null, null
            )
        }
        return Result.Saved(Uri.fromFile(target), target.name)
    }

    /** Appends ` (1)`, ` (2)`, ... so an export never overwrites an existing gallery item. */
    private fun uniqueFile(dir: File, displayName: String): File {
        var candidate = File(dir, displayName)
        if (!candidate.exists()) return candidate
        val dot = displayName.lastIndexOf('.')
        val stem = if (dot > 0) displayName.substring(0, dot) else displayName
        val ext = if (dot > 0) displayName.substring(dot) else ""
        var index = 1
        while (candidate.exists()) {
            candidate = File(dir, "$stem ($index)$ext")
            index++
        }
        return candidate
    }

    companion object {
        /**
         * Produces a safe, informative file name.
         *
         * Strips directory separators, control characters and Windows-reserved characters; caps the
         * length; and guarantees an extension consistent with the MIME type so the Gallery classifies
         * the item correctly.
         */
        fun sanitiseFileName(rawName: String, mimeType: String, kind: MediaKind): String {
            val extension = extensionFor(mimeType, kind)
            val base = rawName
                .substringBeforeLast('.', rawName)
                .filter { it.isLetterOrDigit() || it == '-' || it == '_' || it == ' ' || it == '.' }
                .trim()
                .ifEmpty { "duolink-${kind.wireTag}" }
                .take(80)
            return "$base$extension"
        }

        private fun extensionFor(mimeType: String, kind: MediaKind): String = when (mimeType.lowercase()) {
            "image/jpeg" -> ".jpg"
            "image/png" -> ".png"
            "image/webp" -> ".webp"
            "image/heic", "image/heif" -> ".heic"
            "video/mp4" -> ".mp4"
            "video/3gpp" -> ".3gp"
            "video/webm" -> ".webm"
            "video/quicktime" -> ".mov"
            else -> if (kind.isVideo) ".mp4" else ".jpg"
        }
    }
}
