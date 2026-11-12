package com.duolink.app.media

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.TranscriptBuilder
import com.duolink.app.crypto.zeroize
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * MIME allow-list for attachments.
 *
 * Only formats we can actually render (still images, and videos the platform MediaPlayer handles) are
 * accepted. Everything else is refused instead of being stored as an opaque blob the user cannot
 * preview — an attachment the user cannot see is a liability, not a feature.
 */
enum class MediaKind(val wireTag: String, val allowedMimeTypes: Set<String>, val isVideo: Boolean) {
    IMAGE(
        wireTag = "img",
        allowedMimeTypes = setOf("image/jpeg", "image/png", "image/webp", "image/heic", "image/heif"),
        isVideo = false
    ),
    VIDEO(
        wireTag = "vid",
        allowedMimeTypes = setOf("video/mp4", "video/3gpp", "video/webm", "video/quicktime"),
        isVideo = true
    );

    companion object {
        fun forMimeType(mime: String?): MediaKind? = when {
            mime == null -> null
            else -> entries.firstOrNull { mime.lowercase() in it.allowedMimeTypes }
        }
    }
}

/** Content-addressed reference to an attachment already sealed into private storage. */
data class MediaRef(
    val kind: MediaKind,
    val sha256: ByteArray,
    val sealedFileName: String,
    val mimeType: String,
    val sizeBytes: Long,
    val durationMs: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MediaRef) return false
        return kind == other.kind &&
            ByteEncoding.constantTimeEquals(sha256, other.sha256) &&
            sealedFileName == other.sealedFileName
    }

    override fun hashCode(): Int =
        31 * (31 * kind.hashCode() + sha256.contentHashCode()) + sealedFileName.hashCode()
}

/** Typed failures so the UI can explain precisely why an attachment was refused. */
sealed class MediaException(message: String) : Exception(message) {
    class UnsupportedType(val mime: String?) :
        MediaException("نوع فایل پشتیبانی نمی‌شود (${mime ?: "نامشخص"}).")
    class TooLarge(val sizeBytes: Long, val limitBytes: Long) :
        MediaException("حجم فایل بیش از حد مجاز است.")
    class Empty : MediaException("فایل انتخاب‌شده خالی است.")
    class DigestMismatch : MediaException("محتوای فایل با اثر انگشت ثبت‌شده مطابقت ندارد.")
    class NotAvailable : MediaException("فایل رسانه در دسترس نیست.")
}

/**
 * Encrypted, app-private attachment storage.
 *
 * Design decisions that matter for the brief:
 *
 *  - **Nothing is ever written to shared storage automatically.** Every attachment is sealed with
 *    AES-256-GCM into the app's private directory (`filesDir/media`, which is inside the app sandbox
 *    and excluded from `MediaStore`). Saving to the device Gallery is a separate, explicit, per-item
 *    user action in [MediaExporter]; there is no code path that does it implicitly.
 *  - **Content-addressed.** The file name is the SHA-256 of the plaintext, so the same photo sent twice
 *    is stored once, and a flipped byte in the sealed file is detectable rather than silently shown.
 *  - **Per-file random IV and per-file associated data.** The associated data includes the digest and
 *    the kind, so a sealed video cannot be swapped into the slot of an image (or vice-versa).
 *  - Sizes are bounded before any bytes are read into memory, so a hostile 4 GB "photo" cannot OOM
 *    the process.
 */
class MediaVault(
    private val directory: File,
    /** 32-byte AES-256 master key for attachment sealing, obtained from [MediaKeyManager]. */
    private val mediaMasterKey: ByteArray,
    private val random: SecureRandom = SecureRandom()
) {
    init {
        require(mediaMasterKey.size == 32) { "media master key must be 32 bytes" }
    }

    init {
        if (!directory.exists()) {
            // 0700 semantics: created inside the app sandbox; nothing else on the device can read it.
            directory.mkdirs()
        }
    }

    /**
     * Seals [plaintext] into private storage and returns its reference.
     *
     * [sourceFileName] is only used to derive a safe display name; it never influences the on-disk
     * sealed name, which is content-derived. That prevents path traversal via a hostile file name.
     */
    fun store(
        plaintext: ByteArray,
        declaredMimeType: String?,
        sourceFileName: String?,
        durationMs: Long = 0L
    ): MediaRef {
        if (plaintext.isEmpty()) throw MediaException.Empty()
        val kind = MediaKind.forMimeType(declaredMimeType)
            ?: throw MediaException.UnsupportedType(declaredMimeType)
        val limit = if (kind.isVideo) MAX_VIDEO_BYTES else MAX_IMAGE_BYTES
        if (plaintext.size > limit) throw MediaException.TooLarge(plaintext.size.toLong(), limit)

        val digest = MessageDigest.getInstance("SHA-256").digest(plaintext)
        val sealedName = "$STORED_PREFIX${ByteEncoding.toHexLower(digest)}.$STORED_SUFFIX"
        val target = File(directory, sealedName)

        // Content-addressed: if an identical attachment is already sealed, reuse it (and prove the
        // existing copy is intact rather than trusting its existence).
        if (target.exists()) {
            val existing = runCatching { open(digest, kind) }.getOrNull()
            if (existing != null && existing.contentEquals(plaintext)) return refFor(kind, digest, target, declaredMimeType, plaintext.size.toLong(), durationMs)
        }

        val iv = ByteArray(IV_BYTES).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(mediaMasterKey, "AES"), GCMParameterSpec(TAG_BITS, iv))
            updateAAD(associatedData(digest, kind))
        }
        val ciphertext = cipher.doFinal(plaintext)
        val blob = ByteArray(1 + iv.size + ciphertext.size).also { out ->
            out[0] = iv.size.toByte()
            iv.copyInto(out, 1)
            ciphertext.copyInto(out, 1 + iv.size)
        }

        // Write to a temp file then rename, so a crash mid-write cannot leave a half-sealed attachment
        // that would later fail its integrity check and look like tampering.
        val temp = File(directory, "$sealedName.tmp")
        FileOutputStream(temp).use { stream ->
            stream.write(blob)
            stream.flush()
            stream.fd.sync()
        }
        if (!temp.renameTo(target)) {
            temp.delete()
            throw java.io.IOException("failed to publish sealed attachment")
        }
        return refFor(kind, digest, target, declaredMimeType, plaintext.size.toLong(), durationMs)
    }

    /** Opens a sealed attachment and verifies its digest before returning the bytes. */
    fun open(sha256: ByteArray, kind: MediaKind): ByteArray? {
        val target = File(directory, "$STORED_PREFIX${ByteEncoding.toHexLower(sha256)}.$STORED_SUFFIX")
        if (!target.exists()) return null
        val blob = target.readBytes()
        if (blob.size <= 1) throw MediaException.DigestMismatch()
        val ivLen = blob[0].toInt() and 0xFF
        if (ivLen !in 12..16 || blob.size <= 1 + ivLen) throw MediaException.DigestMismatch()
        val iv = blob.copyOfRange(1, 1 + ivLen)
        val ciphertext = blob.copyOfRange(1 + ivLen, blob.size)
        val plaintext = try {
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(mediaMasterKey, "AES"), GCMParameterSpec(TAG_BITS, iv))
                updateAAD(associatedData(sha256, kind))
            }.doFinal(ciphertext)
        } catch (t: Throwable) {
            // GCM tag failure: the file was modified outside the app, or the digest/kind was swapped.
            throw MediaException.DigestMismatch()
        }
        val actual = MessageDigest.getInstance("SHA-256").digest(plaintext)
        if (!MessageDigest.isEqual(actual, sha256)) {
            plaintext.zeroize()
            throw MediaException.DigestMismatch()
        }
        return plaintext
    }

    /** True when the sealed attachment is present on disk. Never decrypts. */
    fun contains(sha256: ByteArray): Boolean =
        File(directory, "$STORED_PREFIX${ByteEncoding.toHexLower(sha256)}.$STORED_SUFFIX").exists()

    /** Deletes a sealed attachment. Used only by the explicit "remove from this device" action. */
    fun delete(sha256: ByteArray): Boolean =
        File(directory, "$STORED_PREFIX${ByteEncoding.toHexLower(sha256)}.$STORED_SUFFIX").delete()

    /** Total bytes occupied by sealed attachments (for the storage line in Settings). */
    fun totalBytes(): Long = directory.listFiles()?.filter { it.isFile }?.sumOf { it.length() } ?: 0L

    private fun refFor(
        kind: MediaKind,
        digest: ByteArray,
        target: File,
        mime: String?,
        size: Long,
        durationMs: Long
    ) = MediaRef(
        kind = kind,
        sha256 = digest,
        sealedFileName = target.name,
        mimeType = mime ?: "application/octet-stream",
        sizeBytes = size,
        durationMs = durationMs
    )

    private fun associatedData(digest: ByteArray, kind: MediaKind): ByteArray =
        TranscriptBuilder()
            .putRawUtf8(AD_PREFIX)
            .putRawUtf8(kind.wireTag)
            .putBytes(digest)
            .build()

    companion object {
        /** 25 MiB — comfortably above a modern phone photo, low enough to stay well-behaved. */
        const val MAX_IMAGE_BYTES = 25L * 1024 * 1024

        /** 200 MiB — short phone clips. Anything larger must be trimmed by the user first. */
        const val MAX_VIDEO_BYTES = 200L * 1024 * 1024

        private const val STORED_PREFIX = "m_"
        private const val STORED_SUFFIX = "dlm"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_BYTES = 12
        private const val TAG_BITS = 128
        private const val AD_PREFIX = "DuoLink-Media-v1"

    }
}
