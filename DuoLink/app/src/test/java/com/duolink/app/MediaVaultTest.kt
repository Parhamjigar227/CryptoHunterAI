package com.duolink.app

import com.duolink.app.crypto.InMemoryByteStore
import com.duolink.app.crypto.JcaAesGcmSealer
import com.duolink.app.media.MediaException
import com.duolink.app.media.MediaKeyManager
import com.duolink.app.media.MediaKind
import com.duolink.app.media.MediaVault
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Attachment storage tests (JVM, real files in a temp dir, real AES-256-GCM).
 *
 * The security properties asserted here are the ones the brief names explicitly:
 *  - media lives in private storage encrypted, never in plaintext;
 *  - nothing is written to shared/Gallery storage by this layer at all;
 *  - a modified or swapped attachment is detected, not silently rendered.
 */
class MediaVaultTest {

    private val random = SecureRandom()
    private val masterKey = ByteArray(32).also { random.nextBytes(it) }

    private fun newVault(): Pair<MediaVault, File> {
        val dir = Files.createTempDirectory("duolink-media-test").toFile()
        return MediaVault(dir, masterKey, random) to dir
    }

    private fun jpegBytes(size: Int = 4096): ByteArray =
        ByteArray(size).also { random.nextBytes(it) }

    // ---- private storage ------------------------------------------------

    @Test
    fun attachmentIsStoredSealedNotInPlaintext() {
        val (vault, dir) = newVault()
        val plaintext = jpegBytes()
        val ref = vault.store(plaintext, "image/jpeg", "IMG_0001.jpg")

        assertEquals(MediaKind.IMAGE, ref.kind)
        assertEquals(plaintext.size.toLong(), ref.sizeBytes)
        // Exactly one file, and it is NOT the plaintext.
        val files = dir.listFiles()!!.filter { it.isFile }
        assertEquals(1, files.size)
        val onDisk = files.single().readBytes()
        assertFalse(
            onDisk.size == plaintext.size && onDisk.contentEquals(plaintext),
            "attachment must not be written in the clear"
        )
        // The file name is content-addressed, not user-controlled.
        assertTrue(files.single().name.startsWith("m_"))
        assertTrue(files.single().name.endsWith(".dlm"))
    }

    @Test
    fun roundTripReturnsTheExactOriginalBytes() {
        val (vault, _) = newVault()
        val plaintext = jpegBytes(100_000)
        val ref = vault.store(plaintext, "image/jpeg", "photo.jpg")

        val reopened = vault.open(ref.sha256, ref.kind)
        assertNotNull(reopened)
        assertContentEquals(plaintext, reopened)
    }

    @Test
    fun digestIsTheSha256OfThePlaintext() {
        val (vault, _) = newVault()
        val plaintext = jpegBytes(512)
        val ref = vault.store(plaintext, "image/png", "shot.png")
        val expected = MessageDigest.getInstance("SHA-256").digest(plaintext)
        assertContentEquals(expected, ref.sha256)
    }

    @Test
    fun sameContentIsStoredOnce() {
        val (vault, dir) = newVault()
        val bytes = jpegBytes()
        val first = vault.store(bytes, "image/jpeg", "a.jpg")
        val second = vault.store(bytes, "image/jpeg", "b.jpg")

        assertContentEquals(first.sha256, second.sha256)
        assertEquals(1, dir.listFiles()!!.count { it.isFile }, "identical content must not be duplicated")
    }

    @Test
    fun nothingIsEverWrittenOutsideTheVaultDirectory() {
        // The vault has no reference to MediaStore or Environment at all; this asserts the only files
        // created are inside the directory it was handed.
        val (vault, dir) = newVault()
        val before = dir.parentFile!!.listFiles()?.map { it.name }?.toSet() ?: emptySet()
        vault.store(jpegBytes(), "image/jpeg", "x.jpg")
        val after = dir.parentFile!!.listFiles()?.map { it.name }?.toSet() ?: emptySet()
        assertEquals(before, after, "vault must not create files outside its own directory")
    }

    // ---- negative security ----------------------------------------------

    @Test
    fun tamperedSealedFileIsDetected() {
        val (vault, dir) = newVault()
        val ref = vault.store(jpegBytes(), "image/jpeg", "p.jpg")
        val file = dir.listFiles()!!.single { it.isFile }
        val raw = file.readBytes()
        raw[raw.size / 2] = (raw[raw.size / 2].toInt() xor 0x80).toByte()
        file.writeBytes(raw)

        try {
            vault.open(ref.sha256, ref.kind)
            throw AssertionError("expected MediaException.DigestMismatch for a tampered file")
        } catch (expected: MediaException.DigestMismatch) {
            // correct: GCM tag failure
        }
    }

    @Test
    fun sealedFileCannotBeReinterpretedAsTheOtherKind() {
        val (vault, dir) = newVault()
        val ref = vault.store(jpegBytes(), "image/jpeg", "p.jpg")
        // Kind is in the associated data: asking for the same digest as a video must fail closed.
        try {
            val asVideo = vault.open(ref.sha256, MediaKind.VIDEO)
            throw AssertionError("expected a failure, got ${asVideo?.size} bytes")
        } catch (expected: MediaException.DigestMismatch) {
            // correct
        }
    }

    @Test
    fun missingAttachmentReturnsNullRatherThanThrowing() {
        val (vault, _) = newVault()
        assertNull(vault.open(ByteArray(32), MediaKind.IMAGE))
        assertFalse(vault.contains(ByteArray(32)))
    }

    // ---- validation ------------------------------------------------------

    @Test
    fun unsupportedMimeTypeIsRefusedWithAPersianMessage() {
        val (vault, dir) = newVault()
        try {
            vault.store(jpegBytes(), "application/pdf", "doc.pdf")
            throw AssertionError("expected UnsupportedType")
        } catch (expected: MediaException.UnsupportedType) {
            assertTrue(expected.message!!.contains("پشتیبانی"))
        }
        assertEquals(0, dir.listFiles()!!.count { it.isFile })
    }

    @Test
    fun nullMimeTypeIsRefusedRatherThanGuessed() {
        val (vault, _) = newVault()
        try {
            vault.store(jpegBytes(), null, "mystery.bin")
            throw AssertionError("expected UnsupportedType")
        } catch (expected: MediaException.UnsupportedType) {
            // correct
        }
    }

    @Test
    fun emptyAttachmentIsRefused() {
        val (vault, _) = newVault()
        try {
            vault.store(ByteArray(0), "image/jpeg", "empty.jpg")
            throw AssertionError("expected Empty")
        } catch (expected: MediaException.Empty) {
            // correct
        }
    }

    @Test
    fun oversizeImageIsRefusedBeforeWritingAnything() {
        val (vault, dir) = newVault()
        val tooBig = ByteArray((MediaVault.MAX_IMAGE_BYTES + 1).toInt())
        try {
            vault.store(tooBig, "image/jpeg", "huge.jpg")
            throw AssertionError("expected TooLarge")
        } catch (expected: MediaException.TooLarge) {
            assertTrue(expected.message!!.contains("حجم"))
        }
        assertEquals(0, dir.listFiles()!!.count { it.isFile })
    }

    @Test
    fun videoAndImageLimitsAreDifferent() {
        assertTrue(MediaVault.MAX_VIDEO_BYTES > MediaVault.MAX_IMAGE_BYTES)
    }

    @Test
    fun videoRoundTripsWithDuration() {
        val (vault, _) = newVault()
        val bytes = ByteArray(50_000).also { random.nextBytes(it) }
        val ref = vault.store(bytes, "video/mp4", "clip.mp4", durationMs = 12_500L)
        assertEquals(MediaKind.VIDEO, ref.kind)
        assertEquals(12_500L, ref.durationMs)
        assertContentEquals(bytes, vault.open(ref.sha256, ref.kind))
    }

    @Test
    fun deleteRemovesTheAttachment() {
        val (vault, _) = newVault()
        val ref = vault.store(jpegBytes(), "image/jpeg", "d.jpg")
        assertTrue(vault.contains(ref.sha256))
        assertTrue(vault.delete(ref.sha256))
        assertFalse(vault.contains(ref.sha256))
    }

    @Test
    fun hostiledisplayFileNameCannotEscapeTheDirectory() {
        val (vault, dir) = newVault()
        val ref = vault.store(jpegBytes(), "image/jpeg", "../../../etc/passwd")
        // Store name is content-derived regardless of the supplied name.
        assertTrue(ref.sealedFileName.startsWith("m_"))
        assertEquals(1, dir.listFiles()!!.count { it.isFile })
    }

    @Test
    fun totalBytesReflectsStoredAttachments() {
        val (vault, _) = newVault()
        assertEquals(0L, vault.totalBytes())
        vault.store(jpegBytes(1000), "image/jpeg", "a.jpg")
        assertTrue(vault.totalBytes() > 0L)
    }

    // ---- key management --------------------------------------------------

    @Test
    fun mediaKeyIsCreatedOnceAndSealedAtRest() {
        val backing = InMemoryByteStore()
        val manager = MediaKeyManager(backing, JcaAesGcmSealer(), random)

        val first = manager.obtainOrCreate()
        assertIs<MediaKeyManager.KeyState.Ready>(first)
        assertEquals(32, first.masterKey.size)

        // A second call must return the same key, not silently rotate it (which would orphan media).
        val second = manager.obtainOrCreate()
        assertIs<MediaKeyManager.KeyState.Ready>(second)
        assertContentEquals(first.masterKey, second.masterKey)

        // The stored blob must not contain the raw key.
        val stored = backing.readState(MediaKeyManager.KEY)
        assertIs<com.duolink.app.crypto.RawStoreRead.Present>(stored)
        val asLatin1 = String(stored.bytes, Charsets.ISO_8859_1)
        assertFalse(asLatin1.contains(String(first.masterKey, Charsets.ISO_8859_1)))
    }

    @Test
    fun corruptedMediaKeyFailsClosedInsteadOfRotating() {
        val backing = InMemoryByteStore()
        val manager = MediaKeyManager(backing, JcaAesGcmSealer(), random)
        manager.obtainOrCreate()
        backing.corruptRawBytesForTesting(MediaKeyManager.KEY) { raw ->
            raw.copyOf().also { it[it.size - 2] = (it[it.size - 2].toInt() xor 0xFF).toByte() }
        }
        // Rotating silently would make every stored attachment permanently unreadable while looking
        // like it worked, so corruption must be reported.
        assertIs<MediaKeyManager.KeyState.Corrupted>(manager.obtainOrCreate())
    }

    @Test
    fun aDifferentMediaKeyCannotOpenAnotherVaultsFiles() {
        val dir = Files.createTempDirectory("duolink-media-cross").toFile()
        val originalKey = ByteArray(32).also { random.nextBytes(it) }
        val otherKey = ByteArray(32).also { random.nextBytes(it) }
        val stored = MediaVault(dir, originalKey, random).store(jpegBytes(), "image/jpeg", "x.jpg")

        try {
            MediaVault(dir, otherKey, random).open(stored.sha256, stored.kind)
            throw AssertionError("expected DigestMismatch when the vault key differs")
        } catch (expected: MediaException.DigestMismatch) {
            // correct
        }
    }
}
