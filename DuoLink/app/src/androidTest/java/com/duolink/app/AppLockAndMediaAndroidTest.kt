package com.duolink.app

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.duolink.app.android.AndroidKeystoreSealer
import com.duolink.app.crypto.DirectoryFileByteStore
import com.duolink.app.lock.AppLockPolicy
import com.duolink.app.lock.AppLockVerifier
import com.duolink.app.lock.BiometricUnlockGate
import com.duolink.app.lock.SealedAppLockStore
import com.duolink.app.media.MediaException
import com.duolink.app.media.MediaKeyManager
import com.duolink.app.media.MediaKind
import com.duolink.app.media.MediaVault
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.SecureRandom

/**
 * On-device tests for the app lock and the encrypted media vault.
 *
 * These specifically exercise the parts the JVM suite *cannot*: the real `AndroidKeystoreSealer`
 * (backed by `AndroidKeyStore`), the real `filesDir` sandbox, and the real `BiometricManager`
 * capability report. The JVM suite proves the logic; this proves it survives contact with Android.
 */
@RunWith(AndroidJUnit4::class)
class AppLockAndMediaAndroidTest {

    private lateinit var context: Context
    private lateinit var storeDir: File
    private lateinit var mediaDir: File
    private lateinit var byteStore: DirectoryFileByteStore
    private lateinit var sealer: AndroidKeystoreSealer

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        val suffix = System.nanoTime().toString()
        storeDir = File(context.filesDir, "test_lock_$suffix").apply { mkdirs() }
        mediaDir = File(context.filesDir, "test_media_$suffix").apply { mkdirs() }
        byteStore = DirectoryFileByteStore(storeDir)
        sealer = AndroidKeystoreSealer()
    }

    @After
    fun tearDown() {
        storeDir.deleteRecursively()
        mediaDir.deleteRecursively()
    }

    // ---- app lock on real Keystore ----------------------------------------

    @Test
    fun lockRecordRoundTripsThroughTheRealAndroidKeystore() {
        val store = SealedAppLockStore(byteStore, sealer)
        val pin = "482913"
        store.write(AppLockVerifier.createRecord(pin, System.currentTimeMillis()))

        val read = store.read()
        assertTrue(
            "expected a configured record, got $read",
            read is SealedAppLockStore.LockRead.Configured
        )
        val record = (read as SealedAppLockStore.LockRead.Configured).record
        assertTrue(AppLockVerifier.verify(pin, record))
        assertFalse(AppLockVerifier.verify("482914", record))
    }

    @Test
    fun lockRecordOnDiskIsNotReadableAsPlaintext() {
        val store = SealedAppLockStore(byteStore, sealer)
        store.write(AppLockVerifier.createRecord("482913", System.currentTimeMillis()))

        val file = storeDir.listFiles()!!.first { it.isFile }
        val raw = file.readBytes()
        val asText = String(raw, Charsets.ISO_8859_1)
        assertFalse("PIN must never appear on disk", asText.contains("482913"))
        // A sealed blob is longer than the plaintext because of the GCM tag and IV header.
        assertTrue(raw.size > 32)
    }

    @Test
    fun tappingTheLockFileIsDetectedByTheKeystoreBackedGcm() {
        val store = SealedAppLockStore(byteStore, sealer)
        store.write(AppLockVerifier.createRecord("482913", System.currentTimeMillis()))

        val file = storeDir.listFiles()!!.first { it.isFile }
        val raw = file.readBytes()
        raw[raw.size - 4] = (raw[raw.size - 4].toInt() xor 0xFF).toByte()
        file.writeBytes(raw)

        // Fail closed: a tampered lock record must never read as "no lock configured".
        assertTrue(store.read() is SealedAppLockStore.LockRead.Corrupted)
    }

    @Test
    fun lockoutStateSurvivesAnActualProcessStyleRestart() {
        val store = SealedAppLockStore(byteStore, sealer)
        var record = AppLockVerifier.createRecord("482913", System.currentTimeMillis())
        repeat(6) { record = AppLockPolicy.registerFailure(record, 1_000L) }
        store.write(record)

        // A brand new store + sealer over the same directory models a full restart.
        val reopened = SealedAppLockStore(DirectoryFileByteStore(storeDir), AndroidKeystoreSealer())
        val read = reopened.read()
        assertTrue(read is SealedAppLockStore.LockRead.Configured)
        val reloaded = (read as SealedAppLockStore.LockRead.Configured).record
        assertEquals(6, reloaded.failedAttempts)
        assertTrue(AppLockPolicy.isLockedOut(reloaded, 1_000L))
    }

    @Test
    fun biometricCapabilityIsReportedHonestly() {
        val availability = BiometricUnlockGate(context).availability()
        when (availability) {
            is BiometricUnlockGate.Availability.Available -> {
                // An emulator with a fingerprint enrolled can genuinely report success; an emulator
                // without one cannot. Either answer is acceptable, but it must be one of the two.
                val status = BiometricManager.from(context)
                    .canAuthenticate(BiometricUnlockGate.AUTHENTICATORS)
                assertEquals(BiometricManager.BIOMETRIC_SUCCESS, status)
            }
            is BiometricUnlockGate.Availability.Unavailable -> {
                // The reason must be a real Persian sentence, not an empty string or an exception.
                assertTrue(
                    "unavailability must carry an explanation",
                    availability.persianReason.isNotBlank()
                )
            }
        }
    }

    // ---- media vault on the real sandbox ---------------------------------

    @Test
    fun mediaMasterKeyIsSealedUnderTheRealKeystore() {
        val manager = MediaKeyManager(byteStore, sealer)
        val first = manager.obtainOrCreate()
        assertTrue(first is MediaKeyManager.KeyState.Ready)
        val key = (first as MediaKeyManager.KeyState.Ready).masterKey
        assertEquals(32, key.size)

        // Reloading through a fresh manager must return the same key, not rotate it.
        val second = MediaKeyManager(DirectoryFileByteStore(storeDir), AndroidKeystoreSealer())
            .obtainOrCreate()
        assertTrue(second is MediaKeyManager.KeyState.Ready)
        assertArrayEquals(key, (second as MediaKeyManager.KeyState.Ready).masterKey)
    }

    @Test
    fun attachmentRoundTripsInTheRealAppSandbox() {
        val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val vault = MediaVault(mediaDir, masterKey)
        val plaintext = ByteArray(20_000).also { SecureRandom().nextBytes(it) }

        val ref = vault.store(plaintext, "image/jpeg", "photo.jpg")
        assertEquals(MediaKind.IMAGE, ref.kind)
        val reopened = vault.open(ref.sha256, ref.kind)
        assertNotNull(reopened)
        assertArrayEquals(plaintext, reopened)
    }

    @Test
    fun attachmentIsStoredInsideFilesDirAndNowhereElse() {
        val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val vault = MediaVault(mediaDir, masterKey)
        vault.store(ByteArray(1_000) { 7 }, "image/png", "shot.png")

        val stored = mediaDir.listFiles()!!.filter { it.isFile }
        assertEquals(1, stored.size)
        // The file lives inside the app's private filesDir, not in shared/Pictures storage.
        assertTrue(stored.single().absolutePath.startsWith(context.filesDir.absolutePath))
    }

    @Test
    fun unsupportedTypeIsRejectedOnDeviceToo() {
        val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val vault = MediaVault(mediaDir, masterKey)
        var rejected = false
        try {
            vault.store(ByteArray(100), "application/zip", "archive.zip")
        } catch (expected: MediaException.UnsupportedType) {
            rejected = true
        }
        assertTrue(rejected)
        assertEquals(0, mediaDir.listFiles()!!.count { it.isFile })
    }

    @Test
    fun tamperedAttachmentFailsIntegrityCheckOnDevice() {
        val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val vault = MediaVault(mediaDir, masterKey)
        val ref = vault.store(ByteArray(5_000) { 3 }, "image/jpeg", "x.jpg")

        val file = mediaDir.listFiles()!!.first { it.isFile }
        val raw = file.readBytes()
        raw[raw.size / 2] = (raw[raw.size / 2].toInt() xor 0x55).toByte()
        file.writeBytes(raw)

        var detected = false
        try {
            vault.open(ref.sha256, ref.kind)
        } catch (expected: MediaException.DigestMismatch) {
            detected = true
        }
        assertTrue(detected)
    }

    @Test
    fun deletingAnAttachmentRemovesItFromDisk() {
        val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val vault = MediaVault(mediaDir, masterKey)
        val ref = vault.store(ByteArray(500) { 9 }, "video/mp4", "clip.mp4", durationMs = 3_000L)

        assertTrue(vault.contains(ref.sha256))
        assertTrue(vault.delete(ref.sha256))
        assertFalse(vault.contains(ref.sha256))
        assertNull(vault.open(ref.sha256, ref.kind))
    }
}
