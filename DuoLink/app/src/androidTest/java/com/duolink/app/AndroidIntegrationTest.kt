package com.duolink.app

import android.content.Context
import android.graphics.Color
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.duolink.app.android.AndroidKeystoreSealer
import com.duolink.app.android.AndroidKeystoreVault
import com.duolink.app.android.QrBitmapCodec
import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.DirectoryFileByteStore
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.KeyProtectionTier
import com.duolink.app.pairing.ArchivedPeerReadResult
import com.duolink.app.pairing.PairingCoordinator
import com.duolink.app.pairing.PairingRejectionReason
import com.duolink.app.pairing.PairingStateSnapshot
import com.duolink.app.pairing.PeerTrustStore
import com.duolink.app.pairing.TrustStoreComponent
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyStore

/**
 * Android Instrumentation Integration Tests (`./gradlew connectedDebugAndroidTest`).
 *
 * Exercises real `AndroidKeyStore` hardware/OS keys, `AES-256-GCM` sealing, `SHA256withECDSA`
 * identity signing, API 31+ Keystore ECDH, API 26–30 software-wrapped `SPK_dh` fallback,
 * CameraX-padded Y-plane + ZXing QR round-trips, process-restart persistence in `filesDir`,
 * and fail-closed trust/SPK corruption recovery.
 *
 * NOTE: Requires an attached Android device or emulator (`minSdk = 26+`) to execute.
 */
@RunWith(AndroidJUnit4::class)
class AndroidIntegrationTest {

    private lateinit var appContext: Context
    private lateinit var testDirA: File
    private lateinit var testDirB: File
    private lateinit var sealerA: AndroidKeystoreSealer
    private lateinit var sealerB: AndroidKeystoreSealer
    private val aliasMskA = "duolink_itest_msk_a"
    private val aliasMskB = "duolink_itest_msk_b"
    private val prefixVaultA = "duolink_itest_a"
    private val prefixVaultB = "duolink_itest_b"

    @Before
    fun setUp() {
        appContext = ApplicationProvider.getApplicationContext()
        testDirA = File(appContext.filesDir, "itest_store_a").also {
            it.deleteRecursively()
            it.mkdirs()
        }
        testDirB = File(appContext.filesDir, "itest_store_b").also {
            it.deleteRecursively()
            it.mkdirs()
        }
        sealerA = AndroidKeystoreSealer(aliasMskA).also { it.deleteKeyForTesting() }
        sealerB = AndroidKeystoreSealer(aliasMskB).also { it.deleteKeyForTesting() }
    }

    @After
    fun tearDown() {
        AndroidKeystoreVault(
            packageManager = appContext.packageManager,
            sealer = sealerA,
            byteStore = DirectoryFileByteStore(testDirA),
            aliasPrefix = prefixVaultA
        ).purgeAllForTesting()
        AndroidKeystoreVault(
            packageManager = appContext.packageManager,
            sealer = sealerB,
            byteStore = DirectoryFileByteStore(testDirB),
            aliasPrefix = prefixVaultB
        ).purgeAllForTesting()
        sealerA.deleteKeyForTesting()
        sealerB.deleteKeyForTesting()
        testDirA.deleteRecursively()
        testDirB.deleteRecursively()
    }

    @Test
    fun androidKeystoreKeyGenerationAndAesGcmSealUnseal() {
        val aad = "duolink:itest:aad".toByteArray(StandardCharsets.UTF_8)
        val plaintext = "نسرین خانم — تست رمزنگاری AndroidKeyStore".toByteArray(StandardCharsets.UTF_8)

        val sealed1 = sealerA.seal(plaintext, aad)
        val sealed2 = sealerA.seal(plaintext, aad)
        assertFalse(
            "Randomized IV in AndroidKeyStore AES-GCM must produce distinct ciphertexts",
            sealed1.contentEquals(sealed2)
        )
        assertArrayEquals(plaintext, sealerA.unseal(sealed1, aad))
        assertArrayEquals(plaintext, sealerA.unseal(sealed2, aad))

        // Key material must not be exportable via SecretKey.getEncoded()
        val ks = KeyStore.getInstance(AndroidKeystoreSealer.KEYSTORE_PROVIDER).apply { load(null) }
        val skEntry = ks.getEntry(aliasMskA, null) as KeyStore.SecretKeyEntry
        assertNull("AndroidKeyStore SecretKey.encoded must be null", skEntry.secretKey.encoded)

        // Wrong AAD must fail AEAD authentication
        val wrongAadFailed = try {
            sealerA.unseal(sealed1, "wrong-aad".toByteArray(StandardCharsets.UTF_8))
            false
        } catch (_: Exception) {
            true
        }
        assertTrue("AES-GCM must reject mismatched AAD", wrongAadFailed)

        // Bit flip must fail AEAD authentication
        val tampered = sealed1.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 0x01).toByte() }
        val bitFlipFailed = try {
            sealerA.unseal(tampered, aad)
            false
        } catch (_: Exception) {
            true
        }
        assertTrue("AES-GCM must reject bit-flipped ciphertext", bitFlipFailed)

        val mskStatus = sealerA.queryProtectionStatus()
        assertTrue("MSK must reside inside AndroidKeyStore", mskStatus.isKeystoreNonExportable)
    }

    @Test
    fun identityKeySigningAndVerificationInAndroidKeystore() {
        val vault = AndroidKeystoreVault(
            packageManager = appContext.packageManager,
            sealer = sealerA,
            byteStore = DirectoryFileByteStore(testDirA),
            aliasPrefix = prefixVaultA
        )
        val identity = vault.getOrCreateLocalIdentity(1_735_000_000L)
        assertEquals(16, identity.deviceId.size)
        assertEquals(91, identity.identitySigningPublicKeySpki.size)
        assertTrue(
            EcP256Crypto.verifySignedPreKey(
                identity.deviceId,
                identity.identitySigningPublicKeySpki,
                identity.currentSignedPreKey
            )
        )

        val message = "duolink-android-keystore-sign-test".toByteArray(StandardCharsets.UTF_8)
        val signature = vault.signWithIdentityKey(message)
        assertTrue(
            EcP256Crypto.verifySha256Ecdsa(
                identity.identitySigningPublicKeySpki,
                message,
                signature
            )
        )

        val ks = KeyStore.getInstance(AndroidKeystoreSealer.KEYSTORE_PROVIDER).apply { load(null) }
        val privEntry = ks.getEntry("${prefixVaultA}_ik_sig_p256_v1", null) as KeyStore.PrivateKeyEntry
        assertNull("AndroidKeyStore ECDSA PrivateKey.encoded must be null", privEntry.privateKey.encoded)
    }

    @Test
    fun naturalApi26To30DefaultVaultUsesSoftwareWrappedSpkAndCompletesPairing() {
        assumeTrue(
            "Natural API 26-30 default vault test applies only to Android 8.0-11 (API 26-30)",
            Build.VERSION.SDK_INT in Build.VERSION_CODES.O..30
        )

        val storeA = DirectoryFileByteStore(testDirA)
        val storeB = DirectoryFileByteStore(testDirB)
        // Default constructor (forceSoftwareSpkFallback = false) on real API 26-30 OS
        val vaultA = AndroidKeystoreVault(appContext.packageManager, sealerA, storeA, aliasPrefix = prefixVaultA)
        val vaultB = AndroidKeystoreVault(appContext.packageManager, sealerB, storeB, aliasPrefix = prefixVaultB)
        val coordA = PairingCoordinator(vaultA, PeerTrustStore(storeA, sealerA))
        val coordB = PairingCoordinator(vaultB, PeerTrustStore(storeB, sealerB))

        val t0 = 1_735_000_050L
        val reportA = vaultA.getKeyProtectionReport(t0)
        assertTrue(reportA.identitySigningKey.isKeystoreNonExportable)
        assertTrue(reportA.storageWrappingKey.isKeystoreNonExportable)
        assertEquals(KeyProtectionTier.SOFTWARE_WRAPPED_AT_REST, reportA.activeSignedPreKey.tier)
        assertFalse(reportA.activeSignedPreKey.isHardwareBacked)
        assertFalse(reportA.activeSignedPreKey.isKeystoreNonExportable)

        val offer = coordA.startInitiatorOffer(t0).getOrThrow()
        val resp = coordB.processScannedQr(offer.qrString, t0 + 1)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
        coordA.processScannedQr(resp.acceptQrToDisplay, t0 + 2)
        val recA = coordA.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()
        val recB = coordB.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()
        assertArrayEquals(recA.rootPairingKey, recB.rootPairingKey)
    }

    @Test
    fun peerIdentityChangeWarningBlocksUnacknowledgedConfirmAndRequiresExplicitAck() {
        val storeA = DirectoryFileByteStore(testDirA)
        val storeB = DirectoryFileByteStore(testDirB)
        val vaultA = AndroidKeystoreVault(appContext.packageManager, sealerA, storeA, aliasPrefix = prefixVaultA)
        val vaultB = AndroidKeystoreVault(appContext.packageManager, sealerB, storeB, aliasPrefix = prefixVaultB)
        val coordA = PairingCoordinator(vaultA, PeerTrustStore(storeA, sealerA))
        val coordB = PairingCoordinator(vaultB, PeerTrustStore(storeB, sealerB))

        val t0 = 1_735_002_000L
        val offer1 = coordA.startInitiatorOffer(t0).getOrThrow()
        val resp1 = coordB.processScannedQr(offer1.qrString, t0 + 1)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
        coordA.processScannedQr(resp1.acceptQrToDisplay, t0 + 2)
        coordA.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()
        coordB.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()

        // Device A keeps identity (archives B's old identity); Device B rotates identity key in AndroidKeyStore
        assertTrue(coordA.unpairForSecureRePairing(rotateDeviceIdentity = false, nowEpochSec = t0 + 10).isSuccess)
        assertTrue(coordB.unpairForSecureRePairing(rotateDeviceIdentity = true, nowEpochSec = t0 + 10).isSuccess)

        val offer2 = coordA.startInitiatorOffer(t0 + 20).getOrThrow()
        val resp2 = coordB.processScannedQr(offer2.qrString, t0 + 21)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
        val init2 = coordA.processScannedQr(resp2.acceptQrToDisplay, t0 + 22)
                as PairingCoordinator.QrProcessResult.InitiatorReadyToConfirm

        assertTrue("Device A must detect peer identity key rotation", init2.previousPeerChanged)
        assertFalse("Device B must see Device A kept its identity key", resp2.previousPeerChanged)

        // Confirming on Device A without acknowledging key change MUST fail closed
        assertTrue(
            coordA.confirmSafetyFingerprint(
                fullSafetyNumberComparedViaTrustedChannel = true,
                nowEpochSec = t0 + 23,
                acknowledgeKeyChange = false
            ).isFailure
        )

        // Confirming with explicit key-change acknowledgement succeeds
        assertTrue(
            coordA.confirmSafetyFingerprint(
                fullSafetyNumberComparedViaTrustedChannel = true,
                nowEpochSec = t0 + 24,
                acknowledgeKeyChange = true
            ).isSuccess
        )
    }

    @Test
    fun ecdhOnApi31PlusAndAccurateProtectionReporting() {
        assumeTrue("Hardware/Keystore ECDH requires Android 12 (API 31+)", Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)

        val vaultA = AndroidKeystoreVault(
            packageManager = appContext.packageManager,
            sealer = sealerA,
            byteStore = DirectoryFileByteStore(testDirA),
            aliasPrefix = prefixVaultA,
            forceSoftwareSpkFallback = false
        )
        val idA = vaultA.getOrCreateLocalIdentity(1_735_000_100L)
        val peerSoftwareKp = EcP256Crypto.generateSoftwareP256KeyPair()

        val secretFromVault = vaultA.agreeWithSignedPreKey(
            localSpkId = idA.currentSignedPreKey.spkId,
            peerPublicKeySpki = peerSoftwareKp.public.encoded
        )
        val secretFromPeer = EcP256Crypto.ecdhSharedSecret(
            localPrivateKey = peerSoftwareKp.private,
            peerPublicKeySpki = idA.currentSignedPreKey.publicKeySpki
        )
        assertArrayEquals(secretFromPeer, secretFromVault)

        val report = vaultA.getKeyProtectionReport(1_735_000_100L)
        assertTrue(report.identitySigningKey.isKeystoreNonExportable)
        assertTrue(report.storageWrappingKey.isKeystoreNonExportable)
        if (report.activeSignedPreKey.tier == KeyProtectionTier.SOFTWARE_WRAPPED_AT_REST) {
            // OEM KeyMint HAL declined PURPOSE_AGREE_KEY and fell back cleanly to MSK-wrapped SPK.
            assertFalse(report.activeSignedPreKey.isHardwareBacked)
            assertFalse(report.activeSignedPreKey.isKeystoreNonExportable)
        } else {
            assertTrue(report.activeSignedPreKey.isKeystoreNonExportable)
        }
    }

    @Test
    fun softwareSpkFallbackForApi26To30ReportsHonestlyAndComputesExactEcdh() {
        val vaultFallback = AndroidKeystoreVault(
            packageManager = appContext.packageManager,
            sealer = sealerA,
            byteStore = DirectoryFileByteStore(testDirA),
            aliasPrefix = prefixVaultA,
            forceSoftwareSpkFallback = true
        )
        val id = vaultFallback.getOrCreateLocalIdentity(1_735_000_200L)
        val peerSoftwareKp = EcP256Crypto.generateSoftwareP256KeyPair()

        val shared1 = vaultFallback.agreeWithSignedPreKey(
            localSpkId = id.currentSignedPreKey.spkId,
            peerPublicKeySpki = peerSoftwareKp.public.encoded
        )
        val shared2 = EcP256Crypto.ecdhSharedSecret(
            localPrivateKey = peerSoftwareKp.private,
            peerPublicKeySpki = id.currentSignedPreKey.publicKeySpki
        )
        assertArrayEquals(shared2, shared1)

        val report = vaultFallback.getKeyProtectionReport(1_735_000_200L)
        assertTrue("IK_sig must remain in AndroidKeyStore", report.identitySigningKey.isKeystoreNonExportable)
        assertTrue("MSK must remain in AndroidKeyStore", report.storageWrappingKey.isKeystoreNonExportable)
        assertEquals(
            "Fallback SPK_dh MUST be reported as SOFTWARE_WRAPPED_AT_REST",
            KeyProtectionTier.SOFTWARE_WRAPPED_AT_REST,
            report.activeSignedPreKey.tier
        )
        assertFalse("Software SPK_dh must NEVER be reported as hardware-backed", report.activeSignedPreKey.isHardwareBacked)
        assertFalse("Software SPK_dh must NEVER be reported as non-exportable", report.activeSignedPreKey.isKeystoreNonExportable)
    }

    @Test
    fun cameraXYPlaneStrideExtractionAndZxingMutualQrHandshake() {
        val storeA = DirectoryFileByteStore(testDirA)
        val storeB = DirectoryFileByteStore(testDirB)
        val vaultA = AndroidKeystoreVault(appContext.packageManager, sealerA, storeA, aliasPrefix = prefixVaultA)
        val vaultB = AndroidKeystoreVault(appContext.packageManager, sealerB, storeB, aliasPrefix = prefixVaultB)
        // A SEPARATE seeded generator for each device. Sharing one instance would tie the two devices'
        // random streams to execution order, which is a subtle way to make a test depend on which
        // coordinator draws first. Independent instances keep them uncoupled but reproducible.
        fun seededRandom(): java.security.SecureRandom =
            java.security.SecureRandom.getInstance("SHA1PRNG").apply { setSeed(0x0DDBA11L) }
        val coordA = PairingCoordinator(vaultA, PeerTrustStore(storeA, sealerA), secureRandom = seededRandom())
        val coordB = PairingCoordinator(vaultB, PeerTrustStore(storeB, sealerB), secureRandom = seededRandom())

        val t0 = 1_735_000_500L
        val offer = coordA.startInitiatorOffer(t0).getOrThrow()

        val renderSizePx = 420
        val offerBitmap = QrBitmapCodec.renderQrBitmap(offer.qrString, sizePx = renderSizePx)

        // ROOT CAUSE, NOW ESTABLISHED (was recorded here as "known flakiness" before).
        //
        // This test used to fail on roughly one CI job in four with a null decode. The payload embeds a
        // nonce, a session id and DER-encoded signatures, so its length varies per run (590/651/654
        // observed), and the failure looked random because only some lengths failed.
        //
        // The real cause was in the renderer, not the test: QRCodeWriter stretches the symbol to fill
        // the requested pixel width, so when the module count does not divide 420 the modules come out
        // fractional pixels wide and the writer rounds row by row. Against ZXing Core 3.5.4, 9 of 141
        // payload lengths fail to round trip that way. `renderQrBitmap` now asks for the natural module
        // count and renders at a whole number of pixels per module, so this is fixed at the source.
        //
        // `QrRenderDecodeRoundTripTest` (JVM, every length in the window, every run) is the guard that
        // keeps it fixed. The assertions below are unchanged and still require the full payload to
        // round-trip byte-for-byte.

        // Simulate CameraX ImageProxy YUV_420_888 plane with interleaved stride + ISP row padding
        val width = offerBitmap.width
        val height = offerBitmap.height
        val pixelStride = 2
        val rowStride = width * pixelStride + 32
        val yBuffer = ByteBuffer.allocateDirect(rowStride * height)
        for (y in 0 until height) {
            for (x in 0 until width) {
                val pixel = offerBitmap.getPixel(x, y)
                val luma = if (pixel == Color.BLACK) 0x10.toByte() else 0xF0.toByte()
                val idx = y * rowStride + x * pixelStride
                yBuffer.put(idx, luma)
            }
        }
        yBuffer.rewind()

        val contiguousY = QrBitmapCodec.extractContiguousLuminance(
            buffer = yBuffer,
            width = width,
            height = height,
            rowStride = rowStride,
            pixelStride = pixelStride
        )
        val decodedOfferText = QrBitmapCodec.decodeLuminance(contiguousY, width, height)
        // Explicit message: on failure the old assertion printed two enormous opaque strings, which made
        // this look like a payload mismatch rather than "the decoder returned null".
        assertTrue(
            "QR decode returned null for a ${offer.qrString.length}-char payload rendered at " +
                "${offerBitmap.width}px (module size ${offerBitmap.width / 101}). " +
                "A null result here means the rendered matrix was not readable, not that the payload differed.",
            decodedOfferText != null
        )
        assertEquals(offer.qrString, decodedOfferText)

        val responderStep = coordB.processScannedQr(decodedOfferText!!, t0 + 2)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm

        // Render & scan ACCEPT QR through padded Y-plane (pixelStride = 1, rowStride = width + 64)
        val acceptBmp = QrBitmapCodec.renderQrBitmap(responderStep.acceptQrToDisplay, sizePx = renderSizePx)
        val acceptRowStride = acceptBmp.width + 64
        val acceptBuffer = ByteBuffer.allocateDirect(acceptRowStride * acceptBmp.height)
        for (y in 0 until acceptBmp.height) {
            for (x in 0 until acceptBmp.width) {
                val luma = if (acceptBmp.getPixel(x, y) == Color.BLACK) 0.toByte() else 0xFF.toByte()
                acceptBuffer.put(y * acceptRowStride + x, luma)
            }
        }
        acceptBuffer.rewind()
        val acceptY = QrBitmapCodec.extractContiguousLuminance(
            buffer = acceptBuffer,
            width = acceptBmp.width,
            height = acceptBmp.height,
            rowStride = acceptRowStride,
            pixelStride = 1
        )
        val decodedAcceptText = QrBitmapCodec.decodeLuminance(acceptY, acceptBmp.width, acceptBmp.height)
        assertEquals(responderStep.acceptQrToDisplay, decodedAcceptText)

        val initiatorStep = coordA.processScannedQr(decodedAcceptText!!, t0 + 4)
                as PairingCoordinator.QrProcessResult.InitiatorReadyToConfirm

        assertEquals(responderStep.safetyNumber, initiatorStep.safetyNumber)
        val recA = coordA.confirmSafetyFingerprint(
            fullSafetyNumberComparedViaTrustedChannel = true,
            nowEpochSec = t0 + 5
        ).getOrThrow()
        val recB = coordB.confirmSafetyFingerprint(
            fullSafetyNumberComparedViaTrustedChannel = true,
            nowEpochSec = t0 + 5
        ).getOrThrow()
        assertArrayEquals(recA.rootPairingKey, recB.rootPairingKey)
    }

    @Test
    fun appRestartPersistenceAndCorruptedTrustStoreFailClosedRecovery() {
        val t0 = 1_735_001_000L

        // Boot #1: Pair Device A and Device B
        val offerQrUsed: String
        val initialDeviceIdHexA: String
        val expectedRootKeyHex: String
        run {
            val storeA = DirectoryFileByteStore(testDirA)
            val storeB = DirectoryFileByteStore(testDirB)
            val vaultA = AndroidKeystoreVault(appContext.packageManager, sealerA, storeA, aliasPrefix = prefixVaultA)
            val vaultB = AndroidKeystoreVault(appContext.packageManager, sealerB, storeB, aliasPrefix = prefixVaultB)
            initialDeviceIdHexA = vaultA.getOrCreateLocalIdentity(t0).deviceIdHex

            val coordA = PairingCoordinator(vaultA, PeerTrustStore(storeA, sealerA))
            val coordB = PairingCoordinator(vaultB, PeerTrustStore(storeB, sealerB))

            val offer = coordA.startInitiatorOffer(t0).getOrThrow()
            offerQrUsed = offer.qrString
            val resp = coordB.processScannedQr(offerQrUsed, t0 + 1)
                    as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
            coordA.processScannedQr(resp.acceptQrToDisplay, t0 + 2)

            val recA = coordA.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()
            coordB.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()
            expectedRootKeyHex = ByteEncoding.toHexLower(recA.rootPairingKey)
        }

        // Boot #2 (simulated process restart): reconstruct stores & vaults from disk + AndroidKeyStore
        run {
            val storeA = DirectoryFileByteStore(testDirA)
            val storeB = DirectoryFileByteStore(testDirB)
            val vaultA = AndroidKeystoreVault(appContext.packageManager, sealerA, storeA, aliasPrefix = prefixVaultA)
            val vaultB = AndroidKeystoreVault(appContext.packageManager, sealerB, storeB, aliasPrefix = prefixVaultB)
            assertEquals(initialDeviceIdHexA, vaultA.getOrCreateLocalIdentity(t0 + 10).deviceIdHex)

            val trustA = PeerTrustStore(storeA, sealerA)
            val trustB = PeerTrustStore(storeB, sealerB)
            val coordA = PairingCoordinator(vaultA, trustA)
            val coordB = PairingCoordinator(vaultB, trustB)

            val snapA = coordA.currentStateSnapshot(t0 + 10) as PairingStateSnapshot.PairedActive
            assertEquals(expectedRootKeyHex, ByteEncoding.toHexLower(snapA.peerRecord.rootPairingKey))

            // Unpair B cleanly so B archives A's identity, then verify replay ledger still rejects offerQrUsed!
            assertTrue(coordB.unpairForSecureRePairing(rotateDeviceIdentity = false, nowEpochSec = t0 + 11).isSuccess)
            assertTrue(trustB.readArchivedPreviousPeer() is ArchivedPeerReadResult.Valid)

            val replayAttempt = coordB.processScannedQr(offerQrUsed, t0 + 12)
            assertTrue(replayAttempt is PairingCoordinator.QrProcessResult.Rejected)
            assertEquals(
                PairingRejectionReason.REPLAYED_SESSION,
                (replayAttempt as PairingCoordinator.QrProcessResult.Rejected).reason
            )

            // Corrupt archived_peer_v1.bin on Device B -> MUST fail closed!
            val archivedFile = File(testDirB, "${PeerTrustStore.KEY_ARCHIVED_PEER}.bin")
            assertTrue(archivedFile.exists())
            val corruptedBytes = archivedFile.readBytes().also {
                it[it.lastIndex] = (it.last().toInt() xor 0xFF).toByte()
            }
            archivedFile.writeBytes(corruptedBytes)

            assertTrue(trustB.readArchivedPreviousPeer() is ArchivedPeerReadResult.Corrupted)
            val corruptedSnap = coordB.currentStateSnapshot(t0 + 15)
            assertTrue(corruptedSnap is PairingStateSnapshot.TrustStorageCorrupted)
            assertEquals(
                TrustStoreComponent.ARCHIVED_PEER,
                (corruptedSnap as PairingStateSnapshot.TrustStorageCorrupted).component
            )
            assertTrue(coordB.startInitiatorOffer(t0 + 15).isFailure)
            assertTrue(coordB.unpairForSecureRePairing(false, t0 + 15).isFailure)
            assertTrue(coordB.recoverFromCorruptedStorage(confirmDestructiveRecovery = false, nowEpochSec = t0 + 16).isFailure)

            // Explicit user-confirmed destructive recovery restores healthy state with rotated identity
            val recovered = coordB.recoverFromCorruptedStorage(
                confirmDestructiveRecovery = true,
                nowEpochSec = t0 + 17
            )
            assertTrue(recovered.isSuccess)
            assertEquals(PairingStateSnapshot.UnpairedIdle, coordB.currentStateSnapshot(t0 + 18))
        }
    }
}
