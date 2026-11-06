package com.duolink.app

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.DirectoryFileByteStore
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.HkdfSha256
import com.duolink.app.crypto.InMemoryByteStore
import com.duolink.app.crypto.JcaAesGcmSealer
import com.duolink.app.crypto.KeyProtectionTier
import com.duolink.app.crypto.KeyVaultStorageCorruptedException
import com.duolink.app.crypto.RawStoreRead
import com.duolink.app.crypto.SafetyFingerprint
import com.duolink.app.crypto.SealedSoftwareKeyVault
import com.duolink.app.crypto.VaultHealth
import com.duolink.app.pairing.ArchivedPeerReadResult
import com.duolink.app.pairing.PairingCoordinator
import com.duolink.app.pairing.PairingRejectionReason
import com.duolink.app.pairing.PairingStateSnapshot
import com.duolink.app.pairing.PairingValidationException
import com.duolink.app.pairing.PeerTrustStore
import com.duolink.app.pairing.PinnedPeerReadResult
import com.duolink.app.pairing.QrPairingCodec
import com.duolink.app.pairing.ReplayLedgerReadResult
import com.duolink.app.pairing.TrustStoreComponent
import org.junit.Test
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.GeneralSecurityException

class PairingAndCryptoTest {

    // -------------------------------------------------------------------------
    // 1. RFC 5869 Official HKDF-SHA256 Test Vectors
    // -------------------------------------------------------------------------

    @Test
    fun rfc5869TestVector1() {
        val ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = hexToBytes("000102030405060708090a0b0c")
        val info = hexToBytes("f0f1f2f3f4f5f6f7f8f9")
        val expectedPrk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        val expectedOkm =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

        val prk = HkdfSha256.extract(salt, ikm)
        val okm = HkdfSha256.deriveKey(ikm, salt, info, 42)
        check(ByteEncoding.toHexLower(prk) == expectedPrk) { "RFC 5869 Case 1 PRK mismatch" }
        check(ByteEncoding.toHexLower(okm) == expectedOkm) { "RFC 5869 Case 1 OKM mismatch" }
    }

    @Test
    fun rfc5869TestVector2LongInputs() {
        val ikm = ByteArray(80) { it.toByte() }
        val salt = ByteArray(80) { (0x60 + it).toByte() }
        val info = ByteArray(80) { (0xb0 + it).toByte() }
        val expectedOkm =
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f1d87"
        val okm = HkdfSha256.deriveKey(ikm, salt, info, 82)
        check(ByteEncoding.toHexLower(okm) == expectedOkm) { "RFC 5869 Case 2 OKM mismatch" }
    }

    @Test
    fun rfc5869TestVector3EmptySaltAndInfo() {
        val ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val expectedOkm =
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        val okm = HkdfSha256.deriveKey(ikm, ByteArray(0), ByteArray(0), 42)
        check(ByteEncoding.toHexLower(okm) == expectedOkm) { "RFC 5869 Case 3 OKM mismatch" }
    }

    // -------------------------------------------------------------------------
    // 2. StorageSealer (AES-256-GCM + AAD)
    // -------------------------------------------------------------------------

    @Test
    fun storageSealerRoundTripAndTamperRejection() {
        val sealer = JcaAesGcmSealer()
        val aad = "duolink:test:aad".toByteArray(StandardCharsets.UTF_8)
        val secret = "نسرین خانم — تست رمزنگاری محلی".toByteArray(StandardCharsets.UTF_8)

        val sealed1 = sealer.seal(secret, aad)
        val sealed2 = sealer.seal(secret, aad)
        check(!sealed1.contentEquals(sealed2)) { "Random IV must make repeated seals distinct" }
        check(sealer.unseal(sealed1, aad).contentEquals(secret)) { "Unseal failed" }

        expectThrows<GeneralSecurityException>("Wrong AAD must fail GCM tag verification") {
            sealer.unseal(sealed1, "duolink:wrong:aad".toByteArray(StandardCharsets.UTF_8))
        }

        val flipped = sealed1.copyOf()
        flipped[flipped.lastIndex] = (flipped.last().toInt() xor 0x01).toByte()
        expectThrows<GeneralSecurityException>("Bit flip in ciphertext/tag must fail GCM") {
            sealer.unseal(flipped, aad)
        }
    }

    // -------------------------------------------------------------------------
    // 3. DeviceKeyVault, ECDSA-P256, ECDH-P256 & Pre-Key Rotation
    // -------------------------------------------------------------------------

    @Test
    fun ecdhSharedSecretSymmetryAndPreKeyRotation() {
        val vaultA = SealedSoftwareKeyVault()
        val vaultB = SealedSoftwareKeyVault()
        val idA = vaultA.getOrCreateLocalIdentity(1_700_000_000L)
        val idB = vaultB.getOrCreateLocalIdentity(1_700_000_000L)

        check(EcP256Crypto.verifySignedPreKey(idA.deviceId, idA.identitySigningPublicKeySpki, idA.currentSignedPreKey))
        check(EcP256Crypto.verifySignedPreKey(idB.deviceId, idB.identitySigningPublicKeySpki, idB.currentSignedPreKey))

        val sharedAB = vaultA.agreeWithSignedPreKey(
            localSpkId = idA.currentSignedPreKey.spkId,
            peerPublicKeySpki = idB.currentSignedPreKey.publicKeySpki
        )
        val sharedBA = vaultB.agreeWithSignedPreKey(
            localSpkId = idB.currentSignedPreKey.spkId,
            peerPublicKeySpki = idA.currentSignedPreKey.publicKeySpki
        )
        check(sharedAB.contentEquals(sharedBA)) { "ECDH shared secrets must match identically" }

        val spk2 = vaultA.rotateSignedPreKey(1_700_000_100L)
        check(spk2.spkId == 2) { "Expected rotated SPK id 2" }
        val sharedOld = vaultA.agreeWithSignedPreKey(1, idB.currentSignedPreKey.publicKeySpki)
        check(sharedOld.contentEquals(sharedBA)) { "Retained previous SPK must still work" }

        vaultA.rotateSignedPreKey(1_700_000_200L) // spk 3
        vaultA.rotateSignedPreKey(1_700_000_300L) // spk 4 -> evicts spk 1
        expectThrows<GeneralSecurityException>("Evicted SPK #1 must be purged") {
            vaultA.agreeWithSignedPreKey(1, idB.currentSignedPreKey.publicKeySpki)
        }
    }

    // -------------------------------------------------------------------------
    // 4. Safety Number Symmetry & Sensitivity
    // -------------------------------------------------------------------------

    @Test
    fun safetyFingerprintIsOrderIndependentAndCollisionSensitive() {
        val vaultA = SealedSoftwareKeyVault()
        val vaultB = SealedSoftwareKeyVault()
        val vaultMallory = SealedSoftwareKeyVault()
        val idA = vaultA.getOrCreateLocalIdentity(1_700_000_000L)
        val idB = vaultB.getOrCreateLocalIdentity(1_700_000_000L)
        val idM = vaultMallory.getOrCreateLocalIdentity(1_700_000_000L)

        val snAB = SafetyFingerprint.computeSafetyNumber(
            idA.deviceId,
            idA.identitySigningPublicKeySpki,
            idB.deviceId,
            idB.identitySigningPublicKeySpki
        )
        val snBA = SafetyFingerprint.computeSafetyNumber(
            idB.deviceId,
            idB.identitySigningPublicKeySpki,
            idA.deviceId,
            idA.identitySigningPublicKeySpki
        )
        check(snAB == snBA) { "Safety Number must be identical regardless of initiator/responder order" }

        val digitsOnly = snAB.filter { it.isDigit() }
        check(digitsOnly.length == 60) { "Safety Number must contain exactly 60 digits, got ${digitsOnly.length}" }

        val snAM = SafetyFingerprint.computeSafetyNumber(
            idA.deviceId,
            idA.identitySigningPublicKeySpki,
            idM.deviceId,
            idM.identitySigningPublicKeySpki
        )
        check(snAB != snAM) { "MITM identity substitution must alter Safety Number" }
    }

    // -------------------------------------------------------------------------
    // 5. Mutual QR Handshake Happy Path & Shared Key Equality
    // -------------------------------------------------------------------------

    @Test
    fun mutualTwoStepQrPairingDerivesIdenticalRootKeyAndSafetyNumber() {
        val envA = TestNode(1_700_010_000L)
        val envB = TestNode(1_700_010_000L)
        val t0 = 1_700_010_050L

        val offer = envA.coordinator.startInitiatorOffer(t0).getOrThrow()
        check(offer.qrString.startsWith(QrPairingCodec.URI_PREFIX))

        val stepB = envB.coordinator.processScannedQr(offer.qrString, t0 + 5)
        check(stepB is PairingCoordinator.QrProcessResult.ResponderReadyToConfirm)
        check(!stepB.previousPeerChanged)
        check(envB.trustStore.readPinnedPeer() is PinnedPeerReadResult.None) {
            "Peer MUST NOT be persisted before explicit user Safety Number confirmation"
        }

        val stepA = envA.coordinator.processScannedQr(stepB.acceptQrToDisplay, t0 + 10)
        check(stepA is PairingCoordinator.QrProcessResult.InitiatorReadyToConfirm)
        check(stepA.safetyNumber == stepB.safetyNumber) { "Both devices must compute identical 60-digit Safety Number" }
        check(stepA.publicHandshakeTranscriptId == stepB.publicHandshakeTranscriptId) {
            "Both devices must compute identical public handshake transcript ID"
        }

        val recA = envA.coordinator.confirmSafetyFingerprint(
            fullSafetyNumberComparedViaTrustedChannel = true,
            nowEpochSec = t0 + 15
        ).getOrThrow()
        val recB = envB.coordinator.confirmSafetyFingerprint(
            fullSafetyNumberComparedViaTrustedChannel = true,
            nowEpochSec = t0 + 15
        ).getOrThrow()

        check(recA.rootPairingKey.contentEquals(recB.rootPairingKey)) {
            "Derived 256-bit K_pair_root must match bit-for-bit on both devices"
        }
        check(recA.safetyNumberVerified && recB.safetyNumberVerified)
        check(recA.peerDeviceId.contentEquals(envB.localId.deviceId))
        check(recB.peerDeviceId.contentEquals(envA.localId.deviceId))
    }

    // -------------------------------------------------------------------------
    // 6. Security Rejection Tests: Tampering, Expiry, Skew, Replay, 3rd Device, MITM
    // -------------------------------------------------------------------------

    @Test
    fun tamperedQrPayloadIsRejected() {
        val envA = TestNode(1_700_020_000L)
        val envB = TestNode(1_700_020_000L)
        val offer = envA.coordinator.startInitiatorOffer(1_700_020_010L).getOrThrow()

        val rawBytes = ByteEncoding.decodeBase64UrlStrict(offer.qrString.removePrefix(QrPairingCodec.URI_PREFIX))
        rawBytes[30] = (rawBytes[30].toInt() xor 0xFF).toByte()
        val tamperedQr = QrPairingCodec.URI_PREFIX + ByteEncoding.encodeBase64Url(rawBytes)

        val res = envB.coordinator.processScannedQr(tamperedQr, 1_700_020_015L)
        check(res is PairingCoordinator.QrProcessResult.Rejected)
        check(
            res.reason == PairingRejectionReason.INVALID_IDENTITY_SIGNATURE ||
                res.reason == PairingRejectionReason.INVALID_PUBLIC_KEY ||
                res.reason == PairingRejectionReason.MALFORMED_PAYLOAD
        ) { "Unexpected rejection reason for tampered QR: ${res.reason}" }
    }

    @Test
    fun expiredQrAndFutureClockSkewAreRejected() {
        val envA = TestNode(1_700_030_000L)
        val envB = TestNode(1_700_030_000L)
        val t0 = 1_700_030_000L
        val offer = envA.coordinator.startInitiatorOffer(t0).getOrThrow()

        val expiredRes = envB.coordinator.processScannedQr(offer.qrString, t0 + 301L)
        check(expiredRes is PairingCoordinator.QrProcessResult.Rejected)
        check(expiredRes.reason == PairingRejectionReason.EXPIRED_QR)

        val skewRes = envB.coordinator.processScannedQr(offer.qrString, t0 - 120L)
        check(skewRes is PairingCoordinator.QrProcessResult.Rejected)
        check(skewRes.reason == PairingRejectionReason.FUTURE_TIMESTAMP_SKEW)
    }

    @Test
    fun replayedOfferAndAcceptPacketsAreRejected() {
        val envA = TestNode(1_700_040_000L)
        val envB = TestNode(1_700_040_000L)
        val t0 = 1_700_040_000L
        val offer = envA.coordinator.startInitiatorOffer(t0).getOrThrow()

        val firstScan = envB.coordinator.processScannedQr(offer.qrString, t0 + 2)
        check(firstScan is PairingCoordinator.QrProcessResult.ResponderReadyToConfirm)

        envB.coordinator.cancelPendingPairing()
        val replayScan = envB.coordinator.processScannedQr(offer.qrString, t0 + 5)
        check(replayScan is PairingCoordinator.QrProcessResult.Rejected)
        check(replayScan.reason == PairingRejectionReason.REPLAYED_SESSION)
    }

    @Test
    fun selfPairingIsRejected() {
        val envA = TestNode(1_700_050_000L)
        val t0 = 1_700_050_000L
        val offer = envA.coordinator.startInitiatorOffer(t0).getOrThrow()
        val selfRes = envA.coordinator.processScannedQr(offer.qrString, t0 + 1)
        check(selfRes is PairingCoordinator.QrProcessResult.Rejected)
        check(selfRes.reason == PairingRejectionReason.SELF_PAIRING_FORBIDDEN)
    }

    @Test
    fun thirdDevicePairingAttemptIsBlockedOncePaired() {
        val envA = TestNode(1_700_060_000L)
        val envB = TestNode(1_700_060_000L)
        val envIntruder = TestNode(1_700_060_000L)
        val t0 = 1_700_060_000L

        val offer = envA.coordinator.startInitiatorOffer(t0).getOrThrow()
        val resp = envB.coordinator.processScannedQr(offer.qrString, t0 + 1)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
        envA.coordinator.processScannedQr(resp.acceptQrToDisplay, t0 + 2)
        envA.coordinator.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()
        envB.coordinator.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()

        val intruderOffer = envIntruder.coordinator.startInitiatorOffer(t0 + 10).getOrThrow()
        val blockedScan = envA.coordinator.processScannedQr(intruderOffer.qrString, t0 + 11)
        check(blockedScan is PairingCoordinator.QrProcessResult.Rejected)
        check(blockedScan.reason == PairingRejectionReason.THIRD_DEVICE_BLOCKED)

        val blockedNewOffer = envA.coordinator.startInitiatorOffer(t0 + 12)
        check(blockedNewOffer.isFailure)
    }

    @Test
    fun acceptPacketBoundToDifferentOfferIsRejected() {
        val envA1 = TestNode(1_700_070_000L)
        val envA2 = TestNode(1_700_070_000L)
        val envB = TestNode(1_700_070_000L)
        val t0 = 1_700_070_000L

        val offer1 = envA1.coordinator.startInitiatorOffer(t0).getOrThrow()
        envA2.coordinator.startInitiatorOffer(t0).getOrThrow()

        val respTo1 = envB.coordinator.processScannedQr(offer1.qrString, t0 + 1)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm

        val wrongTarget = envA2.coordinator.processScannedQr(respTo1.acceptQrToDisplay, t0 + 2)
        check(wrongTarget is PairingCoordinator.QrProcessResult.Rejected)
        check(wrongTarget.reason == PairingRejectionReason.SESSION_MISMATCH)
    }

    @Test
    fun activeMitmQrSubstitutionProducesDivergentSafetyNumbers() {
        val alice = TestNode(1_700_080_000L)
        val bob = TestNode(1_700_080_000L)
        val malloryToAlice = TestNode(1_700_080_000L)
        val malloryToBob = TestNode(1_700_080_000L)
        val t0 = 1_700_080_000L

        val aliceOffer = alice.coordinator.startInitiatorOffer(t0).getOrThrow()
        val mAcceptForAlice = malloryToAlice.coordinator.processScannedQr(aliceOffer.qrString, t0 + 1)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
        val aliceConfirmStage = alice.coordinator.processScannedQr(mAcceptForAlice.acceptQrToDisplay, t0 + 2)
                as PairingCoordinator.QrProcessResult.InitiatorReadyToConfirm

        val mOfferForBob = malloryToBob.coordinator.startInitiatorOffer(t0 + 1).getOrThrow()
        val bobConfirmStage = bob.coordinator.processScannedQr(mOfferForBob.qrString, t0 + 2)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm

        check(aliceConfirmStage.safetyNumber != bobConfirmStage.safetyNumber) {
            "Active MITM substitution MUST yield different 60-digit Safety Numbers on Alice and Bob"
        }
    }

    // -------------------------------------------------------------------------
    // 7. Secure Re-Pairing & Key-Change Warning Detection
    // -------------------------------------------------------------------------

    @Test
    fun secureRePairingFlagsKeyChangeAndRequiresExplicitAcknowledgement() {
        val envA = TestNode(1_700_090_000L)
        val envB = TestNode(1_700_090_000L)
        val t0 = 1_700_090_000L

        val offer1 = envA.coordinator.startInitiatorOffer(t0).getOrThrow()
        val resp1 = envB.coordinator.processScannedQr(offer1.qrString, t0 + 1)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
        envA.coordinator.processScannedQr(resp1.acceptQrToDisplay, t0 + 2)
        envA.coordinator.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()
        envB.coordinator.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()

        check(envA.coordinator.unpairForSecureRePairing(rotateDeviceIdentity = false, nowEpochSec = t0 + 100).isSuccess)
        check(envB.coordinator.unpairForSecureRePairing(rotateDeviceIdentity = true, nowEpochSec = t0 + 100).isSuccess)

        val offer2 = envA.coordinator.startInitiatorOffer(t0 + 110).getOrThrow()
        val resp2 = envB.coordinator.processScannedQr(offer2.qrString, t0 + 111)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
        val init2 = envA.coordinator.processScannedQr(resp2.acceptQrToDisplay, t0 + 112)
                as PairingCoordinator.QrProcessResult.InitiatorReadyToConfirm

        check(init2.previousPeerChanged) { "Device A must detect that Device B's identity key changed" }
        check(!resp2.previousPeerChanged) { "Device B must see that Device A kept the same identity key" }

        val unacknowledged = envA.coordinator.confirmSafetyFingerprint(
            fullSafetyNumberComparedViaTrustedChannel = true,
            nowEpochSec = t0 + 115,
            acknowledgeKeyChange = false
        )
        check(unacknowledged.isFailure) { "Key change must block confirmation until explicitly acknowledged" }

        val acknowledged = envA.coordinator.confirmSafetyFingerprint(
            fullSafetyNumberComparedViaTrustedChannel = true,
            nowEpochSec = t0 + 116,
            acknowledgeKeyChange = true
        )
        check(acknowledged.isSuccess)
    }

    // -------------------------------------------------------------------------
    // 8. QR Luminance Padding Extraction & Malformed Input Resilience
    // -------------------------------------------------------------------------

    @Test
    fun malformedAndGarbageQrStringsAreSafelyRejected() {
        val env = TestNode(1_700_100_000L)
        val inputs = listOf(
            "",
            "https://example.com/evil",
            "duolink://pair/v1?p=!!!not_base64!!!",
            "duolink://pair/v1?p=" + ByteEncoding.encodeBase64Url(ByteArray(12) { 0x42 }),
            "duolink://pair/v99?p=AAAA"
        )
        for (bad in inputs) {
            val r = env.coordinator.processScannedQr(bad, 1_700_100_010L)
            check(r is PairingCoordinator.QrProcessResult.Rejected) {
                "Expected rejection for malformed input '$bad'"
            }
        }
    }

    @Test
    fun forgedSpkSignatureInsideQrPacketIsRejected() {
        val envA = TestNode(1_700_110_000L)
        val envB = TestNode(1_700_110_000L)
        val t0 = 1_700_110_000L
        val offer = envA.coordinator.startInitiatorOffer(t0).getOrThrow()

        val decoded = QrPairingCodec.decodeAndVerifySignatures(offer.qrString)
        val forgedSpkSig: ByteArray = decoded.senderSpk.signatureByIdentityKey.copyOf()
        forgedSpkSig[forgedSpkSig.size - 1] = (forgedSpkSig[forgedSpkSig.size - 1].toInt() xor 0x01).toByte()
        val forgedIdentity = com.duolink.app.crypto.LocalIdentityPublic(
            deviceId = decoded.senderDeviceId,
            identitySigningPublicKeySpki = decoded.senderIkSigSpki,
            currentSignedPreKey = decoded.senderSpk.copyOfWithSig(forgedSpkSig)
        )
        val reSignedQrWithBadSpk = QrPairingCodec.encodeSignedPacket(
            role = decoded.role,
            sessionId = decoded.sessionId,
            issuedAtEpochSec = decoded.issuedAtEpochSec,
            expiresAtEpochSec = decoded.expiresAtEpochSec,
            localIdentity = forgedIdentity,
            senderNonce = decoded.senderNonce,
            targetInitiatorDeviceId = null,
            boundOfferDigest = null,
            keyVault = envA.vault
        )

        val res = envB.coordinator.processScannedQr(reSignedQrWithBadSpk, t0 + 2)
        check(res is PairingCoordinator.QrProcessResult.Rejected)
        check(res.reason == PairingRejectionReason.INVALID_SPK_SIGNATURE) {
            "Expected INVALID_SPK_SIGNATURE, got ${res.reason}"
        }
    }

    @Test
    fun invalidNonP256SpkiIsRejected() {
        val fakeSpki = ByteArray(91) { 0x30 }
        expectThrows<GeneralSecurityException>("Malformed SPKI must be rejected") {
            EcP256Crypto.decodeAndValidateP256PublicKey(fakeSpki)
        }
    }

    @Test
    fun canonicalBase64UrlAndQrBinaryCodecRejectNonCanonicalAndTrailingBytes() {
        val envA = TestNode(1_700_120_000L)
        val t0 = 1_700_120_000L
        val offer = envA.coordinator.startInitiatorOffer(t0).getOrThrow()

        // 1) Appending a trailing byte inside the Base64URL payload MUST fail strict wire decoding
        val raw = ByteEncoding.decodeBase64UrlStrict(offer.qrString.removePrefix(QrPairingCodec.URI_PREFIX))
        val withTrailing = raw + byteArrayOf(0x00)
        val trailingQr = QrPairingCodec.URI_PREFIX + ByteEncoding.encodeBase64Url(withTrailing)
        expectThrows<PairingValidationException>("Trailing bytes in QR packet must be rejected") {
            QrPairingCodec.decodeAndVerifySignatures(trailingQr)
        }

        // 2) Padding '=' in Base64URL must be rejected by strict canonical decoder
        expectThrows<IllegalArgumentException>("Base64URL padding must be rejected") {
            ByteEncoding.decodeBase64UrlStrict("AQID=")
        }
    }

    // -------------------------------------------------------------------------
    // 9. NEW MILESTONE 2 REVIEW REGRESSION TESTS (Findings 1, 2, 3, 6)
    // -------------------------------------------------------------------------

    @Test
    fun corruptedArchivedPeerBlocksRePairingFailClosedUntilExplicitRecovery() {
        val envA = TestNode(1_700_200_000L)
        val envB = TestNode(1_700_200_000L)
        val envC = TestNode(1_700_200_000L)
        val t0 = 1_700_200_000L

        // Pair A & B, then unpair A so archived_peer_v1 is recorded on A
        val offer1 = envA.coordinator.startInitiatorOffer(t0).getOrThrow()
        val resp1 = envB.coordinator.processScannedQr(offer1.qrString, t0 + 1)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
        envA.coordinator.processScannedQr(resp1.acceptQrToDisplay, t0 + 2)
        envA.coordinator.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()
        envB.coordinator.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()

        check(envA.coordinator.unpairForSecureRePairing(false, t0 + 10).isSuccess)
        check(envA.trustStore.readArchivedPreviousPeer() is ArchivedPeerReadResult.Valid)

        // Flip 1 bit in archived_peer_v1 -> MUST NOT return None! MUST block re-pairing fail-closed!
        envA.trustRawStore.corruptRawBytesForTesting(PeerTrustStore.KEY_ARCHIVED_PEER) { bytes ->
            bytes.also { it[it.lastIndex] = (it.last().toInt() xor 0x01).toByte() }
        }
        val corruptedRead = envA.trustStore.readArchivedPreviousPeer()
        check(corruptedRead is ArchivedPeerReadResult.Corrupted) {
            "Corrupted archived_peer_v1 MUST return Corrupted, got $corruptedRead"
        }

        val snap = envA.coordinator.currentStateSnapshot(t0 + 12)
        check(snap is PairingStateSnapshot.TrustStorageCorrupted && snap.component == TrustStoreComponent.ARCHIVED_PEER)

        // Offer creation, QR scanning, and normal unpairing MUST all fail closed
        check(envA.coordinator.startInitiatorOffer(t0 + 13).isFailure)
        val incomingFromC = envC.coordinator.startInitiatorOffer(t0 + 13).getOrThrow()
        val scanRes = envA.coordinator.processScannedQr(incomingFromC.qrString, t0 + 14)
        check(scanRes is PairingCoordinator.QrProcessResult.Rejected)
        check(scanRes.reason == PairingRejectionReason.TRUST_STORAGE_CORRUPTED)
        check(envA.coordinator.unpairForSecureRePairing(false, t0 + 15).isFailure)

        // Recovery without explicit confirmation MUST fail
        check(envA.coordinator.recoverFromCorruptedStorage(confirmDestructiveRecovery = false, nowEpochSec = t0 + 16).isFailure)

        // Explicit destructive recovery succeeds, rotates device identity, and restores UnpairedIdle
        val oldDeviceIdHex = envA.localId.deviceIdHex
        val freshIdentity = envA.coordinator.recoverFromCorruptedStorage(
            confirmDestructiveRecovery = true,
            nowEpochSec = t0 + 17
        ).getOrThrow()
        check(freshIdentity.deviceIdHex != oldDeviceIdHex) {
            "Explicit recovery must issue a fresh device identity"
        }
        check(envA.coordinator.currentStateSnapshot(t0 + 18) is PairingStateSnapshot.UnpairedIdle)

        // Also test 0-byte truncation of archived_peer_v1 -> MUST also return Corrupted
        envA.trustRawStore.writeZeroByteEntryForTesting(PeerTrustStore.KEY_ARCHIVED_PEER)
        check(envA.trustStore.readArchivedPreviousPeer() is ArchivedPeerReadResult.Corrupted)
    }

    @Test
    fun corruptedPinnedPeerAndDeletedOrCorruptedReplayLedgerFailClosed() {
        val envA = TestNode(1_700_210_000L)
        val envB = TestNode(1_700_210_000L)
        val t0 = 1_700_210_000L

        val offer = envA.coordinator.startInitiatorOffer(t0).getOrThrow()
        val resp = envB.coordinator.processScannedQr(offer.qrString, t0 + 1)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
        envA.coordinator.processScannedQr(resp.acceptQrToDisplay, t0 + 2)
        envA.coordinator.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()
        envB.coordinator.confirmSafetyFingerprint(true, t0 + 3).getOrThrow()

        // 1) Deleting replay_ledger_v1 alongside active pinned_peer_v1 MUST be flagged as Corrupted!
        envA.trustRawStore.delete(PeerTrustStore.KEY_REPLAY_LEDGER)
        val snapDeletedReplay = envA.coordinator.currentStateSnapshot(t0 + 5)
        check(
            snapDeletedReplay is PairingStateSnapshot.TrustStorageCorrupted &&
                snapDeletedReplay.component == TrustStoreComponent.REPLAY_LEDGER
        ) { "Deleting replay_ledger_v1 while paired MUST fail closed, got $snapDeletedReplay" }

        // 2) Corrupting replay_ledger_v1 bytes on Device B MUST fail closed instead of resetting to empty list!
        envB.trustRawStore.corruptRawBytesForTesting(PeerTrustStore.KEY_REPLAY_LEDGER) { bytes ->
            bytes.also { it[it.lastIndex] = (it.last().toInt() xor 0x55).toByte() }
        }
        check(envB.trustStore.readReplayLedger() is ReplayLedgerReadResult.Corrupted)
        check(envB.coordinator.unpairForSecureRePairing(false, t0 + 6).isFailure)

        // 3) Recover Device B, pair again, then corrupt pinned_peer_v1 -> MUST fail closed!
        envA.coordinator.recoverFromCorruptedStorage(true, t0 + 7).getOrThrow()
        envB.coordinator.recoverFromCorruptedStorage(true, t0 + 7).getOrThrow()
        val offer2 = envA.coordinator.startInitiatorOffer(t0 + 8).getOrThrow()
        val resp2 = envB.coordinator.processScannedQr(offer2.qrString, t0 + 9)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
        envA.coordinator.processScannedQr(resp2.acceptQrToDisplay, t0 + 10)
        envA.coordinator.confirmSafetyFingerprint(true, t0 + 11).getOrThrow()

        envA.trustRawStore.corruptRawBytesForTesting(PeerTrustStore.KEY_PINNED_PEER) { bytes ->
            bytes.also { it[10] = (it[10].toInt() xor 0xFF).toByte() }
        }
        check(envA.trustStore.readPinnedPeer() is PinnedPeerReadResult.Corrupted)
        val snapPinnedCorrupt = envA.coordinator.currentStateSnapshot(t0 + 12)
        check(
            snapPinnedCorrupt is PairingStateSnapshot.TrustStorageCorrupted &&
                snapPinnedCorrupt.component == TrustStoreComponent.PINNED_PEER
        )
    }

    @Test
    fun corruptedOrDeletedSpkMetadataAndSealedSpkFailClosed() {
        val sealer = JcaAesGcmSealer()
        val vaultStore = InMemoryByteStore()
        val vault = SealedSoftwareKeyVault(sealer = sealer, byteStore = vaultStore)
        val trustStore = PeerTrustStore(InMemoryByteStore(), sealer)
        val coordinator = PairingCoordinator(vault, trustStore)
        val t0 = 1_700_220_000L

        vault.getOrCreateLocalIdentity(t0)
        check(vault.checkVaultHealth() is VaultHealth.Healthy)

        // Case 1: Corrupt spk_entries_v2 -> MUST NOT return emptyList() or reset spkId to 1!
        val originalSpkMeta = (vaultStore.readState("spk_entries_v2") as RawStoreRead.Present).bytes
        vaultStore.corruptRawBytesForTesting("spk_entries_v2") { bytes ->
            bytes.also { it[it.lastIndex] = (it.last().toInt() xor 0x01).toByte() }
        }
        check(vault.checkVaultHealth() is VaultHealth.Corrupted)
        expectThrows<KeyVaultStorageCorruptedException>("Corrupted SPK metadata must throw fail-closed") {
            vault.getOrCreateLocalIdentity(t0 + 1)
        }
        val snap1 = coordinator.currentStateSnapshot(t0 + 1)
        check(snap1 is PairingStateSnapshot.TrustStorageCorrupted && snap1.component == TrustStoreComponent.KEY_VAULT)
        check(coordinator.startInitiatorOffer(t0 + 1).isFailure)

        // Restore valid spk_entries_v2, then test deleting spk_entries_v2 while vault_init_v2 remains
        vaultStore.write("spk_entries_v2", originalSpkMeta)
        check(vault.checkVaultHealth() is VaultHealth.Healthy)
        vaultStore.delete("spk_entries_v2")
        check(vault.checkVaultHealth() is VaultHealth.Corrupted)

        // Restore valid spk_entries_v2, then corrupt sealed_spk_v2_1 private key blob
        vaultStore.write("spk_entries_v2", originalSpkMeta)
        vaultStore.corruptRawBytesForTesting("sealed_spk_v2_1") { bytes ->
            bytes.also { it[it.lastIndex] = (it.last().toInt() xor 0x0F).toByte() }
        }
        check(vault.checkVaultHealth() is VaultHealth.Corrupted)

        // Explicit coordinator recovery restores vault & trust health cleanly
        check(coordinator.recoverFromCorruptedStorage(confirmDestructiveRecovery = true, nowEpochSec = t0 + 5).isSuccess)
        check(vault.checkVaultHealth() is VaultHealth.Healthy)
    }

    @Test
    fun atomicDirectoryFileByteStoreCrashRecoveryAndZeroByteDetection() {
        val tempDir = Files.createTempDirectory("duolink_crash_test").toFile()
        try {
            val fileStore = DirectoryFileByteStore(tempDir)
            val committedPayload = "committed-v1-security-record".toByteArray(StandardCharsets.UTF_8)
            fileStore.write("pinned_peer_v1", committedPayload)

            // 1) Simulate crash during an update write leaving an incomplete .tmp file alongside intact .bin
            val orphanUpdateTmp = File(tempDir, "pinned_peer_v1.bin.tmp")
            orphanUpdateTmp.writeBytes(byteArrayOf(0x01, 0x02))
            val readAfterUpdateCrash = fileStore.readState("pinned_peer_v1")
            check(readAfterUpdateCrash is RawStoreRead.Present && readAfterUpdateCrash.bytes.contentEquals(committedPayload)) {
                "Committed record must survive interrupted .tmp update intact"
            }
            check(!orphanUpdateTmp.exists()) { "Orphaned .tmp file must be cleaned up on read" }

            // 2) Simulate crash during initial creation before .bin ever existed
            val orphanInitialTmp = File(tempDir, "never_committed.bin.tmp")
            orphanInitialTmp.writeBytes(byteArrayOf(0xAA.toByte()))
            val readInitialCrash = fileStore.readState("never_committed")
            check(readInitialCrash is RawStoreRead.Missing)
            check(!orphanInitialTmp.exists())

            // 3) Simulate 0-byte truncated security file on disk -> MUST return CorruptedIo, NEVER Missing!
            val truncatedBin = File(tempDir, "archived_peer_v1.bin")
            truncatedBin.writeBytes(ByteArray(0))
            val zeroRead = fileStore.readState("archived_peer_v1")
            check(zeroRead is RawStoreRead.CorruptedIo) {
                "Zero-byte security file MUST be reported as CorruptedIo, got $zeroRead"
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun keyProtectionReportSeparatesIdentityWrappingAndSoftwareSpkHonestly() {
        val vault = SealedSoftwareKeyVault()
        val report = vault.getKeyProtectionReport(1_700_230_000L)

        check(report.activeSignedPreKey.tier == KeyProtectionTier.SOFTWARE_WRAPPED_AT_REST)
        check(!report.activeSignedPreKey.isHardwareBacked) {
            "Software-wrapped SPK_dh MUST NEVER claim hardware backing"
        }
        check(!report.activeSignedPreKey.isKeystoreNonExportable) {
            "Software-wrapped SPK_dh MUST NEVER claim Keystore non-exportability"
        }
        check(report.identitySigningKey.keyRolePersian != report.storageWrappingKey.keyRolePersian)
        check(report.storageWrappingKey.keyRolePersian != report.activeSignedPreKey.keyRolePersian)
    }

    @Test
    fun confirmSafetyFingerprintRequiresFull60DigitTrustedChannelComparison() {
        val envA = TestNode(1_700_240_000L)
        val envB = TestNode(1_700_240_000L)
        val t0 = 1_700_240_000L

        val offer = envA.coordinator.startInitiatorOffer(t0).getOrThrow()
        val resp = envB.coordinator.processScannedQr(offer.qrString, t0 + 1)
                as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
        val init = envA.coordinator.processScannedQr(resp.acceptQrToDisplay, t0 + 2)
                as PairingCoordinator.QrProcessResult.InitiatorReadyToConfirm

        check(init.publicHandshakeTranscriptId.length == 14) { "Expected XXXX-XXXX-XXXX diagnostic ID" }
        check(init.safetyNumber.filter { it.isDigit() }.length == 60)

        // Attempting to confirm without comparing all 60 digits via trusted channel MUST fail!
        val rejected = envA.coordinator.confirmSafetyFingerprint(
            fullSafetyNumberComparedViaTrustedChannel = false,
            nowEpochSec = t0 + 3
        )
        check(rejected.isFailure)
        check(envA.trustStore.readPinnedPeer() is PinnedPeerReadResult.None)

        // Confirming after full 60-digit verification succeeds
        check(envA.coordinator.confirmSafetyFingerprint(true, t0 + 4).isSuccess)
    }

    @Test
    fun simulatedProcessRestartPreservesIdentityTrustReplayAndMonotonicSpkId() {
        val dirA = Files.createTempDirectory("duolink_restart_a").toFile()
        val dirB = Files.createTempDirectory("duolink_restart_b").toFile()
        val fixedMskA = ByteArray(32) { (0x11 + it).toByte() }
        val fixedMskB = ByteArray(32) { (0x61 + it).toByte() }
        val t0 = 1_700_250_000L

        try {
            val usedOfferQr: String
            val initialIdHexA: String
            val pairedRootHex: String

            // Process lifetime #1
            run {
                val sealerA = JcaAesGcmSealer(fixedMskA)
                val sealerB = JcaAesGcmSealer(fixedMskB)
                val vaultA = SealedSoftwareKeyVault(sealerA, DirectoryFileByteStore(dirA))
                val vaultB = SealedSoftwareKeyVault(sealerB, DirectoryFileByteStore(dirB))
                initialIdHexA = vaultA.getOrCreateLocalIdentity(t0).deviceIdHex

                // Rotate SPK 4 times so SPK #1 and #2 are pruned, highestIssuedSpkId == 5
                repeat(4) { idx -> vaultA.rotateSignedPreKey(t0 + idx + 1) }
                check(vaultA.getOrCreateLocalIdentity(t0 + 5).currentSignedPreKey.spkId == 5)

                val coordA = PairingCoordinator(vaultA, PeerTrustStore(DirectoryFileByteStore(dirA), sealerA))
                val coordB = PairingCoordinator(vaultB, PeerTrustStore(DirectoryFileByteStore(dirB), sealerB))

                val offer = coordA.startInitiatorOffer(t0 + 10).getOrThrow()
                usedOfferQr = offer.qrString
                val resp = coordB.processScannedQr(usedOfferQr, t0 + 11)
                        as PairingCoordinator.QrProcessResult.ResponderReadyToConfirm
                coordA.processScannedQr(resp.acceptQrToDisplay, t0 + 12)
                val recA = coordA.confirmSafetyFingerprint(true, t0 + 13).getOrThrow()
                coordB.confirmSafetyFingerprint(true, t0 + 13).getOrThrow()
                pairedRootHex = ByteEncoding.toHexLower(recA.rootPairingKey)
            }

            // Process lifetime #2 (brand-new objects over persisted DirectoryFileByteStore)
            run {
                val sealerA = JcaAesGcmSealer(fixedMskA)
                val sealerB = JcaAesGcmSealer(fixedMskB)
                val vaultA = SealedSoftwareKeyVault(sealerA, DirectoryFileByteStore(dirA))
                val vaultB = SealedSoftwareKeyVault(sealerB, DirectoryFileByteStore(dirB))

                val reloadedIdA = vaultA.getOrCreateLocalIdentity(t0 + 20)
                check(reloadedIdA.deviceIdHex == initialIdHexA) { "Device ID must persist across restart" }
                check(reloadedIdA.currentSignedPreKey.spkId == 5) { "Active SPK ID #5 must persist across restart" }

                val rotatedAfterRestart = vaultA.rotateSignedPreKey(t0 + 21)
                check(rotatedAfterRestart.spkId == 6) { "Monotonic SPK ID must advance to 6 after restart" }

                val coordA = PairingCoordinator(vaultA, PeerTrustStore(DirectoryFileByteStore(dirA), sealerA))
                val coordB = PairingCoordinator(vaultB, PeerTrustStore(DirectoryFileByteStore(dirB), sealerB))

                val snapA = coordA.currentStateSnapshot(t0 + 22) as PairingStateSnapshot.PairedActive
                check(ByteEncoding.toHexLower(snapA.peerRecord.rootPairingKey) == pairedRootHex)

                // Unpair B and verify persistent replay ledger on disk still blocks usedOfferQr after restart!
                check(coordB.unpairForSecureRePairing(false, t0 + 25).isSuccess)
                val replayAfterRestart = coordB.processScannedQr(usedOfferQr, t0 + 26)
                check(replayAfterRestart is PairingCoordinator.QrProcessResult.Rejected)
                check(replayAfterRestart.reason == PairingRejectionReason.REPLAYED_SESSION)
            }
        } finally {
            dirA.deleteRecursively()
            dirB.deleteRecursively()
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private class TestNode(initEpochSec: Long) {
        val sealer = JcaAesGcmSealer()
        val vaultRawStore = InMemoryByteStore()
        val trustRawStore = InMemoryByteStore()
        val vault = SealedSoftwareKeyVault(sealer = sealer, byteStore = vaultRawStore)
        val localId = vault.getOrCreateLocalIdentity(initEpochSec)
        val trustStore = PeerTrustStore(trustRawStore, sealer)
        val coordinator = PairingCoordinator(vault, trustStore)
    }

    private fun com.duolink.app.crypto.SignedPreKeyPublic.copyOfWithSig(
        newSig: ByteArray
    ): com.duolink.app.crypto.SignedPreKeyPublic =
        com.duolink.app.crypto.SignedPreKeyPublic(
            spkId = this.spkId,
            publicKeySpki = this.publicKeySpki,
            signatureByIdentityKey = newSig,
            createdAtEpochSec = this.createdAtEpochSec
        )

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        return ByteArray(clean.length / 2) { idx ->
            clean.substring(idx * 2, idx * 2 + 2).toInt(16).toByte()
        }
    }

    private inline fun <reified T : Throwable> expectThrows(message: String, block: () -> Unit) {
        var threwExpected = false
        try {
            block()
        } catch (t: Throwable) {
            if (t is T) {
                threwExpected = true
            } else {
                throw AssertionError("$message — expected ${T::class.java.simpleName}, got ${t::class.java.simpleName}: ${t.message}", t)
            }
        }
        if (!threwExpected) {
            throw AssertionError("$message — expected ${T::class.java.simpleName} to be thrown, but nothing was thrown")
        }
    }
}
