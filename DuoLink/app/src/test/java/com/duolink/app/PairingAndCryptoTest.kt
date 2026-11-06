package com.duolink.app

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.HkdfSha256
import com.duolink.app.crypto.JcaAesGcmSealer
import com.duolink.app.crypto.SafetyFingerprint
import com.duolink.app.crypto.SealedSoftwareKeyVault
import com.duolink.app.pairing.InMemoryByteStore
import com.duolink.app.pairing.PairingCoordinator
import com.duolink.app.pairing.PairingRejectionReason
import com.duolink.app.pairing.PairingStateSnapshot
import com.duolink.app.pairing.PeerTrustStore
import com.duolink.app.pairing.QrPairingCodec
import com.duolink.app.pairing.QrProcessResult
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PairingAndCryptoTest {

    private class TestDevice(
        val nowEpochSec: Long = 1_762_000_000L,
        val byteStore: InMemoryByteStore = InMemoryByteStore(),
        val sealer: JcaAesGcmSealer = JcaAesGcmSealer()
    ) {
        val vault = SealedSoftwareKeyVault(sealer = sealer, initialNowEpochSec = nowEpochSec)
        val trustStore = PeerTrustStore(byteStore = byteStore, sealer = sealer)
        val coordinator = PairingCoordinator(keyVault = vault, trustStore = trustStore)
    }

    @Test
    fun rfc5869_hkdfSha256_officialTestVectors_matchBitForBit() {
        // RFC 5869 Appendix A.1 (SHA-256)
        val ikm1 = ByteEncoding.fromHexStrict("0b".repeat(22))
        val salt1 = ByteEncoding.fromHexStrict("000102030405060708090a0b0c")
        val info1 = ByteEncoding.fromHexStrict("f0f1f2f3f4f5f6f7f8f9")
        val expectedPrk1 = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        val expectedOkm1 =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

        val prk1 = HkdfSha256.extract(salt1, ikm1)
        assertEquals(expectedPrk1, ByteEncoding.toHexLower(prk1))
        val okm1 = HkdfSha256.deriveKey(ikm1, salt1, info1, 42)
        assertEquals(expectedOkm1, ByteEncoding.toHexLower(okm1))

        // RFC 5869 Appendix A.3 (SHA-256, zero-length salt & info)
        val expectedPrk3 = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        val expectedOkm3 =
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        val prk3 = HkdfSha256.extract(ByteArray(0), ikm1)
        assertEquals(expectedPrk3, ByteEncoding.toHexLower(prk3))
        val okm3 = HkdfSha256.deriveKey(ikm1, null, ByteArray(0), 42)
        assertEquals(expectedOkm3, ByteEncoding.toHexLower(okm3))
    }

    @Test
    fun aes256GcmSealer_usesFreshRandomIvAndRejectsCiphertextOrAadTampering() {
        val sealer = JcaAesGcmSealer()
        val plaintext = "نسرین خانم — داده محرمانه جفت‌سازی".toByteArray(StandardCharsets.UTF_8)
        val aad = "duolink:test:v1".toByteArray(StandardCharsets.UTF_8)

        val c1 = sealer.seal(plaintext, aad)
        val c2 = sealer.seal(plaintext, aad)
        assertFalse(c1.contentEquals(c2), "Repeated AES-GCM seals must never reuse IVs")

        assertContentEquals(plaintext, sealer.unseal(c1, aad))
        assertContentEquals(plaintext, sealer.unseal(c2, aad))

        // Tamper 1 bit in ciphertext/tag
        val tampered = c1.copyOf()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 0x01).toByte()
        assertFailsWith<GeneralSecurityException> {
            sealer.unseal(tampered, aad)
        }

        // Wrong AAD context
        val wrongAad = "duolink:other_context:v1".toByteArray(StandardCharsets.UTF_8)
        assertFailsWith<GeneralSecurityException> {
            sealer.unseal(c1, wrongAad)
        }
    }

    @Test
    fun ecP256Validation_rejectsWrongCurveAndEnforcesDeterministicDeviceId() {
        val device = TestDevice()
        val spki = device.vault.getIdentityPublicKeySpki()
        val id1 = EcP256Crypto.computeDeviceId(spki)
        val id2 = device.vault.getDeviceId()
        assertEquals(32, id1.length)
        assertEquals(id1, id2)

        // secp384r1 key must be rejected by strict P-256 curve validator
        val kpg384 = KeyPairGenerator.getInstance("EC")
        kpg384.initialize(ECGenParameterSpec("secp384r1"))
        val wrongCurveSpki = kpg384.generateKeyPair().public.encoded
        assertFailsWith<GeneralSecurityException> {
            EcP256Crypto.validateAndParsePublicKey(wrongCurveSpki)
        }
    }

    @Test
    fun happyPath_twoDeviceMutualQrPairing_derivesIdenticalSafetyNumberAndRootKey() {
        val now = 1_762_000_000L
        val phoneA = TestDevice(now)
        val phoneNasrin = TestDevice(now)

        // Step 1: Phone A creates OFFER QR
        val offerSnap = phoneA.coordinator.startInitiatorOffer(now).getOrThrow()
        assertFalse(phoneA.coordinator.isPaired())

        // Step 2: Nasrin's phone scans OFFER QR and creates ACCEPT QR
        val respResult = phoneNasrin.coordinator.processScannedQr(offerSnap.offerQrUri, now + 5)
        val responderReady = assertIs<QrProcessResult.ResponderReadyToConfirm>(respResult)
        assertEquals(phoneA.coordinator.getLocalDeviceId(), responderReady.peerDeviceId)
        assertFalse(phoneNasrin.coordinator.isPaired(), "Responder must NOT be paired before explicit confirmation")

        // Step 3: Phone A scans Nasrin's ACCEPT QR
        val initResult = phoneA.coordinator.processScannedQr(responderReady.acceptQrUri, now + 10)
        val initiatorReady = assertIs<QrProcessResult.InitiatorReadyToConfirm>(initResult)
        assertEquals(phoneNasrin.coordinator.getLocalDeviceId(), initiatorReady.peerDeviceId)
        assertFalse(phoneA.coordinator.isPaired(), "Initiator must NOT be paired before explicit confirmation")

        // Both devices must display the exact same 60-digit Safety Number & Session Verification Code
        assertEquals(responderReady.safetyNumber, initiatorReady.safetyNumber)
        assertEquals(12, responderReady.safetyNumber.split(" ").size)
        assertEquals(responderReady.sessionVerificationCode, initiatorReady.sessionVerificationCode)

        // Step 4: Explicit confirmation on BOTH devices
        val recordOnA = phoneA.coordinator.confirmSafetyFingerprint(now + 15).getOrThrow()
        assertTrue(phoneA.coordinator.isPaired())
        assertFalse(phoneNasrin.coordinator.isPaired(), "Peer remains unpaired until its own user confirms")

        val recordOnNasrin = phoneNasrin.coordinator.confirmSafetyFingerprint(now + 18).getOrThrow()
        assertTrue(phoneNasrin.coordinator.isPaired())

        // Derived 256-bit RootPairingKey must match bit-for-bit on both phones
        assertEquals(32, recordOnA.rootPairingKey.size)
        assertContentEquals(recordOnA.rootPairingKey, recordOnNasrin.rootPairingKey)
        assertEquals(recordOnA.safetyNumber, recordOnNasrin.safetyNumber)
    }

    @Test
    fun qrTampering_modifyingPayloadOrSignatureInOfferOrAccept_isRejected() {
        val now = 1_762_000_000L
        val phoneA = TestDevice(now)
        val phoneB = TestDevice(now)

        val offerUri = phoneA.coordinator.startInitiatorOffer(now).getOrThrow().offerQrUri
        val decodedOffer = (QrPairingCodec.decodeUri(offerUri) as QrPairingCodec.CodecResult.Ok).packet
            as QrPairingCodec.DecodedQrPacket.Offer

        // Tamper 1 byte in nonce while keeping original signature
        val tamperedNonce = decodedOffer.nonce.copyOf()
        tamperedNonce[0] = (tamperedNonce[0].toInt() xor 0xFF).toByte()
        val forgedOfferUri = QrPairingCodec.encodeOfferUri(
            sessionId = decodedOffer.sessionId,
            senderDeviceId = decodedOffer.senderDeviceId,
            senderIkSigSpki = decodedOffer.senderIkSigSpki,
            senderSpk = decodedOffer.senderSpk,
            nonce = tamperedNonce,
            issuedAtEpochSec = decodedOffer.issuedAtEpochSec,
            expiresAtEpochSec = decodedOffer.expiresAtEpochSec,
            signature = decodedOffer.signature
        )

        val res1 = phoneB.coordinator.processScannedQr(forgedOfferUri, now + 2)
        val rej1 = assertIs<QrProcessResult.Rejected>(res1)
        assertEquals(PairingRejectionReason.TAMPERED_SIGNATURE, rej1.reason)

        // Valid offer -> tamper signature on ACCEPT QR
        val validResp = assertIs<QrProcessResult.ResponderReadyToConfirm>(
            phoneB.coordinator.processScannedQr(offerUri, now + 3)
        )
        val decodedAccept = (QrPairingCodec.decodeUri(validResp.acceptQrUri) as QrPairingCodec.CodecResult.Ok).packet
            as QrPairingCodec.DecodedQrPacket.Accept
        val badSig = decodedAccept.signature.copyOf()
        badSig[badSig.lastIndex] = (badSig.last().toInt() xor 0x01).toByte()
        val forgedAcceptUri = QrPairingCodec.encodeAcceptUri(
            sessionId = decodedAccept.sessionId,
            targetPeerDeviceId = decodedAccept.targetPeerDeviceId,
            offerTranscriptDigest = decodedAccept.offerTranscriptDigest,
            senderDeviceId = decodedAccept.senderDeviceId,
            senderIkSigSpki = decodedAccept.senderIkSigSpki,
            senderSpk = decodedAccept.senderSpk,
            nonce = decodedAccept.nonce,
            issuedAtEpochSec = decodedAccept.issuedAtEpochSec,
            expiresAtEpochSec = decodedAccept.expiresAtEpochSec,
            signature = badSig
        )

        val res2 = phoneA.coordinator.processScannedQr(forgedAcceptUri, now + 5)
        val rej2 = assertIs<QrProcessResult.Rejected>(res2)
        assertEquals(PairingRejectionReason.TAMPERED_SIGNATURE, rej2.reason)
    }

    @Test
    fun identitySubstitution_validAttackerKeyClaimingVictimDeviceId_isRejected() {
        val now = 1_762_000_000L
        val victim = TestDevice(now)
        val attacker = TestDevice(now)
        val responder = TestDevice(now)

        val sessionBytes = ByteArray(16) { 0x42 }
        val sessionId = ByteEncoding.toHexLower(sessionBytes)
        val nonce = ByteArray(32) { 0x11 }
        val attackerSpk = attacker.vault.getCurrentSignedPreKey(now)

        // Attacker signs transcript claiming victim's deviceId with attacker's IK_sig
        val fakeTranscript = QrPairingCodec.buildOfferSigningTranscript(
            sessionId = sessionId,
            senderDeviceId = victim.vault.getDeviceId(),
            senderIkSigSpki = attacker.vault.getIdentityPublicKeySpki(),
            senderSpk = attackerSpk,
            nonce = nonce,
            issuedAtEpochSec = now,
            expiresAtEpochSec = now + 300
        )
        val sig = attacker.vault.signWithIdentity(fakeTranscript)
        val fakeUri = QrPairingCodec.encodeOfferUri(
            sessionId = sessionId,
            senderDeviceId = victim.vault.getDeviceId(),
            senderIkSigSpki = attacker.vault.getIdentityPublicKeySpki(),
            senderSpk = attackerSpk,
            nonce = nonce,
            issuedAtEpochSec = now,
            expiresAtEpochSec = now + 300,
            signature = sig
        )

        val res = responder.coordinator.processScannedQr(fakeUri, now + 1)
        val rej = assertIs<QrProcessResult.Rejected>(res)
        assertEquals(PairingRejectionReason.IDENTITY_SUBSTITUTION, rej.reason)
    }

    @Test
    fun mitmAttacks_splicedAcceptIsRejected_andDualMitmExposesMismatchedSafetyNumbers() {
        val now = 1_762_000_000L
        val alice = TestDevice(now)
        val nasrin = TestDevice(now)
        val mallory = TestDevice(now)

        // Case A: Mallory intercepts Alice's offer, creates Mallory's own offer to Nasrin,
        // and tries to feed Nasrin's ACCEPT back to Alice -> rejected by targetPeerDeviceId / offerDigest!
        alice.coordinator.startInitiatorOffer(now).getOrThrow()
        val malloryOffer = mallory.coordinator.startInitiatorOffer(now).getOrThrow()
        val nasrinAcceptToMallory = assertIs<QrProcessResult.ResponderReadyToConfirm>(
            nasrin.coordinator.processScannedQr(malloryOffer.offerQrUri, now + 2)
        )
        val spliceAttempt = alice.coordinator.processScannedQr(nasrinAcceptToMallory.acceptQrUri, now + 4)
        val spliceRej = assertIs<QrProcessResult.Rejected>(spliceAttempt)
        assertEquals(PairingRejectionReason.WRONG_PEER_TARGET, spliceRej.reason)

        // Case B: Full active dual-QR MITM (Alice <-> Mallory1 and Mallory2 <-> Nasrin)
        val alice2 = TestDevice(now)
        val nasrin2 = TestDevice(now)
        val mallory2 = TestDevice(now)

        val aliceOffer = alice2.coordinator.startInitiatorOffer(now).getOrThrow()
        val malloryRespToAlice = assertIs<QrProcessResult.ResponderReadyToConfirm>(
            mallory2.coordinator.processScannedQr(aliceOffer.offerQrUri, now + 1)
        )
        val aliceStage = assertIs<QrProcessResult.InitiatorReadyToConfirm>(
            alice2.coordinator.processScannedQr(malloryRespToAlice.acceptQrUri, now + 2)
        )

        // Mallory separately initiates with Nasrin
        val malloryFresh = TestDevice(now)
        val malloryOffer2 = malloryFresh.coordinator.startInitiatorOffer(now + 3).getOrThrow()
        val nasrinStage = assertIs<QrProcessResult.ResponderReadyToConfirm>(
            nasrin2.coordinator.processScannedQr(malloryOffer2.offerQrUri, now + 4)
        )

        // Safety numbers displayed on Alice's phone and Nasrin's phone MUST strictly differ!
        assertNotEquals(aliceStage.safetyNumber, nasrinStage.safetyNumber)
        assertNotEquals(aliceStage.sessionVerificationCode, nasrinStage.sessionVerificationCode)
    }

    @Test
    fun replayAttack_rescanningOfferOrAcceptEvenAfterRestart_isRejected() {
        val now = 1_762_000_000L
        val phoneA = TestDevice(now)
        val sharedDisk = InMemoryByteStore()
        val sharedSealer = JcaAesGcmSealer()
        val phoneB = TestDevice(now, byteStore = sharedDisk, sealer = sharedSealer)

        val offer = phoneA.coordinator.startInitiatorOffer(now).getOrThrow()
        val firstScan = phoneB.coordinator.processScannedQr(offer.offerQrUri, now + 5)
        val acceptReady = assertIs<QrProcessResult.ResponderReadyToConfirm>(firstScan)

        // Immediate replay of same OFFER QR on Phone B -> rejected
        val replay1 = phoneB.coordinator.processScannedQr(offer.offerQrUri, now + 6)
        assertEquals(PairingRejectionReason.REPLAYED_NONCE, assertIs<QrProcessResult.Rejected>(replay1).reason)

        // Simulate app process restart on Phone B (new coordinator reading sealed persistent store)
        val phoneBRestarted = PairingCoordinator(
            keyVault = phoneB.vault,
            trustStore = PeerTrustStore(byteStore = sharedDisk, sealer = sharedSealer)
        )
        val replayAfterRestart = phoneBRestarted.processScannedQr(offer.offerQrUri, now + 10)
        assertEquals(
            PairingRejectionReason.REPLAYED_NONCE,
            assertIs<QrProcessResult.Rejected>(replayAfterRestart).reason
        )

        // Initiator scans ACCEPT once -> succeeds, second scan of same ACCEPT -> REPLAYED_NONCE
        assertIs<QrProcessResult.InitiatorReadyToConfirm>(
            phoneA.coordinator.processScannedQr(acceptReady.acceptQrUri, now + 12)
        )
        val acceptReplay = phoneA.coordinator.processScannedQr(acceptReady.acceptQrUri, now + 13)
        assertEquals(
            PairingRejectionReason.REPLAYED_NONCE,
            assertIs<QrProcessResult.Rejected>(acceptReplay).reason
        )
    }

    @Test
    fun expiredAndFutureSkewedQrPayloads_areRejected() {
        val now = 1_762_000_000L
        val phoneA = TestDevice(now)
        val phoneB = TestDevice(now)

        val offer = phoneA.coordinator.startInitiatorOffer(now).getOrThrow()

        // Scan 10 minutes later (past 5-min TTL + 60s clock skew grace) -> EXPIRED_PAYLOAD
        val expiredRes = phoneB.coordinator.processScannedQr(offer.offerQrUri, now + 600)
        assertEquals(
            PairingRejectionReason.EXPIRED_PAYLOAD,
            assertIs<QrProcessResult.Rejected>(expiredRes).reason
        )

        // Scan when receiver clock is far behind (offer appears >60s in the future) -> EXPIRED_PAYLOAD
        val futureSkewRes = phoneB.coordinator.processScannedQr(offer.offerQrUri, now - 120)
        assertEquals(
            PairingRejectionReason.EXPIRED_PAYLOAD,
            assertIs<QrProcessResult.Rejected>(futureSkewRes).reason
        )
    }

    @Test
    fun selfPairingAndWrongPeerAccept_areRejected() {
        val now = 1_762_000_000L
        val phoneA = TestDevice(now)
        val phoneB = TestDevice(now)
        val phoneC = TestDevice(now)

        val offerA = phoneA.coordinator.startInitiatorOffer(now).getOrThrow()

        // Self-scan on Phone A -> SELF_PAIRING_ATTEMPT
        val selfRes = phoneA.coordinator.processScannedQr(offerA.offerQrUri, now + 1)
        assertEquals(
            PairingRejectionReason.SELF_PAIRING_ATTEMPT,
            assertIs<QrProcessResult.Rejected>(selfRes).reason
        )

        // Phone B creates ACCEPT addressed to Phone A; Phone C tries to scan it -> WRONG_PEER_TARGET
        phoneC.coordinator.startInitiatorOffer(now).getOrThrow()
        val acceptForA = assertIs<QrProcessResult.ResponderReadyToConfirm>(
            phoneB.coordinator.processScannedQr(offerA.offerQrUri, now + 2)
        )
        val wrongPeerRes = phoneC.coordinator.processScannedQr(acceptForA.acceptQrUri, now + 3)
        assertEquals(
            PairingRejectionReason.WRONG_PEER_TARGET,
            assertIs<QrProcessResult.Rejected>(wrongPeerRes).reason
        )
    }

    @Test
    fun unauthorizedThirdDevice_isStrictlyBlockedWhenAlreadyPaired() {
        val now = 1_762_000_000L
        val phoneA = TestDevice(now)
        val phoneNasrin = TestDevice(now)
        val intruder = TestDevice(now)

        // Pair Phone A <-> Nasrin
        val offer = phoneA.coordinator.startInitiatorOffer(now).getOrThrow()
        val resp = assertIs<QrProcessResult.ResponderReadyToConfirm>(
            phoneNasrin.coordinator.processScannedQr(offer.offerQrUri, now + 1)
        )
        assertIs<QrProcessResult.InitiatorReadyToConfirm>(
            phoneA.coordinator.processScannedQr(resp.acceptQrUri, now + 2)
        )
        phoneA.coordinator.confirmSafetyFingerprint(now + 3).getOrThrow()
        phoneNasrin.coordinator.confirmSafetyFingerprint(now + 3).getOrThrow()

        // Phone A cannot even start a new initiator offer while paired
        assertTrue(phoneA.coordinator.startInitiatorOffer(now + 10).isFailure)

        // Intruder generates valid QR and scans on Nasrin's phone -> THIRD_DEVICE_BLOCKED
        val intruderOffer = intruder.coordinator.startInitiatorOffer(now + 10).getOrThrow()
        val joinAttempt = phoneNasrin.coordinator.processScannedQr(intruderOffer.offerQrUri, now + 11)
        assertEquals(
            PairingRejectionReason.THIRD_DEVICE_BLOCKED,
            assertIs<QrProcessResult.Rejected>(joinAttempt).reason
        )
        // Original pairing remains untouched
        assertEquals(phoneA.coordinator.getLocalDeviceId(), phoneNasrin.coordinator.getPinnedPeer()?.peerDeviceId)
    }

    @Test
    fun keyChangeWarning_andSecureRePairingProcedure_enforceExplicitWarningAndAcknowledge() {
        val now = 1_762_000_000L
        val phoneA = TestDevice(now)
        val phoneNasrinOld = TestDevice(now)

        // Initial pairing: Phone A <-> Nasrin (old phone)
        val offer1 = phoneA.coordinator.startInitiatorOffer(now).getOrThrow()
        val resp1 = assertIs<QrProcessResult.ResponderReadyToConfirm>(
            phoneNasrinOld.coordinator.processScannedQr(offer1.offerQrUri, now + 1)
        )
        assertIs<QrProcessResult.InitiatorReadyToConfirm>(
            phoneA.coordinator.processScannedQr(resp1.acceptQrUri, now + 2)
        )
        val initialRecord = phoneA.coordinator.confirmSafetyFingerprint(now + 3).getOrThrow()
        phoneNasrinOld.coordinator.confirmSafetyFingerprint(now + 3).getOrThrow()

        // Nasrin gets a new phone (new identity keypair)
        val phoneNasrinNew = TestDevice(now + 100)
        val newNasrinOffer = phoneNasrinNew.coordinator.startInitiatorOffer(now + 100).getOrThrow()

        // 1. Direct identity check surfaces KeyChangeAlert
        assertNull(phoneA.coordinator.verifyPinnedPeerIdentityKey(phoneNasrinOld.vault.getIdentityPublicKeySpki()))
        val directAlert = phoneA.coordinator.verifyPinnedPeerIdentityKey(
            phoneNasrinNew.vault.getIdentityPublicKeySpki()
        )
        assertNotNull(directAlert)
        assertEquals(initialRecord.safetyNumber, directAlert.previousSafetyNumber)
        assertNotEquals(directAlert.previousSafetyNumber, directAlert.newSafetyNumber)

        // 2. Scanning new phone's QR in verifyExistingPeerMode surfaces blocking PEER_KEY_CHANGED_WARNING
        val verifyRes = phoneA.coordinator.processScannedQr(
            rawQrText = newNasrinOffer.offerQrUri,
            nowEpochSec = now + 105,
            verifyExistingPeerMode = true
        )
        val warningRej = assertIs<QrProcessResult.Rejected>(verifyRes)
        assertEquals(PairingRejectionReason.PEER_KEY_CHANGED_WARNING, warningRej.reason)
        assertNotNull(warningRej.keyChangeAlert)
        // Pinned key MUST NOT be silently overwritten!
        assertEquals(phoneNasrinOld.vault.getDeviceId(), phoneA.coordinator.getPinnedPeer()?.peerDeviceId)

        // 3. User executes Secure Re-Pairing Reset on Phone A
        phoneA.coordinator.unpairForSecureRePairing(regenerateDeviceIdentity = false, nowEpochSec = now + 110)
        assertIs<PairingStateSnapshot.Unpaired>(phoneA.coordinator.currentStateSnapshot(now + 110))

        // 4. Phone A scans Nasrin's new phone Offer QR -> KeyChangeAlert from archived peer is attached!
        val rePairResp = assertIs<QrProcessResult.ResponderReadyToConfirm>(
            phoneA.coordinator.processScannedQr(newNasrinOffer.offerQrUri, now + 112)
        )
        assertNotNull(rePairResp.keyChangeFromPreviousPeer)
        assertEquals(initialRecord.safetyNumber, rePairResp.keyChangeFromPreviousPeer?.previousSafetyNumber)

        // Confirming WITHOUT acknowledgeKeyChange=true MUST fail!
        assertTrue(phoneA.coordinator.confirmSafetyFingerprint(now + 115, acknowledgeKeyChange = false).isFailure)

        // Confirming WITH explicit acknowledgeKeyChange=true succeeds, and Nasrin's new phone confirms too
        val newRecordOnA = phoneA.coordinator.confirmSafetyFingerprint(
            nowEpochSec = now + 116,
            acknowledgeKeyChange = true
        ).getOrThrow()
        assertIs<QrProcessResult.InitiatorReadyToConfirm>(
            phoneNasrinNew.coordinator.processScannedQr(rePairResp.acceptQrUri, now + 117)
        )
        val newRecordOnNasrin = phoneNasrinNew.coordinator.confirmSafetyFingerprint(now + 118).getOrThrow()

        assertEquals(phoneNasrinNew.vault.getDeviceId(), newRecordOnA.peerDeviceId)
        assertContentEquals(newRecordOnA.rootPairingKey, newRecordOnNasrin.rootPairingKey)
        assertNotEquals(initialRecord.rootPairingKey.toList(), newRecordOnA.rootPairingKey.toList())
    }

    @Test
    fun samePeerIdentityVerification_updatesRotatedSignedPreKeyWithoutBreakingPairing() {
        val now = 1_762_000_000L
        val phoneA = TestDevice(now)
        val phoneNasrin = TestDevice(now)

        val offer = phoneA.coordinator.startInitiatorOffer(now).getOrThrow()
        val resp = assertIs<QrProcessResult.ResponderReadyToConfirm>(
            phoneNasrin.coordinator.processScannedQr(offer.offerQrUri, now + 1)
        )
        assertIs<QrProcessResult.InitiatorReadyToConfirm>(
            phoneA.coordinator.processScannedQr(resp.acceptQrUri, now + 2)
        )
        phoneA.coordinator.confirmSafetyFingerprint(now + 3).getOrThrow()
        phoneNasrin.coordinator.confirmSafetyFingerprint(now + 3).getOrThrow()
        assertEquals(1, phoneA.coordinator.getPinnedPeer()?.peerSpkId)

        // Nasrin rotates her Signed Pre-Key (spkId = 2) while keeping same IK_sig
        val rotatedSpk = phoneNasrin.coordinator.rotateSignedPreKey(now + 50)
        assertEquals(2, rotatedSpk.spkId)
        assertFalse(
            phoneNasrin.vault.getIdentityPublicKeySpki().contentEquals(rotatedSpk.publicKeySpki),
            "SPK_dh must remain distinct from IK_sig"
        )

        // Build a fresh signed verification QR carrying Nasrin's rotated SPK
        val sessionId = ByteEncoding.toHexLower(ByteArray(16) { 0x24 })
        val nonce = ByteArray(32) { 0x33 }
        val transcript = QrPairingCodec.buildOfferSigningTranscript(
            sessionId = sessionId,
            senderDeviceId = phoneNasrin.vault.getDeviceId(),
            senderIkSigSpki = phoneNasrin.vault.getIdentityPublicKeySpki(),
            senderSpk = rotatedSpk,
            nonce = nonce,
            issuedAtEpochSec = now + 55,
            expiresAtEpochSec = now + 355
        )
        val sig = phoneNasrin.vault.signWithIdentity(transcript)
        val verifyQr = QrPairingCodec.encodeOfferUri(
            sessionId = sessionId,
            senderDeviceId = phoneNasrin.vault.getDeviceId(),
            senderIkSigSpki = phoneNasrin.vault.getIdentityPublicKeySpki(),
            senderSpk = rotatedSpk,
            nonce = nonce,
            issuedAtEpochSec = now + 55,
            expiresAtEpochSec = now + 355,
            signature = sig
        )

        val verified = assertIs<QrProcessResult.ExistingPeerVerified>(
            phoneA.coordinator.processScannedQr(verifyQr, now + 60, verifyExistingPeerMode = true)
        )
        assertTrue(verified.preKeyUpdated)
        assertEquals(2, phoneA.coordinator.getPinnedPeer()?.peerSpkId)
    }

    @Test
    fun malformedOversizedWrongSchemeAndWrongVersionInputs_failClosedSafely() {
        val device = TestDevice()
        val invalidInputs = listOf(
            "",
            "   ",
            "https://example.com/pair?p=abc",
            "duolink://pair/v1?p=",
            "duolink://pair/v1?p=not!valid!base64==",
            "duolink://pair/v1?p=" + "A".repeat(3000),
            // Version 99 packet
            "duolink://pair/v1?p=" + ByteEncoding.encodeBase64Url(ByteArray(80) { if (it == 0) 99 else 1 })
        )
        for (raw in invalidInputs) {
            val res = device.coordinator.processScannedQr(raw, 1_762_000_000L)
            assertIs<QrProcessResult.Rejected>(res)
        }
    }

    @Test
    fun base64UrlStrictDecoder_rejectsPaddingWhitespaceAndTrailingBitMalleability() {
        val original = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val canonical = ByteEncoding.encodeBase64Url(original) // "AQIDBA"
        assertContentEquals(original, ByteEncoding.decodeBase64UrlStrict(canonical))

        // Reject '=' padding
        assertFailsWith<IllegalArgumentException> {
            ByteEncoding.decodeBase64UrlStrict("$canonical==")
        }
        // Flip unused low bits of final Base64 sextet ('A' -> 'B' changes trailing 4 zero bits)
        val malleable = canonical.dropLast(1) + "B"
        assertFailsWith<IllegalArgumentException> {
            ByteEncoding.decodeBase64UrlStrict(malleable)
        }
    }

    @Test
    fun invalidCurveAttack_corruptedPublicKeyCoordinateOffCurve_isRejected() {
        val kp = EcP256Crypto.generateSoftwareEcP256KeyPair()
        val spki = kp.public.encoded.copyOf()
        // Flip 1 bit in the X coordinate inside uncompressed EC point (last 64 bytes of 91-byte SPKI)
        spki[spki.size - 40] = (spki[spki.size - 40].toInt() xor 0x01).toByte()
        assertFailsWith<Exception> {
            EcP256Crypto.validateAndParsePublicKey(spki)
        }
    }

    @Test
    fun keyPurposeSeparation_reusingIdentitySigningKeyAsSignedPreKey_isRejected() {
        val now = 1_762_000_000L
        val device = TestDevice(now)
        val ikSpki = device.vault.getIdentityPublicKeySpki()
        val deviceId = device.vault.getDeviceId()
        val badTranscript = EcP256Crypto.buildSignedPreKeyTranscript(
            deviceId = deviceId,
            spkId = 99,
            issuedAtEpochSec = now,
            expiresAtEpochSec = now + 3600,
            spkPublicKeySpki = ikSpki // Illegally reusing IK_sig as SPK_dh
        )
        val sig = device.vault.signWithIdentity(badTranscript)
        val reusedSpk = com.duolink.app.crypto.SignedPreKeyPublic(
            spkId = 99,
            publicKeySpki = ikSpki,
            issuedAtEpochSec = now,
            expiresAtEpochSec = now + 3600,
            signature = sig
        )
        assertFalse(EcP256Crypto.verifySignedPreKey(deviceId, ikSpki, reusedSpk))
    }

    @Test
    fun directoryFileByteStore_persistsEncryptedTrustStoreAndFailsClosedOnDiskTampering() {
        val tempDir = java.nio.file.Files.createTempDirectory("duolink_store_test").toFile()
        try {
            val now = 1_762_000_000L
            val sealer = JcaAesGcmSealer()
            val fileStore = com.duolink.app.pairing.DirectoryFileByteStore(tempDir)
            val phoneA = PairingCoordinator(
                keyVault = SealedSoftwareKeyVault(sealer, now),
                trustStore = PeerTrustStore(fileStore, sealer)
            )
            val phoneB = TestDevice(now)

            val offer = phoneA.startInitiatorOffer(now).getOrThrow()
            val resp = assertIs<QrProcessResult.ResponderReadyToConfirm>(
                phoneB.coordinator.processScannedQr(offer.offerQrUri, now + 1)
            )
            assertIs<QrProcessResult.InitiatorReadyToConfirm>(
                phoneA.processScannedQr(resp.acceptQrUri, now + 2)
            )
            val saved = phoneA.confirmSafetyFingerprint(now + 3).getOrThrow()

            // Reload from disk using same key
            val reloadedStore = PeerTrustStore(com.duolink.app.pairing.DirectoryFileByteStore(tempDir), sealer)
            val reloaded = reloadedStore.loadPinnedPeer()
            assertNotNull(reloaded)
            assertEquals(saved.safetyNumber, reloaded.safetyNumber)
            assertContentEquals(saved.rootPairingKey, reloaded.rootPairingKey)

            // Corrupt 1 byte in encrypted file on disk -> must fail closed with GeneralSecurityException
            val rawBytes = fileStore.read("pinned_peer_v1")!!
            rawBytes[rawBytes.lastIndex] = (rawBytes.last().toInt() xor 0x01).toByte()
            fileStore.write("pinned_peer_v1", rawBytes)
            assertFailsWith<GeneralSecurityException> {
                reloadedStore.loadPinnedPeer()
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun expiredStagedConfirmation_cannotBeConfirmedAfterTtlWindow() {
        val now = 1_762_000_000L
        val phoneA = TestDevice(now)
        val phoneB = TestDevice(now)

        val offer = phoneA.coordinator.startInitiatorOffer(now).getOrThrow()
        assertIs<QrProcessResult.ResponderReadyToConfirm>(
            phoneB.coordinator.processScannedQr(offer.offerQrUri, now + 2)
        )

        // Attempt to confirm 15 minutes later (past expiry) -> rejected and state cleared
        val lateConfirm = phoneB.coordinator.confirmSafetyFingerprint(now + 900)
        assertTrue(lateConfirm.isFailure)
        assertFalse(phoneB.coordinator.isPaired())
        assertIs<PairingStateSnapshot.Unpaired>(phoneB.coordinator.currentStateSnapshot(now + 900))
    }
}
