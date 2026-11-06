package com.duolink.app.pairing

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.DeviceKeyVault
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.SafetyFingerprint
import com.duolink.app.crypto.SignedPreKeyPublic
import com.duolink.app.crypto.TranscriptBuilder
import com.duolink.app.crypto.zeroize
import java.security.SecureRandom

/**
 * Coordinates DuoLink's strictly two-device mutual QR pairing, replay & tamper protection,
 * third-device rejection, peer key-change warning, and explicit two-party fingerprint confirmation.
 */
class PairingCoordinator(
    private val keyVault: DeviceKeyVault,
    private val trustStore: PeerTrustStore,
    private val secureRandom: SecureRandom = SecureRandom()
) {
    companion object {
        const val OFFER_TTL_SEC: Long = 300L        // 5 minutes
        const val MAX_OFFER_WINDOW_SEC: Long = 600L // Hard upper bound on exp - iat
        const val CLOCK_SKEW_TOLERANCE_SEC: Long = 60L
    }

    private data class ActiveOfferSession(
        val sessionId: String,
        val localSpk: SignedPreKeyPublic,
        val offerNonce: ByteArray,
        val offerQrUri: String,
        val offerTranscriptDigest: ByteArray,
        val issuedAtEpochSec: Long,
        val expiresAtEpochSec: Long
    )

    private data class StagedConfirmation(
        val role: PairingStateSnapshot.AwaitingUserConfirmation.Role,
        val acceptQrUri: String?,
        val candidateRecord: PairedPeerRecord,
        val sessionVerificationCode: String,
        val expiresAtEpochSec: Long,
        val keyChangeAlert: KeyChangeAlert?
    )

    private var activeOffer: ActiveOfferSession? = null
    private var stagedConfirmation: StagedConfirmation? = null

    @Synchronized
    fun getLocalDeviceId(): String = keyVault.getDeviceId()

    @Synchronized
    fun getLocalIdentityDigits(): String = SafetyFingerprint.computeSingleIdentityDigits(
        deviceId = keyVault.getDeviceId(),
        ikSpki = keyVault.getIdentityPublicKeySpki()
    )

    @Synchronized
    fun isHardwareKeyBacked(): Boolean = keyVault.isHardwareBacked

    @Synchronized
    fun getHardwareKeyDescription(): String = keyVault.hardwareDescription

    @Synchronized
    fun getCurrentSignedPreKey(nowEpochSec: Long = currentEpochSec()): SignedPreKeyPublic =
        keyVault.getCurrentSignedPreKey(nowEpochSec)

    @Synchronized
    fun rotateSignedPreKey(nowEpochSec: Long = currentEpochSec()): SignedPreKeyPublic =
        keyVault.rotateSignedPreKey(nowEpochSec)

    @Synchronized
    fun isPaired(): Boolean = trustStore.loadPinnedPeer() != null

    @Synchronized
    fun getPinnedPeer(): PairedPeerRecord? = trustStore.loadPinnedPeer()

    @Synchronized
    fun currentStateSnapshot(nowEpochSec: Long = currentEpochSec()): PairingStateSnapshot {
        val pinned = trustStore.loadPinnedPeer()
        if (pinned != null) {
            return PairingStateSnapshot.Paired(
                peerDeviceId = pinned.peerDeviceId,
                safetyNumber = pinned.safetyNumber,
                pairedAtEpochSec = pinned.pairedAtEpochSec,
                peerSpkId = pinned.peerSpkId
            )
        }
        val staged = stagedConfirmation
        if (staged != null) {
            if (nowEpochSec <= staged.expiresAtEpochSec + CLOCK_SKEW_TOLERANCE_SEC) {
                return PairingStateSnapshot.AwaitingUserConfirmation(
                    role = staged.role,
                    acceptQrUri = staged.acceptQrUri,
                    peerDeviceId = staged.candidateRecord.peerDeviceId,
                    safetyNumber = staged.candidateRecord.safetyNumber,
                    sessionVerificationCode = staged.sessionVerificationCode,
                    expiresAtEpochSec = staged.expiresAtEpochSec,
                    keyChangeAlert = staged.keyChangeAlert
                )
            } else {
                clearStagedConfirmation()
            }
        }
        val offer = activeOffer
        if (offer != null) {
            if (nowEpochSec <= offer.expiresAtEpochSec + CLOCK_SKEW_TOLERANCE_SEC) {
                return PairingStateSnapshot.OfferCreated(
                    sessionId = offer.sessionId,
                    offerQrUri = offer.offerQrUri,
                    expiresAtEpochSec = offer.expiresAtEpochSec
                )
            } else {
                activeOffer = null
            }
        }
        return PairingStateSnapshot.Unpaired
    }

    /**
     * Creates a signed Initiator OFFER QR URI. Refuses if already paired with a peer.
     */
    @Synchronized
    fun startInitiatorOffer(nowEpochSec: Long = currentEpochSec()): Result<PairingStateSnapshot.OfferCreated> {
        if (trustStore.loadPinnedPeer() != null) {
            return Result.failure(IllegalStateException(PairingRejectionReason.THIRD_DEVICE_BLOCKED.persianTitle))
        }
        clearStagedConfirmation()

        val sessionIdBytes = ByteArray(QrPairingCodec.SESSION_ID_BYTES).also { secureRandom.nextBytes(it) }
        val sessionId = ByteEncoding.toHexLower(sessionIdBytes)
        val nonce = ByteArray(QrPairingCodec.NONCE_BYTES).also { secureRandom.nextBytes(it) }
        val localDeviceId = keyVault.getDeviceId()
        val localIkSpki = keyVault.getIdentityPublicKeySpki()
        val localSpk = keyVault.getCurrentSignedPreKey(nowEpochSec)
        val exp = nowEpochSec + OFFER_TTL_SEC

        val transcript = QrPairingCodec.buildOfferSigningTranscript(
            sessionId = sessionId,
            senderDeviceId = localDeviceId,
            senderIkSigSpki = localIkSpki,
            senderSpk = localSpk,
            nonce = nonce,
            issuedAtEpochSec = nowEpochSec,
            expiresAtEpochSec = exp
        )
        val signature = keyVault.signWithIdentity(transcript)
        val uri = QrPairingCodec.encodeOfferUri(
            sessionId = sessionId,
            senderDeviceId = localDeviceId,
            senderIkSigSpki = localIkSpki,
            senderSpk = localSpk,
            nonce = nonce,
            issuedAtEpochSec = nowEpochSec,
            expiresAtEpochSec = exp,
            signature = signature
        )

        activeOffer = ActiveOfferSession(
            sessionId = sessionId,
            localSpk = localSpk,
            offerNonce = nonce,
            offerQrUri = uri,
            offerTranscriptDigest = ByteEncoding.sha256(transcript),
            issuedAtEpochSec = nowEpochSec,
            expiresAtEpochSec = exp
        )
        return Result.success(
            PairingStateSnapshot.OfferCreated(
                sessionId = sessionId,
                offerQrUri = uri,
                expiresAtEpochSec = exp
            )
        )
    }

    /**
     * Processes a scanned QR URI in either normal pairing mode or peer identity verification mode.
     *
     * @param verifyExistingPeerMode When true and already paired, checks whether a scanned QR
     *   matches the pinned peer identity or surfaces an explicit PEER_KEY_CHANGED_WARNING if the
     *   contact's key changed (instead of a generic third-device block).
     */
    @Synchronized
    fun processScannedQr(
        rawQrText: String,
        nowEpochSec: Long = currentEpochSec(),
        verifyExistingPeerMode: Boolean = false
    ): QrProcessResult {
        val decoded = when (val res = QrPairingCodec.decodeUri(rawQrText)) {
            is QrPairingCodec.CodecResult.Err -> return QrProcessResult.Rejected(res.reason)
            is QrPairingCodec.CodecResult.Ok -> res.packet
        }

        // 1. Validate curve, canonical SPKI, and cryptographic binding deviceId == H(IK_sig_pub)
        val computedSenderId = try {
            EcP256Crypto.computeDeviceId(decoded.senderIkSigSpki)
        } catch (_: Exception) {
            return QrProcessResult.Rejected(PairingRejectionReason.TAMPERED_SIGNATURE)
        }
        if (computedSenderId != decoded.senderDeviceId) {
            return QrProcessResult.Rejected(PairingRejectionReason.IDENTITY_SUBSTITUTION)
        }

        // 2. Reject scanning our own QR code
        val localDeviceId = keyVault.getDeviceId()
        if (decoded.senderDeviceId == localDeviceId) {
            return QrProcessResult.Rejected(PairingRejectionReason.SELF_PAIRING_ATTEMPT)
        }

        // 3. Verify timestamps & TTL window BEFORE touching state
        if (!isFreshTimestampWindow(decoded.issuedAtEpochSec, decoded.expiresAtEpochSec, nowEpochSec)) {
            return QrProcessResult.Rejected(PairingRejectionReason.EXPIRED_PAYLOAD)
        }

        // 4. Verify packet outer signature under senderIkSigSpki AND SPK signature
        if (!EcP256Crypto.verifyIdentitySignature(
                ikSigPublicKeySpki = decoded.senderIkSigSpki,
                transcript = decoded.signedTranscript,
                signatureBytes = decoded.signature
            )
        ) {
            return QrProcessResult.Rejected(PairingRejectionReason.TAMPERED_SIGNATURE)
        }
        if (!EcP256Crypto.verifySignedPreKey(
                deviceId = decoded.senderDeviceId,
                ikSigPublicKeySpki = decoded.senderIkSigSpki,
                spk = decoded.senderSpk
            )
        ) {
            return QrProcessResult.Rejected(PairingRejectionReason.TAMPERED_SIGNATURE)
        }
        if (nowEpochSec > decoded.senderSpk.expiresAtEpochSec + CLOCK_SKEW_TOLERANCE_SEC) {
            return QrProcessResult.Rejected(PairingRejectionReason.EXPIRED_PAYLOAD)
        }

        // 5. Enforce replay check against persistent sealed ledger
        val replayToken = computeReplayToken(decoded)
        if (trustStore.hasSeenReplayToken(replayToken)) {
            return QrProcessResult.Rejected(PairingRejectionReason.REPLAYED_NONCE)
        }

        // 6. Check existing pinned peer state (2-device exclusivity & key-change warning)
        val existingPeer = trustStore.loadPinnedPeer()
        if (existingPeer != null) {
            return handleScanWhenAlreadyPaired(
                existingPeer = existingPeer,
                decoded = decoded,
                replayToken = replayToken,
                verifyExistingPeerMode = verifyExistingPeerMode
            )
        }

        // 7. Unpaired state: route OFFER (Responder) vs ACCEPT (Initiator)
        return when (decoded) {
            is QrPairingCodec.DecodedQrPacket.Offer ->
                handleOfferAsResponder(decoded, replayToken, nowEpochSec)
            is QrPairingCodec.DecodedQrPacket.Accept ->
                handleAcceptAsInitiator(decoded, replayToken, nowEpochSec)
        }
    }

    /**
     * Checks an observed peer identity public key (e.g., during handshake or manual verification)
     * against the currently pinned peer. Returns KeyChangeAlert if the key changed.
     */
    @Synchronized
    fun verifyPinnedPeerIdentityKey(presentedIkSigSpki: ByteArray): KeyChangeAlert? {
        val pinned = trustStore.loadPinnedPeer() ?: return null
        if (ByteEncoding.constantTimeEquals(pinned.peerIkSigSpki, presentedIkSigSpki)) {
            return null
        }
        val newDeviceId = EcP256Crypto.computeDeviceId(presentedIkSigSpki)
        val newSafetyNumber = SafetyFingerprint.computeSafetyNumber(
            localDeviceId = keyVault.getDeviceId(),
            localIkSpki = keyVault.getIdentityPublicKeySpki(),
            peerDeviceId = newDeviceId,
            peerIkSpki = presentedIkSigSpki
        )
        return KeyChangeAlert(
            previousDeviceId = pinned.peerDeviceId,
            previousSafetyNumber = pinned.safetyNumber,
            newDeviceId = newDeviceId,
            newSafetyNumber = newSafetyNumber
        )
    }

    /**
     * Explicit user confirmation gate on THIS device.
     * If a previous peer's key changed across re-pairing, [acknowledgeKeyChange] MUST be true.
     */
    @Synchronized
    fun confirmSafetyFingerprint(
        nowEpochSec: Long = currentEpochSec(),
        acknowledgeKeyChange: Boolean = false
    ): Result<PairedPeerRecord> {
        val staged = stagedConfirmation
            ?: return Result.failure(IllegalStateException("نشست در انتظار تأییدی وجود ندارد"))
        if (nowEpochSec > staged.expiresAtEpochSec + CLOCK_SKEW_TOLERANCE_SEC) {
            clearStagedConfirmation()
            return Result.failure(IllegalStateException(PairingRejectionReason.EXPIRED_PAYLOAD.persianTitle))
        }
        if (staged.keyChangeAlert != null && !acknowledgeKeyChange) {
            return Result.failure(
                IllegalStateException("تغییر کلید امنیتی مخاطب باید به‌طور صریح توسط کاربر تأیید شود")
            )
        }
        val confirmedRecord = staged.candidateRecord.copy(pairedAtEpochSec = nowEpochSec)
        trustStore.savePinnedPeer(confirmedRecord)
        activeOffer = null
        stagedConfirmation = null
        return Result.success(confirmedRecord)
    }

    @Synchronized
    fun cancelPendingSession() {
        activeOffer = null
        clearStagedConfirmation()
    }

    /**
     * Secure unpair / re-pairing reset procedure:
     * Archives the previous peer fingerprint (so key-change alerts still fire on re-pair),
     * clears the active pairing slot, and rotates this device's Signed Pre-Key.
     */
    @Synchronized
    fun unpairForSecureRePairing(
        regenerateDeviceIdentity: Boolean = false,
        nowEpochSec: Long = currentEpochSec()
    ) {
        activeOffer = null
        clearStagedConfirmation()
        trustStore.archiveAndClearPinnedPeer()
        if (regenerateDeviceIdentity) {
            keyVault.resetIdentityKeys(nowEpochSec)
        } else {
            keyVault.rotateSignedPreKey(nowEpochSec)
        }
    }

    private fun handleScanWhenAlreadyPaired(
        existingPeer: PairedPeerRecord,
        decoded: QrPairingCodec.DecodedQrPacket,
        replayToken: ByteArray,
        verifyExistingPeerMode: Boolean
    ): QrProcessResult {
        val sameIdentityKey = ByteEncoding.constantTimeEquals(
            existingPeer.peerIkSigSpki,
            decoded.senderIkSigSpki
        )
        if (sameIdentityKey) {
            trustStore.recordReplayToken(replayToken)
            var updated = false
            if (decoded.senderSpk.spkId > existingPeer.peerSpkId) {
                trustStore.savePinnedPeer(
                    existingPeer.copy(
                        peerSpkId = decoded.senderSpk.spkId,
                        peerSpkDhSpki = decoded.senderSpk.publicKeySpki,
                        peerSpkIssuedAtSec = decoded.senderSpk.issuedAtEpochSec,
                        peerSpkExpiresAtSec = decoded.senderSpk.expiresAtEpochSec,
                        peerSpkSignature = decoded.senderSpk.signature
                    )
                )
                updated = true
            }
            return QrProcessResult.ExistingPeerVerified(
                peerDeviceId = existingPeer.peerDeviceId,
                safetyNumber = existingPeer.safetyNumber,
                preKeyUpdated = updated
            )
        }

        // Different identity key presented while already paired!
        if (verifyExistingPeerMode) {
            val newSafety = SafetyFingerprint.computeSafetyNumber(
                localDeviceId = keyVault.getDeviceId(),
                localIkSpki = keyVault.getIdentityPublicKeySpki(),
                peerDeviceId = decoded.senderDeviceId,
                peerIkSpki = decoded.senderIkSigSpki
            )
            val alert = KeyChangeAlert(
                previousDeviceId = existingPeer.peerDeviceId,
                previousSafetyNumber = existingPeer.safetyNumber,
                newDeviceId = decoded.senderDeviceId,
                newSafetyNumber = newSafety
            )
            return QrProcessResult.Rejected(
                reason = PairingRejectionReason.PEER_KEY_CHANGED_WARNING,
                keyChangeAlert = alert
            )
        }

        return QrProcessResult.Rejected(PairingRejectionReason.THIRD_DEVICE_BLOCKED)
    }

    private fun handleOfferAsResponder(
        offer: QrPairingCodec.DecodedQrPacket.Offer,
        replayToken: ByteArray,
        nowEpochSec: Long
    ): QrProcessResult {
        val localDeviceId = keyVault.getDeviceId()
        val localIkSpki = keyVault.getIdentityPublicKeySpki()
        val localSpk = keyVault.getCurrentSignedPreKey(nowEpochSec)

        val acceptNonce = ByteArray(QrPairingCodec.NONCE_BYTES).also { secureRandom.nextBytes(it) }
        val offerDigest = ByteEncoding.sha256(offer.signedTranscript)
        val acceptExp = nowEpochSec + OFFER_TTL_SEC

        val acceptTranscript = QrPairingCodec.buildAcceptSigningTranscript(
            sessionId = offer.sessionId,
            targetPeerDeviceId = offer.senderDeviceId,
            offerTranscriptDigest = offerDigest,
            senderDeviceId = localDeviceId,
            senderIkSigSpki = localIkSpki,
            senderSpk = localSpk,
            nonce = acceptNonce,
            issuedAtEpochSec = nowEpochSec,
            expiresAtEpochSec = acceptExp
        )
        val acceptSig = keyVault.signWithIdentity(acceptTranscript)
        val acceptUri = QrPairingCodec.encodeAcceptUri(
            sessionId = offer.sessionId,
            targetPeerDeviceId = offer.senderDeviceId,
            offerTranscriptDigest = offerDigest,
            senderDeviceId = localDeviceId,
            senderIkSigSpki = localIkSpki,
            senderSpk = localSpk,
            nonce = acceptNonce,
            issuedAtEpochSec = nowEpochSec,
            expiresAtEpochSec = acceptExp,
            signature = acceptSig
        )

        val dhSecret = keyVault.agreeWithSignedPreKey(localSpk.spkId, offer.senderSpk.publicKeySpki)
        val rootPairingKey = EcP256Crypto.deriveRootPairingKey(
            dhSharedSecret = dhSecret,
            sessionId = offer.sessionId,
            offerNonce = offer.nonce,
            acceptNonce = acceptNonce,
            offerDeviceId = offer.senderDeviceId,
            offerIkSpki = offer.senderIkSigSpki,
            acceptDeviceId = localDeviceId,
            acceptIkSpki = localIkSpki
        )

        val safetyNumber = SafetyFingerprint.computeSafetyNumber(
            localDeviceId = localDeviceId,
            localIkSpki = localIkSpki,
            peerDeviceId = offer.senderDeviceId,
            peerIkSpki = offer.senderIkSigSpki
        )
        val sessionCode = SafetyFingerprint.computeSessionVerificationCode(
            sessionId = offer.sessionId,
            offerDigest = offerDigest,
            offerNonce = offer.nonce,
            acceptNonce = acceptNonce
        )
        val keyChangeAlert = checkArchivedPeerKeyChange(
            newPeerDeviceId = offer.senderDeviceId,
            newPeerIkSpki = offer.senderIkSigSpki,
            newSafetyNumber = safetyNumber
        )

        trustStore.recordReplayToken(replayToken)
        activeOffer = null
        clearStagedConfirmation()
        stagedConfirmation = StagedConfirmation(
            role = PairingStateSnapshot.AwaitingUserConfirmation.Role.RESPONDER,
            acceptQrUri = acceptUri,
            candidateRecord = PairedPeerRecord(
                peerDeviceId = offer.senderDeviceId,
                peerIkSigSpki = offer.senderIkSigSpki,
                peerSpkId = offer.senderSpk.spkId,
                peerSpkDhSpki = offer.senderSpk.publicKeySpki,
                peerSpkIssuedAtSec = offer.senderSpk.issuedAtEpochSec,
                peerSpkExpiresAtSec = offer.senderSpk.expiresAtEpochSec,
                peerSpkSignature = offer.senderSpk.signature,
                safetyNumber = safetyNumber,
                rootPairingKey = rootPairingKey,
                pairedAtEpochSec = nowEpochSec
            ),
            sessionVerificationCode = sessionCode,
            expiresAtEpochSec = acceptExp,
            keyChangeAlert = keyChangeAlert
        )

        return QrProcessResult.ResponderReadyToConfirm(
            acceptQrUri = acceptUri,
            peerDeviceId = offer.senderDeviceId,
            safetyNumber = safetyNumber,
            sessionVerificationCode = sessionCode,
            expiresAtEpochSec = acceptExp,
            keyChangeFromPreviousPeer = keyChangeAlert
        )
    }

    private fun handleAcceptAsInitiator(
        accept: QrPairingCodec.DecodedQrPacket.Accept,
        replayToken: ByteArray,
        nowEpochSec: Long
    ): QrProcessResult {
        val localDeviceId = keyVault.getDeviceId()
        if (accept.targetPeerDeviceId != localDeviceId) {
            return QrProcessResult.Rejected(PairingRejectionReason.WRONG_PEER_TARGET)
        }
        val pendingOffer = activeOffer
            ?: return QrProcessResult.Rejected(PairingRejectionReason.NO_ACTIVE_OFFER_SESSION)

        if (nowEpochSec > pendingOffer.expiresAtEpochSec + CLOCK_SKEW_TOLERANCE_SEC) {
            activeOffer = null
            return QrProcessResult.Rejected(PairingRejectionReason.EXPIRED_PAYLOAD)
        }
        if (accept.sessionId != pendingOffer.sessionId) {
            return QrProcessResult.Rejected(PairingRejectionReason.OFFER_DIGEST_MISMATCH)
        }
        if (!ByteEncoding.constantTimeEquals(accept.offerTranscriptDigest, pendingOffer.offerTranscriptDigest)) {
            return QrProcessResult.Rejected(PairingRejectionReason.OFFER_DIGEST_MISMATCH)
        }

        val localIkSpki = keyVault.getIdentityPublicKeySpki()
        val dhSecret = keyVault.agreeWithSignedPreKey(
            localSpkId = pendingOffer.localSpk.spkId,
            peerDhPublicKeySpki = accept.senderSpk.publicKeySpki
        )
        val rootPairingKey = EcP256Crypto.deriveRootPairingKey(
            dhSharedSecret = dhSecret,
            sessionId = pendingOffer.sessionId,
            offerNonce = pendingOffer.offerNonce,
            acceptNonce = accept.nonce,
            offerDeviceId = localDeviceId,
            offerIkSpki = localIkSpki,
            acceptDeviceId = accept.senderDeviceId,
            acceptIkSpki = accept.senderIkSigSpki
        )

        val safetyNumber = SafetyFingerprint.computeSafetyNumber(
            localDeviceId = localDeviceId,
            localIkSpki = localIkSpki,
            peerDeviceId = accept.senderDeviceId,
            peerIkSpki = accept.senderIkSigSpki
        )
        val sessionCode = SafetyFingerprint.computeSessionVerificationCode(
            sessionId = pendingOffer.sessionId,
            offerDigest = pendingOffer.offerTranscriptDigest,
            offerNonce = pendingOffer.offerNonce,
            acceptNonce = accept.nonce
        )
        val keyChangeAlert = checkArchivedPeerKeyChange(
            newPeerDeviceId = accept.senderDeviceId,
            newPeerIkSpki = accept.senderIkSigSpki,
            newSafetyNumber = safetyNumber
        )

        trustStore.recordReplayToken(replayToken)
        activeOffer = null
        clearStagedConfirmation()
        stagedConfirmation = StagedConfirmation(
            role = PairingStateSnapshot.AwaitingUserConfirmation.Role.INITIATOR,
            acceptQrUri = null,
            candidateRecord = PairedPeerRecord(
                peerDeviceId = accept.senderDeviceId,
                peerIkSigSpki = accept.senderIkSigSpki,
                peerSpkId = accept.senderSpk.spkId,
                peerSpkDhSpki = accept.senderSpk.publicKeySpki,
                peerSpkIssuedAtSec = accept.senderSpk.issuedAtEpochSec,
                peerSpkExpiresAtSec = accept.senderSpk.expiresAtEpochSec,
                peerSpkSignature = accept.senderSpk.signature,
                safetyNumber = safetyNumber,
                rootPairingKey = rootPairingKey,
                pairedAtEpochSec = nowEpochSec
            ),
            sessionVerificationCode = sessionCode,
            expiresAtEpochSec = accept.expiresAtEpochSec,
            keyChangeAlert = keyChangeAlert
        )

        return QrProcessResult.InitiatorReadyToConfirm(
            peerDeviceId = accept.senderDeviceId,
            safetyNumber = safetyNumber,
            sessionVerificationCode = sessionCode,
            keyChangeFromPreviousPeer = keyChangeAlert
        )
    }

    private fun checkArchivedPeerKeyChange(
        newPeerDeviceId: String,
        newPeerIkSpki: ByteArray,
        newSafetyNumber: String
    ): KeyChangeAlert? {
        val archived = trustStore.loadArchivedPreviousPeer() ?: return null
        if (ByteEncoding.constantTimeEquals(archived.peerIkSigSpki, newPeerIkSpki)) {
            return null
        }
        return KeyChangeAlert(
            previousDeviceId = archived.peerDeviceId,
            previousSafetyNumber = archived.safetyNumber,
            newDeviceId = newPeerDeviceId,
            newSafetyNumber = newSafetyNumber
        )
    }

    private fun isFreshTimestampWindow(iat: Long, exp: Long, now: Long): Boolean {
        if (exp <= iat) return false
        if (exp - iat > MAX_OFFER_WINDOW_SEC) return false
        if (iat > now + CLOCK_SKEW_TOLERANCE_SEC) return false
        if (now > exp + CLOCK_SKEW_TOLERANCE_SEC) return false
        return true
    }

    private fun computeReplayToken(packet: QrPairingCodec.DecodedQrPacket): ByteArray {
        val typeLabel = when (packet) {
            is QrPairingCodec.DecodedQrPacket.Offer -> "OFFER"
            is QrPairingCodec.DecodedQrPacket.Accept -> "ACCEPT"
        }
        val transcript = TranscriptBuilder()
            .putUtf8("DUOLINK-REPLAY-TOKEN-V1")
            .putUtf8(typeLabel)
            .putUtf8(packet.sessionId)
            .putUtf8(packet.senderDeviceId)
            .putBytes(packet.nonce)
            .build()
        return ByteEncoding.sha256(transcript)
    }

    private fun clearStagedConfirmation() {
        stagedConfirmation?.candidateRecord?.rootPairingKey?.zeroize()
        stagedConfirmation = null
    }

    private fun currentEpochSec(): Long = System.currentTimeMillis() / 1000L
}
