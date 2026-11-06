package com.duolink.app.pairing

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.DeviceKeyVault
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.HkdfSha256
import com.duolink.app.crypto.LocalIdentityPublic
import com.duolink.app.crypto.SafetyFingerprint
import com.duolink.app.crypto.SignedPreKeyPublic
import com.duolink.app.crypto.VaultHealth
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays

/**
 * Coordinates DuoLink's two-person mutual QR pairing, replay protection, single-peer pinning,
 * key-change detection, fail-closed corruption handling, and secure re-pairing.
 */
class PairingCoordinator(
    private val keyVault: DeviceKeyVault,
    private val trustStore: PeerTrustStore,
    private val secureRandom: SecureRandom = SecureRandom(),
    private val qrTtlSeconds: Long = DEFAULT_QR_TTL_SECONDS,
    private val maxClockSkewSeconds: Long = DEFAULT_CLOCK_SKEW_SECONDS
) {
    private var activeInitiatorOffer: ActiveInitiatorOffer? = null
    private var pendingConfirmation: PendingPairingConfirmation? = null

    private data class ActiveInitiatorOffer(
        val qrString: String,
        val packet: PairingQrPacket,
        val localSpkIdUsed: Int
    )

    data class OfferGenerationResult(
        val qrString: String,
        val sessionIdHex: String,
        val expiresAtEpochSec: Long
    )

    sealed class QrProcessResult {
        data class ResponderReadyToConfirm(
            val acceptQrToDisplay: String,
            val safetyNumber: String,
            val publicHandshakeTranscriptId: String,
            val peerDeviceIdHex: String,
            val previousPeerChanged: Boolean,
            val previousPeerDeviceIdHex: String?
        ) : QrProcessResult()

        data class InitiatorReadyToConfirm(
            val safetyNumber: String,
            val publicHandshakeTranscriptId: String,
            val peerDeviceIdHex: String,
            val previousPeerChanged: Boolean,
            val previousPeerDeviceIdHex: String?
        ) : QrProcessResult()

        data class Rejected(
            val reason: PairingRejectionReason,
            val detail: String
        ) : QrProcessResult()
    }

    /**
     * Evaluates both key-vault metadata health and trust-store health. Any corruption immediately
     * surfaces as [TrustStoreHealth.Corrupted] so every pairing/re-pairing flow fails closed.
     */
    @Synchronized
    fun inspectCombinedSecurityHealth(): TrustStoreHealth {
        when (val vaultHealth = keyVault.checkVaultHealth()) {
            is VaultHealth.Corrupted -> return TrustStoreHealth.Corrupted(
                component = TrustStoreComponent.KEY_VAULT,
                reason = vaultHealth.reason
            )
            is VaultHealth.Healthy -> {}
        }
        return trustStore.inspectHealth()
    }

    @Synchronized
    fun currentStateSnapshot(nowEpochSec: Long = currentEpochSec()): PairingStateSnapshot {
        when (val health = inspectCombinedSecurityHealth()) {
            is TrustStoreHealth.Corrupted -> return PairingStateSnapshot.TrustStorageCorrupted(
                component = health.component,
                technicalReason = health.reason
            )
            is TrustStoreHealth.Healthy -> {}
        }

        when (val pinned = trustStore.readPinnedPeer()) {
            is PinnedPeerReadResult.Corrupted -> return PairingStateSnapshot.TrustStorageCorrupted(
                component = TrustStoreComponent.PINNED_PEER,
                technicalReason = pinned.reason
            )
            is PinnedPeerReadResult.Valid -> return PairingStateSnapshot.PairedActive(pinned.record)
            is PinnedPeerReadResult.None -> {}
        }

        val pending = pendingConfirmation
        if (pending != null) {
            return PairingStateSnapshot.AwaitingUserConfirmation(
                peerDeviceIdHex = ByteEncoding.toHexLower(pending.peerDeviceId),
                safetyNumber = pending.safetyNumber,
                publicHandshakeTranscriptId = pending.publicHandshakeTranscriptId,
                responseAcceptQrPayload = pending.responseQrStringForPeer,
                previousPeerChanged = pending.previousPeerChanged,
                previousPeerDeviceIdHex = pending.previousPeerDeviceIdHex
            )
        }

        val offer = activeInitiatorOffer
        if (offer != null && nowEpochSec <= offer.packet.expiresAtEpochSec) {
            return PairingStateSnapshot.InitiatorOfferReady(
                offerQrPayload = offer.qrString,
                sessionIdHex = ByteEncoding.toHexLower(offer.packet.sessionId),
                expiresAtEpochSec = offer.packet.expiresAtEpochSec
            )
        } else if (offer != null) {
            activeInitiatorOffer = null
        }
        return PairingStateSnapshot.UnpairedIdle
    }

    /**
     * Step 1 (Device A): Creates a fresh signed `OFFER` QR payload.
     * Refuses if security storage is corrupted or if a peer is already pinned.
     */
    @Synchronized
    fun startInitiatorOffer(nowEpochSec: Long = currentEpochSec()): Result<OfferGenerationResult> {
        ensureSecurityStorageHealthyResult()?.let { return Result.failure(it) }

        when (val pinned = trustStore.readPinnedPeer()) {
            is PinnedPeerReadResult.Valid -> return Result.failure(
                PairingValidationException(
                    PairingRejectionReason.THIRD_DEVICE_BLOCKED,
                    PairingRejectionReason.THIRD_DEVICE_BLOCKED.persianMessage
                )
            )
            is PinnedPeerReadResult.Corrupted -> return Result.failure(
                PairingValidationException(
                    PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                    pinned.reason
                )
            )
            is PinnedPeerReadResult.None -> {}
        }

        pendingConfirmation = null
        val localIdentity = try {
            keyVault.getOrCreateLocalIdentity(nowEpochSec)
        } catch (e: Exception) {
            return Result.failure(
                PairingValidationException(
                    PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                    e.message ?: PairingRejectionReason.TRUST_STORAGE_CORRUPTED.persianMessage,
                    e
                )
            )
        }

        val sessionId = ByteArray(16).also { secureRandom.nextBytes(it) }
        val offerNonce = ByteArray(32).also { secureRandom.nextBytes(it) }
        val expiresAt = nowEpochSec + qrTtlSeconds

        val qrString = QrPairingCodec.encodeSignedPacket(
            role = QrPacketRole.OFFER,
            sessionId = sessionId,
            issuedAtEpochSec = nowEpochSec,
            expiresAtEpochSec = expiresAt,
            localIdentity = localIdentity,
            senderNonce = offerNonce,
            targetInitiatorDeviceId = null,
            boundOfferDigest = null,
            keyVault = keyVault
        )
        val parsed = QrPairingCodec.decodeAndVerifySignatures(qrString)
        activeInitiatorOffer = ActiveInitiatorOffer(
            qrString = qrString,
            packet = parsed,
            localSpkIdUsed = localIdentity.currentSignedPreKey.spkId
        )
        return Result.success(
            OfferGenerationResult(
                qrString = qrString,
                sessionIdHex = ByteEncoding.toHexLower(sessionId),
                expiresAtEpochSec = expiresAt
            )
        )
    }

    /**
     * Processes a scanned QR string as either:
     * - Responder scanning an `OFFER` QR (when unpaired/idle), OR
     * - Initiator scanning the matching `ACCEPT` QR for its active `OFFER`.
     *
     * Fails closed with [PairingRejectionReason.TRUST_STORAGE_CORRUPTED] if any trust, archive,
     * replay, or SPK metadata store is corrupted.
     */
    @Synchronized
    fun processScannedQr(
        qrText: String,
        nowEpochSec: Long = currentEpochSec()
    ): QrProcessResult {
        ensureSecurityStorageHealthyResult()?.let { err ->
            return QrProcessResult.Rejected(err.reason, err.message)
        }

        when (val existingPeer = trustStore.readPinnedPeer()) {
            is PinnedPeerReadResult.Valid -> return QrProcessResult.Rejected(
                PairingRejectionReason.THIRD_DEVICE_BLOCKED,
                PairingRejectionReason.THIRD_DEVICE_BLOCKED.persianMessage
            )
            is PinnedPeerReadResult.Corrupted -> return QrProcessResult.Rejected(
                PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                existingPeer.reason
            )
            is PinnedPeerReadResult.None -> {}
        }

        val packet = try {
            QrPairingCodec.decodeAndVerifySignatures(qrText)
        } catch (e: PairingValidationException) {
            return QrProcessResult.Rejected(e.reason, e.reason.persianMessage)
        } catch (e: Exception) {
            return QrProcessResult.Rejected(
                PairingRejectionReason.MALFORMED_PAYLOAD,
                PairingRejectionReason.MALFORMED_PAYLOAD.persianMessage
            )
        }

        if (packet.issuedAtEpochSec > nowEpochSec + maxClockSkewSeconds) {
            return QrProcessResult.Rejected(
                PairingRejectionReason.FUTURE_TIMESTAMP_SKEW,
                PairingRejectionReason.FUTURE_TIMESTAMP_SKEW.persianMessage
            )
        }
        if (nowEpochSec > packet.expiresAtEpochSec) {
            return QrProcessResult.Rejected(
                PairingRejectionReason.EXPIRED_QR,
                PairingRejectionReason.EXPIRED_QR.persianMessage
            )
        }

        val localIdentity = try {
            keyVault.getOrCreateLocalIdentity(nowEpochSec)
        } catch (e: Exception) {
            return QrProcessResult.Rejected(
                PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                e.message ?: PairingRejectionReason.TRUST_STORAGE_CORRUPTED.persianMessage
            )
        }

        if (ByteEncoding.constantTimeEquals(packet.senderDeviceId, localIdentity.deviceId) ||
            ByteEncoding.constantTimeEquals(packet.senderIkSigSpki, localIdentity.identitySigningPublicKeySpki)
        ) {
            return QrProcessResult.Rejected(
                PairingRejectionReason.SELF_PAIRING_FORBIDDEN,
                PairingRejectionReason.SELF_PAIRING_FORBIDDEN.persianMessage
            )
        }

        val replayToken = buildReplayToken(packet)
        val seenReplay = try {
            trustStore.hasSeenReplayToken(replayToken)
        } catch (e: TrustStorageCorruptedException) {
            return QrProcessResult.Rejected(
                PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                e.message ?: PairingRejectionReason.TRUST_STORAGE_CORRUPTED.persianMessage
            )
        }
        if (seenReplay) {
            return QrProcessResult.Rejected(
                PairingRejectionReason.REPLAYED_SESSION,
                PairingRejectionReason.REPLAYED_SESSION.persianMessage
            )
        }

        return when (packet.role) {
            QrPacketRole.OFFER -> handleIncomingOffer(packet, localIdentity, replayToken, nowEpochSec)
            QrPacketRole.ACCEPT -> handleIncomingAccept(packet, localIdentity, replayToken, nowEpochSec)
        }
    }

    /**
     * Explicit user confirmation of the **complete 60-digit Safety Number** compared through an
     * independent trusted channel (in person or direct trusted voice call).
     *
     * Rules enforced:
     * 1. Security storage (`trustStore` + `keyVault`) MUST be healthy (fail-closed).
     * 2. [fullSafetyNumberComparedViaTrustedChannel] MUST be `true`.
     * 3. If [PendingPairingConfirmation.previousPeerChanged] is `true`, [acknowledgeKeyChange] MUST also be `true`.
     */
    @Synchronized
    fun confirmSafetyFingerprint(
        fullSafetyNumberComparedViaTrustedChannel: Boolean,
        nowEpochSec: Long = currentEpochSec(),
        acknowledgeKeyChange: Boolean = false
    ): Result<PairedPeerRecord> {
        ensureSecurityStorageHealthyResult()?.let { return Result.failure(it) }

        if (!fullSafetyNumberComparedViaTrustedChannel) {
            return Result.failure(
                IllegalStateException(
                    "مقایسه کامل تمام ۶۰ رقم کد امنیتی از طریق یک کانال مستقل و مورد اعتماد الزامی است"
                )
            )
        }

        when (val pinned = trustStore.readPinnedPeer()) {
            is PinnedPeerReadResult.Valid -> return Result.failure(
                PairingValidationException(
                    PairingRejectionReason.THIRD_DEVICE_BLOCKED,
                    PairingRejectionReason.THIRD_DEVICE_BLOCKED.persianMessage
                )
            )
            is PinnedPeerReadResult.Corrupted -> return Result.failure(
                PairingValidationException(
                    PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                    pinned.reason
                )
            )
            is PinnedPeerReadResult.None -> {}
        }

        val pending = pendingConfirmation
            ?: return Result.failure(IllegalStateException("هیچ جلسه جفت‌سازی در انتظار تأیید وجود ندارد"))

        if (pending.previousPeerChanged && !acknowledgeKeyChange) {
            return Result.failure(
                IllegalStateException("تغییر کلید امنیتی مخاطب شناسایی شده و نیازمند تأیید آگاهانه است")
            )
        }

        val record = PairedPeerRecord(
            peerDeviceId = pending.peerDeviceId.copyOf(),
            peerIkSigSpki = pending.peerIkSigSpki.copyOf(),
            peerSpkId = pending.peerSpk.spkId,
            peerSpkPubSpki = pending.peerSpk.publicKeySpki.copyOf(),
            peerSpkSignature = pending.peerSpk.signatureByIdentityKey.copyOf(),
            peerSpkCreatedAtEpochSec = pending.peerSpk.createdAtEpochSec,
            rootPairingKey = pending.derivedRootPairingKey.copyOf(),
            safetyNumber = pending.safetyNumber,
            pairedAtEpochSec = nowEpochSec,
            safetyNumberVerified = true
        )
        return try {
            trustStore.savePinnedPeer(record)
            Arrays.fill(pending.derivedRootPairingKey, 0.toByte())
            pendingConfirmation = null
            activeInitiatorOffer = null
            Result.success(record)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    @Synchronized
    fun cancelPendingPairing() {
        pendingConfirmation?.let { Arrays.fill(it.derivedRootPairingKey, 0.toByte()) }
        pendingConfirmation = null
        activeInitiatorOffer = null
    }

    /**
     * Explicit user-initiated unpairing / secure re-pairing flow.
     * Archives the previous peer identity so re-pairing with a different identity key triggers
     * an explicit key-change warning.
     *
     * Fails closed with [Result.failure] if security storage is corrupted (never silently wipes
     * corrupted archives).
     */
    @Synchronized
    fun unpairForSecureRePairing(
        rotateDeviceIdentity: Boolean = false,
        nowEpochSec: Long = currentEpochSec()
    ): Result<Unit> {
        ensureSecurityStorageHealthyResult()?.let { return Result.failure(it) }
        return try {
            cancelPendingPairing()
            trustStore.archiveAndClearPinnedPeer()
            if (rotateDeviceIdentity) {
                keyVault.resetIdentityKeys(nowEpochSec)
            } else {
                keyVault.rotateSignedPreKey(nowEpochSec)
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Explicit destructive recovery procedure required when `pinned_peer_v1`, `archived_peer_v1`,
     * `replay_ledger_v1`, or `spk_entries_v2` is corrupted.
     *
     * Requires [confirmDestructiveRecovery] = `true`, purges corrupted local security files, rotates
     * device identity keys (`IK_sig` + `SPK_dh`), and re-initializes an authenticated replay ledger.
     */
    @Synchronized
    fun recoverFromCorruptedStorage(
        confirmDestructiveRecovery: Boolean,
        nowEpochSec: Long = currentEpochSec()
    ): Result<LocalIdentityPublic> {
        if (!confirmDestructiveRecovery) {
            return Result.failure(
                IllegalStateException("تأیید صریح کاربر برای بازیابی و بازنشانی ذخیره‌سازی امن الزامی است")
            )
        }
        return try {
            cancelPendingPairing()
            trustStore.purgeCorruptedTrustStateForRecovery()
            val freshIdentity = keyVault.resetIdentityKeys(nowEpochSec)
            when (val health = inspectCombinedSecurityHealth()) {
                is TrustStoreHealth.Corrupted -> Result.failure(
                    PairingValidationException(
                        PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                        health.reason
                    )
                )
                is TrustStoreHealth.Healthy -> Result.success(freshIdentity)
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun ensureSecurityStorageHealthyResult(): PairingValidationException? {
        return when (val health = inspectCombinedSecurityHealth()) {
            is TrustStoreHealth.Healthy -> null
            is TrustStoreHealth.Corrupted -> PairingValidationException(
                PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                "${PairingRejectionReason.TRUST_STORAGE_CORRUPTED.persianMessage} [${health.component}: ${health.reason}]"
            )
        }
    }

    private fun handleIncomingOffer(
        offer: PairingQrPacket,
        localIdentity: LocalIdentityPublic,
        replayToken: ByteArray,
        nowEpochSec: Long
    ): QrProcessResult {
        if (activeInitiatorOffer != null) {
            return QrProcessResult.Rejected(
                PairingRejectionReason.UNEXPECTED_PACKET_ROLE,
                "این دستگاه منتظر اسکن کد پاسخ (ACCEPT) است، نه کد درخواست جدید"
            )
        }

        val previousCheck = evaluateArchivedPeerHistoryStrict(offer.senderIkSigSpki)
            ?: return QrProcessResult.Rejected(
                PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                PairingRejectionReason.TRUST_STORAGE_CORRUPTED.persianMessage
            )

        val acceptNonce = ByteArray(32).also { secureRandom.nextBytes(it) }
        val expiresAt = nowEpochSec + qrTtlSeconds

        val acceptQr = QrPairingCodec.encodeSignedPacket(
            role = QrPacketRole.ACCEPT,
            sessionId = offer.sessionId,
            issuedAtEpochSec = nowEpochSec,
            expiresAtEpochSec = expiresAt,
            localIdentity = localIdentity,
            senderNonce = acceptNonce,
            targetInitiatorDeviceId = offer.senderDeviceId,
            boundOfferDigest = offer.rawTranscriptDigestSha256,
            keyVault = keyVault
        )
        val acceptParsed = QrPairingCodec.decodeAndVerifySignatures(acceptQr)

        val rootKey = try {
            deriveRootPairingKey(
                localSpkId = localIdentity.currentSignedPreKey.spkId,
                peerSpk = offer.senderSpk,
                initiatorIdentitySpki = offer.senderIkSigSpki,
                responderIdentitySpki = localIdentity.identitySigningPublicKeySpki,
                initiatorDeviceId = offer.senderDeviceId,
                responderDeviceId = localIdentity.deviceId,
                sessionId = offer.sessionId,
                offerDigest = offer.rawTranscriptDigestSha256,
                acceptDigest = acceptParsed.rawTranscriptDigestSha256,
                offerNonce = offer.senderNonce,
                acceptNonce = acceptNonce
            )
        } catch (e: Exception) {
            return QrProcessResult.Rejected(
                PairingRejectionReason.INVALID_PUBLIC_KEY,
                PairingRejectionReason.INVALID_PUBLIC_KEY.persianMessage
            )
        }

        val safetyNumber = SafetyFingerprint.computeSafetyNumber(
            localDeviceId = localIdentity.deviceId,
            localIdentityPublicKeySpki = localIdentity.identitySigningPublicKeySpki,
            peerDeviceId = offer.senderDeviceId,
            peerIdentityPublicKeySpki = offer.senderIkSigSpki
        )
        val publicTranscriptId = SafetyFingerprint.computePublicHandshakeTranscriptId(
            sessionId = offer.sessionId,
            offerDigest = offer.rawTranscriptDigestSha256,
            offerNonce = offer.senderNonce,
            acceptNonce = acceptNonce
        )

        try {
            trustStore.recordReplayToken(replayToken)
        } catch (e: TrustStorageCorruptedException) {
            Arrays.fill(rootKey, 0.toByte())
            return QrProcessResult.Rejected(
                PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                e.message ?: PairingRejectionReason.TRUST_STORAGE_CORRUPTED.persianMessage
            )
        }

        pendingConfirmation?.let { Arrays.fill(it.derivedRootPairingKey, 0.toByte()) }
        pendingConfirmation = PendingPairingConfirmation(
            sessionId = offer.sessionId.copyOf(),
            peerDeviceId = offer.senderDeviceId.copyOf(),
            peerIkSigSpki = offer.senderIkSigSpki.copyOf(),
            peerSpk = offer.senderSpk,
            derivedRootPairingKey = rootKey,
            safetyNumber = safetyNumber,
            publicHandshakeTranscriptId = publicTranscriptId,
            responseQrStringForPeer = acceptQr,
            previousPeerChanged = previousCheck.first,
            previousPeerDeviceIdHex = previousCheck.second
        )

        return QrProcessResult.ResponderReadyToConfirm(
            acceptQrToDisplay = acceptQr,
            safetyNumber = safetyNumber,
            publicHandshakeTranscriptId = publicTranscriptId,
            peerDeviceIdHex = ByteEncoding.toHexLower(offer.senderDeviceId),
            previousPeerChanged = previousCheck.first,
            previousPeerDeviceIdHex = previousCheck.second
        )
    }

    private fun handleIncomingAccept(
        accept: PairingQrPacket,
        localIdentity: LocalIdentityPublic,
        replayToken: ByteArray,
        nowEpochSec: Long
    ): QrProcessResult {
        val activeOffer = activeInitiatorOffer
            ?: return QrProcessResult.Rejected(
                PairingRejectionReason.UNEXPECTED_PACKET_ROLE,
                "هیچ درخواست جفت‌سازی فعالی روی این دستگاه وجود ندارد"
            )

        if (nowEpochSec > activeOffer.packet.expiresAtEpochSec) {
            activeInitiatorOffer = null
            return QrProcessResult.Rejected(
                PairingRejectionReason.EXPIRED_QR,
                "درخواست جفت‌سازی اولیه منقضی شده است؛ کد جدید بسازید"
            )
        }

        val targetInitId = accept.targetInitiatorDeviceId
        val boundOfferDigest = accept.boundOfferDigest
        if (targetInitId == null ||
            boundOfferDigest == null ||
            !ByteEncoding.constantTimeEquals(accept.sessionId, activeOffer.packet.sessionId) ||
            !ByteEncoding.constantTimeEquals(targetInitId, localIdentity.deviceId) ||
            !ByteEncoding.constantTimeEquals(boundOfferDigest, activeOffer.packet.rawTranscriptDigestSha256)
        ) {
            return QrProcessResult.Rejected(
                PairingRejectionReason.SESSION_MISMATCH,
                PairingRejectionReason.SESSION_MISMATCH.persianMessage
            )
        }

        val previousCheck = evaluateArchivedPeerHistoryStrict(accept.senderIkSigSpki)
            ?: return QrProcessResult.Rejected(
                PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                PairingRejectionReason.TRUST_STORAGE_CORRUPTED.persianMessage
            )

        val rootKey = try {
            deriveRootPairingKey(
                localSpkId = activeOffer.localSpkIdUsed,
                peerSpk = accept.senderSpk,
                initiatorIdentitySpki = localIdentity.identitySigningPublicKeySpki,
                responderIdentitySpki = accept.senderIkSigSpki,
                initiatorDeviceId = localIdentity.deviceId,
                responderDeviceId = accept.senderDeviceId,
                sessionId = activeOffer.packet.sessionId,
                offerDigest = activeOffer.packet.rawTranscriptDigestSha256,
                acceptDigest = accept.rawTranscriptDigestSha256,
                offerNonce = activeOffer.packet.senderNonce,
                acceptNonce = accept.senderNonce
            )
        } catch (e: Exception) {
            return QrProcessResult.Rejected(
                PairingRejectionReason.INVALID_PUBLIC_KEY,
                PairingRejectionReason.INVALID_PUBLIC_KEY.persianMessage
            )
        }

        val safetyNumber = SafetyFingerprint.computeSafetyNumber(
            localDeviceId = localIdentity.deviceId,
            localIdentityPublicKeySpki = localIdentity.identitySigningPublicKeySpki,
            peerDeviceId = accept.senderDeviceId,
            peerIdentityPublicKeySpki = accept.senderIkSigSpki
        )
        val publicTranscriptId = SafetyFingerprint.computePublicHandshakeTranscriptId(
            sessionId = activeOffer.packet.sessionId,
            offerDigest = activeOffer.packet.rawTranscriptDigestSha256,
            offerNonce = activeOffer.packet.senderNonce,
            acceptNonce = accept.senderNonce
        )

        try {
            trustStore.recordReplayToken(replayToken)
        } catch (e: TrustStorageCorruptedException) {
            Arrays.fill(rootKey, 0.toByte())
            return QrProcessResult.Rejected(
                PairingRejectionReason.TRUST_STORAGE_CORRUPTED,
                e.message ?: PairingRejectionReason.TRUST_STORAGE_CORRUPTED.persianMessage
            )
        }

        pendingConfirmation?.let { Arrays.fill(it.derivedRootPairingKey, 0.toByte()) }
        pendingConfirmation = PendingPairingConfirmation(
            sessionId = activeOffer.packet.sessionId.copyOf(),
            peerDeviceId = accept.senderDeviceId.copyOf(),
            peerIkSigSpki = accept.senderIkSigSpki.copyOf(),
            peerSpk = accept.senderSpk,
            derivedRootPairingKey = rootKey,
            safetyNumber = safetyNumber,
            publicHandshakeTranscriptId = publicTranscriptId,
            responseQrStringForPeer = null,
            previousPeerChanged = previousCheck.first,
            previousPeerDeviceIdHex = previousCheck.second
        )
        activeInitiatorOffer = null

        return QrProcessResult.InitiatorReadyToConfirm(
            safetyNumber = safetyNumber,
            publicHandshakeTranscriptId = publicTranscriptId,
            peerDeviceIdHex = ByteEncoding.toHexLower(accept.senderDeviceId),
            previousPeerChanged = previousCheck.first,
            previousPeerDeviceIdHex = previousCheck.second
        )
    }

    /**
     * Evaluates historical archived peer state strictly:
     * - [ArchivedPeerReadResult.None] -> `false to null`
     * - [ArchivedPeerReadResult.Valid] -> `changed to prevHex`
     * - [ArchivedPeerReadResult.Corrupted] -> `null` (caller MUST block fail-closed!)
     */
    private fun evaluateArchivedPeerHistoryStrict(candidateIkSpki: ByteArray): Pair<Boolean, String?>? {
        return when (val prev = trustStore.readArchivedPreviousPeer()) {
            is ArchivedPeerReadResult.None -> false to null
            is ArchivedPeerReadResult.Corrupted -> null
            is ArchivedPeerReadResult.Valid -> {
                val changed = !ByteEncoding.constantTimeEquals(prev.identity.peerIkSigSpki, candidateIkSpki)
                changed to ByteEncoding.toHexLower(prev.identity.peerDeviceId)
            }
        }
    }

    private fun deriveRootPairingKey(
        localSpkId: Int,
        peerSpk: SignedPreKeyPublic,
        initiatorIdentitySpki: ByteArray,
        responderIdentitySpki: ByteArray,
        initiatorDeviceId: ByteArray,
        responderDeviceId: ByteArray,
        sessionId: ByteArray,
        offerDigest: ByteArray,
        acceptDigest: ByteArray,
        offerNonce: ByteArray,
        acceptNonce: ByteArray
    ): ByteArray {
        val ecdhShared = keyVault.agreeWithSignedPreKey(localSpkId, peerSpk.publicKeySpki)
        return try {
            val salt = MessageDigest.getInstance("SHA-256").run {
                update("DuoLink-PairSalt-v1".toByteArray(StandardCharsets.UTF_8))
                update(sessionId)
                update(offerNonce)
                update(acceptNonce)
                digest()
            }
            val infoPrefix = "DuoLink-PairRoot-v1".toByteArray(StandardCharsets.UTF_8)
            val infoBuf = ByteBuffer.allocate(
                infoPrefix.size +
                    16 + 16 +
                    4 + initiatorIdentitySpki.size +
                    4 + responderIdentitySpki.size +
                    32 + 32
            )
            infoBuf.put(infoPrefix)
            infoBuf.put(initiatorDeviceId)
            infoBuf.put(responderDeviceId)
            infoBuf.putInt(initiatorIdentitySpki.size)
            infoBuf.put(initiatorIdentitySpki)
            infoBuf.putInt(responderIdentitySpki.size)
            infoBuf.put(responderIdentitySpki)
            infoBuf.put(offerDigest)
            infoBuf.put(acceptDigest)

            HkdfSha256.deriveKey(
                ikm = ecdhShared,
                salt = salt,
                info = infoBuf.array(),
                outputLength = 32
            )
        } finally {
            Arrays.fill(ecdhShared, 0.toByte())
        }
    }

    private fun buildReplayToken(packet: PairingQrPacket): ByteArray {
        val buf = ByteBuffer.allocate(1 + 16 + 16 + 32)
        buf.put(packet.role.wireCode)
        buf.put(packet.sessionId)
        buf.put(packet.senderDeviceId)
        buf.put(packet.senderNonce)
        return buf.array()
    }

    companion object {
        const val DEFAULT_QR_TTL_SECONDS: Long = 300L
        const val DEFAULT_CLOCK_SKEW_SECONDS: Long = 90L

        fun currentEpochSec(): Long = System.currentTimeMillis() / 1000L
    }
}
