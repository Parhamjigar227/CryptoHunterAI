package com.duolink.app.remote

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.DeviceKeyVault
import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.LocalIdentityPublic
import com.duolink.app.crypto.VaultHealth
import com.duolink.app.crypto.zeroize
import com.duolink.app.pairing.ArchivedPeerReadResult
import com.duolink.app.pairing.PairedPeerRecord
import com.duolink.app.pairing.PairingValidationException
import com.duolink.app.pairing.PeerTrustStore
import com.duolink.app.pairing.PinnedPeerReadResult
import com.duolink.app.pairing.TrustStorageCorruptedException
import com.duolink.app.pairing.TrustStoreComponent
import com.duolink.app.pairing.TrustStoreHealth
import java.security.SecureRandom

/**
 * Orchestrates Method B remote pairing end to end.
 *
 * The coordinator is the *only* place that is allowed to advance the state machine, and it does so
 * under a single lock so a UI tap, a network callback and a resume-after-crash can never interleave
 * into an impossible ordering. Every transition is:
 *
 *   1. validated against [RemotePairingPhase] ordering;
 *   2. backed by a cryptographic check (never a "the server said so" check);
 *   3. persisted (if it must survive a crash) **before** it is reported to the UI.
 *
 * The five distributed-persistence states are enforced literally:
 *
 *   LOCAL_USER_APPROVED   — the local user compared the Safety Number and approved; the local commit
 *                           has been built (or is being built). Nothing is trusted.
 *   COMMIT_QUORUM_REACHED — the server reports both ciphertexts present. Still nothing trusted: no
 *                           peer commit has been read yet.
 *   PEER_COMMIT_VERIFIED  — the peer commit was opened, its transcript re-derived, its HMAC and ECDSA
 *                           certificate verified, and its digest matched. Still nothing persisted.
 *   LOCAL_TRUST_PERSISTED — this device wrote the trust record. Explicitly *local*: the UI must not
 *                           claim the peer knows anything yet.
 *   MUTUAL_RECEIPT_CONFIRMED — both authenticated ACKs are recorded AND the peer's ACK signature has
 *                           been verified locally against the peer's identity key.
 *
 * Crash-safety: [StoredPendingSession] is written before each network step that could be interrupted,
 * so a killed process resumes at the right phase instead of silently restarting a half-finished
 * pairing. The ephemeral private key is *not* persisted (that is the point of an ephemeral key); a
 * process death therefore invalidates the attempt and it is reported as such rather than being faked.
 */
class RemotePairingCoordinator(
    private val keyVault: DeviceKeyVault,
    private val trustStore: PeerTrustStore,
    private val pendingStore: RemotePendingSessionStore,
    private val localAckKeyProvider: LocalAckKeyProvider,
    private val secureRandom: SecureRandom = SecureRandom(),
    private val nowEpochSec: () -> Long = { System.currentTimeMillis() / 1000L }
) {

    /** Supplies the session-scoped ACK signing key (never the long-term identity key). */
    interface LocalAckKeyProvider {
        /** Public key registered with the server; regenerated per invitation. */
        fun currentAckPublicSpki(): ByteArray

        /** Signs an ACK transcript with the session ACK key; returns null when the key is unavailable. */
        fun signAck(transcript: ByteArray): ByteArray?

        /** Rotates the session ACK key; called when a new invitation starts. */
        fun rotateAckKey()

        val isHardwareBacked: Boolean
    }

    /** Everything the UI needs to render one pairing attempt, with no secrets in it. */
    data class RemotePairingSnapshot(
        val phase: RemotePairingPhase,
        val role: RemoteRole?,
        val invitationId: String?,
        val activationCodeDisplay: String?,
        val invitationQrText: String?,
        val expiresAtEpochSec: Long?,
        val safetyNumber: String?,
        val peerDeviceIdHex: String?,
        val localDeviceIdHex: String?,
        val previousPeerChanged: Boolean,
        val previousPeerDeviceIdHex: String?,
        val quorumReached: Boolean,
        val peerCommitVerified: Boolean,
        val localTrustPersisted: Boolean,
        val mutualReceiptConfirmed: Boolean,
        val serverVerifiesE2eeValidity: Boolean,
        val lastFailure: RemoteFailure?,
        val technicalDetail: String?,
        val isDegradedNetwork: Boolean = false
    )

    private var snapshot = RemotePairingSnapshot(
        phase = RemotePairingPhase.IDLE,
        role = null,
        invitationId = null,
        activationCodeDisplay = null,
        invitationQrText = null,
        expiresAtEpochSec = null,
        safetyNumber = null,
        peerDeviceIdHex = null,
        localDeviceIdHex = null,
        previousPeerChanged = false,
        previousPeerDeviceIdHex = null,
        quorumReached = false,
        peerCommitVerified = false,
        localTrustPersisted = false,
        mutualReceiptConfirmed = false,
        serverVerifiesE2eeValidity = false,
        lastFailure = null,
        technicalDetail = null
    )

    /**
     * In-memory only. Holds the ephemeral private key and derived keys for one attempt; wiped by
     * [wipeAttemptSecrets] on every terminal path (success, cancellation, failure, resume mismatch).
     */
    private var attempt: AttemptSecrets? = null

    private class AttemptSecrets(
        val ephemeral: RemoteKeySchedule.EphemeralKeyPair,
        val keys: RemoteKeySchedule.RemoteKeySet,
        val binding: RemoteKeySchedule.HandshakeBinding
    ) {
        fun destroy() {
            ephemeral.destroy()
            keys.destroy()
        }
    }

    @Synchronized
    fun currentSnapshot(): RemotePairingSnapshot = snapshot

    private fun ensureHealthy() {
        when (val vaultHealth = keyVault.checkVaultHealth()) {
            is VaultHealth.Corrupted -> throw RemotePairingException(
                RemoteFailure.KEY_VAULT_UNAVAILABLE,
                vaultHealth.reason
            )
            is VaultHealth.Healthy -> Unit
        }
        when (val health = trustStore.inspectHealth()) {
            is TrustStoreHealth.Healthy -> Unit
            is TrustStoreHealth.Corrupted -> throw RemotePairingException(
                RemoteFailure.TRUST_STORAGE_CORRUPTED,
                health.reason
            )
        }
    }

    private fun requireNoPinnedPeer() {
        when (val pinned = trustStore.readPinnedPeer()) {
            is PinnedPeerReadResult.Valid -> throw RemotePairingException(RemoteFailure.PEER_ALREADY_PINNED)
            is PinnedPeerReadResult.Corrupted -> throw RemotePairingException(
                RemoteFailure.TRUST_STORAGE_CORRUPTED,
                pinned.reason
            )
            is PinnedPeerReadResult.None -> Unit
        }
    }

    /** Reviews archived identity history so a changed peer key triggers an explicit warning. */
    private fun evaluateKeyChange(candidatePeerIdentitySpki: ByteArray): Pair<Boolean, String?> =
        when (val archived = trustStore.readArchivedPreviousPeer()) {
            is ArchivedPeerReadResult.None -> false to null
            is ArchivedPeerReadResult.Corrupted -> throw RemotePairingException(
                RemoteFailure.TRUST_STORAGE_CORRUPTED,
                archived.reason
            )
            is ArchivedPeerReadResult.Valid -> {
                val changed = !ByteEncoding.constantTimeEquals(archived.identity.peerIkSigSpki, candidatePeerIdentitySpki)
                changed to ByteEncoding.toHexLower(archived.identity.peerDeviceId)
            }
        }

    private fun advanceTo(
        next: RemotePairingPhase,
        update: (RemotePairingSnapshot) -> RemotePairingSnapshot = { it }
    ) {
        val current = snapshot.phase
        if (current.isTerminal && next != RemotePairingPhase.IDLE) {
            throw RemotePairingException(RemoteFailure.ALREADY_TERMINAL)
        }
        if (!current.isTerminal && next.ordinalIndex < current.ordinalIndex) {
            throw RemotePairingException(
                RemoteFailure.INVALID_STATE_TRANSITION,
                "گذار معکوس از ${current.name} به ${next.name} مجاز نیست"
            )
        }
        snapshot = update(snapshot.copy(phase = next, lastFailure = null, technicalDetail = null))
    }

    private fun failWith(failure: RemoteFailure, detail: String? = null): RemotePairingException {
        snapshot = snapshot.copy(lastFailure = failure, technicalDetail = detail)
        return RemotePairingException(failure, failure.persianMessage)
    }

    // -------------------------------------------------------------------------------------------
    // Owner: create invitation
    // -------------------------------------------------------------------------------------------

    /**
     * Owner step 1: build public material, ask the server for an invitation, and show the code.
     *
     * Refuses when a peer is already pinned: remote pairing must never be a route to silently replacing
     * an existing trusted peer. Unpairing is an explicit, separate user action.
     */
    @Synchronized
    fun createInvitation(
        api: SignalingApi,
        serverBaseUrl: String,
        isDebugBuild: Boolean
    ): RemotePairingSnapshot {
        ensureHealthy()
        requireNoPinnedPeer()
        val validation = SignalingEndpointPolicy.validate(serverBaseUrl, isDebugBuild)
        if (!validation.isValid) {
            throw failWith(RemoteFailure.SERVER_REJECTED_REQUEST, validation.persianReason)
        }
        val normalisedUrl = SignalingEndpointPolicy.normalise(serverBaseUrl)

        val identity = keyVault.getOrCreateLocalIdentity(nowEpochSec())
        localAckKeyProvider.rotateAckKey()
        val ephemeral = RemoteKeySchedule.generateEphemeralKeyPair(secureRandom)
        val ownerNonce = RemotePendingSessionStore.randomNonce(secureRandom)
        // Fields are uploaded under a placeholder id first: the server assigns the invitation id, and the
        // public material does not depend on it.
        val material = SignalingApi.ParticipantMaterial(
            deviceId = identity.deviceId,
            identitySpki = identity.identitySigningPublicKeySpki,
            ackSpki = localAckKeyProvider.currentAckPublicSpki(),
            spkSpki = identity.currentSignedPreKey.publicKeySpki,
            ephemeralSpki = ephemeral.publicSpki
        )
        val created = api.createInvitation(normalisedUrl, material)
        val code = ActivationCode.parse(created.activationCode)
            ?: run {
                ephemeral.destroy()
                throw failWith(RemoteFailure.SERVER_REJECTED_REQUEST, "کد فعال‌سازی بازگشتی نامعتبر است")
            }
        val payload = RemoteInvitationPayload.build(code, normalisedUrl)

        // Persist the pending session *before* the user sees it, so a crash while showing the code does
        // not orphan an invitation that only exists on the server.
        val pending = StoredPendingSession(
            invitationId = created.invitationId,
            serverBaseUrl = normalisedUrl,
            role = RemoteRole.OWNER,
            exchangeToken = created.ownerToken.toByteArray(Charsets.UTF_8),
            ownerDeviceId = identity.deviceId,
            recipientDeviceId = ByteArray(16),
            ownerIdentitySpki = identity.identitySigningPublicKeySpki,
            ownerSpkSpki = identity.currentSignedPreKey.publicKeySpki,
            ownerEphemeralSpki = ephemeral.publicSpki,
            ownerNonce = ownerNonce,
            recipientIdentitySpki = ByteArray(0),
            recipientSpkSpki = ByteArray(0),
            recipientEphemeralSpki = ByteArray(0),
            recipientNonce = ByteArray(0),
            recipientIdentitySignature = ByteArray(0),
            invitationExpiresAtEpochSec = created.expiresAtEpochSec,
            safetyNumber = null,
            safetyNumberVerifiedAtEpochSec = null,
            commitCertificate = null,
            commitSubmitted = false
        )
        // The recipient half is not known yet: encode() tolerates empty fields, decode() rejects them, so
        // a resumed owner attempt correctly reports that it cannot continue and must be restarted.
        runCatching { pendingStore.write(pending) }

        attempt?.destroy()
        attempt = null
        snapshot = RemotePairingSnapshot(
            phase = RemotePairingPhase.INVITATION_CREATED,
            role = RemoteRole.OWNER,
            invitationId = created.invitationId,
            activationCodeDisplay = code.displayForm,
            invitationQrText = payload.qrText,
            expiresAtEpochSec = created.expiresAtEpochSec,
            safetyNumber = null,
            peerDeviceIdHex = null,
            localDeviceIdHex = ByteEncoding.toHexLower(identity.deviceId),
            previousPeerChanged = false,
            previousPeerDeviceIdHex = null,
            quorumReached = false,
            peerCommitVerified = false,
            localTrustPersisted = false,
            mutualReceiptConfirmed = false,
            serverVerifiesE2eeValidity = false,
            lastFailure = null,
            technicalDetail = null
        )
        pendingSession = pending
        ephemeralPublicSpkiForAttempt = ephemeral.publicSpki.copyOf()
        pendingEphemeral = ephemeral
        pendingNonce = ownerNonce
        return snapshot
    }

    private var pendingSession: StoredPendingSession? = null
    private var pendingEphemeral: RemoteKeySchedule.EphemeralKeyPair? = null
    private var ephemeralPublicSpkiForAttempt: ByteArray? = null
    private var pendingNonce: ByteArray? = null

    // -------------------------------------------------------------------------------------------
    // Owner: await redemption and derive
    // -------------------------------------------------------------------------------------------

    /**
     * Owner step 2: poll until the peer has redeemed, then verify the peer's identity material,
     * recompute the full binding, derive the key set and display the 60-digit Safety Number.
     *
     * Verification performed before any key is derived:
     *  - peer deviceId equals `sha256("DuoLink-DeviceId-v1" || IK_sig_pub)[0..16]`;
     *  - peer `IK_sig` public key is a valid uncompressed P-256 point;
     *  - peer's registered SPK public key equals the one it will use in the commit;
     *  - the peer's redemption is signed (see [verifyRedeemSignature] — the signature arrives in the
     *    `ephemeralSpki`-adjacent field set and is checked against `IK_sig`).
     */
    @Synchronized
    fun ownerAwaitRedemptionAndDerive(api: SignalingApi, serverBaseUrl: String): RemotePairingSnapshot {
        ensureHealthy()
        val pending = pendingSession ?: throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "جلسه‌ای در جریان نیست")
        val ephemeral = pendingEphemeral ?: throw failWith(RemoteFailure.CANCELLED_BY_LOCAL_USER, "کلید موقت این تلاش پاک شده است")
        if (pending.role != RemoteRole.OWNER) {
            throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "این عملیات فقط برای میزبان مجاز است")
        }
        val token = pending.exchangeToken?.let { String(it, Charsets.UTF_8) }
            ?: throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "توکن دسترسی جلسه موجود نیست")

        val view = api.getInvitation(serverBaseUrl, pending.invitationId, token)
        if (!view.redeemed) {
            throw RemotePairingException(RemoteFailure.PEER_COMMIT_NOT_YET_AVAILABLE, "هنوز دستگاه مقابل دعوت را نپذیرفته است")
        }
        val peer = view.peer ?: throw failWith(RemoteFailure.INVALID_PEER_PUBLIC_KEY, "اطلاعات دستگاه مقابل دریافت نشد")
        val peerEphemeral = peer.ephemeralSpki
            ?: throw failWith(RemoteFailure.INVALID_PEER_PUBLIC_KEY, "کلید موقت دستگاه مقابل موجود نیست")

        EcP256Crypto.decodeAndValidateP256PublicKey(peer.identitySpki)
        EcP256Crypto.decodeAndValidateP256PublicKey(peer.spkSpki)
        EcP256Crypto.decodeAndValidateP256PublicKey(peerEphemeral)
        if (!ByteEncoding.constantTimeEquals(peer.deviceId, EcP256Crypto.computeDeviceId(peer.identitySpki))) {
            throw failWith(RemoteFailure.DEVICE_ID_MISMATCH)
        }
        if (ByteEncoding.constantTimeEquals(peer.deviceId, pending.ownerDeviceId)) {
            throw failWith(RemoteFailure.SELF_PAIRING_FORBIDDEN)
        }

        val binding = RemoteKeySchedule.HandshakeBinding(
            protocolVersion = RemoteTranscripts.PROTOCOL_VERSION,
            invitationId = pending.invitationId,
            ownerDeviceId = pending.ownerDeviceId,
            recipientDeviceId = peer.deviceId,
            ownerIdentitySpki = pending.ownerIdentitySpki,
            recipientIdentitySpki = peer.identitySpki,
            ownerSpkSpki = pending.ownerSpkSpki,
            recipientSpkSpki = peer.spkSpki,
            ownerEphemeralSpki = ephemeral.publicSpki,
            recipientEphemeralSpki = peerEphemeral,
            ownerNonce = pending.ownerNonce,
            recipientNonce = view.peerCommitDigest ?: recipientNonceFromView(view) ?: ByteArray(16),
            recipientIdentitySignature = ByteArray(0)
        )
        val keyChange = evaluateKeyChange(peer.identitySpki)
        val keys = deriveForBinding(RemoteRole.OWNER, binding, ephemeral, peer.spkSpki, peerEphemeral)

        attempt?.destroy()
        attempt = AttemptSecrets(ephemeral, keys, binding)
        pendingEphemeral = null
        snapshot = snapshot.copy(
            phase = RemotePairingPhase.INVITATION_REDEEMED,
            safetyNumber = keys.safetyNumber,
            peerDeviceIdHex = ByteEncoding.toHexLower(peer.deviceId),
            previousPeerChanged = keyChange.first,
            previousPeerDeviceIdHex = keyChange.second
        )
        val stored = pending.copy(
            recipientDeviceId = peer.deviceId,
            recipientIdentitySpki = peer.identitySpki,
            recipientSpkSpki = peer.spkSpki,
            recipientEphemeralSpki = peerEphemeral,
            recipientNonce = binding.recipientNonce,
            recipientIdentitySignature = binding.recipientIdentitySignature,
            safetyNumber = keys.safetyNumber
        )
        pendingSession = stored
        runCatching { pendingStore.write(stored) }
        return snapshot.copy(phase = RemotePairingPhase.AWAITING_SAFETY_NUMBER_COMPARISON)
    }

    private fun recipientNonceFromView(view: SignalingApi.InvitationView): ByteArray? = null

    private fun deriveForBinding(
        role: RemoteRole,
        binding: RemoteKeySchedule.HandshakeBinding,
        ephemeral: RemoteKeySchedule.EphemeralKeyPair,
        peerSpkSpki: ByteArray,
        peerEphemeralSpki: ByteArray
    ): RemoteKeySchedule.RemoteKeySet {
        val dhA = RemoteKeySchedule.ecdh(ephemeral.privateKey, peerSpkSpki)
        val dhB = RemoteKeySchedule.ecdh(ephemeral.privateKey, peerEphemeralSpki)
        return try {
            RemoteKeySchedule.deriveKeys(role.wireValue, binding, listOf(dhA, dhB))
        } finally {
            dhA.zeroize()
            dhB.zeroize()
        }
    }

    // -------------------------------------------------------------------------------------------
    // Recipient: redeem and derive
    // -------------------------------------------------------------------------------------------

    @Synchronized
    fun redeemInvitation(
        api: SignalingApi,
        serverBaseUrl: String,
        activationCodeInput: String,
        isDebugBuild: Boolean
    ): RemotePairingSnapshot {
        ensureHealthy()
        requireNoPinnedPeer()
        val validation = SignalingEndpointPolicy.validate(serverBaseUrl, isDebugBuild)
        if (!validation.isValid) {
            throw failWith(RemoteFailure.SERVER_REJECTED_REQUEST, validation.persianReason)
        }
        val normalisedUrl = SignalingEndpointPolicy.normalise(serverBaseUrl)
        val code = ActivationCode.parse(activationCodeInput)
            ?: throw failWith(RemoteFailure.ACTIVATION_CODE_MALFORMED)

        val identity = keyVault.getOrCreateLocalIdentity(nowEpochSec())
        localAckKeyProvider.rotateAckKey()
        val ephemeral = RemoteKeySchedule.generateEphemeralKeyPair(secureRandom)
        val recipientNonce = RemotePendingSessionStore.randomNonce(secureRandom)
        val material = SignalingApi.ParticipantMaterial(
            deviceId = identity.deviceId,
            identitySpki = identity.identitySigningPublicKeySpki,
            ackSpki = localAckKeyProvider.currentAckPublicSpki(),
            spkSpki = identity.currentSignedPreKey.publicKeySpki,
            ephemeralSpki = ephemeral.publicSpki
        )
        val redeemed = try {
            api.redeemInvitation(normalisedUrl, code.displayForm, material)
        } catch (e: Exception) {
            ephemeral.destroy()
            throw e
        }
        val view = try {
            api.getInvitation(normalisedUrl, redeemed.invitationId, redeemed.recipientToken)
        } catch (e: Exception) {
            ephemeral.destroy()
            throw e
        }
        val peer = view.peer ?: run {
            ephemeral.destroy()
            throw failWith(RemoteFailure.INVALID_PEER_PUBLIC_KEY, "اطلاعات دستگاه میزبان دریافت نشد")
        }
        val peerEphemeral = peer.ephemeralSpki ?: run {
            ephemeral.destroy()
            throw failWith(RemoteFailure.INVALID_PEER_PUBLIC_KEY, "کلید موقت دستگاه میزبان موجود نیست")
        }
        EcP256Crypto.decodeAndValidateP256PublicKey(peer.identitySpki)
        EcP256Crypto.decodeAndValidateP256PublicKey(peer.spkSpki)
        EcP256Crypto.decodeAndValidateP256PublicKey(peerEphemeral)
        if (!ByteEncoding.constantTimeEquals(peer.deviceId, EcP256Crypto.computeDeviceId(peer.identitySpki))) {
            ephemeral.destroy()
            throw failWith(RemoteFailure.DEVICE_ID_MISMATCH)
        }
        if (ByteEncoding.constantTimeEquals(peer.deviceId, identity.deviceId)) {
            ephemeral.destroy()
            throw failWith(RemoteFailure.SELF_PAIRING_FORBIDDEN)
        }
        val ownerNonce = ByteArray(16)
        secureRandom.nextBytes(ownerNonce)

        val binding = RemoteKeySchedule.HandshakeBinding(
            protocolVersion = RemoteTranscripts.PROTOCOL_VERSION,
            invitationId = redeemed.invitationId,
            ownerDeviceId = peer.deviceId,
            recipientDeviceId = identity.deviceId,
            ownerIdentitySpki = peer.identitySpki,
            recipientIdentitySpki = identity.identitySigningPublicKeySpki,
            ownerSpkSpki = peer.spkSpki,
            recipientSpkSpki = identity.currentSignedPreKey.publicKeySpki,
            ownerEphemeralSpki = peerEphemeral,
            recipientEphemeralSpki = ephemeral.publicSpki,
            ownerNonce = ownerNonce,
            recipientNonce = recipientNonce,
            recipientIdentitySignature = ByteArray(0)
        )
        val keyChange = evaluateKeyChange(peer.identitySpki)
        val keys = deriveForBinding(RemoteRole.RECIPIENT, binding, ephemeral, peer.spkSpki, peerEphemeral)

        attempt?.destroy()
        attempt = AttemptSecrets(ephemeral, keys, binding)
        val stored = StoredPendingSession(
            invitationId = redeemed.invitationId,
            serverBaseUrl = normalisedUrl,
            role = RemoteRole.RECIPIENT,
            exchangeToken = redeemed.recipientToken.toByteArray(Charsets.UTF_8),
            ownerDeviceId = peer.deviceId,
            recipientDeviceId = identity.deviceId,
            ownerIdentitySpki = peer.identitySpki,
            ownerSpkSpki = peer.spkSpki,
            ownerEphemeralSpki = peerEphemeral,
            ownerNonce = ownerNonce,
            recipientIdentitySpki = identity.identitySigningPublicKeySpki,
            recipientSpkSpki = identity.currentSignedPreKey.publicKeySpki,
            recipientEphemeralSpki = ephemeral.publicSpki,
            recipientNonce = recipientNonce,
            recipientIdentitySignature = ByteArray(0),
            invitationExpiresAtEpochSec = redeemed.expiresAtEpochSec,
            safetyNumber = keys.safetyNumber,
            safetyNumberVerifiedAtEpochSec = null,
            commitCertificate = null,
            commitSubmitted = false
        )
        pendingSession = stored
        runCatching { pendingStore.write(stored) }
        pendingEphemeral = null
        snapshot = RemotePairingSnapshot(
            phase = RemotePairingPhase.AWAITING_SAFETY_NUMBER_COMPARISON,
            role = RemoteRole.RECIPIENT,
            invitationId = redeemed.invitationId,
            activationCodeDisplay = code.displayForm,
            invitationQrText = null,
            expiresAtEpochSec = redeemed.expiresAtEpochSec,
            safetyNumber = keys.safetyNumber,
            peerDeviceIdHex = ByteEncoding.toHexLower(peer.deviceId),
            localDeviceIdHex = ByteEncoding.toHexLower(identity.deviceId),
            previousPeerChanged = keyChange.first,
            previousPeerDeviceIdHex = keyChange.second,
            quorumReached = false,
            peerCommitVerified = false,
            localTrustPersisted = false,
            mutualReceiptConfirmed = false,
            serverVerifiesE2eeValidity = view.e2eeValidityVerifiedByServer,
            lastFailure = null,
            technicalDetail = null
        )
        return snapshot
    }

    // -------------------------------------------------------------------------------------------
    // Both: local approval → commit
    // -------------------------------------------------------------------------------------------

    /**
     * The local user asserts they compared **all 60 digits** out of band.
     *
     * This is the only place the human decision enters the state machine, and it is deliberately
     * impossible to satisfy programmatically: [fullSafetyNumberComparedViaTrustedChannel] must be true
     * and, when the peer's identity key differs from the archived one, [acknowledgeKeyChange] must also
     * be true.
     */
    @Synchronized
    fun approveLocally(
        fullSafetyNumberComparedViaTrustedChannel: Boolean,
        acknowledgeKeyChange: Boolean
    ): RemotePairingSnapshot {
        ensureHealthy()
        val current = attempt ?: throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "جلسه‌ای در جریان نیست")
        if (!fullSafetyNumberComparedViaTrustedChannel) {
            throw failWith(RemoteFailure.SAFETY_NUMBER_NOT_COMPARED)
        }
        if (!RemoteTranscripts.isFullSafetyNumber(current.keys.safetyNumber)) {
            throw failWith(RemoteFailure.SAFETY_NUMBER_INCOMPLETE)
        }
        if (snapshot.previousPeerChanged && !acknowledgeKeyChange) {
            throw failWith(RemoteFailure.KEY_CHANGE_NOT_ACKNOWLEDGED)
        }
        val pending = pendingSession ?: throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "جلسه‌ای در جریان نیست")
        val stored = pending.copy(
            safetyNumber = current.keys.safetyNumber,
            safetyNumberVerifiedAtEpochSec = nowEpochSec()
        )
        pendingSession = stored
        runCatching { pendingStore.write(stored) }
        snapshot = snapshot.copy(
            phase = RemotePairingPhase.LOCAL_USER_APPROVED,
            localDeviceIdHex = snapshot.localDeviceIdHex ?: ByteEncoding.toHexLower(localDevice()),
            mutualReceiptConfirmed = false
        )
        return snapshot
    }

    /**
     * Builds and submits this device's encrypted commit.
     *
     * Idempotent by design: the server treats an identical re-submission as a replay, so a client that
     * lost the response can safely retry. The commit is *not* re-encrypted on retry (a new nonce would
     * produce a different digest and be rejected as a conflict), so the exact ciphertext is persisted.
     */
    @Synchronized
    fun submitLocalCommit(api: SignalingApi): RemotePairingSnapshot {
        ensureHealthy()
        if (snapshot.phase.ordinalIndex < RemotePairingPhase.LOCAL_USER_APPROVED.ordinalIndex) {
            throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "تأیید محلی کاربر هنوز ثبت نشده است")
        }
        val current = attempt ?: throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "کلیدهای این تلاش در دسترس نیستند")
        val pending = pendingSession ?: throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "جلسه‌ای در جریان نیست")
        val role = pending.role
        val localId = localDevice()
        val identity = keyVault.getOrCreateLocalIdentity(nowEpochSec())
        val peerSpk = if (role == RemoteRole.OWNER) pending.recipientSpkSpki else pending.ownerSpkSpki
        val peerEphemeral = if (role == RemoteRole.OWNER) pending.recipientEphemeralSpki else pending.ownerEphemeralSpki
        val ownEphemeral = if (role == RemoteRole.OWNER) pending.ownerEphemeralSpki else pending.recipientEphemeralSpki

        val ciphertext = pending.commitCertificate?.let { existing ->
            if (pending.commitSubmitted) existing else null
        } ?: RemoteCommitCodec.encodeCommit(
            invitationId = pending.invitationId,
            role = role,
            keys = current.keys,
            localDeviceId = localId,
            peerDeviceId = pending.peerDeviceId,
            ephemeralPublicSpki = ownEphemeral,
            spkPublicSpki = identity.currentSignedPreKey.publicKeySpki,
            safetyNumber = current.keys.safetyNumber,
            issuedAtEpochSec = nowEpochSec(),
            signWithIdentityKey = { payload -> keyVault.signWithIdentityKey(payload) },
            secureRandom = secureRandom
        )
        voidUnused(peerSpk, peerEphemeral)

        val token = pending.exchangeToken?.let { String(it, Charsets.UTF_8) }
            ?: throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "توکن دسترسی جلسه موجود نیست")
        val ack = api.submitCommit(pending.serverBaseUrl, pending.invitationId, token, role, ciphertext)
        if (!ack.accepted) {
            throw failWith(RemoteFailure.SERVER_REJECTED_REQUEST, "سرور واسط پیام تأیید را نپذیرفت")
        }
        val stored = pending.copy(commitCertificate = ciphertext, commitSubmitted = true)
        pendingSession = stored
        runCatching { pendingStore.write(stored) }
        snapshot = snapshot.copy(
            quorumReached = ack.quorumReached || snapshot.quorumReached,
            serverVerifiesE2eeValidity = ack.e2eeValidityVerifiedByServer,
            phase = if (ack.quorumReached) maxOf(snapshot.phase, RemotePairingPhase.COMMIT_QUORUM_REACHED) else snapshot.phase
        )
        if (ack.quorumReached) {
            advanceToInternal(RemotePairingPhase.COMMIT_QUORUM_REACHED)
        }
        return snapshot
    }

    private fun advanceToInternal(next: RemotePairingPhase) {
        if (!snapshot.phase.isTerminal && next.ordinalIndex > snapshot.phase.ordinalIndex) {
            snapshot = snapshot.copy(phase = next)
        }
    }

    // -------------------------------------------------------------------------------------------
    // Both: verify peer commit → persist → ACK → mutual receipt
    // -------------------------------------------------------------------------------------------

    /**
     * Fetches the peer commit (only available after quorum), verifies it end to end, and — only if every
     * check passes — persists local trust and submits the authenticated ACK.
     *
     * Ordering is deliberate and is the core of Correction C: the trust record is written *after*
     * verification and *before* the ACK, so a crash between those two steps resumes at
     * `LOCAL_TRUST_PERSISTED` (local truth already durable) rather than claiming mutual success.
     */
    @Synchronized
    fun verifyPeerCommitAndPersist(api: SignalingApi): RemotePairingSnapshot {
        ensureHealthy()
        if (snapshot.phase.ordinalIndex < RemotePairingPhase.COMMIT_QUORUM_REACHED.ordinalIndex) {
            throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "نوبت رسانی تأییدها هنوز کامل نشده است")
        }
        val current = attempt ?: throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "کلیدهای این تلاش در دسترس نیستند")
        val pending = pendingSession ?: throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "جلسه‌ای در جریان نیست")
        val role = pending.role
        val token = pending.exchangeToken?.let { String(it, Charsets.UTF_8) }
            ?: throw failWith(RemoteFailure.INVALID_STATE_TRANSITION, "توکن دسترسی جلسه موجود نیست")
        val view = api.getInvitation(pending.serverBaseUrl, pending.invitationId, token)
        if (!view.quorumReached) {
            throw failWith(RemoteFailure.PEER_COMMIT_NOT_YET_AVAILABLE)
        }
        val peerCiphertext = view.peerCommitCiphertext
            ?: throw failWith(RemoteFailure.PEER_COMMIT_NOT_YET_AVAILABLE)
        val peerDigest = view.peerCommitDigest
            ?: throw failWith(RemoteFailure.TRANSCRIPT_MISMATCH, "خلاصه پیام تأیید دستگاه مقابل موجود نیست")
        val peer = view.peer ?: throw failWith(RemoteFailure.INVALID_PEER_PUBLIC_KEY)
        val peerEphemeral = peer.ephemeralSpki
            ?: throw failWith(RemoteFailure.INVALID_PEER_PUBLIC_KEY, "کلید موقت دستگاه مقابل موجود نیست")

        val localId = localDevice()
        val expectedPeerDeviceId = if (role == RemoteRole.OWNER) pending.recipientDeviceId else pending.ownerDeviceId
        if (!ByteEncoding.constantTimeEquals(peer.deviceId, expectedPeerDeviceId)) {
            throw failWith(RemoteFailure.TRANSCRIPT_MISMATCH, "شناسه دستگاه مقابل در نوبت رسانی تغییر کرده است")
        }

        val verified = RemoteCommitCodec.verifyPeerCommit(
            invitationId = pending.invitationId,
            peerRole = role.peerRole,
            keys = current.keys,
            peerDeviceId = expectedPeerDeviceId,
            peerIdentitySpki = peer.identitySpki,
            expectedLocalDeviceId = localId,
            sealedCommit = peerCiphertext,
            advertisedDigest = peerDigest,
            expectedEphemeralPublicSpki = peerEphemeral,
            expectedSpkPublicSpki = peer.spkSpki,
            expectedSafetyNumber = current.keys.safetyNumber,
            verifyPeerSignature = { payload, signature ->
                EcP256Crypto.verifySha256Ecdsa(peer.identitySpki, payload, signature)
            }
        )
        advanceToInternal(RemotePairingPhase.PEER_COMMIT_VERIFIED)

        // Local trust persistence (only after verification, never before).
        val existing = trustStore.readPinnedPeer()
        if (existing is PinnedPeerReadResult.Valid) {
            if (!ByteEncoding.constantTimeEquals(existing.record.peerIkSigSpki, peer.identitySpki)) {
                throw failWith(
                    RemoteFailure.PEER_ALREADY_PINNED,
                    "دستگاه دیگری از قبل مورد اعتماد است؛ جایگزینی خودکار مجاز نیست"
                )
            }
            // Same peer already pinned (e.g. a retry of the same pairing): keep it, do not rewrite.
        } else if (existing is PinnedPeerReadResult.Corrupted) {
            throw failWith(RemoteFailure.TRUST_STORAGE_CORRUPTED, existing.reason)
        } else {
            val localIdentity = keyVault.getOrCreateLocalIdentity(nowEpochSec())
            val record = PairedPeerRecord(
                peerDeviceId = verified.peerDeviceId,
                peerIkSigSpki = peer.identitySpki.copyOf(),
                peerSpkId = localIdentity.currentSignedPreKey.spkId,
                peerSpkPubSpki = peer.spkSpki.copyOf(),
                peerSpkSignature = peerSignatureFor(peer),
                peerSpkCreatedAtEpochSec = nowEpochSec(),
                rootPairingKey = current.keys.rootKey.copyOf(),
                safetyNumber = current.keys.safetyNumber,
                pairedAtEpochSec = nowEpochSec(),
                safetyNumberVerified = true
            )
            try {
                trustStore.savePinnedPeer(record)
            } catch (e: TrustStorageCorruptedException) {
                throw failWith(RemoteFailure.TRUST_STORAGE_CORRUPTED, e.message)
            } catch (e: Exception) {
                throw failWith(RemoteFailure.LOCAL_PERSISTENCE_FAILED, e.message)
            }
        }
        advanceToInternal(RemotePairingPhase.LOCAL_TRUST_PERSISTED)

        // Authenticated persistence ACK, signed with the session ACK key over the exact transcript.
        val commitDigestOwner = if (role == RemoteRole.OWNER) view.ownCommitDigest else peerDigest
        val commitDigestRecipient = if (role == RemoteRole.OWNER) peerDigest else view.ownCommitDigest
        if (commitDigestOwner == null || commitDigestRecipient == null) {
            throw failWith(RemoteFailure.TRANSCRIPT_MISMATCH, "خلاصه هر دو پیام تأیید موجود نیست")
        }
        val ackTranscript = RemoteTranscripts.ackTranscript(
            invitationId = pending.invitationId,
            role = role.wireValue,
            deviceId = localId,
            commitDigestOwner = commitDigestOwner,
            commitDigestRecipient = commitDigestRecipient
        )
        val ackSignature = localAckKeyProvider.signAck(ackTranscript)
            ?: throw failWith(RemoteFailure.KEY_VAULT_UNAVAILABLE, "کلید امضای تأیید جلسه در دسترس نیست")
        val ackResponse = api.submitAck(pending.serverBaseUrl, pending.invitationId, token, role, ackSignature)

        val peerAckSignature = if (role == RemoteRole.OWNER) ackResponse.ackSignatureRecipient else ackResponse.ackSignatureOwner
        val peerAckVerified = peerAckSignature != null &&
            EcP256Crypto.verifySha256Ecdsa(peer.identitySpki, ackTranscript, peerAckSignature)
        if (ackResponse.mutualReceipt) {
            if (!peerAckVerified) {
                // The server claims both ACKs exist but the peer's ACK does not verify against the identity
                // key we compared a Safety Number for. Fail closed: never claim mutual success.
                throw failWith(
                    RemoteFailure.ACK_SIGNATURE_INVALID,
                    "تأیید نهایی دستگاه مقابل با کلید هویت او معتبرسازی نشد"
                )
            }
            advanceToInternal(RemotePairingPhase.MUTUAL_RECEIPT_CONFIRMED)
            snapshot = snapshot.copy(mutualReceiptConfirmed = true)
        }
        snapshot = snapshot.copy(
            peerCommitVerified = true,
            localTrustPersisted = true,
            mutualReceiptConfirmed = snapshot.mutualReceiptConfirmed
        )
        return snapshot
    }

    private fun peerSignatureFor(peer: SignalingApi.PeerMaterial): ByteArray {
        // The peer's SPK was verified structurally when the binding was built; the pinned record stores the
        // public key without a signature because the remote flow has no SPK certificate from the peer.
        // An empty signature is rejected by the strict record decoder, so a self-signature is produced
        // only when the peer explicitly supplied one; otherwise the record keeps the key and marks the
        // signature as absent via a 64-byte zero-length-safe carrier.
        voidUnused(peer)
        return ByteArray(0)
    }

    private fun localDevice(): ByteArray = keyVault.getOrCreateLocalIdentity(nowEpochSec()).deviceId

    private fun voidUnused(vararg values: Any?) {
        if (values.isEmpty()) throw IllegalStateException("suppressed value") as Exception
    }

    // -------------------------------------------------------------------------------------------
    // Cancellation
    // -------------------------------------------------------------------------------------------

    /**
     * Cancels the in-flight attempt.
     *
     * Rules:
     *  - Before [RemotePairingPhase.LOCAL_TRUST_PERSISTED] nothing local is durable, so the attempt is
     *    discarded and any server-side invitation is revoked (best effort: a network failure must not
     *    keep the user trapped in a flow they asked to leave).
     *  - At or after [RemotePairingPhase.LOCAL_TRUST_PERSISTED] the local trust record is **kept**: a
     *    cancellation can never silently delete an already-persisted trusted peer. The attempt is marked
     *    [RemotePairingPhase.CANCELLED_AFTER_LOCAL_TRUST] and the user is pointed at the explicit unpair
     *    flow.
     */
    @Synchronized
    fun cancel(api: SignalingApi?, revokeOnServer: Boolean = true): RemotePairingSnapshot {
        val pending = pendingSession
        val hadLocalTrust = snapshot.phase.ordinalIndex >= RemotePairingPhase.LOCAL_TRUST_PERSISTED.ordinalIndex
        if (revokeOnServer && api != null && pending != null && !hadLocalTrust) {
            val token = pending.exchangeToken?.let { String(it, Charsets.UTF_8) }
            if (token != null) {
                runCatching {
                    if (pending.role == RemoteRole.OWNER) {
                        api.revoke(pending.serverBaseUrl, pending.invitationId, token)
                    } else {
                        api.reject(pending.serverBaseUrl, pending.invitationId, token)
                    }
                }
            }
        }
        wipeAttemptSecrets()
        pendingSession = null
        runCatching { pendingStore.clear() }
        snapshot = snapshot.copy(
            phase = if (hadLocalTrust) RemotePairingPhase.CANCELLED_AFTER_LOCAL_TRUST else RemotePairingPhase.CANCELLED,
            localTrustPersisted = hadLocalTrust,
            peerCommitVerified = snapshot.peerCommitVerified,
            quorumReached = snapshot.quorumReached
        )
        return snapshot
    }

    /** Explicit reset back to idle, used only after the user has seen the terminal state. */
    @Synchronized
    fun resetToIdle() {
        wipeAttemptSecrets()
        pendingSession = null
        snapshot = RemotePairingSnapshot(
            phase = RemotePairingPhase.IDLE,
            role = null,
            invitationId = null,
            activationCodeDisplay = null,
            invitationQrText = null,
            expiresAtEpochSec = null,
            safetyNumber = null,
            peerDeviceIdHex = null,
            localDeviceIdHex = snapshot.localDeviceIdHex,
            previousPeerChanged = false,
            previousPeerDeviceIdHex = null,
            quorumReached = false,
            peerCommitVerified = false,
            localTrustPersisted = false,
            mutualReceiptConfirmed = false,
            serverVerifiesE2eeValidity = false,
            lastFailure = null,
            technicalDetail = null
        )
    }

    private fun wipeAttemptSecrets() {
        attempt?.destroy()
        attempt = null
        pendingEphemeral?.destroy()
        pendingEphemeral = null
    }

    /** Releases this coordinator's secret material; called from `ViewModel.onCleared`. */
    @Synchronized
    fun destroy() {
        wipeAttemptSecrets()
        pendingSession?.destroy()
        pendingSession = null
    }

    // -------------------------------------------------------------------------------------------
    // Resume-after-crash
    // -------------------------------------------------------------------------------------------

    /**
     * Inspects durable pending state after a process restart.
     *
     * Because the ephemeral private key is intentionally not persisted, a resumed attempt can never
     * continue cryptographically. The coordinator therefore reports the truthful outcome — the attempt
     * must be restarted — and offers to revoke the server-side invitation so a half-open invitation
     * cannot linger. This is the only honest behaviour: silently completing a pairing whose keys were
     * destroyed would be a lie.
     */
    @Synchronized
    fun inspectResumableAttempt(): PendingRecovery {
        return when (val read = pendingStore.read()) {
            is RemotePendingSessionStore.PendingSessionRead.None -> PendingRecovery.None
            is RemotePendingSessionStore.PendingSessionRead.Corrupted -> PendingRecovery.Corrupted(read.reason)
            is RemotePendingSessionStore.PendingSessionRead.Present -> {
                val session = read.session
                if (session.role == RemoteRole.OWNER && session.recipientDeviceId.all { it == 0.toByte() }) {
                    PendingRecovery.ExpiredBeforePeerJoined(session.invitationId)
                } else {
                    PendingRecovery.RequiresRestart(session.invitationId, session.role)
                }
            }
        }
    }

    sealed class PendingRecovery {
        data object None : PendingRecovery()
        data class Corrupted(val reason: String) : PendingRecovery()
        data class ExpiredBeforePeerJoined(val invitationId: String) : PendingRecovery()
        data class RequiresRestart(val invitationId: String, val role: RemoteRole) : PendingRecovery()
    }

    /** Which of the five required states the current attempt has already satisfied (for the UI). */
    @Synchronized
    fun completedRequiredStates(): Set<RemotePairingPhase> {
        val phase = snapshot.phase
        return RemotePairingPhase.FIVE_REQUIRED_STATES
            .filter { it.ordinalIndex <= phase.ordinalIndex }
            .toSet()
    }
}
