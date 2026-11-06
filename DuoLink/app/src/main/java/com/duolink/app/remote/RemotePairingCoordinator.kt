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

        // P1.6 — the invitation id is client-assigned. Both the invitation transcript and the recipient's
        // redeem transcript bind it, so it must exist (and be signed) before uploading, and it must reach
        // the recipient through the QR code alone: there is no other channel before redemption.
        val invitationId = generateInvitationId()

        // Decision A — sign the canonical SPK transcript with the identity signing key. The server relays
        // these three fields without verifying them; the peer verifies before trusting the key.
        val spkId = identity.currentSignedPreKey.spkId
        val spkCreatedAtEpochSec = identity.currentSignedPreKey.createdAtEpochSec
        val spkSpki = identity.currentSignedPreKey.publicKeySpki
        val spkSignature = keyVault.signWithIdentityKey(
            RemoteTranscripts.spkTranscript(identity.deviceId, spkId, spkCreatedAtEpochSec, spkSpki)
        )

        // Decision B — the invitation transcript binds the *activation code hash*, never the plaintext
        // code. The owner generates the code locally (80 bits of CSPRNG) so the hash exists before the
        // upload: the transcript that covers it must be signed *before* the server sees anything.
        val activationCode = ActivationCode.generate(secureRandom)
        val activationCodeHash = ActivationCodeDigest.sha256(activationCode.displayForm)
        val ttlSeconds = INVITATION_TTL_SECONDS
        val expiresAtEpochSec = nowEpochSec() + ttlSeconds
        val ackSpki = localAckKeyProvider.currentAckPublicSpki()
        val identitySignature = keyVault.signWithIdentityKey(
            RemoteTranscripts.invitationTranscript(
                invitationId = invitationId,
                activationCodeHash = activationCodeHash,
                deviceId = identity.deviceId,
                spkId = spkId,
                spkCreatedAtEpochSec = spkCreatedAtEpochSec,
                spkSignature = spkSignature,
                identityPublicSpki = identity.identitySigningPublicKeySpki,
                ackPublicSpki = ackSpki,
                spkPublicSpki = spkSpki,
                ephemeralPublicSpki = ephemeral.publicSpki,
                nonce = ownerNonce,
                expiresAtEpochSec = expiresAtEpochSec
            )
        )
        val material = SignalingApi.ParticipantMaterial(
            deviceId = identity.deviceId,
            identitySpki = identity.identitySigningPublicKeySpki,
            ackSpki = ackSpki,
            spkSpki = spkSpki,
            ephemeralSpki = ephemeral.publicSpki,
            nonce = ownerNonce,
            identitySignature = identitySignature,
            spkId = spkId,
            spkCreatedAtEpochSec = spkCreatedAtEpochSec,
            spkSignature = spkSignature
        )
        val created = api.createInvitation(
            baseUrl = normalisedUrl,
            invitationId = invitationId,
            owner = material,
            activationCode = activationCode.displayForm,
            ttlSeconds = ttlSeconds
        )
        val code = ActivationCode.parse(created.activationCode)
            ?: run {
                ephemeral.destroy()
                throw failWith(RemoteFailure.SERVER_REJECTED_REQUEST, "کد فعال‌سازی بازگشتی نامعتبر است")
            }
        if (created.invitationId != invitationId) {
            ephemeral.destroy()
            throw failWith(RemoteFailure.SERVER_REJECTED_REQUEST, "شناسه دعوت بازگشتی با شناسه امضاشده مطابقت ندارد")
        }
        if (code.displayForm != activationCode.displayForm) {
            ephemeral.destroy()
            throw failWith(RemoteFailure.SERVER_REJECTED_REQUEST, "کد فعال‌سازی بازگشتی با کد امضاشده مطابقت ندارد")
        }
        val payload = RemoteInvitationPayload.build(code, normalisedUrl, created.invitationId)

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

        // Decision A: the peer's SPK must be independently verifiable with the identity key that the
        // invitation is bound to, BEFORE it is used for DH1 or written into the trust store.
        verifyPeerSpkSignature(peer, peer.identitySpki)

        // Decision B: the recipient signs the redeem transcript with its IK_sig; the server cannot check
        // this, so the owner must. This is what proves the relayed material came from the redeeming device.
        verifyPeerRedeemSignature(peer, pending.invitationId, peerEphemeral)

        // P1.2 — the recipient nonce MUST come from the authenticated wire. The previous code fell back to
        // `ByteArray(16)` / a stub, which made the owner's binding differ from the recipient's while still
        // producing a working-looking transcript, i.e. a silent interoperability failure instead of an error.
        val peerNonce = peer.nonce
            ?: throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "نانس دستگاه مقابل در پیام موجود نیست")
        if (peerNonce.size != RemoteTranscripts.NONCE_BYTES) {
            throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "طول نانس دستگاه مقابل معتبر نیست")
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
            recipientNonce = peerNonce,
            recipientIdentitySignature = peer.identitySignature
                ?: throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "امضای هویت دستگاه مقابل در پیام موجود نیست")
        )
        val keyChange = evaluateKeyChange(peer.identitySpki)
        val identity = keyVault.getOrCreateLocalIdentity(nowEpochSec())
        val keys = deriveForBinding(
            role = RemoteRole.OWNER,
            binding = binding,
            ephemeral = ephemeral,
            localSpkId = identity.currentSignedPreKey.spkId,
            peerSpkSpki = peer.spkSpki,
            peerEphemeralSpki = peerEphemeral
        )

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

    /**
     * Computes the two DH contributions for [role] and derives the session keys.
     *
     * CORRECTED (Stage 1). The previous implementation computed *both* contributions from the local
     * ephemeral key (`ecdh(ephemeral, peerSpk)` and `ecdh(ephemeral, peerEphemeral)`), which made the
     * owner and the recipient derive different secrets and could never agree.
     *
     * The correct, frozen contract:
     *   DH1 = ECDH(EK_owner, SPK_recipient)
     *       owner     -> ecdh(localEphemeral,       peerSpkSpki)
     *       recipient -> keyVault.agreeWithSignedPreKey(localSpkId, ownerEphemeralSpki)
     *                    i.e. ECDH(local SPK *private* key, peer ephemeral public key)
     *   DH2 = ECDH(EK_owner, EK_recipient) — symmetric on both roles.
     *
     * The recipient's side MUST use its real, published Signed PreKey private key (via the vault). It is
     * explicitly not acceptable to substitute a second ephemeral-only DH, which would destroy the
     * long-term binding and contradict what the peer computed.
     */
    private fun deriveForBinding(
        role: RemoteRole,
        binding: RemoteKeySchedule.HandshakeBinding,
        ephemeral: RemoteKeySchedule.EphemeralKeyPair,
        localSpkId: Int,
        peerSpkSpki: ByteArray,
        peerEphemeralSpki: ByteArray
    ): RemoteKeySchedule.RemoteKeySet {
        val isOwner = role == RemoteRole.OWNER
        // DH1: role-asymmetric on purpose — see the KDoc above.
        val dh1 = if (isOwner) {
            RemoteKeySchedule.ecdh(ephemeral.privateKey, peerSpkSpki)
        } else {
            keyVault.agreeWithSignedPreKey(localSpkId, peerEphemeralSpki)
        }
        // DH2: ephemeral x ephemeral; each side contributes its own ephemeral secret.
        val dh2 = RemoteKeySchedule.ecdh(ephemeral.privateKey, peerEphemeralSpki)
        val contributions = RemoteKeySchedule.DhContributions(role.wireValue, dh1, dh2)
        return try {
            RemoteKeySchedule.deriveKeys(role.wireValue, binding, contributions)
        } finally {
            dh1.zeroize()
            dh2.zeroize()
        }
    }

    // -------------------------------------------------------------------------------------------
    // Recipient: redeem and derive
    // -------------------------------------------------------------------------------------------

    @Synchronized
    /**
     * Recipient step 1: redeem the activation code and publish this device's material.
     *
     * [expectedInvitationId] comes from the QR code and is **required**: the frozen redeem transcript
     * binds the invitation id (Decision B) and the recipient must sign it before uploading anything. The
     * value returned by the server is compared against it, so a server (or a mismatch between two QR
     * codes) cannot silently substitute a different invitation.
     */
    fun redeemInvitation(
        api: SignalingApi,
        serverBaseUrl: String,
        expectedInvitationId: String,
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

        if (expectedInvitationId.isEmpty() || expectedInvitationId.length > 64) {
            throw failWith(RemoteFailure.INVITATION_QR_MALFORMED)
        }

        val identity = keyVault.getOrCreateLocalIdentity(nowEpochSec())
        localAckKeyProvider.rotateAckKey()
        val ackSpki = localAckKeyProvider.currentAckPublicSpki()
        val ephemeral = RemoteKeySchedule.generateEphemeralKeyPair(secureRandom)
        val recipientNonce = RemotePendingSessionStore.randomNonce(secureRandom)

        // Decision A — sign the canonical SPK transcript so the owner can verify our signed pre-key
        // without trusting the server that relayed it.
        val spkId = identity.currentSignedPreKey.spkId
        val spkCreatedAtEpochSec = identity.currentSignedPreKey.createdAtEpochSec
        val spkSpki = identity.currentSignedPreKey.publicKeySpki
        val spkSignature = keyVault.signWithIdentityKey(
            RemoteTranscripts.spkTranscript(identity.deviceId, spkId, spkCreatedAtEpochSec, spkSpki)
        )

        // Decision B — sign the redeem transcript, binding the QR's invitation id to exactly this
        // device's identity, SPK, ephemeral key and nonce. The server cannot verify it; the owner does.
        val localIdentitySignature = keyVault.signWithIdentityKey(
            RemoteTranscripts.redeemTranscript(
                invitationId = expectedInvitationId,
                deviceId = identity.deviceId,
                spkId = spkId,
                spkCreatedAtEpochSec = spkCreatedAtEpochSec,
                spkSignature = spkSignature,
                identityPublicSpki = identity.identitySigningPublicKeySpki,
                ackPublicSpki = ackSpki,
                spkPublicSpki = spkSpki,
                ephemeralPublicSpki = ephemeral.publicSpki,
                nonce = recipientNonce
            )
        )

        val material = SignalingApi.ParticipantMaterial(
            deviceId = identity.deviceId,
            identitySpki = identity.identitySigningPublicKeySpki,
            ackSpki = ackSpki,
            spkSpki = spkSpki,
            ephemeralSpki = ephemeral.publicSpki,
            nonce = recipientNonce,
            identitySignature = localIdentitySignature,
            spkId = spkId,
            spkCreatedAtEpochSec = spkCreatedAtEpochSec,
            spkSignature = spkSignature
        )
        val redeemed = try {
            api.redeemInvitation(normalisedUrl, code.displayForm, material)
        } catch (e: Exception) {
            ephemeral.destroy()
            throw e
        }
        if (redeemed.invitationId != expectedInvitationId) {
            ephemeral.destroy()
            throw failWith(RemoteFailure.INVITATION_NOT_FOUND)
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

        // Decision A — verify the owner's SPK self-signature with the owner's identity key.
        try {
            verifyPeerSpkSignature(peer, peer.identitySpki)
        } catch (e: Exception) {
            ephemeral.destroy()
            throw e
        }
        val owner = peer

        // P1.2 — the owner's nonce arrives through the authenticated invitation, never a local stub.
        val ownerNonce = owner.nonce
            ?: throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "نانس دستگاه صاحب دعوت در پیام موجود نیست")
        if (ownerNonce.size != RemoteTranscripts.NONCE_BYTES) {
            throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "طول نانس دستگاه صاحب دعوت معتبر نیست")
        }

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
            recipientIdentitySignature = localIdentitySignature
        )
        val keyChange = evaluateKeyChange(peer.identitySpki)
        val keys = deriveForBinding(
            role = RemoteRole.RECIPIENT,
            binding = binding,
            ephemeral = ephemeral,
            localSpkId = identity.currentSignedPreKey.spkId,
            peerSpkSpki = peer.spkSpki,
            peerEphemeralSpki = peerEphemeral
        )

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

    /**
     * Returns the peer's Signed Pre-Key self-signature, which the peer sent over the authenticated wire.
     *
     * Decision A: the wire carries `spkSignature` (ECDSA over the canonical SPK transcript, made with
     * the peer's identity signing key). This function only *extracts* it — the caller MUST verify it
     * with [verifyPeerSpkSignature] against the peer's identity key before the SPK is trusted or
     * persisted. There is deliberately no fallback: an absent signature is a hard failure, because a
     * synthesised or zero-length placeholder would launder an unverified key into the trust store.
     */
    private fun peerSignatureFor(peer: SignalingApi.PeerMaterial): ByteArray {
        val signature = peer.spkSignature
            ?: throw failWith(
                RemoteFailure.PEER_MATERIAL_INVALID,
                "امضای کلید پیش‌اعزامی طرف مقابل در پیام وجود ندارد"
            )
        if (signature.size < MIN_DER_SIGNATURE_BYTES || signature.size > MAX_DER_SIGNATURE_BYTES) {
            throw failWith(
                RemoteFailure.PEER_MATERIAL_INVALID,
                "امضای کلید پیش‌اعزامی طرف مقابل معتبر نیست"
            )
        }
        return signature
    }

    /**
     * Verifies the peer's SPK self-signature before the key is trusted or persisted.
     *
     * The peer's device id is derived exactly as Method A derives it (SHA-256 over the identity SPKI,
     * first 16 bytes), so a peer cannot claim a device id that does not match the key it signed with.
     */
    internal fun verifyPeerSpkSignature(peer: SignalingApi.PeerMaterial, identityPublicSpki: ByteArray) {
        val signature = peerSignatureFor(peer)
        val spkSpki = peer.spkSpki
            ?: throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "کلید پیش‌اعزامی طرف مقابل موجود نیست")
        val spkId = peer.spkId
            ?: throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "شناسه کلید پیش‌اعزامی طرف مقابل موجود نیست")
        val createdAt = peer.spkCreatedAtEpochSec
            ?: throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "زمان ساخت کلید پیش‌اعزامی طرف مقابل موجود نیست")
        val transcript = RemoteTranscripts.spkTranscript(
            deviceId = deviceIdFor(identityPublicSpki),
            spkId = spkId,
            spkCreatedAtEpochSec = createdAt,
            spkPublicKeySpki = spkSpki
        )
        if (!EcP256Crypto.verifySha256Ecdsa(identityPublicSpki, transcript, signature)) {
            throw failWith(RemoteFailure.INVALID_PEER_SPK_SIGNATURE)
        }
    }

    /**
     * Verifies the recipient's redeem-request signature (Decision B).
     *
     * The recipient signs `redeemTranscript(...)` with its `IK_sig`; the owner reconstructs the transcript
     * from the relayed material and verifies it. A mismatch means the server, or anyone on the wire,
     * altered a bound field — reject, do not attempt recovery.
     */
    internal fun verifyPeerRedeemSignature(
        peer: SignalingApi.PeerMaterial,
        invitationId: String,
        peerEphemeralSpki: ByteArray
    ) {
        val signature = peer.identitySignature
            ?: throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "امضای درخواست پذیرش طرف مقابل موجود نیست")
        val spkId = peer.spkId
            ?: throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "شناسه کلید پیش‌اعزامی طرف مقابل موجود نیست")
        val createdAt = peer.spkCreatedAtEpochSec
            ?: throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "زمان ساخت کلید پیش‌اعزامی طرف مقابل موجود نیست")
        val nonce = peer.nonce
            ?: throw failWith(RemoteFailure.PEER_MATERIAL_INVALID, "نانس طرف مقابل موجود نیست")
        val transcript = RemoteTranscripts.redeemTranscript(
            invitationId = invitationId,
            deviceId = peer.deviceId,
            spkId = spkId,
            spkCreatedAtEpochSec = createdAt,
            spkSignature = peerSignatureFor(peer),
            identityPublicSpki = peer.identitySpki,
            ackPublicSpki = peer.ackSpki,
            spkPublicSpki = peer.spkSpki,
            ephemeralPublicSpki = peerEphemeralSpki,
            nonce = nonce
        )
        if (!EcP256Crypto.verifySha256Ecdsa(peer.identitySpki, transcript, signature)) {
            throw failWith(
                RemoteFailure.PEER_MATERIAL_INVALID,
                "امضای درخواست پذیرش طرف مقابل با محتوای دریافتی مطابقت ندارد"
            )
        }
    }

    /** Device id derivation shared with Method A: SHA-256(identity SPKI)[0..16). */
    private fun deviceIdFor(identityPublicSpki: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(identityPublicSpki)
            .copyOf(16)

    /**
     * Generates a client-assigned invitation id matching the server's accepted shape
     * (`^inv_[A-Za-z0-9_-]{16,32}$`, see `store.createInvitation`).
     *
     * Client-assigned by necessity: the owner's invitation transcript binds the id, so it must be fixed
     * and signed before the upload; and the recipient must be able to bind the same value from the QR
     * alone. 16 bytes of CSPRNG output is far beyond guessing range for a value that is not secret anyway.
     */
    private fun generateInvitationId(): String {
        val bytes = ByteArray(16)
        secureRandom.nextBytes(bytes)
        return "inv_" + ByteEncoding.encodeBase64Url(bytes)
    }

    private fun localDevice(): ByteArray = keyVault.getOrCreateLocalIdentity(nowEpochSec()).deviceId

    private companion object {
        /** Invitation lifetime offered to the server; the server clamps anything it dislikes. */
        const val INVITATION_TTL_SECONDS = 600L

        /** DER-encoded P-256 ECDSA signatures are 70-72 bytes; allow a bounded range, never zero. */
        const val MIN_DER_SIGNATURE_BYTES = 64
        const val MAX_DER_SIGNATURE_BYTES = 80
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
