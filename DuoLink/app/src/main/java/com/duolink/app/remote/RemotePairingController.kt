package com.duolink.app.remote

import com.duolink.app.crypto.DeviceKeyVault
import com.duolink.app.pairing.PeerTrustStore
import java.security.SecureRandom

/**
 * UI-facing orchestration for Method B ("اتصال از راه دور با کد"), as a **plain, Compose-free class**.
 *
 * WHY THIS IS SEPARATE FROM [RemotePairingCoordinator]
 * The coordinator implements the wire protocol: eleven phases, eleven signatures, a two-DH transcript.
 * It is deliberately synchronous and blocking, and it must stay that way so every step is testable and
 * auditable without a framework. This class adds only what a screen needs on top of it:
 *
 *  - a single observable state that Compose can render;
 *  - a human-readable countdown derived from the SERVER's expiry (never a local guess);
 *  - the two-step join (`resolve` then `redeem`) that the numeric flow requires;
 *  - clipboard-safe handling of the code, and nothing else.
 *
 * Everything security-relevant - key generation, transcript binding, signature verification, the trust
 * write - stays inside [RemotePairingCoordinator]. Nothing here decides whether pairing succeeded.
 *
 * THREADING
 * No internal threads, no coroutine dependency: callers invoke these methods from a background
 * dispatcher and publish [state] to the UI. Keeping it dispatcher-free is what lets the whole thing be
 * unit-tested on the JVM with a fake clock, which is the only way this logic gets real coverage on CI.
 */
class RemotePairingController(
    private val coordinator: RemotePairingCoordinator,
    private val api: SignalingApi,
    private val isDebugBuild: Boolean,
    private val nowEpochSec: () -> Long = { System.currentTimeMillis() / 1000L },
    private val secureRandom: SecureRandom = SecureRandom()
) {

    /** Where the user is in the two-step flow, in terms the UI can switch on directly. */
    enum class Step {
        /** Nothing in progress; show the two entry options. */
        IDLE,

        /** Owner: a code exists and is waiting to be typed on the other phone. */
        OWNER_SHOWING_CODE,

        /** Joiner: waiting for the user's 10 digits. */
        JOINER_ENTERING_CODE,

        /** Joiner: code resolved, redeem request in flight. */
        JOINER_CONNECTING,

        /** Both: the handshake is running, before the Safety Number is shown. */
        HANDSHAKE_IN_PROGRESS,

        /** Both: Safety Numbers are on screen and must be compared by the humans. */
        AWAITING_APPROVAL,

        /** Both: approved and confirmed; the conversation can open. */
        COMPLETED,

        /** Terminal failure; [RemotePairingState.failurePersian] says what happened. */
        FAILED,

        /** The invitation is no longer usable (expired, cancelled or redeemed elsewhere). */
        CLOSED
    }

    /**
     * Everything a screen needs. Contains no secrets: no code hash, no keys, no nonces, no tokens.
     *
     * The activation code itself IS present, because the owner must be able to read it aloud and copy it.
     * It is never logged and never persisted by this class; see [RemotePairingController.destroy].
     */
    data class RemotePairingState(
        val step: Step = Step.IDLE,
        val codeDisplay: String? = null,
        /**
         * Seconds left before the code dies, from the server's expiry. Zero once expired. The UI shows
         * this verbatim rather than running its own timer from a local start time, because a phone with a
         * skewed clock would then display a countdown that disagrees with the server - and the user would
         * be told a dead code is still good, or a live one is dead.
         */
        val secondsRemaining: Long = 0L,
        val isExpired: Boolean = false,
        val failurePersian: String? = null,
        val failureIsRetryable: Boolean = false,
        val failureIsSecurityAlarming: Boolean = false,
        val safetyNumber: String? = null,
        val peerDeviceIdHex: String? = null,
        val previousPeerChanged: Boolean = false,
        val previousPeerDeviceIdHex: String? = null,
        /** True once the local device has stored its approval; the peer's may still be outstanding. */
        val localApproved: Boolean = false,
        /** True only when BOTH devices have committed and the mutual receipt is confirmed. */
        val bothApproved: Boolean = false,
        /** Technical detail for the collapsible security section; never shown by default. */
        val technicalDetail: String? = null
    )

    @Volatile
    var state: RemotePairingState = RemotePairingState()
        private set

    /** Set when the flow reached a terminal failure, so the UI can offer "try again" without guessing. */
    val hasFailed: Boolean get() = state.step == Step.FAILED

    // ---------------------------------------------------------------------------------------------
    // Owner side
    // ---------------------------------------------------------------------------------------------

    /**
     * Mints a numeric invitation and returns the code the user should read out.
     *
     * The code shown is the one the server confirmed it stored: [SignalingApi.CreatedInvitation] echoes
     * the canonical form back. Displaying a locally generated code would risk showing the user digits that
     * the server never received (if the upload silently normalised something differently), and the other
     * phone would then reject a code the user read out correctly.
     */
    fun startAsOwner(serverBaseUrl: String): RemotePairingState {
        return runCatching {
            val snapshot = coordinator.createInvitation(api, serverBaseUrl, isDebugBuild)
            val code = snapshot.activationCodeDisplay
                ?: throw RemotePairingException(RemoteFailure.SERVER_REJECTED_REQUEST, "سرور کد دعوت را تأیید نکرد")
            val expiresAt = snapshot.expiresAtEpochSec
                ?: throw RemotePairingException(RemoteFailure.SERVER_REJECTED_REQUEST, "زمان انقضای دعوت از سرور دریافت نشد")
            state = RemotePairingState(
                step = Step.OWNER_SHOWING_CODE,
                codeDisplay = code,
                secondsRemaining = remainingSeconds(expiresAt),
                isExpired = remainingSeconds(expiresAt) <= 0L,
                safetyNumber = snapshot.safetyNumber,
                technicalDetail = snapshot.technicalDetail ?: snapshot.lastFailure?.name
            )
            state
        }.getOrElse { failure ->
            failWith(failure, Step.FAILED)
        }
    }

    /**
     * Owner: wait for the other phone to redeem, then derive the shared keys.
     *
     * Blocking and interruptible: the coordinator polls the server internally. The UI calls this from a
     * background dispatcher while showing [Step.HANDSHAKE_IN_PROGRESS], and calls [cancel] to stop it.
     */
    fun awaitRedemption(serverBaseUrl: String): RemotePairingState {
        state = state.copy(step = Step.HANDSHAKE_IN_PROGRESS)
        return runCatching {
            val snapshot = coordinator.ownerAwaitRedemptionAndDerive(api, serverBaseUrl)
            publishFromSnapshot(snapshot)
        }.getOrElse { failure ->
            if (isCancellation(failure)) {
                // A user cancellation is not an error: the invitation was revoked deliberately.
                state = state.copy(step = Step.CLOSED, failurePersian = RemoteFailure.USER_DECLINED.persianMessage)
                state
            } else {
                failWith(failure, Step.FAILED)
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Joiner side
    // ---------------------------------------------------------------------------------------------

    /** Joiner: show the numeric-entry screen. */
    fun beginJoining(): RemotePairingState {
        state = RemotePairingState(step = Step.JOINER_ENTERING_CODE)
        return state
    }

    /**
     * Joiner: resolve the typed code, then redeem it.
     *
     * Two calls, in this order, and the order is not incidental. The redeem transcript binds the
     * invitation id, and the joiner signs that transcript *before* transmitting anything, so it needs the
     * id first. The QR flow avoids this step because the payload already carries `?i=`.
     *
     * Resolving does NOT consume the code: the invitation stays CREATED until [redeemInvitation] runs, so
     * a failure between the two steps leaves the invitation usable and the user can simply retry.
     */
    fun joinWithCode(serverBaseUrl: String, typedCode: String): RemotePairingState {
        val parsed = ActivationCode.parse(typedCode)
            ?: return failWith(
                RemotePairingException(RemoteFailure.ACTIVATION_CODE_MALFORMED),
                Step.JOINER_ENTERING_CODE
            )
        state = state.copy(step = Step.JOINER_CONNECTING, codeDisplay = parsed.displayForm, failurePersian = null)
        return runCatching {
            val invitationId = coordinator.resolveCodeToInvitationId(
                api = api,
                serverBaseUrl = serverBaseUrl,
                activationCodeInput = parsed.displayForm,
                isDebugBuild = isDebugBuild
            )
            val snapshot = coordinator.redeemInvitation(
                api = api,
                serverBaseUrl = serverBaseUrl,
                expectedInvitationId = invitationId,
                activationCodeInput = parsed.displayForm,
                isDebugBuild = isDebugBuild
            )
            publishFromSnapshot(snapshot)
        }.getOrElse { failure ->
            // Return to the entry screen on recoverable input errors so the user can fix a typo; go to a
            // terminal state only when the invitation itself is dead.
            val failureKind = (failure as? RemotePairingException)?.failure
            val terminal = failureKind != null && (
                failureKind == RemoteFailure.INVITATION_EXPIRED ||
                    failureKind == RemoteFailure.INVITATION_ALREADY_REDEEMED ||
                    failureKind == RemoteFailure.INVITATION_REVOKED ||
                    failureKind.isSecurityAlarming
                )
            failWith(failure, if (terminal) Step.CLOSED else Step.JOINER_ENTERING_CODE)
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Shared final steps
    // ---------------------------------------------------------------------------------------------

    /**
     * Records the local user's explicit approval after they compared the 60-digit Safety Number.
     *
     * Both flags are required and neither is inferred. [fullSafetyNumberCompared] is passed straight
     * through to the coordinator, which refuses to proceed on `false`: comparing only the first line is a
     * real attack (a matching prefix proves almost nothing), and defaulting it to `true` would make the
     * check decorative.
     */
    fun approve(fullSafetyNumberCompared: Boolean, acknowledgeKeyChange: Boolean): RemotePairingState {
        return runCatching {
            val snapshot = coordinator.approveLocally(fullSafetyNumberCompared, acknowledgeKeyChange)
            publishFromSnapshot(snapshot)
        }.getOrElse { failure -> failWith(failure, Step.AWAITING_APPROVAL) }
    }

    /** Publishes this device's encrypted commit. Still not "paired" - the peer's commit must verify too. */
    fun sendCommit(): RemotePairingState {
        return runCatching {
            publishFromSnapshot(coordinator.submitLocalCommit(api))
        }.getOrElse { failure -> failWith(failure, Step.AWAITING_APPROVAL) }
    }

    /**
     * Verifies the peer's commit and writes the trust record. Only after this returns COMPLETED may the
     * UI say "اتصال با موفقیت برقرار شد".
     */
    fun verifyPeerAndFinish(): RemotePairingState {
        return runCatching {
            publishFromSnapshot(coordinator.verifyPeerCommitAndPersist(api))
        }.getOrElse { failure -> failWith(failure, Step.AWAITING_APPROVAL) }
    }

    /**
     * Cancels the current attempt.
     *
     * [revokeOnServer] is true for the owner: leaving a live invitation behind would keep a code usable
     * that the user believes they cancelled, and the brief explicitly requires that a cancelled code be
     * rejected. The joiner has nothing to revoke.
     */
    fun cancel(revokeOnServer: Boolean): RemotePairingState {
        return runCatching {
            coordinator.cancel(api, revokeOnServer)
            state = RemotePairingState(step = Step.CLOSED, failurePersian = "اتصال لغو شد")
            state
        }.getOrElse {
            // Even if the server call failed, the local session must be gone: never leave the UI in a state
            // that implies an attempt is still live when the user asked to stop.
            coordinator.resetToIdle()
            state = RemotePairingState(step = Step.CLOSED, failurePersian = "اتصال لغو شد")
            state
        }
    }

    /** Returns to the two-option screen, discarding any finished attempt. */
    fun reset(): RemotePairingState {
        coordinator.resetToIdle()
        state = RemotePairingState()
        return state
    }

    /**
     * Recomputes the countdown. The UI calls this on a one-second tick.
     *
     * An expired countdown does NOT by itself declare the invitation dead: only the server can decide
     * that, and a client-side clock that is a few seconds fast must not cancel a perfectly good
     * invitation. The UI shows "منقضی شده" locally and the next server call is authoritative.
     */
    fun tick(expiresAtEpochSec: Long?): RemotePairingState {
        if (expiresAtEpochSec == null) return state
        val remaining = remainingSeconds(expiresAtEpochSec)
        val expired = remaining <= 0L
        // The guard must compare BOTH fields it would write. Comparing only `secondsRemaining` meant an
        // invitation that expired while the counter was already at 0 never set `isExpired`, so the screen
        // kept showing a dead code as if it were still valid. Found by a skewed-clock test.
        if (remaining == state.secondsRemaining && expired == state.isExpired) return state
        state = state.copy(secondsRemaining = remaining, isExpired = expired)
        return state
    }

    /** Wipes local secrets for this attempt. Must be called when the screen leaves the composition. */
    fun destroy() {
        coordinator.destroy()
        state = RemotePairingState()
    }

    // ---------------------------------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------------------------------

    private fun remainingSeconds(expiresAtEpochSec: Long): Long =
        (expiresAtEpochSec - nowEpochSec()).coerceAtLeast(0L)

    private fun publishFromSnapshot(snapshot: RemotePairingCoordinator.RemotePairingSnapshot): RemotePairingState {
        state = state.copy(
            step = mapPhase(snapshot),
            safetyNumber = snapshot.safetyNumber ?: state.safetyNumber,
            peerDeviceIdHex = snapshot.peerDeviceIdHex ?: state.peerDeviceIdHex,
            previousPeerChanged = snapshot.previousPeerChanged,
            previousPeerDeviceIdHex = snapshot.previousPeerDeviceIdHex,
            localApproved = snapshot.localTrustPersisted,
            bothApproved = snapshot.mutualReceiptConfirmed,
            technicalDetail = snapshot.technicalDetail ?: snapshot.lastFailure?.name,
            failurePersian = snapshot.lastFailure?.persianMessage,
            failureIsRetryable = snapshot.lastFailure?.isRetryable ?: false,
            failureIsSecurityAlarming = snapshot.lastFailure?.isSecurityAlarming ?: false
        )
        return state
    }

    /**
     * Maps the protocol's eleven phases onto the screen's steps.
     *
     * Deliberately a total `when` with no `else`: adding a phase to the enum then breaks compilation here,
     * which is the desired behaviour - a new protocol phase that silently fell into "still connecting"
     * would stall the UI with no explanation.
     */
    private fun mapPhase(snapshot: RemotePairingCoordinator.RemotePairingSnapshot): Step {
        return when (snapshot.phase) {
            RemotePairingPhase.IDLE -> Step.IDLE

            // Owner minted an invitation and is showing the code.
            RemotePairingPhase.INVITATION_CREATED -> Step.OWNER_SHOWING_CODE

            // The joiner's material has arrived; keys are being derived and verified. Nothing is trusted
            // yet, so this is still "connecting" and the UI must not imply success.
            RemotePairingPhase.INVITATION_REDEEMED -> Step.HANDSHAKE_IN_PROGRESS

            // The Safety Number exists and the humans must compare it.
            RemotePairingPhase.AWAITING_SAFETY_NUMBER_COMPARISON -> Step.AWAITING_APPROVAL

            // Local approval recorded, but the peer may not have approved: still awaiting approval. This
            // is the phase where a one-sided approval must NOT be presented as success.
            RemotePairingPhase.LOCAL_USER_APPROVED,
            RemotePairingPhase.COMMIT_QUORUM_REACHED,
            RemotePairingPhase.PEER_COMMIT_VERIFIED,
            RemotePairingPhase.LOCAL_TRUST_PERSISTED -> Step.AWAITING_APPROVAL

            // Both devices have authenticated each other's persistence. THIS is success.
            RemotePairingPhase.MUTUAL_RECEIPT_CONFIRMED ->
                if (snapshot.mutualReceiptConfirmed) Step.COMPLETED else Step.AWAITING_APPROVAL

            RemotePairingPhase.CANCELLED,
            RemotePairingPhase.CANCELLED_AFTER_LOCAL_TRUST,
            RemotePairingPhase.TERMINAL -> Step.CLOSED

            // Fail-closed states. There is no FAILED phase on the wire; BLOCKED is the fail-closed one and
            // carries lastFailure, which the UI renders.
            RemotePairingPhase.BLOCKED -> Step.FAILED
        }
    }

    /** True when the throwable represents a deliberate user cancellation rather than a fault. */
    private fun isCancellation(throwable: Throwable): Boolean =
        throwable is RemotePairingException && throwable.failure == RemoteFailure.USER_DECLINED

    private fun failWith(throwable: Throwable, step: Step): RemotePairingState {
        val remote = throwable as? RemotePairingException
        val failure = remote?.failure
        state = state.copy(
            step = step,
            failurePersian = failure?.persianMessage
                ?: throwable.message
                ?: "خطای نامشخص در جریان اتصال",
            failureIsRetryable = failure?.isRetryable ?: false,
            failureIsSecurityAlarming = failure?.isSecurityAlarming ?: false,
            technicalDetail = failure?.name ?: throwable.javaClass.simpleName
        )
        return state
    }
}
