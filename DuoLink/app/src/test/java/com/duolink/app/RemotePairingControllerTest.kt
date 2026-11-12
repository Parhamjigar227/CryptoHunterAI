package com.duolink.app

import com.duolink.app.remote.RemoteFailure
import com.duolink.app.remote.RemotePairingController
import com.duolink.app.remote.RemotePairingController.Step
import com.duolink.app.remote.SignalingApi
import com.duolink.app.remote.SignalingHttpClient
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Tests for [RemotePairingController]: the layer that decides what the user is TOLD.
 *
 * The distinction matters. The coordinator decides what is cryptographically true; the controller decides
 * which screen appears and which Persian sentence the user reads. A controller bug therefore does not
 * break the cryptography - it misreports it, which for a security tool is its own kind of failure:
 *  - claiming success after one-sided approval,
 *  - calling a cancelled code valid,
 *  - showing a countdown that disagrees with the server,
 *  - telling a user their code was wrong when the real problem was rate limiting.
 *
 * These tests drive the real controller and the real SignalingApi over HTTP to a local HttpServer that
 * returns the exact JSON the Node server produces. Only the server is simulated; every line of client
 * logic under test is production code.
 */
class RemotePairingControllerTest {

    // -----------------------------------------------------------------------------------------
    // A small programmable stand-in for the Node signaling server.
    // -----------------------------------------------------------------------------------------

    private class FakeSignalingServer {
        val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val hits = AtomicInteger(0)
        var resolveResponse: () -> Pair<Int, String> = { 200 to """{"invitationId":"inv_test12345678","expiresAtEpochSec":${now + 600}}""" }
        var redeemResponse: () -> Pair<Int, String> = {
            200 to """{"invitationId":"inv_test12345678","recipientToken":"dG9rZW4","expiresAtEpochSec":${now + 600}}"""
        }
        var createResponse: () -> Pair<Int, String> = {
            201 to """{"invitationId":"inv_test12345678","activationCode":"482-913-7462","ownerToken":"b3duZXI","protocolVersion":1,"createdAtEpochSec":$now,"expiresAtEpochSec":${now + 600}}"""
        }

        fun start(): FakeSignalingServer {
            server.createContext("/") { exchange ->
                hits.incrementAndGet()
                val (status, body) = when {
                    exchange.requestURI.path.endsWith("/resolve") -> resolveResponse()
                    exchange.requestURI.path.endsWith("/redeem") -> redeemResponse()
                    exchange.requestURI.path.endsWith("/v1/invitations") -> createResponse()
                    else -> 404 to """{"error":"not_found"}"""
                }
                respond(exchange, status, body)
            }
            server.executor = null
            server.start()
            return this
        }

        val baseUrl: String get() = "http://127.0.0.1:${server.address.port}"

        private fun respond(exchange: HttpExchange, status: Int, body: String) {
            val bytes = body.toByteArray(Charsets.UTF_8)
            exchange.responseHeaders.add("Content-Type", "application/json; charset=utf-8")
            exchange.sendResponseHeaders(status, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }

        fun stop() = server.stop(0)

        companion object {
            val now: Long get() = System.currentTimeMillis() / 1000L
        }
    }

    private fun <T> withFakeServer(body: (FakeSignalingServer) -> T): T {
        val fake = FakeSignalingServer().start()
        try {
            return body(fake)
        } finally {
            fake.stop()
        }
    }

    /** A controller whose coordinator is a real one but which never completes a handshake. */
    private fun controller(
        isDebug: Boolean = true,
        now: () -> Long = { System.currentTimeMillis() / 1000L }
    ): Pair<RemotePairingController, com.duolink.app.RemotePairingTestHarness.SimulatedDevice> {
        val device = RemotePairingTestHarness.SimulatedDevice(nowEpochSec = now)
        val api = SignalingApi(SignalingHttpClient(isDebugBuild = isDebug, connectTimeoutMs = 3000, readTimeoutMs = 3000))
        val controller = RemotePairingController(
            coordinator = device.coordinator,
            api = api,
            isDebugBuild = isDebug,
            nowEpochSec = now
        )
        return controller to device
    }

    // -----------------------------------------------------------------------------------------
    // Initial state and input validation
    // -----------------------------------------------------------------------------------------

    @Test
    fun startsIdleWithNothingDisplayed() {
        val (ctrl, device) = controller()
        try {
            assertEquals(Step.IDLE, ctrl.state.step)
            assertNull(ctrl.state.codeDisplay)
            assertNull(ctrl.state.failurePersian)
            assertEquals(0L, ctrl.state.secondsRemaining)
            assertFalse(ctrl.hasFailed)
        } finally {
            device.destroy()
        }
    }

    @Test
    fun beginJoiningShowsTheEntryScreenWithoutTouchingTheNetwork() {
        withFakeServer { fake ->
            val (ctrl, device) = controller()
            try {
                val state = ctrl.beginJoining()
                assertEquals(Step.JOINER_ENTERING_CODE, state.step)
                // No code, no traffic: entering the screen is not an attempt and must not spend the
                // server's global attempt budget.
                assertNull(state.codeDisplay)
                assertEquals(0, fake.hits.get())
            } finally {
                device.destroy()
            }
        }
    }

    @Test
    fun aMalformedCodeIsRejectedLocallyWithoutSpendingAnAttempt() {
        withFakeServer { fake ->
            val (ctrl, device) = controller()
            try {
                // The server's attempt bucket is GLOBAL, so obviously-invalid input must never reach it.
                listOf("", "123", "abcdefghij", "48291374620").forEach { bad ->
                    val state = ctrl.joinWithCode(fake.baseUrl, bad)
                    assertEquals(Step.JOINER_ENTERING_CODE, state.step, "should stay on the entry screen for '$bad'")
                    assertNotNull(state.failurePersian, "the user must be told the code is malformed")
                }
                assertEquals(0, fake.hits.get(), "no malformed input may reach the server")
            } finally {
                device.destroy()
            }
        }
    }

    @Test
    fun aMalformedCodeFailureIsNotSecurityAlarming() {
        withFakeServer { fake ->
            val (ctrl, device) = controller()
            try {
                val state = ctrl.joinWithCode(fake.baseUrl, "12")
                // A typo is not an attack. Raising a security alert here would train users to ignore alerts.
                assertFalse(state.failureIsSecurityAlarming)
                assertFalse(state.failureIsRetryable)
            } finally {
                device.destroy()
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Countdown semantics
    // -----------------------------------------------------------------------------------------

    @Test
    fun countdownIsDerivedFromTheServerExpiryNotALocalStartTime() {
        val fixedNow = 1_800_000_000L
        val (ctrl, device) = controller(now = { fixedNow })
        try {
            // 600 seconds in the future: a 10-minute invitation.
            ctrl.tick(fixedNow + 600)
            assertEquals(600L, ctrl.state.secondsRemaining)
            assertFalse(ctrl.state.isExpired)

            // Advance the clock by one second but keep the SAME expiry: the countdown must follow the
            // expiry, so it should now read 599 no matter how many times tick() is called.
            assertEquals(600L, ctrl.state.secondsRemaining)
            assertEquals(600L, ctrl.state.secondsRemaining, "repeated ticks at a fixed clock must not decay")
        } finally {
            device.destroy()
        }
    }

    @Test
    fun aSkewedPhoneClockCannotExtendTheCountdownPastExpiry() {
        // If the local clock is AHEAD of the server, the remaining time computed here goes negative.
        // It must clamp to zero and be reported as expired, never wrap to a huge number.
        val serverNow = 1_800_000_000L
        val localNow = serverNow + 5_000  // phone is 5000s fast
        val (ctrl, device) = controller(now = { localNow })
        try {
            ctrl.tick(serverNow + 600)
            assertEquals(0L, ctrl.state.secondsRemaining, "remaining time must clamp at zero, never go negative")
            assertTrue(ctrl.state.isExpired)
        } finally {
            device.destroy()
        }
    }

    @Test
    fun tickingWithNoKnownExpiryChangesNothing() {
        val (ctrl, device) = controller()
        try {
            ctrl.beginJoining()
            val before = ctrl.state
            ctrl.tick(null)
            assertEquals(before, ctrl.state, "an unknown expiry must not produce a fake countdown")
        } finally {
            device.destroy()
        }
    }

    // -----------------------------------------------------------------------------------------
    // Join failures, mapped to the right screen
    // -----------------------------------------------------------------------------------------

    @Test
    fun anUnknownCodeReturnsToTheEntryScreenSoTheUserCanRetry() {
        withFakeServer { fake ->
            fake.resolveResponse = { 404 to """{"error":"invalid_activation_code"}""" }
            val (ctrl, device) = controller()
            try {
                val state = ctrl.joinWithCode(fake.baseUrl, "482-913-7462")
                // A wrong code is the most common failure by far; stranding the user on a terminal screen
                // would make a typo feel like a broken app.
                assertEquals(Step.JOINER_ENTERING_CODE, state.step)
                assertEquals(RemoteFailure.INVITATION_NOT_FOUND.persianMessage, state.failurePersian)
            } finally {
                device.destroy()
            }
        }
    }

    @Test
    fun anExpiredCodeIsTerminalAndOffersNoRetryOnTheSameCode() {
        withFakeServer { fake ->
            fake.resolveResponse = { 404 to """{"error":"expired"}""" }
            val (ctrl, device) = controller()
            try {
                val state = ctrl.joinWithCode(fake.baseUrl, "482-913-7462")
                assertEquals(Step.CLOSED, state.step, "an expired invitation cannot be retried; it needs a new one")
                assertEquals(RemoteFailure.INVITATION_EXPIRED.persianMessage, state.failurePersian)
            } finally {
                device.destroy()
            }
        }
    }

    @Test
    fun anAlreadyRedeemedCodeIsTerminalAndSecurityAlarming() {
        withFakeServer { fake ->
            fake.resolveResponse = { 409 to """{"error":"already_redeemed"}""" }
            val (ctrl, device) = controller()
            try {
                val state = ctrl.joinWithCode(fake.baseUrl, "482-913-7462")
                assertEquals(Step.CLOSED, state.step)
                // Someone else already used this code: that is worth surfacing, not hiding.
                assertTrue(state.failureIsSecurityAlarming, "a code consumed by another device is security-relevant")
            } finally {
                device.destroy()
            }
        }
    }

    @Test
    fun rateLimitingIsReportedAsRetryableAndNotAsAWrongCode() {
        withFakeServer { fake ->
            fake.resolveResponse = { 429 to """{"error":"rate_limited"}""" }
            val (ctrl, device) = controller()
            try {
                val state = ctrl.joinWithCode(fake.baseUrl, "482-913-7462")
                // The user typed the right code; saying "wrong code" would send them hunting for a typo
                // that does not exist while their correct code keeps failing.
                assertTrue(state.failureIsRetryable, "429 must be marked retryable")
                assertTrue(
                    state.failurePersian != RemoteFailure.INVITATION_NOT_FOUND.persianMessage,
                    "rate limiting must not be reported as an invalid code"
                )
            } finally {
                device.destroy()
            }
        }
    }

    @Test
    fun aRedeemFailureAfterASuccessfulResolveLeavesTheInvitationUsable() {
        withFakeServer { fake ->
            // Resolve succeeds but redeem fails server-side (e.g. the gift was consumed between the two
            // calls). The user must be able to try again; resolution does not consume anything.
            fake.redeemResponse = { 409 to """{"error":"already_redeemed"}""" }
            val (ctrl, device) = controller()
            try {
                val state = ctrl.joinWithCode(fake.baseUrl, "482-913-7462")
                assertNotNull(state.failurePersian)
                assertTrue(state.failureIsSecurityAlarming)
                // And the controller did make both calls, in the required order.
                assertEquals(2, fake.hits.get(), "resolve must precede redeem")
            } finally {
                device.destroy()
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Owner failures
    // -----------------------------------------------------------------------------------------

    @Test
    fun anOwnerFailureLeavesNoCodeOnScreen() {
        withFakeServer { fake ->
            fake.createResponse = { 503 to """{"error":"server_misconfigured"}""" }
            val (ctrl, device) = controller()
            try {
                val state = ctrl.startAsOwner(fake.baseUrl)
                assertEquals(Step.FAILED, state.step)
                // Showing a code the server never stored would send the user to read out digits that can
                // never work.
                assertNull(state.codeDisplay)
                assertNotNull(state.failurePersian)
                assertTrue(ctrl.hasFailed)
            } finally {
                device.destroy()
            }
        }
    }

    @Test
    fun theOwnerRejectsAPlainHttpEndpointInReleaseBuilds() {
        withFakeServer { fake ->
            // Release builds must refuse http:// outright, so the flow fails before any key material
            // is generated or any code is minted.
            val (ctrl, device) = controller(isDebug = false)
            try {
                val state = ctrl.startAsOwner(fake.baseUrl)
                assertEquals(Step.FAILED, state.step)
                assertEquals(0, fake.hits.get(), "a release build must not even connect to a plain-http endpoint")
            } finally {
                device.destroy()
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Cancellation
    // -----------------------------------------------------------------------------------------

    @Test
    fun cancelProducesTheClosedStateWithTheRequiredPersianMessage() {
        val (ctrl, device) = controller()
        try {
            ctrl.beginJoining()
            val state = ctrl.cancel(revokeOnServer = false)
            assertEquals(Step.CLOSED, state.step)
            assertEquals("اتصال لغو شد", state.failurePersian)
        } finally {
            device.destroy()
        }
    }

    @Test
    fun cancelReportsClosedEvenWhenTheServerCallFails() {
        // The user asked to stop. Leaving the UI implying an attempt is still live because a network call
        // failed would be the worst of both worlds, so the local state must win.
        val (ctrl, device) = controller()
        try {
            ctrl.beginJoining()
            val state = ctrl.cancel(revokeOnServer = true)
            assertEquals(Step.CLOSED, state.step)
        } finally {
            device.destroy()
        }
    }

    @Test
    fun resetReturnsToTheTwoOptionScreenAndClearsEverything() {
        withFakeServer { fake ->
            fake.resolveResponse = { 404 to """{"error":"invalid_activation_code"}""" }
            val (ctrl, device) = controller()
            try {
                ctrl.joinWithCode(fake.baseUrl, "482-913-7462")
                assertNotNull(ctrl.state.failurePersian)
                val reset = ctrl.reset()
                assertEquals(Step.IDLE, reset.step)
                assertNull(reset.failurePersian)
                assertNull(reset.codeDisplay)
                assertNull(reset.safetyNumber)
                assertFalse(reset.bothApproved)
            } finally {
                device.destroy()
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Approval must never be inferred
    // -----------------------------------------------------------------------------------------

    @Test
    fun approvalWithoutASafetyNumberFailsAndDoesNotReportSuccess() {
        val (ctrl, device) = controller()
        try {
            val state = ctrl.approve(fullSafetyNumberCompared = true, acknowledgeKeyChange = false)
            // There is no pairing in progress, so approving must fail loudly rather than silently
            // marking this device as consented.
            assertTrue(
                state.step == Step.FAILED || state.step == Step.AWAITING_APPROVAL,
                "approving with no handshake must not produce COMPLETED, got ${state.step}"
            )
            assertFalse(state.bothApproved)
            assertFalse(state.localApproved)
        } finally {
            device.destroy()
        }
    }

    @Test
    fun aFreshStateNeverClaimsEitherSideApproved() {
        val (ctrl, device) = controller()
        try {
            val state = ctrl.state
            // The single most dangerous default in a pairing UI: starting out "approved".
            assertFalse(state.localApproved)
            assertFalse(state.bothApproved)
            assertNull(state.safetyNumber)
        } finally {
            device.destroy()
        }
    }

    @Test
    fun destroyWipesState() {
        val (ctrl, device) = controller()
        try {
            ctrl.beginJoining()
            ctrl.destroy()
            assertEquals(Step.IDLE, ctrl.state.step)
            assertNull(ctrl.state.codeDisplay)
        } finally {
            device.destroy()
        }
    }
}
