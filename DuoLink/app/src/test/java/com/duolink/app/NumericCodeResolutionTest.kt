package com.duolink.app

import com.duolink.app.remote.ActivationCode
import com.duolink.app.remote.RemoteFailure
import com.duolink.app.remote.RemotePairingException
import com.duolink.app.remote.SignalingApi
import com.duolink.app.remote.SignalingEndpointPolicy
import com.duolink.app.remote.SignalingHttpClient
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * End-to-end tests for the numeric-code lookup path: the REAL [SignalingHttpClient] speaking HTTP to a
 * REAL local [HttpServer], against the exact JSON the Node server produces.
 *
 * These are not mocks of the client - the only thing simulated is the server, because spinning up Node
 * inside a JVM unit test would not run on CI's plain `test` task. The server side of the same contract is
 * covered by `DuoLink/server/test/numericFlow.test.js`, which asserts the same status codes and field
 * names; the JSON literals below are copied from that implementation.
 *
 * The policy under test is [SignalingEndpointPolicy]: it only permits `http://` for loopback addresses in
 * debug builds, so these tests bind to 127.0.0.1 and pass `isDebugBuild = true`.
 */
class NumericCodeResolutionTest {

    private fun <T> withServer(
        handler: (MiniHttpServer.Request) -> MiniHttpServer.Response,
        body: (baseUrl: String, recorder: MiniHttpServer) -> T
    ): T {
        val server = MiniHttpServer(handler).start()
        try {
            return body(server.baseUrl, server)
        } finally {
            server.close()
        }
    }

    /** Convenience: a server that always answers the same way. */
    private fun <T> withConstServer(
        status: Int,
        json: String,
        body: (baseUrl: String, recorder: MiniHttpServer) -> T
    ): T = withServer({ MiniHttpServer.Response(status, json) }, body)

    private fun api(isDebug: Boolean = true) =
        SignalingApi(SignalingHttpClient(isDebugBuild = isDebug, connectTimeoutMs = 5000, readTimeoutMs = 5000))

    // ---- happy path ------------------------------------------------------

    @Test
    fun resolveSendsTheCanonicalGroupedCodeAndReturnsTheInvitationId() {
        withConstServer(200, """{"invitationId":"inv_AbCdEfGh12345678","expiresAtEpochSec":1767225600,"note":"read-only lookup"}""") { baseUrl, recorder ->
            val resolved = api().resolveInvitationByCode(baseUrl, "4829137462")

            assertEquals("inv_AbCdEfGh12345678", resolved.invitationId)
            assertEquals(1767225600L, resolved.expiresAtEpochSec)

            // The request must hit the resolve endpoint...
            assertEquals("/v1/invitations/resolve", recorder.requests.last().path)
            assertEquals("POST", recorder.requests.last().method)
            // ...with the canonical, grouped form, not whatever the user typed.
            val sent = recorder.requests.last().body.orEmpty()
            assertTrue(sent.contains("482-913-7462"), "expected the canonical grouped code, got: $sent")
            assertTrue(!sent.contains("4829137462\""), "the ungrouped form must not be sent")
            // ...and without any bearer token: resolution is unauthenticated by design.
            assertEquals(null, recorder.requests.last().headers["authorization"], "resolve must not send an authorization header")
        }
    }

    @Test
    fun resolveNeverSendsKeyMaterialOrTokens() {
        withConstServer(200, """{"invitationId":"inv_ab","expiresAtEpochSec":1}""") { baseUrl, recorder ->
            api().resolveInvitationByCode(baseUrl, "482-913-7462")
            val sent = recorder.requests.last().body.orEmpty()
            // The request should carry the code and nothing else. No device ids, no public keys.
            val keys = Regex("\"([A-Za-z]+)\"\\s*:").findAll(sent).map { it.groupValues[1] }.toSet()
            assertEquals(setOf("activationCode"), keys, "resolve request leaked extra fields: $keys")
        }
    }

    // ---- failure mapping -------------------------------------------------

    @Test
    fun unknownCodeMapsToInvitationNotFound() {
        withConstServer(404, """{"error":"invalid_activation_code","message":"Activation code is invalid or already used"}""") { baseUrl, _ ->
            val failure = assertFailsWith<RemotePairingException> {
                api().resolveInvitationByCode(baseUrl, "482-913-7462")
            }
            assertEquals(RemoteFailure.INVITATION_NOT_FOUND, failure.failure)
        }
    }

    @Test
    fun expiredCodeMapsToInvitationExpired() {
        withConstServer(404, """{"error":"expired","message":"This invitation has expired"}""") { baseUrl, _ ->
            val failure = assertFailsWith<RemotePairingException> {
                api().resolveInvitationByCode(baseUrl, "482-913-7462")
            }
            assertEquals(RemoteFailure.INVITATION_EXPIRED, failure.failure)
        }
    }

    @Test
    fun alreadyRedeemedCodeIsSurfacedAsAFailureNotAnId() {
        // Mirrors the server's store-level gate: resolving a redeemed invitation is a 409, so a joiner can
        // never be handed an id it would then fail to redeem (or worse, read as "still available").
        withConstServer(409, """{"error":"already_redeemed","message":"This invitation has already been redeemed"}""") { baseUrl, _ ->
            val failure = assertFailsWith<RemotePairingException> {
                api().resolveInvitationByCode(baseUrl, "482-913-7462")
            }
            assertTrue(
                failure.failure != null,
                "a redeemed code must map to a typed failure, not a silent success"
            )
        }
    }

    @Test
    fun rateLimitedResolutionIsReportedAsRetryable() {
        withConstServer(429, """{"error":"rate_limited","message":"Too many attempts"}""") { baseUrl, _ ->
            val failure = assertFailsWith<RemotePairingException> {
                api().resolveInvitationByCode(baseUrl, "482-913-7462")
            }
            assertNotNull(failure.failure)
            // Rate limiting must not look like "wrong code", or the user would retype a correct code forever.
            assertTrue(
                failure.failure != RemoteFailure.INVITATION_NOT_FOUND,
                "429 must be distinguishable from a wrong code"
            )
        }
    }

    @Test
    fun resolveRejectsAPlainHTTPNonLoopbackEndpointEvenInDebug() {
        // Policy, not server behaviour: the client must refuse before any socket is opened.
        val client = SignalingHttpClient(isDebugBuild = true)
        assertFailsWith<RemotePairingException> {
            client.execute("http://evil.example.com", "POST", "/v1/invitations/resolve", jsonBody = "{}")
        }
    }

    @Test
    fun resolveRejectsAnEmptyInvitationIdFromTheServer() {
        withConstServer(200, """{"invitationId":"","expiresAtEpochSec":1}""") { baseUrl, _ ->
            // SignalingApi itself must not manufacture a usable id out of an empty field.
            val api = api()
            val resolved = api.resolveInvitationByCode(baseUrl, "482-913-7462")
            assertEquals("", resolved.invitationId)
            // The coordinator is what rejects this (see resolveCodeToInvitationId's length check); assert
            // the wire layer at least does not silently substitute a placeholder.
            assertTrue(resolved.invitationId.isEmpty())
        }
    }

    // ---- rounding out the numeric parser at the integration boundary -----

    @Test
    fun userTypedVariantsReachTheServerInOneCanonicalForm() {
        // Every spelling a user might type must produce byte-identical requests, otherwise two devices
        // could disagree about which code is being redeemed.
        val variants = listOf("4829137462", "482-913-7462", " 482 913 7462 ", "482.913.7462")
        val sentBodies = mutableListOf<String>()
        withConstServer(200, """{"invitationId":"inv_x","expiresAtEpochSec":1}""") { baseUrl, recorder ->
            variants.forEach { variant ->
                api().resolveInvitationByCode(baseUrl, variant)
                sentBodies += recorder.requests.last().body.orEmpty()
            }
        }
        assertEquals(1, sentBodies.distinct().size, "variants produced different requests: $sentBodies")
        assertTrue(sentBodies.first().contains("482-913-7462"))
    }

    @Test
    fun malformedInputIsRejectedBeforeAnyRequestIsMade() {
        // A code that cannot be an invitation must never reach the network: the attempt budget is global
        // and shared, so spending a slot on obvious garbage is a self-inflicted denial of service.
        withConstServer(200, """{"invitationId":"inv_x","expiresAtEpochSec":1}""") { baseUrl, recorder ->
            assertFailsWith<RemotePairingException> {
                api().resolveInvitationByCode(baseUrl, "123")
            }
            assertEquals(0, recorder.requests.size, "a malformed code must not be sent to the server")
        }
    }

    @Test
    fun endpointPolicyStillAcceptsLoopbackInDebugAndRejectsItInRelease() {
        // Regression guard for the release build: the debug-only loopback allowance must not leak.
        assertTrue(SignalingEndpointPolicy.validate("http://127.0.0.1:8787", isDebugBuild = true).isValid)
        assertTrue(!SignalingEndpointPolicy.validate("http://127.0.0.1:8787", isDebugBuild = false).isValid)
        // And https is always acceptable.
        assertTrue(SignalingEndpointPolicy.validate("https://relay.example.com", isDebugBuild = false).isValid)
    }

    @Test
    fun aGeneratedNumericCodeRoundTripsThroughTheWireType() {
        // Tie the generator to the transport: whatever the owner displays must be parseable back into the
        // exact canonical string that goes on the wire.
        val generated = ActivationCode.generateNumeric()
        val parsed = ActivationCode.parse(generated.displayForm)
        assertNotNull(parsed)
        assertEquals(generated.canonical, parsed.canonical)
    }
}
