package com.duolink.app

import com.duolink.app.crypto.InMemoryByteStore
import com.duolink.app.remote.ServerEndpointStore
import com.duolink.app.remote.SignalingEndpointPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Tests for endpoint resolution, which is the difference between "the APK can reach a server" and
 * "the APK tries a reserved domain that never resolves".
 *
 * Version 0.4.0 hard-coded `https://relay.duolink.invalid` with no override, so the shipped APK could
 * not talk to any server at all. These tests pin the replacement behaviour.
 *
 * The defaults are injected rather than read from BuildConfig so the same code can be exercised for
 * BOTH build types in one JVM run - the release rule (HTTPS only) is the one that matters and a debug
 * build is the only place a loopback HTTP address is allowed.
 */
class ServerEndpointStoreTest {

    /** Records what the policy would allow, mirroring SignalingEndpointPolicy for a chosen build type. */
    private class FakeDefaults(
        private val default: String,
        private val isDebug: Boolean
    ) : ServerEndpointStore.EndpointDefaults {
        override fun buildTimeDefault(): String = default
        override fun policyAllows(rawUrl: String): Boolean =
            SignalingEndpointPolicy.validate(rawUrl, isDebug).isValid

        override fun normalise(rawUrl: String): String = SignalingEndpointPolicy.normalise(rawUrl)
    }

    private fun store(default: String = "https://relay.example.com", isDebug: Boolean = false) =
        ServerEndpointStore(InMemoryByteStore(), FakeDefaults(default, isDebug))

    @Test
    fun buildTimeDefaultIsUsedWhenNothingIsSaved() {
        val resolution = store().resolve()
        assertIs<ServerEndpointStore.Resolution.Ready>(resolution)
        assertEquals("https://relay.example.com", resolution.baseUrl)
        assertEquals(ServerEndpointStore.Source.BUILD_TIME, resolution.source)
    }

    @Test
    fun anEmptyBuildTimeDefaultAsksForConfigurationInsteadOfGuessing() {
        // This is the shipped-0.4.0 case generalised: no usable endpoint must produce an explicit
        // "needs configuration" state, never an attempt against a placeholder host.
        val resolution = store(default = "").resolve()
        assertIs<ServerEndpointStore.Resolution.NeedsConfiguration>(resolution)
    }

    @Test
    fun aSavedOverrideWinsOverTheBuildTimeDefault() {
        val s = store()
        val saved = s.saveOverride("https://my-own-relay.example.org")
        assertTrue(saved.isSuccess)
        val resolution = s.resolve()
        assertIs<ServerEndpointStore.Resolution.Ready>(resolution)
        assertEquals("https://my-own-relay.example.org", resolution.baseUrl)
        assertEquals(ServerEndpointStore.Source.SAVED_OVERRIDE, resolution.source)
    }

    @Test
    fun theOverrideIsNormalisedBeforeItIsReturned() {
        val s = store()
        // Trailing path and slash are not part of a base URL; normalise() drops them.
        assertTrue(s.saveOverride("https://relay.example.com/some/path/").isSuccess)
        val resolution = s.resolve()
        assertIs<ServerEndpointStore.Resolution.Ready>(resolution)
        assertEquals("https://relay.example.com", resolution.baseUrl)
    }

    @Test
    fun clearingTheOverrideFallsBackToTheBuildTimeDefault() {
        val s = store()
        assertTrue(s.saveOverride("https://temporary.example.net").isSuccess)
        s.clearOverride()
        assertNull(s.readSavedOverride())
        val resolution = s.resolve()
        assertIs<ServerEndpointStore.Resolution.Ready>(resolution)
        assertEquals(ServerEndpointStore.Source.BUILD_TIME, resolution.source)
    }

    @Test
    fun aReleaseBuildRejectsPlaintextHttpOverrides() {
        val s = store(isDebug = false)
        val result = s.saveOverride("http://relay.example.com")
        assertTrue(result.isFailure, "A release build must not accept http:// for a remote host")
        assertNull(s.readSavedOverride(), "A rejected address must not be persisted")
    }

    @Test
    fun aDebugBuildStillRejectsHttpToANonLoopbackHost() {
        // The policy allows http only for loopback; being a debug build does not make arbitrary
        // plaintext acceptable, because that would leak the handshake to the local network.
        val s = store(isDebug = true)
        assertTrue(s.saveOverride("http://192.168.1.50:8787").isFailure)
        assertTrue(s.saveOverride("http://127.0.0.1:8787").isSuccess)
    }

    @Test
    fun emptyAndOverlongAddressesAreRejected() {
        val s = store()
        assertTrue(s.saveOverride("   ").isFailure)
        assertTrue(s.saveOverride("https://" + "a".repeat(SignalingEndpointPolicy.MAX_URL_LENGTH)).isFailure)
        assertNull(s.readSavedOverride())
    }

    @Test
    fun aStoredValueThatThePolicyWouldNowRejectIsIgnoredRatherThanUsed() {
        // Simulates an older build (or a tampered data dir) that saved a plaintext http:// address.
        // Reading must re-validate, otherwise a release build would happily talk cleartext.
        val backing = InMemoryByteStore()
        backing.write(
            ServerEndpointStore.KEY_OVERRIDE,
            "http://evil.example.com".toByteArray(Charsets.UTF_8)
        )
        val s = ServerEndpointStore(backing, FakeDefaults("https://relay.example.com", isDebug = false))
        assertNull(s.readSavedOverride())
        val resolution = s.resolve()
        assertIs<ServerEndpointStore.Resolution.Ready>(resolution)
        assertEquals(ServerEndpointStore.Source.BUILD_TIME, resolution.source)
    }

    @Test
    fun aCorruptStoredValueIsIgnoredRatherThanCrashing() {
        val backing = InMemoryByteStore()
        backing.writeZeroByteEntryForTesting(ServerEndpointStore.KEY_OVERRIDE)
        val s = ServerEndpointStore(backing, FakeDefaults("https://relay.example.com", isDebug = false))
        assertNull(s.readSavedOverride())
        assertIs<ServerEndpointStore.Resolution.Ready>(s.resolve())
    }
}
