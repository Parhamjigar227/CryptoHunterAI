package com.duolink.app.remote

import com.duolink.app.crypto.KeyValueByteStore

/**
 * Resolves which signaling server the app should talk to, and remembers an override the user typed.
 *
 * Why this exists: the endpoint used to be a single hard-coded constant
 * (`https://relay.duolink.invalid`) with no way to change it from inside the app. That made the
 * shipped APK unable to reach any server at all - `.invalid` is a reserved TLD that never resolves -
 * and it meant every move of the server required a new APK build and release.
 *
 * Precedence, highest first:
 *  1. A validated override the user saved from the settings screen.
 *  2. [BuildConfig.DEFAULT_SIGNALING_ENDPOINT], which the build can inject
 *     (`-Pduolink.signalingEndpoint=https://...`) and which falls back to the debug/release default.
 *
 * Every candidate goes through [SignalingEndpointPolicy] before it is returned, so a stored value
 * cannot smuggle in plaintext HTTP on a release build even if it was written by an older version of
 * the app or by a tampered data directory.
 */
class ServerEndpointStore(
    private val store: KeyValueByteStore,
    private val defaults: EndpointDefaults = EndpointDefaults
) {

    /** The build-time defaults and the platform policy. Injectable so tests do not depend on the build. */
    interface EndpointDefaults {
        fun buildTimeDefault(): String
        fun policyAllows(rawUrl: String): Boolean
        fun normalise(rawUrl: String): String
    }

    /** Where the build-time default comes from, and the rule that decides whether a URL is usable. */
    object AndroidDefaults : EndpointDefaults {
        override fun buildTimeDefault(): String = com.duolink.app.BuildConfig.DEFAULT_SIGNALING_ENDPOINT

        override fun policyAllows(rawUrl: String): Boolean =
            SignalingEndpointPolicy.validate(rawUrl, com.duolink.app.BuildConfig.DEBUG).isValid

        override fun normalise(rawUrl: String): String = SignalingEndpointPolicy.normalise(rawUrl)
    }

    sealed interface Resolution {
        /** A usable endpoint, already normalised to `scheme://host[:port]`. */
        data class Ready(val baseUrl: String, val source: Source) : Resolution

        /**
         * Nothing usable is configured. The UI must ask the user for a server address instead of
         * silently attempting a request to a placeholder domain and reporting a confusing network error.
         */
        data class NeedsConfiguration(val reason: String) : Resolution
    }

    enum class Source { SAVED_OVERRIDE, BUILD_TIME }

    /** The endpoint to use right now, or an explicit statement that one must be configured. */
    fun resolve(): Resolution {
        readSavedOverride()?.let { saved ->
            return Resolution.Ready(saved, Source.SAVED_OVERRIDE)
        }

        val buildTime = runCatching { defaults.buildTimeDefault() }.getOrNull().orEmpty()
        if (buildTime.isBlank()) {
            return Resolution.NeedsConfiguration("در این نسخه آدرس سرور تعیین نشده است")
        }
        if (!defaults.policyAllows(buildTime)) {
            // Not fatal: a release build with no compiled-in endpoint is a legitimate configuration, but
            // it must say so rather than pretending the default is usable.
            return Resolution.NeedsConfiguration("آدرس سرور پیش‌فرض معتبر نیست; لطفاً آدرس را دستی وارد کنید")
        }
        return Resolution.Ready(defaults.normalise(buildTime), Source.BUILD_TIME)
    }

    /**
     * Validates and persists a user-supplied address.
     *
     * Returns the normalised value on success. Nothing is written unless the policy accepts it, so a
     * rejected address cannot leave a half-saved value behind for the next launch to pick up.
     */
    fun saveOverride(rawUrl: String): Result<String> {
        val trimmed = rawUrl.trim()
        if (trimmed.isEmpty()) return Result.failure(IllegalArgumentException("آدرس سرور خالی است"))
        if (trimmed.length > SignalingEndpointPolicy.MAX_URL_LENGTH) {
            return Result.failure(IllegalArgumentException("آدرس سرور بیش از حد بلند است"))
        }
        val validation = defaults.let { runCatching { it.policyAllows(trimmed) }.getOrDefault(false) }
        if (!validation) {
            return Result.failure(IllegalArgumentException("آدرس سرور معتبر نیست یا مجاز نیست"))
        }
        val normalised = runCatching { defaults.normalise(trimmed) }.getOrElse {
            return Result.failure(IllegalArgumentException("آدرس سرور قابل خواندن نیست"))
        }
        store.write(KEY_OVERRIDE, normalised.toByteArray(Charsets.UTF_8))
        return Result.success(normalised)
    }

    /** Clears a saved override so the build-time default applies again. */
    fun clearOverride() {
        store.delete(KEY_OVERRIDE)
    }

    /** The saved override, or null. Corrupt/blank/unreadable values are dropped, not returned. */
    fun readSavedOverride(): String? {
        val raw = runCatching {
            when (val state = store.readState(KEY_OVERRIDE)) {
                is KeyValueByteStore.RawStoreRead.Present -> String(state.bytes, Charsets.UTF_8)
                else -> return null
            }
        }.getOrNull() ?: return null

        if (raw.isBlank() || raw.length > SignalingEndpointPolicy.MAX_URL_LENGTH) return null
        // Re-validate on read: the policy may have tightened since the value was written, and a release
        // build must never honour an `http://` address that a debug build once accepted.
        if (!runCatching { defaults.policyAllows(raw) }.getOrDefault(false)) return null
        return runCatching { defaults.normalise(raw) }.getOrNull()
    }

    companion object {
        const val KEY_OVERRIDE = "signaling_endpoint_override"
    }
}
