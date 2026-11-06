package com.duolink.app.remote

import java.net.URI
import java.net.URISyntaxException

/**
 * Enforces where the app is willing to talk.
 *
 * Rule: **release builds may only talk to `https://`**. A debug build may additionally use `http://`
 * *and only* to a loopback address (`127.0.0.1`, `::1`, `localhost`), because that is how a developer
 * reaches a locally started signaling server through `adb reverse tcp:<port> tcp:<port>` without
 * exposing anything on a network. `http://` to any other host is rejected in every build type: there
 * is no reason for a phone to speak plaintext to a remote origin, and allowing it in debug would make
 * it trivially easy to ship by accident.
 *
 * This is a code-level policy, not a build-config convention: it is unit-tested in
 * `RemotePairingUnitTest` for both build types.
 */
object SignalingEndpointPolicy {

    const val DEFAULT_DEBUG_ENDPOINT = "http://127.0.0.1:8787"
    const val DEFAULT_RELEASE_ENDPOINT = "https://"

    private val LOOPBACK_HOSTS = setOf("127.0.0.1", "localhost", "::1", "[::1]")

    data class Validation(val isValid: Boolean, val persianReason: String?)

    /**
     * @param isDebugBuild `BuildConfig.DEBUG`; passed explicitly so JVM tests can exercise both modes.
     */
    fun validate(rawUrl: String?, isDebugBuild: Boolean): Validation {
        val url = rawUrl?.trim().orEmpty()
        if (url.isEmpty()) {
            return Validation(false, "آدرس سرور واسط خالی است")
        }
        if (url.length > MAX_URL_LENGTH) {
            return Validation(false, "آدرس سرور واسط بیش از حد طولانی است")
        }
        val uri = try {
            URI(url)
        } catch (_: URISyntaxException) {
            return Validation(false, "ساختار آدرس سرور واسط نامعتبر است")
        }
        val scheme = uri.scheme?.lowercase()
        val host = uri.host?.lowercase()
        if (scheme == null || host.isNullOrEmpty()) {
            return Validation(false, "آدرس سرور واسط باید شامل پروتکل و نام میزبان باشد")
        }
        if (uri.userInfo != null || uri.fragment != null || uri.query != null) {
            return Validation(false, "آدرس سرور واسط نباید شامل نام کاربری، رمز، کوئری یا بخش باشد")
        }
        if (uri.port != -1 && (uri.port < 1 || uri.port > 65535)) {
            return Validation(false, "شماره پورت آدرس سرور واسط نامعتبر است")
        }
        if (uri.path != null && uri.path != "" && uri.path != "/") {
            return Validation(false, "آدرس سرور واسط نباید مسیر اضافه داشته باشد")
        }
        when (scheme) {
            "https" -> return Validation(true, null)
            "http" -> {
                if (!isDebugBuild) {
                    return Validation(false, "در نسخه نهایی برنامه فقط اتصال HTTPS مجاز است")
                }
                if (host !in LOOPBACK_HOSTS) {
                    return Validation(
                        false,
                        "اتصال HTTP فقط برای آدرس محلی (127.0.0.1) در نسخه آزمایشی مجاز است"
                    )
                }
                return Validation(true, null)
            }
            else -> return Validation(false, "پروتکل آدرس سرور واسط باید HTTPS باشد")
        }
    }

    /** Normalises a validated URL to `scheme://host[:port]` with no trailing slash. */
    fun normalise(rawUrl: String): String {
        val uri = URI(rawUrl.trim())
        val portPart = if (uri.port == -1) "" else ":${uri.port}"
        return "${uri.scheme.lowercase()}://${uri.host.lowercase()}$portPart"
    }

    fun defaultFor(isDebugBuild: Boolean): String =
        if (isDebugBuild) DEFAULT_DEBUG_ENDPOINT else DEFAULT_RELEASE_ENDPOINT

    const val MAX_URL_LENGTH = 300
}
