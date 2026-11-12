package com.duolink.app.messaging

import java.net.URI

/**
 * Endpoint policy for the relay socket.
 *
 * Cleartext `ws://` is allowed only for loopback, because the Android manifest sets
 * `usesCleartextTraffic="false"` and because a relay over plaintext would leak message timing and
 * metadata to anyone on the network even though the payloads stay encrypted. Anything else must be
 * `wss://`.
 */
object RelayEndpointPolicy {
    fun validate(baseUrl: String): String? {
        val uri = try {
            URI(baseUrl)
        } catch (t: Throwable) {
            return "آدرس سرور معتبر نیست."
        }
        val scheme = uri.scheme?.lowercase()
        val host = uri.host
        if (host == null) return "آدرس سرور معتبر نیست."
        return when {
            scheme == "https" || scheme == "wss" -> null
            (scheme == "http" || scheme == "ws") && isLoopback(host) -> null
            scheme == "http" || scheme == "ws" ->
                "برای اتصال به سرور، آدرس باید با https یا wss شروع شود."
            else -> "پروتکل آدرس سرور پشتیبانی نمی‌شود."
        }
    }

    fun isLoopback(host: String): Boolean =
        host == "127.0.0.1" || host == "::1" || host == "localhost" || host == "10.0.2.2"
}
