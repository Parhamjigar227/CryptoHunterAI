package com.duolink.app.remote

import com.duolink.app.crypto.ByteEncoding
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import javax.net.ssl.SSLException

/**
 * Minimal, strict HTTP transport for the signaling protocol.
 *
 * Why hand-rolled instead of Retrofit/OkHttp: the surface is nine endpoints with small JSON bodies,
 * and every byte of the response is a security-relevant input. A ~200-line client with explicit limits
 * is easier to audit than a stack of interceptors, and it adds no dependency to the APK.
 *
 * Hardening rules applied here and nowhere else (so they cannot be forgotten per call site):
 *  1. Only `https://` (or, in debug, loopback `http://`) — enforced by [SignalingEndpointPolicy]
 *     before a connection is opened, not after.
 *  2. No automatic redirects: a 30x is treated as an error. Following a redirect would let a hostile
 *     network downgrade the scheme or move the peer to another origin.
 *  3. Explicit connect/read timeouts; no infinite blocking on a flaky network.
 *  4. Response bodies capped at [MAX_RESPONSE_BYTES]; a hostile server cannot exhaust memory.
 *  5. `Content-Type` must be JSON; HTML error pages (captive portals, proxies) are rejected instead of
 *     being parsed as data.
 *  6. The status code is mapped to a typed [RemoteFailure]; callers never inspect raw HTTP codes.
 *  7. Nothing is logged — no URLs with tokens, no headers, no bodies.
 */
class SignalingHttpClient(
    private val isDebugBuild: Boolean,
    private val connectTimeoutMs: Int = DEFAULT_CONNECT_TIMEOUT_MS,
    private val readTimeoutMs: Int = DEFAULT_READ_TIMEOUT_MS
) {

    data class Response(
        val status: Int,
        val body: String
    )

    /**
     * Performs a request and returns the parsed body, or throws [RemotePairingException] carrying a
     * typed failure. Never returns a success status with a failure payload: protocol-level errors are
     * mapped from the server's `error` field.
     */
    fun execute(
        baseUrl: String,
        method: String,
        path: String,
        bearerToken: String? = null,
        jsonBody: String? = null
    ): String {
        val validation = SignalingEndpointPolicy.validate(baseUrl, isDebugBuild)
        if (!validation.isValid) {
            throw RemotePairingException(
                RemoteFailure.SERVER_REJECTED_REQUEST,
                validation.persianReason ?: "آدرس سرور واسط نامعتبر است"
            )
        }
        val normalised = SignalingEndpointPolicy.normalise(baseUrl)
        val url = try {
            URL("$normalised$path")
        } catch (e: IOException) {
            throw RemotePairingException(RemoteFailure.SERVER_REJECTED_REQUEST, "ساخت آدرس درخواست ممکن نشد", e)
        }
        var connection: HttpURLConnection? = null
        try {
            connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = method
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Cache-Control", "no-store")
            if (bearerToken != null) {
                connection.setRequestProperty("Authorization", "Bearer $bearerToken")
            }
            if (jsonBody != null) {
                val payload = jsonBody.toByteArray(Charsets.UTF_8)
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                connection.setFixedLengthStreamingMode(payload.size)
                connection.outputStream.use { it.write(payload) }
            }

            val status = connection.responseCode
            val contentType = connection.contentType ?: ""
            if (status in 300..399) {
                // Never follow: a redirect is an attempted origin change.
                throw RemotePairingException(
                    RemoteFailure.SERVER_REJECTED_REQUEST,
                    "سرور واسط تلاش کرد درخواست را به آدرس دیگری هدایت کند؛ درخواست متوقف شد"
                )
            }
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.let { readCapped(it) } ?: ""
            if (status in 200..299 && !contentType.contains("application/json", ignoreCase = true) && body.isEmpty()) {
                throw RemotePairingException(
                    RemoteFailure.SERVER_REJECTED_REQUEST,
                    "پاسخ سرور واسط ساختار JSON معتبر نداشت"
                )
            }
            if (status !in 200..299) {
                throw mapErrorStatus(status, body)
            }
            return body
        } catch (e: RemotePairingException) {
            throw e
        } catch (e: SocketTimeoutException) {
            throw RemotePairingException(RemoteFailure.SERVER_UNREACHABLE, cause = e)
        } catch (e: UnknownHostException) {
            throw RemotePairingException(RemoteFailure.NETWORK_UNAVAILABLE, cause = e)
        } catch (e: SSLException) {
            throw RemotePairingException(RemoteFailure.NETWORK_UNAVAILABLE, "اتصال امن TLS برقرار نشد", e)
        } catch (e: IOException) {
            throw RemotePairingException(RemoteFailure.NETWORK_UNAVAILABLE, cause = e)
        } finally {
            connection?.disconnect()
        }
    }

    private fun readCapped(stream: java.io.InputStream): String {
        val buffer = ByteArrayOutputStream(1024)
        val chunk = ByteArray(4096)
        BufferedInputStream(stream).use { input ->
            while (true) {
                val read = input.read(chunk)
                if (read < 0) break
                buffer.write(chunk, 0, read)
                if (buffer.size() > MAX_RESPONSE_BYTES) {
                    throw RemotePairingException(
                        RemoteFailure.SERVER_REJECTED_REQUEST,
                        "پاسخ سرور واسط از حد مجاز بزرگ‌تر است"
                    )
                }
            }
        }
        return buffer.toString("UTF-8")
    }

    /** Maps an HTTP failure to the specific protocol failure it represents. */
    private fun mapErrorStatus(status: Int, body: String): RemotePairingException {
        val error = extractErrorField(body)
        val failure = when (status) {
            401, 403 -> RemoteFailure.SERVER_REJECTED_REQUEST
            404 -> if (error == "expired") RemoteFailure.INVITATION_EXPIRED else RemoteFailure.INVITATION_NOT_FOUND
            409 -> when (error) {
                "already_redeemed" -> RemoteFailure.INVITATION_ALREADY_REDEEMED
                "revoked" -> RemoteFailure.INVITATION_REVOKED
                "rejected" -> RemoteFailure.INVITATION_REJECTED
                "already_mutual" -> RemoteFailure.ALREADY_TERMINAL
                "ack_before_quorum" -> RemoteFailure.PEER_COMMIT_NOT_YET_AVAILABLE
                "invalid_transition", "commit_conflict", "ack_conflict" -> RemoteFailure.INVALID_STATE_TRANSITION
                else -> RemoteFailure.SERVER_REJECTED_REQUEST
            }
            410 -> RemoteFailure.INVITATION_EXPIRED
            413 -> RemoteFailure.SERVER_REJECTED_REQUEST
            429 -> RemoteFailure.RATE_LIMITED
            in 500..599 -> RemoteFailure.SERVER_UNREACHABLE
            else -> RemoteFailure.SERVER_REJECTED_REQUEST
        }
        return RemotePairingException(failure, cause = null)
    }

    /**
     * Extracts the `error` field from a JSON error body without pulling in a JSON parser.
     *
     * The field is a short lowercase token by contract; anything else (HTML, nested objects, missing)
     * yields `null`, which maps to a generic rejection rather than being guessed at.
     */
    private fun extractErrorField(body: String): String? {
        if (body.isEmpty() || body.length > MAX_ERROR_SCAN) return null
        val marker = "\"error\""
        val markerIndex = body.indexOf(marker)
        if (markerIndex < 0) return null
        val colonIndex = body.indexOf(':', markerIndex)
        if (colonIndex < 0) return null
        val quoteStart = body.indexOf('"', colonIndex)
        if (quoteStart < 0) return null
        val quoteEnd = body.indexOf('"', quoteStart + 1)
        if (quoteEnd <= quoteStart + 1) return null
        val token = body.substring(quoteStart + 1, quoteEnd)
        return token.takeIf { it.length in 1..64 && it.all { ch -> ch.isLetterOrDigit() || ch == '_' || ch == '-' } }
    }

    companion object {
        const val DEFAULT_CONNECT_TIMEOUT_MS = 10_000
        const val DEFAULT_READ_TIMEOUT_MS = 15_000
        const val MAX_RESPONSE_BYTES = 64 * 1024
        private const val MAX_ERROR_SCAN = 8 * 1024

        /** Builds a JSON string with correct escaping for the small scalar payloads we send. */
        fun jsonString(value: String): String {
            val builder = StringBuilder(value.length + 2)
            builder.append('"')
            for (ch in value) {
                when (ch) {
                    '\\' -> builder.append("\\\\")
                    '"' -> builder.append("\\\"")
                    '\n' -> builder.append("\\n")
                    '\r' -> builder.append("\\r")
                    '\t' -> builder.append("\\t")
                    else -> if (ch < ' ') {
                        builder.append(String.format(java.util.Locale.US, "\\u%04x", ch.code))
                    } else {
                        builder.append(ch)
                    }
                }
            }
            builder.append('"')
            return builder.toString()
        }

        fun jsonObject(vararg fields: Pair<String, String>): String =
            fields.joinToString(separator = ",", prefix = "{", postfix = "}") { (key, rawValue) ->
                "${jsonString(key)}:$rawValue"
            }

        fun b64u(bytes: ByteArray): String = jsonString(ByteEncoding.encodeBase64Url(bytes))
    }
}
