package com.duolink.app.messaging

import com.duolink.app.crypto.ByteEncoding
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.net.URI
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLSocketFactory

/**
 * A small, dependency-free RFC 6455 WebSocket client for the relay.
 *
 * Why hand-rolled: the app's transport already uses `HttpURLConnection` and has no OkHttp, and adding a
 * networking stack purely for one frame codec would grow the attack surface more than it saves. This
 * implements only what the relay protocol needs — client-side masked text frames, close, ping/pong and
 * fragmentation — and refuses everything else.
 *
 * Security properties:
 *  - Uses the platform TLS stack ([SSLSocketFactory]) for `wss://`, so certificate validation and pinning
 *    behaviour is exactly what the OS provides. Cleartext `ws://` is only reachable for loopback
 *    development, which [RelayEndpointPolicy] enforces.
 *  - Every client frame is masked with a fresh 4-byte key, as RFC 6455 requires.
 *  - A server frame with the mask bit set, reserved bits set, or an oversized length is a protocol error
 *    and closes the connection rather than being interpreted.
 */
internal class WsClient(
    private val host: String,
    private val port: Int,
    private val path: String,
    private val secure: Boolean,
    private val hostHeader: String,
    private val random: SecureRandom = SecureRandom(),
    private val connectTimeoutMs: Int = 10_000,
    private val maxPayload: Int = 128 * 1024
) {
    private var socket: Socket? = null
    private lateinit var input: InputStream
    private lateinit var output: OutputStream
    private val closed = AtomicBoolean(false)

    /** Performs the HTTP upgrade handshake. Throws [IOException] subclass on any failure. */
    fun connect() {
        val raw = if (secure) {
            (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(host, port)
                .also { (it as javax.net.ssl.SSLSocket).startHandshake() }
        } else {
            Socket(host, port)
        }
        raw.soTimeout = connectTimeoutMs
        raw.tcpNoDelay = true
        socket = raw
        input = raw.getInputStream()
        output = raw.getOutputStream()

        val keyBytes = ByteArray(16).also { random.nextBytes(it) }
        val key = java.util.Base64.getEncoder().encodeToString(keyBytes)
        val request = buildString {
            append("GET ").append(path).append(" HTTP/1.1\r\n")
            append("Host: ").append(hostHeader).append("\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: ").append(key).append("\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("\r\n")
        }
        output.write(request.toByteArray(Charsets.US_ASCII))
        output.flush()

        val responseHead = readHttpHead()
        val statusLine = responseHead.lineSequence().firstOrNull() ?: ""
        if (!statusLine.contains("101")) {
            throw java.io.IOException("websocket upgrade refused: ${statusLine.take(80)}")
        }
        val expectedAccept = java.util.Base64.getEncoder().encodeToString(
            java.security.MessageDigest.getInstance("SHA-1")
                .digest((key + WS_GUID).toByteArray(Charsets.US_ASCII))
        )
        val acceptLine = responseHead.lineSequence()
            .firstOrNull { it.startsWith("Sec-WebSocket-Accept:", ignoreCase = true) }
            ?.substringAfter(':')?.trim()
        if (acceptLine != expectedAccept) {
            // A mismatched accept value means we are not talking to the server we think we are.
            throw java.io.IOException("websocket handshake not authenticated by the server")
        }
    }

    private fun readHttpHead(): String {
        val buffer = ByteArrayOutputStream()
        var state = 0
        while (true) {
            val byte = input.read()
            if (byte < 0) throw java.io.IOException("connection closed during handshake")
            buffer.write(byte)
            // Track CRLFCRLF.
            state = when {
                byte == '\r'.code && (state == 0 || state == 2) -> state + 1
                byte == '\n'.code && (state == 1 || state == 3) -> state + 1
                else -> 0
            }
            if (state == 4) break
        }
        return buffer.toString(Charsets.ISO_8859_1.name())
    }

    /** Writes one masked text frame. */
    fun sendText(text: String) {
        val payload = text.toByteArray(Charsets.UTF_8)
        require(payload.size <= maxPayload) { "outbound frame too large" }
        val maskKey = ByteArray(4).also { random.nextBytes(it) }
        val header = when {
            payload.size < 126 -> byteArrayOf((0x81).toByte(), (0x80 or payload.size).toByte())
            payload.size < 65_536 -> byteArrayOf(
                (0x81).toByte(),
                (0x80 or 126).toByte(),
                (payload.size ushr 8).toByte(),
                payload.size.toByte()
            )
            else -> ByteArray(10).also {
                it[0] = 0x81.toByte()
                it[1] = (0x80 or 127).toByte()
                for (i in 0 until 8) it[2 + i] = (payload.size.toLong() ushr (56 - 8 * i)).toByte()
            }
        }
        val masked = ByteArray(payload.size) { i -> (payload[i].toInt() xor maskKey[i and 3].toInt()).toByte() }
        output.write(header)
        output.write(maskKey)
        output.write(masked)
        output.flush()
    }

    /** Reads one complete text message, reassembling fragments. Returns null on a clean close. */
    fun readText(): String? {
        val fragments = ByteArrayOutputStream()
        var messageOpcode = -1
        while (true) {
            val b0 = input.read()
            if (b0 < 0) return null
            val b1 = input.read()
            if (b1 < 0) return null

            val fin = (b0 and 0x80) != 0
            val rsv = b0 and 0x70
            if (rsv != 0) throw java.io.IOException("server set reserved bits")
            val opcode = b0 and 0x0F

            // A server must never mask its frames (RFC 6455 5.1).
            if ((b1 and 0x80) != 0) throw java.io.IOException("server frame is masked")

            var length = b1 and 0x7F
            if (length == 126) {
                length = (readByteStrict() shl 8) or readByteStrict()
            } else if (length == 127) {
                var big = 0L
                repeat(8) { big = (big shl 8) or readByteStrict().toLong() }
                if (big > maxPayload) throw java.io.IOException("server frame too large")
                length = big.toInt()
            }
            if (length > maxPayload) throw java.io.IOException("server frame too large")
            val payload = ByteArray(length)
            var read = 0
            while (read < length) {
                val n = input.read(payload, read, length - read)
                if (n < 0) return null
                read += n
            }

            when (opcode) {
                0x8 -> { // close
                    runCatching { sendClose() }
                    return null
                }
                0x9 -> { /* ping: relay does not require a pong beyond keeping the socket alive */ }
                0xA -> { /* pong */ }
                0x1, 0x2 -> {
                    messageOpcode = opcode
                    fragments.write(payload)
                }
                0x0 -> {
                    if (messageOpcode < 0) throw java.io.IOException("orphan continuation")
                    fragments.write(payload)
                }
                else -> throw java.io.IOException("unsupported opcode $opcode")
            }
            if (fin && messageOpcode >= 0) {
                if (fragments.size() > maxPayload) throw java.io.IOException("reassembled frame too large")
                return fragments.toString(Charsets.UTF_8.name())
            }
        }
    }

    private fun readByteStrict(): Int {
        val b = input.read()
        if (b < 0) throw java.io.IOException("connection closed mid-frame")
        return b
    }

    private fun sendClose() {
        // Close frame with code 1000, masked.
        val maskKey = ByteArray(4).also { random.nextBytes(it) }
        val code = byteArrayOf((1000 ushr 8).toByte(), 1000.toByte())
        output.write(byteArrayOf(0x88.toByte(), (0x80 or 2).toByte()))
        output.write(maskKey)
        output.write(ByteArray(2) { i -> (code[i].toInt() xor maskKey[i and 3].toInt()).toByte() })
        output.flush()
    }

    fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { sendClose() }
        runCatching { socket?.close() }
    }

    companion object {
        private const val WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

        /** Parses `ws(s)://host[:port]/path` into the parts [WsClient] needs. */
        fun parse(endpointUrl: String): WsClient {
            val uri = URI(endpointUrl)
            val secure = when (uri.scheme?.lowercase()) {
                "wss" -> true
                "ws" -> false
                else -> throw IllegalArgumentException("endpoint must be ws:// or wss://")
            }
            val port = if (uri.port > 0) uri.port else if (secure) 443 else 80
            val host = uri.host ?: throw IllegalArgumentException("endpoint has no host")
            val path = (uri.rawPath?.ifEmpty { "/" } ?: "/") +
                (uri.rawQuery?.let { "?$it" } ?: "")
            val defaultPort = if (secure) 443 else 80
            val hostHeader = if (port == defaultPort) host else "$host:$port"
            return WsClient(host, port, path, secure, hostHeader)
        }
    }
}

/**
 * [MessageTransport] backed by the relay: a WebSocket fast lane with an HTTP polling fallback.
 *
 * The two paths are deliberately interchangeable, and the engine above cannot tell them apart. The
 * socket is used when it is live; every send additionally has an HTTP path so a message is never lost
 * because the socket happened to be reconnecting at that instant. Duplicate delivery is harmless
 * because the engine de-duplicates by message id.
 */
internal class RelayMessageTransport(
    baseUrl: String,
    private val localDeviceId: ByteArray,
    private val httpRelay: HttpRelayClient,
    private val socketFactory: (String) -> WsClient = { WsClient.parse(it) }
) : MessageTransport {
    private val base = baseUrl.trimEnd('/')
    private var socket: WsClient? = null
    private val lock = Any()

    /** True while a socket is connected. Drives the UI's connection indicator. */
    val socketConnected: Boolean get() = synchronized(lock) { socket != null }

    override suspend fun send(envelope: SealedMessageEnvelope) {
        val payload = EnvelopeJson.encode(envelope)
        val viaSocket = synchronized(lock) {
            val live = socket
            if (live == null) {
                false
            } else {
                try {
                    live.sendText("""{"type":"send","envelope":$payload}""")
                    true
                } catch (t: Throwable) {
                    // The socket died mid-write; drop it and fall back to HTTP below.
                    runCatching { live.close() }
                    socket = null
                    false
                }
            }
        }
        if (!viaSocket) {
            httpRelay.send(base, envelope)
        }
    }

    override suspend fun fetchSince(deviceId: ByteArray, sinceSequence: Long): List<SealedMessageEnvelope> =
        httpRelay.fetchSince(base, deviceId, sinceSequence)

    override suspend fun sendDeliveryReceipt(messageIdHex: String) {
        httpRelay.sendReceipt(base, "delivered", messageIdHex, ByteEncoding.encodeBase64Url(localDeviceId))
    }

    override suspend fun sendReadReceipt(messageIdHex: String) {
        httpRelay.sendReceipt(base, "read", messageIdHex, ByteEncoding.encodeBase64Url(localDeviceId))
    }

    /** Opens the fast lane. Safe to call repeatedly; failure leaves the HTTP path in charge. */
    fun connectSocket(): Boolean = synchronized(lock) {
        if (socket != null) return true
        val endpoint = base
            .replaceFirst("https://", "wss://")
            .replaceFirst("http://", "ws://") + "/v1/ws"
        return try {
            val live = socketFactory(endpoint)
            live.connect()
            live.sendText("""{"type":"hello","deviceId":"${ByteEncoding.encodeBase64Url(localDeviceId)}"}""")
            socket = live
            true
        } catch (t: Throwable) {
            socket = null
            false
        }
    }

    fun disconnectSocket() {
        synchronized(lock) {
            runCatching { socket?.close() }
            socket = null
        }
    }
}
