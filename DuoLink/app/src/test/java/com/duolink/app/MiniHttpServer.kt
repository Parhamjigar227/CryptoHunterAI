package com.duolink.app

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

/**
 * A tiny HTTP/1.1 server for tests, written on a raw [ServerSocket].
 *
 * WHY NOT `com.sun.net.httpserver.HttpServer`
 * The obvious choice is the JDK's own server, and it works perfectly on a desktop JVM. It does **not**
 * compile as an Android unit test: `testDebugUnitTest` compiles against `android.jar`, whose API surface
 * excludes `com.sun.*`. Using it made the test source set fail to compile in CI while passing locally,
 * which is precisely the kind of "works on my machine" split this suite exists to avoid.
 *
 * A [ServerSocket] lives in `java.base`/`java.net`, which is available to both, so this wrapper behaves the
 * same on a developer machine and in CI.
 *
 * Scope: enough HTTP/1.1 to be spoken to by [java.net.HttpURLConnection] - request line, headers,
 * `Content-Length`-delimited body, one response per connection, then close. No chunked encoding, no
 * keep-alive, no TLS. That is all the signaling client uses, and deliberately so: the client sets a fixed
 * length on every upload and never relies on connection reuse.
 */
class MiniHttpServer(
    private val responder: (Request) -> Response
) : Closeable {

    data class Request(
        val method: String,
        val path: String,
        val headers: Map<String, String>,
        val body: String
    )

    data class Response(
        val status: Int,
        val body: String,
        val contentType: String = "application/json; charset=utf-8"
    )

    private val serverSocket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
    private val workers = CopyOnWriteArrayList<Thread>()

    @Volatile
    private var running = true

    /** Every request received, in order, so tests can assert on what the client actually sent. */
    val requests = CopyOnWriteArrayList<Request>()

    val port: Int get() = serverSocket.localPort
    val baseUrl: String get() = "http://127.0.0.1:$port"

    private val acceptThread = Thread({
        while (running) {
            val socket = try {
                serverSocket.accept()
            } catch (_: Exception) {
                break // closed
            }
            val worker = Thread { handle(socket) }.apply { isDaemon = true }
            workers += worker
            worker.start()
        }
    }, "mini-http-accept").apply { isDaemon = true }

    fun start(): MiniHttpServer {
        acceptThread.start()
        return this
    }

    private fun handle(socket: Socket) {
        socket.use { s ->
            try {
                val input = BufferedInputStream(s.getInputStream())
                val output = BufferedOutputStream(s.getOutputStream())

                val requestLine = readLine(input) ?: return
                val parts = requestLine.split(' ')
                if (parts.size < 2) return
                val method = parts[0]
                val path = parts[1].substringBefore('?')

                val headers = LinkedHashMap<String, String>()
                while (true) {
                    val line = readLine(input) ?: break
                    if (line.isEmpty()) break
                    val idx = line.indexOf(':')
                    if (idx > 0) {
                        headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
                    }
                }

                val contentLength = headers["content-length"]?.toIntOrNull() ?: 0
                val body = if (contentLength > 0) {
                    val bytes = ByteArray(contentLength)
                    var read = 0
                    while (read < contentLength) {
                        val n = input.read(bytes, read, contentLength - read)
                        if (n < 0) break
                        read += n
                    }
                    String(bytes, 0, read, Charsets.UTF_8)
                } else ""

                val request = Request(method, path, headers, body)
                requests += request

                val response = responder(request)
                val payload = response.body.toByteArray(Charsets.UTF_8)
                val reason = when (response.status) {
                    200 -> "OK"
                    201 -> "Created"
                    204 -> "No Content"
                    400 -> "Bad Request"
                    401 -> "Unauthorized"
                    404 -> "Not Found"
                    409 -> "Conflict"
                    429 -> "Too Many Requests"
                    500 -> "Internal Server Error"
                    503 -> "Service Unavailable"
                    else -> "Status"
                }
                val head = buildString {
                    append("HTTP/1.1 ${response.status} $reason\r\n")
                    append("Content-Type: ${response.contentType}\r\n")
                    append("Content-Length: ${payload.size}\r\n")
                    append("Connection: close\r\n")
                    append("\r\n")
                }
                output.write(head.toByteArray(Charsets.UTF_8))
                output.write(payload)
                output.flush()
            } catch (_: Exception) {
                // A client that disconnects mid-request is normal in these tests; never fail the server.
            }
        }
    }

    /** Reads one CRLF- or LF-terminated line as ASCII. Returns null at end of stream. */
    private fun readLine(input: BufferedInputStream): String? {
        val builder = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (builder.isEmpty()) null else builder.toString()
            if (b == '\n'.code) {
                // strip a preceding CR if present
                if (builder.isNotEmpty() && builder.last() == '\r') builder.deleteCharAt(builder.length - 1)
                return builder.toString()
            }
            builder.append(b.toChar())
            if (builder.length > MAX_LINE) return null
        }
    }

    override fun close() {
        running = false
        runCatching { serverSocket.close() }
        runCatching { acceptThread.join(1_000) }
        workers.forEach { runCatching { it.join(1_000) } }
    }

    companion object {
        private const val MAX_LINE = 8192

        /** Convenience for the common case of a server that answers everything the same way. */
        fun always(status: Int, body: String): MiniHttpServer =
            MiniHttpServer { Response(status, body) }.start()
    }
}
