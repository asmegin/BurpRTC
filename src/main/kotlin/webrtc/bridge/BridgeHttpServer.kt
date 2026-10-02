package webrtc.bridge

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.util.Locale
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Small HTTP/1.x transport using only java.base; Burp may omit jdk.httpserver. */
internal class BridgeHttpServer(
    address: InetSocketAddress,
    private val onError: (Exception) -> Unit,
    private val handler: (Request) -> Response
) : Closeable {
    data class Request(val method: String, val path: String, val body: String, val query: String? = null, val headers: Map<String, String> = emptyMap())
    data class Response(val code: Int, val body: String = "", val contentType: String = "text/plain")

    private val listener = ServerSocket()
    private val lock = Any()
    private val clients = HashSet<Socket>()
    @Volatile private var closed = false
    private val workers = ThreadPoolExecutor(
        4, 4, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(32),
        { task -> Thread(task, "webrtc-bridge-worker").apply { isDaemon = true } }
    )
    val port: Int get() = listener.localPort

    init {
        try {
            listener.reuseAddress = true
            listener.bind(address)
            Thread({ acceptLoop() }, "webrtc-bridge-listener").apply { isDaemon = true }.start()
        } catch (e: Exception) {
            close()
            throw e
        }
    }

    private fun acceptLoop() {
        while (!closed) {
            val client = try {
                listener.accept()
            } catch (e: Exception) {
                if (!closed) {
                    onError(e)
                    close()
                }
                return
            }
            synchronized(lock) {
                if (closed) {
                    client.close()
                } else {
                    clients.add(client)
                    try {
                        workers.execute { serve(client) }
                    } catch (_: java.util.concurrent.RejectedExecutionException) {
                        clients.remove(client)
                        client.close()
                    }
                }
            }
        }
    }

    override fun close() {
        synchronized(lock) {
            closed = true
            runCatching { listener.close() }
            clients.forEach { runCatching { it.close() } }
            clients.clear()
            workers.shutdownNow()
        }
    }

    private fun serve(client: Socket) {
        try {
            client.use {
                client.soTimeout = 5_000
                val response = try {
                    handler(readRequest(client))
                } catch (e: HttpFailure) {
                    Response(e.code)
                } catch (_: SocketTimeoutException) {
                    Response(408)
                } catch (e: Exception) {
                    if (!closed) onError(e)
                    Response(500)
                }
                writeResponse(client, response)
            }
        } catch (_: java.io.IOException) {
            // The browser disconnected, or stop() closed an active connection.
        } finally {
            synchronized(lock) { clients.remove(client) }
        }
    }

    private class HttpFailure(val code: Int) : Exception()

    private fun readRequest(client: Socket): Request {
        val input = BufferedInputStream(client.getInputStream())
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        var headerBytes = 0

        fun readByte(): Int {
            if (System.nanoTime() > deadline) throw HttpFailure(408)
            return input.read().also { if (it < 0) throw HttpFailure(400) }
        }

        fun line(): String {
            val bytes = ByteArrayOutputStream()
            while (true) {
                val b = readByte()
                if (++headerBytes > 32 * 1024) throw HttpFailure(431)
                if (b == 13) {
                    if (readByte() != 10) throw HttpFailure(400)
                    headerBytes++
                    return bytes.toString(Charsets.ISO_8859_1)
                }
                if (b == 10) throw HttpFailure(400)
                bytes.write(b)
            }
        }

        val start = line().split(' ')
        if (start.size != 3 || start[2] !in setOf("HTTP/1.0", "HTTP/1.1")) throw HttpFailure(400)
        val uri = try {
            URI(start[1]).also { if (it.path?.startsWith('/') != true) throw HttpFailure(400) }
        } catch (_: java.net.URISyntaxException) {
            throw HttpFailure(400)
        }
        val headers = HashMap<String, String>()
        while (true) {
            val line = line()
            if (line.isEmpty()) break
            val colon = line.indexOf(':')
            if (colon <= 0) throw HttpFailure(400)
            val name = line.substring(0, colon).lowercase(Locale.ROOT)
            if (!name.matches(Regex("[!#$%&'*+.^_`|~0-9a-z-]+"))) throw HttpFailure(400)
            val value = line.substring(colon + 1).trim()
            if (headers.put(name, value) != null && name in setOf("content-length", "transfer-encoding", "host", "origin")) {
                throw HttpFailure(400)
            }
        }
        val transfer = headers["transfer-encoding"]
        val length = headers["content-length"]
        if (transfer != null && length != null) throw HttpFailure(400)
        if (transfer != null && !transfer.equals("chunked", true)) throw HttpFailure(501)
        val size = length?.let {
            if (!it.matches(Regex("[0-9]+"))) throw HttpFailure(400)
            it.toLongOrNull() ?: throw HttpFailure(413)
        } ?: 0L
        if (size > MAX_BODY) throw HttpFailure(413)
        headers["expect"]?.let {
            if (!it.equals("100-continue", true)) throw HttpFailure(417)
            client.getOutputStream().apply {
                write("HTTP/1.1 100 Continue\r\n\r\n".toByteArray(Charsets.US_ASCII))
                flush()
            }
        }
        val body = ByteArrayOutputStream()
        fun readBody(count: Int) {
            if (count > MAX_BODY - body.size()) throw HttpFailure(413)
            val buffer = ByteArray(minOf(count, 8192))
            var remaining = count
            while (remaining > 0) {
                if (System.nanoTime() > deadline) throw HttpFailure(408)
                val n = input.read(buffer, 0, minOf(remaining, buffer.size))
                if (n < 0) throw HttpFailure(400)
                body.write(buffer, 0, n)
                remaining -= n
            }
        }
        if (transfer != null) {
            while (true) {
                val chunk = line().substringBefore(';')
                if (!chunk.matches(Regex("[0-9a-fA-F]+"))) throw HttpFailure(400)
                val count = chunk.toLongOrNull(16) ?: throw HttpFailure(413)
                if (count > MAX_BODY) throw HttpFailure(413)
                if (count == 0L) {
                    while (line().isNotEmpty()) { /* Consume bounded trailers. */ }
                    break
                }
                readBody(count.toInt())
                if (readByte() != 13 || readByte() != 10) throw HttpFailure(400)
            }
        } else {
            readBody(size.toInt())
        }
        return Request(start[0], uri.path, body.toString(Charsets.UTF_8), uri.rawQuery, headers)
    }

    private fun writeResponse(client: Socket, response: Response) {
        val bytes = if (response.code == 204) byteArrayOf() else response.body.toByteArray(Charsets.UTF_8)
        val reason = when (response.code) {
            200 -> "OK"
            204 -> "No Content"
            400 -> "Bad Request"
            403 -> "Forbidden"
            404 -> "Not Found"
            408 -> "Request Timeout"
            413 -> "Content Too Large"
            417 -> "Expectation Failed"
            431 -> "Request Header Fields Too Large"
            501 -> "Not Implemented"
            else -> "Internal Server Error"
        }
        val headers = buildString {
            append("HTTP/1.1 ${response.code} $reason\r\n")
            append("Access-Control-Allow-Origin: *\r\n")
            append("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n")
            append("Access-Control-Allow-Headers: Content-Type\r\n")
            append("Content-Type: ${response.contentType}; charset=utf-8\r\n")
            if (response.code != 204) append("Content-Length: ${bytes.size}\r\n")
            append("Cache-Control: no-store\r\n")
            append("Connection: close\r\n\r\n")
        }
        client.getOutputStream().apply {
            write(headers.toByteArray(Charsets.US_ASCII))
            write(bytes)
            flush()
        }
    }

    private companion object {
        const val MAX_BODY = 1024 * 1024
    }
}
