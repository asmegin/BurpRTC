package webrtc.datachannel

import kotlinx.serialization.json.*
import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocket
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Minimal Chrome DevTools Protocol client (flattened sessions) over java.net.http. */
class CdpClient private constructor() : AutoCloseable {
    private val nextId = AtomicInteger(1)
    private val pending = ConcurrentHashMap<Int, CompletableFuture<JsonObject>>()
    private val listeners = CopyOnWriteArrayList<(String, String?, JsonObject) -> Unit>()
    // Events are dispatched off the socket thread so a listener may issue blocking calls.
    private val events = Executors.newSingleThreadExecutor { Thread(it, "webrtc-cdp-events").apply { isDaemon = true } }
    private val sendLock = Any()
    private lateinit var httpClient: HttpClient
    private lateinit var socket: WebSocket
    @Volatile var closed = false
        private set

    companion object {
        fun connect(url: String, timeoutMs: Long = 10000): CdpClient {
            val client = CdpClient()
            val http = HttpClient.newHttpClient()
            client.httpClient = http
            client.socket = http.newWebSocketBuilder().connectTimeout(Duration.ofMillis(timeoutMs))
                .buildAsync(URI(url), client.Listener()).get(timeoutMs, TimeUnit.MILLISECONDS)
            return client
        }
    }

    private inner class Listener : WebSocket.Listener {
        private val buffer = StringBuilder()
        override fun onText(webSocket: WebSocket, data: CharSequence, last: Boolean): CompletionStage<*>? {
            buffer.append(data)
            if (last) { val text = buffer.toString(); buffer.setLength(0); handle(text) }
            webSocket.request(1)
            return null
        }
        override fun onClose(webSocket: WebSocket, statusCode: Int, reason: String): CompletionStage<*>? { shutdown(); return null }
        override fun onError(webSocket: WebSocket, error: Throwable) { shutdown() }
    }

    private fun handle(text: String) {
        val message = runCatching { Json.parseToJsonElement(text).jsonObject }.getOrNull() ?: return
        val id = (message["id"] as? JsonPrimitive)?.intOrNull
        if (id != null) { pending.remove(id)?.complete(message); return }
        val method = (message["method"] as? JsonPrimitive)?.contentOrNull ?: return
        val session = (message["sessionId"] as? JsonPrimitive)?.contentOrNull
        val params = message["params"] as? JsonObject ?: JsonObject(emptyMap())
        if (!events.isShutdown) events.execute { listeners.forEach { runCatching { it(method, session, params) }.onFailure(webrtc.ui.UiKit::logError) } }
    }

    private fun shutdown() {
        closed = true
        pending.values.forEach { it.completeExceptionally(IllegalStateException("DevTools connection closed")) }
        pending.clear()
        events.shutdownNow()
        if (::httpClient.isInitialized) runCatching { httpClient.close() }
    }

    fun onEvent(listener: (method: String, sessionId: String?, params: JsonObject) -> Unit) { listeners += listener }

    fun call(method: String, params: JsonObject = JsonObject(emptyMap()), sessionId: String? = null, timeoutMs: Long = 15000): JsonObject {
        check(!closed) { "DevTools connection closed" }
        val id = nextId.getAndIncrement()
        val future = CompletableFuture<JsonObject>()
        pending[id] = future
        val message = buildJsonObject { put("id", id); put("method", method); put("params", params); sessionId?.let { put("sessionId", it) } }
        try {
            synchronized(sendLock) { socket.sendText(message.toString(), true).get(timeoutMs, TimeUnit.MILLISECONDS) }
            val response = future.get(timeoutMs, TimeUnit.MILLISECONDS)
            (response["error"] as? JsonObject)?.let { throw IllegalStateException("$method failed: ${(it["message"] as? JsonPrimitive)?.contentOrNull ?: it}") }
            return response["result"] as? JsonObject ?: JsonObject(emptyMap())
        } finally { pending.remove(id) }
    }

    override fun close() {
        runCatching { socket.sendClose(WebSocket.NORMAL_CLOSURE, "done").get(2, TimeUnit.SECONDS) }
        shutdown()
    }
}
