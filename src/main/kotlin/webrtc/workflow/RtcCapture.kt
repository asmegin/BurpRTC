package webrtc.workflow

import burp.api.montoya.MontoyaApi
import burp.api.montoya.websocket.*
import kotlinx.serialization.json.*
import webrtc.bridge.boundedJson
import webrtc.config.ConfigStore
import webrtc.scope.ScopeGate
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.time.Instant
import java.util.UUID

/** Passive native WS decoding, including escaped SDP and Socket.IO JSON envelopes. */
object RtcDecoder {
    data class Decoded(val sdps: List<String>, val candidates: List<String>, val iceServers: List<JsonObject>,
                       val identifiers: Map<String, List<String>>, val sip: Boolean, val truncated: Boolean)
    fun decode(text: String, subprotocol: String = ""): Decoded {
        val sdps = linkedSetOf<String>(); val candidates = linkedSetOf<String>(); val servers = mutableListOf<JsonObject>()
        val ids = linkedMapOf<String, MutableList<String>>()
        val bounded = text.length <= 262144
        if (!bounded) return Decoded(emptyList(), emptyList(), emptyList(), emptyMap(), false, true)
        fun visit(value: JsonElement, depth: Int) {
            if (depth > 12) return
            when (value) {
                is JsonObject -> {
                    if (value["urls"] != null && value["urls"].toString().contains(Regex("(?i)turns?:|stuns?:"))) servers += value
                    value.forEach { (key, item) ->
                        if (key.lowercase() in setOf("room", "roomid", "tenant", "tenantid", "participantid", "producerid", "consumerid", "streamid", "recordingid"))
                            (item as? JsonPrimitive)?.contentOrNull?.let { ids.getOrPut(key) { mutableListOf() }.add(it) }
                        visit(item, depth + 1)
                    }
                }
                is JsonArray -> value.take(512).forEach { visit(it, depth + 1) }
                is JsonPrimitive -> {
                    val raw = value.contentOrNull.orEmpty()
                    if (raw.startsWith("v=0") && raw.contains("m=")) sdps += raw
                    if (raw.removePrefix("a=").startsWith("candidate:")) candidates += raw
                    if ((raw.startsWith('{') || raw.startsWith('[') || raw.startsWith('"')) && boundedJson(raw))
                        runCatching { Json.parseToJsonElement(raw) }.getOrNull()?.let { visit(it, depth + 1) }
                }
                else -> Unit
            }
        }
        val payload = if (Regex("^4[0-6](?:/[^,]*,)?[0-9]*[\\[{]").containsMatchIn(text)) text.dropWhile { it != '[' && it != '{' } else text
        if (boundedJson(payload)) runCatching { Json.parseToJsonElement(payload) }.getOrNull()?.let { visit(it, 0) }
        if (text.startsWith("v=0")) sdps += text
        val sip = (subprotocol.split(',').any { it.trim().equals("sip", true) } || Regex("^(SIP/2.0 [0-9]{3}|[A-Z]+ sips?:\\S+ SIP/2.0)\\r?\\n").containsMatchIn(text))
        if (sip) text.substringAfter("\r\n\r\n", "").takeIf { it.startsWith("v=0") }?.let(sdps::add)
        return Decoded(sdps.take(32), candidates.take(128), servers.distinct().take(32), ids.mapValues { it.value.distinct().take(32) }, sip, false)
    }
}

class RtcCapture(private val config: ConfigStore, private val scope: ScopeGate, private val telemetry: TelemetryTableModel) : WebSocketCreatedHandler {
    var sessions: webrtc.authz.SessionCatalog? = null
    var canaries: webrtc.canary.CanaryRegistry? = null
    fun allowed(url: String) = runCatching {
        ScopeGate.hostAllowed(java.net.URI(url).host, config.config.hostAllowList) && scope.inScope(url)
    }.getOrDefault(false)
    fun record(type: String, url: String, detail: String, data: JsonObject) {
        val raw = buildJsonObject { put("type", type); put("frame", url); put("detail", detail); put("observedAt", Instant.now().toString()); data.forEach { (k, v) -> put(k, v) } }
        telemetry.add(TelemetryEvent(telemetry.nextSeq(), Instant.now().toString(), type, url, "", false, detail, raw.toString()))
    }
    fun http(url: String, content: String, contentType: String, headers: JsonArray) {
        if (!allowed(url)) return
        record("original-policy", url, "Original response policy before injection", buildJsonObject { put("headers", headers); put("contentType", contentType); put("instrumented", config.config.injectionEnabled) })
        if (contentType.contains("json", true) || contentType.contains("sdp", true) || contentType.contains("event-stream", true)) {
            if (contentType.contains("event-stream", true)) content.lineSequence().filter { it.startsWith("data:") }.take(128).forEach { decode(url, "http-sse", it.removePrefix("data:").trimStart(), "", "response") }
            else decode(url, "http", content, "", "response")
        }
    }
    private fun decode(url: String, connection: String, payload: String, protocol: String, direction: String) {
        val d = RtcDecoder.decode(payload, protocol)
        record("signaling-observation", url, "$direction $connection: ${d.sdps.size} SDP, ${d.candidates.size} candidates; SIP=${d.sip}", buildJsonObject {
            put("connectionId", connection); put("direction", direction); put("payload", payload.take(262144)); put("truncated", d.truncated)
            put("sdp", JsonArray(d.sdps.map(::JsonPrimitive))); put("candidates", JsonArray(d.candidates.map(::JsonPrimitive)))
            put("iceServers", JsonArray(d.iceServers)); put("sip", d.sip)
            put("identifiers", buildJsonObject { d.identifiers.forEach { (k, v) -> put(k, JsonArray(v.map(::JsonPrimitive))) } })
        })
    }
    override fun handleWebSocketCreated(created: WebSocketCreated) {
        val req = created.upgradeRequest(); val url = req.url()
        if (!allowed(url)) return
        val connection = UUID.randomUUID().toString()
        val sessionId = sessions?.observe(req, source = "WebSocket handshake")
        val protocol = req.headerValue("Sec-WebSocket-Protocol").orEmpty()
        record("ws-connection", url, "WebSocket connection $connection", buildJsonObject {
            put("connectionId", connection); put("upgrade", req.toString()); put("origin", req.headerValue("Origin").orEmpty()); put("subprotocol", protocol)
        })
        created.webSocket().registerMessageHandler(object : MessageHandler {
            override fun handleTextMessage(message: TextMessage): TextMessageAction {
                if (allowed(url)) {
                    sessions?.observeXmpp(sessionId, url, message.payload(), connection)
                    decode(url, connection, message.payload(), protocol, message.direction().toString())
                    if (message.direction().toString().startsWith("SERVER"))
                        canaries?.scan(message.payload(), url, "WebSocket message to the browser")
                }
                return TextMessageAction.continueWith(message)
            }
            override fun handleBinaryMessage(message: BinaryMessage): BinaryMessageAction {
                if (allowed(url)) record("ws-binary", url, "Binary WebSocket frame; decoder unavailable", buildJsonObject {
                    val bytes = message.payload().getBytes()
                    put("connectionId", connection); put("direction", message.direction().toString()); put("bytes", bytes.size)
                    put("base64", java.util.Base64.getEncoder().encodeToString(bytes.take(65536).toByteArray())); put("truncated", bytes.size > 65536)
                })
                return BinaryMessageAction.continueWith(message)
            }
            override fun onClose() { record("ws-closed", url, "WebSocket closed $connection", buildJsonObject { put("connectionId", connection) }) }
        })
    }
}
