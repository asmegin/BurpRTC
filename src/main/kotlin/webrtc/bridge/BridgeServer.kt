package webrtc.bridge

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.*
import webrtc.config.ConfigStore
import webrtc.config.Detectors
import webrtc.config.SdpMutationConfig
import webrtc.scope.ScopeGate
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.time.LocalTime
import java.time.format.DateTimeFormatter

/**
 * M2 bridge. An embedded loopback HTTP server the injected agent beacons to.
 * (Montoya has no API to synthesize a response from a proxy handler, so a
 * loopback listener is used instead of the spec's sentinel-through-proxy; the
 * outcome — no firewall changes, app-agnostic, bidirectional — is the same.)
 */
class BridgeServer(
    private val api: MontoyaApi,
    private val configStore: ConfigStore,
    private val telemetry: TelemetryTableModel,
    private val activeTests: ActiveTestController = ActiveTestController(configStore, ScopeGate(api)::inScope, telemetry)
) {
    private var server: BridgeHttpServer? = null
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val timeFmt: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS")

    @Synchronized
    fun start() {
        val cfg = configStore.config
        stop()
        try {
            // The Setup screen enforces this too; a configuration loaded from a project file has not been through it.
            require(cfg.bridgeHost.lowercase() in LOOPBACK) { "bridge host must be loopback, not ${cfg.bridgeHost}" }
            val srv = BridgeHttpServer(
                InetSocketAddress(cfg.bridgeHost.removeSurrounding("[", "]"), cfg.bridgePort),
                onError = { api.logging().logToError("[bridge] handler error: ${it.stackTraceToString()}") }
            ) { request ->
                val token = parameter(request, "session").orEmpty()
                val origin = request.headers["origin"].orEmpty()
                val allowedHosts = setOf("${cfg.bridgeHost}:${cfg.bridgePort}", "localhost:${cfg.bridgePort}")
                if (request.path !in setOf(cfg.collectPath, cfg.commandPath)) return@BridgeHttpServer BridgeHttpServer.Response(404)
                if (request.headers["host"] !in allowedHosts || !configStore.bridgeSessions.acceptsOrigin(token, origin))
                    return@BridgeHttpServer BridgeHttpServer.Response(403)
                when (request.path) {
                    cfg.collectPath -> {
                        if (request.method.equals("OPTIONS", true)) BridgeHttpServer.Response(204)
                        else if (request.method == "POST" && parseAndStore(request.body, token, origin)) BridgeHttpServer.Response(204)
                        else BridgeHttpServer.Response(403)
                    }
                    cfg.commandPath -> {
                        if (request.method.equals("OPTIONS", true)) BridgeHttpServer.Response(204)
                        else handleCommand(request)
                    }
                    else -> BridgeHttpServer.Response(404)
                }
            }
            server = srv
            api.logging().logToOutput("[bridge] listening on http://${cfg.bridgeHost}:${cfg.bridgePort}")
        } catch (t: Throwable) {
            api.logging().logToError("[bridge] failed to start on ${cfg.bridgeHost}:${cfg.bridgePort}: ${t.stackTraceToString()}")
        }
    }

    @Synchronized
    fun stop() {
        activeTests.cancelAll()
        configStore.bridgeSessions.clear()
        server?.close()
        server = null
    }

    @Synchronized
    fun restart() = start()

    private fun handleCommand(request: BridgeHttpServer.Request): BridgeHttpServer.Response {
        val cfg = configStore.config
        fun parameter(name: String) = parameter(request, name)
        val frame = parameter("frame").orEmpty()
        val agent = parameter("agent").orEmpty()
        if (!configStore.bridgeSessions.permits(parameter("session").orEmpty(), request.headers["origin"].orEmpty(), frame, agent))
            return BridgeHttpServer.Response(403)
        val allowed = request.method == "GET" && activeTests.pageAllowed(frame)
        val doc = buildJsonObject {
            put("ok", true)
            put("bridge", buildJsonObject {
                put("collect", cfg.collectPath)
                put("command", cfg.commandPath)
            })
            put("commands", buildJsonArray {
                if (allowed && cfg.sdpMutation.enabled) add(buildJsonObject {
                    put("type", "sdp-mutation")
                    put("config", json.encodeToJsonElement(SdpMutationConfig.serializer(), cfg.sdpMutation))
                })
                if (request.method == "GET" && parameter("poll") == "1") {
                    activeTests.commands(agent, frame).forEach { add(it) }
                }
                if (allowed) parameter("autoFuzz")?.let { channel ->
                    activeTests.queueNextOpenFuzz(agent, frame, channel)?.let { id ->
                        activeTests.commands(agent, frame).filter { it["id"]?.jsonPrimitive?.content == id }.forEach { add(it) }
                    }
                }
            })
            put("observe", allowed && activeTests.observing)
            put("authorized", request.method == "GET" && parameter("authorize")?.let {
                activeTests.authorize(agent, frame, it)
            } == true)
        }
        return BridgeHttpServer.Response(200, doc.toString(), "application/json")
    }

    private fun parameter(request: BridgeHttpServer.Request, name: String) = runCatching {
        request.query.orEmpty().split('&').singleOrNull { it.substringBefore('=') == name }
            ?.substringAfter('=', "")?.let { URLDecoder.decode(it, Charsets.UTF_8) }
    }.getOrNull()

    private fun parseAndStore(body: String, token: String, origin: String): Boolean {
        if (body.isBlank() || !boundedJson(body)) return false
        val element = runCatching { json.parseToJsonElement(body) }.getOrNull() ?: return false
        val events = when (element) {
            is JsonArray -> element.mapNotNull { it as? JsonObject }
            is JsonObject -> listOf(element)
            else -> emptyList()
        }
        if (events.size > 128 || events.any { !configStore.bridgeSessions.permits(token, origin, it.strOr("frame", ""), it.strOr("agent", "")) ||
                !activeTests.pageAllowed(it.strOr("frame", "")) }) return false
        for (obj in events) {
            activeTests.observe(obj)
            if ((obj["type"] as? JsonPrimitive)?.contentOrNull != "agent-state") store(obj)
        }
        return true
    }

    private fun store(obj: JsonObject) {
        val type = obj.strOr("type", "unknown")
        val frame = obj.strOr("frame", "top")
        val pcId = obj.strOr("pc", "")
        val raw = obj.toString()
        val private = (obj["private"] as? JsonPrimitive)?.booleanOrNull ?: Detectors.hasPrivateAddress(raw)
        val summary = summarize(type, obj)
        telemetry.add(
            TelemetryEvent(
                seq = telemetry.nextSeq(),
                time = LocalTime.now().format(timeFmt),
                type = type,
                frame = frame,
                pcId = pcId,
                private = private,
                summary = summary,
                raw = raw
            )
        )
    }

    private fun summarize(type: String, obj: JsonObject): String = when (type) {
        "ice" -> obj.strOr("candidate", "")
        "crypto", "selected-pair" -> obj.strOr("detail", obj.strOr("cipher", ""))
        "sdp-local", "sdp-remote" -> "sdp ${obj.strOr("sdp", "").length} bytes"
        "dc-send", "dc-recv", "ws-colibri-send", "ws-colibri-recv" ->
            listOf(obj.strOr("label", ""), obj.strOr("colibriClass", ""), "${obj.strOr("bytes", "")}B").filter { it.isNotEmpty() }.joinToString(" ")
        "dc-created" -> "${obj.strOr("label", "")} ${obj.strOr("detail", "")} (${obj.strOr("state", "unknown")})"
        "assessment-result", "signaling-observation", "ws-connection", "ws-binary", "ws-closed", "original-policy",
        "pc-config", "pc-operation", "ice-input", "getUserMedia-result", "browser-capabilities", "capture-result", "track-state",
        "dc-state", "pc-state", "tls-runtime", "tls-scan-start", "tls-scan-result", "tls-scan-error",
        "getDisplayMedia", "enumerateDevices-result", "browser-checks-error", "message-listener", "message-received", "message-sent",
        "xss-canary-fired", "xss-canary-reflected", "collaborator-interaction", "burp-issue",
        "dc-case", "dc-markers", "dc-health", "dc-load-step", "dc-churn-result", "dc-churn-summary", "ws-admission-result",
        "transport-action-result", "page-error", "ws-colibri", "dc-case-result", "dc-runner", "runner-action", "bridge-log",
        "dc-suite-error", "dc-load-error", "dc-churn-error", "dc-health-error", "ws-admission-error", "transport-action-error" -> obj.strOr("detail", "")
        "getUserMedia" -> obj.strOr("constraints", "")
        "stats-snapshot" -> {
            val rtp = (obj["rtp"] as? kotlinx.serialization.json.JsonArray)?.size ?: 0
            val candidates = (obj["candidates"] as? kotlinx.serialization.json.JsonArray)?.size ?: 0
            "stats snapshot: $rtp RTP stream(s), $candidates candidate(s)"
        }
        "dtls-cert" -> "DTLS ${obj.strOr("role", "?")} certificate ${obj.strOr("algorithm", "")} ${obj.strOr("fingerprint", "")}".trim()
        "flood-result" -> obj.strOr("detail", "renegotiation ${obj.strOr("index", "")}")
        else -> obj.strOr("detail", obj.strOr("summary", ""))
    }

    private fun JsonObject.strOr(key: String, default: String): String =
        (this[key] as? JsonPrimitive)?.contentOrNull ?: default

    companion object {
        val LOOPBACK = setOf("127.0.0.1", "localhost", "::1", "[::1]")
    }

}

/** Reject pathological nesting before a recursive JSON parser sees untrusted input. */
internal fun boundedJson(text: String, maxDepth: Int = 32): Boolean {
    var depth = 0; var quoted = false; var escaped = false
    for (c in text) {
        if (quoted) { if (escaped) escaped = false else if (c == '\\') escaped = true else if (c == '"') quoted = false }
        else when (c) { '"' -> quoted = true; '{', '[' -> if (++depth > maxDepth) return false; '}', ']' -> if (--depth < 0) return false }
    }
    return depth == 0 && !quoted
}
