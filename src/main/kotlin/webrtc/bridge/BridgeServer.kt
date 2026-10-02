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
            val srv = BridgeHttpServer(
                InetSocketAddress(cfg.bridgeHost, cfg.bridgePort),
                onError = { api.logging().logToError("[bridge] handler error: ${it.message}") }
            ) { request ->
                when (request.path) {
                    cfg.collectPath -> {
                        if (!request.method.equals("OPTIONS", true)) parseAndStore(request.body)
                        BridgeHttpServer.Response(204)
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
            api.logging().logToError("[bridge] failed to start on ${cfg.bridgeHost}:${cfg.bridgePort}: ${t.message}")
        }
    }

    @Synchronized
    fun stop() {
        activeTests.cancelAll()
        server?.close()
        server = null
    }

    @Synchronized
    fun restart() = start()

    private fun handleCommand(request: BridgeHttpServer.Request): BridgeHttpServer.Response {
        val cfg = configStore.config
        fun parameter(name: String) = runCatching {
            request.query.orEmpty().split('&').singleOrNull { it.substringBefore('=') == name }
                ?.substringAfter('=', "")?.let { URLDecoder.decode(it, Charsets.UTF_8) }
        }.getOrNull()
        val frame = parameter("frame").orEmpty()
        val agent = parameter("agent").orEmpty()
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
            put("authorized", request.method == "GET" && parameter("authorize")?.let {
                activeTests.authorize(agent, frame, it)
            } == true)
        }
        return BridgeHttpServer.Response(200, doc.toString(), "application/json")
    }

    private fun parseAndStore(body: String) {
        if (body.isBlank()) return
        val element = runCatching { json.parseToJsonElement(body) }.getOrNull() ?: return
        val events = when (element) {
            is JsonArray -> element.mapNotNull { it as? JsonObject }
            is JsonObject -> listOf(element)
            else -> emptyList()
        }
        for (obj in events) {
            activeTests.observe(obj)
            if ((obj["type"] as? JsonPrimitive)?.contentOrNull != "agent-state") store(obj)
        }
    }

    private fun store(obj: JsonObject) {
        val type = obj.strOr("type", "unknown")
        val frame = obj.strOr("frame", "top")
        val pcId = obj.strOr("pc", "")
        val raw = obj.toString()
        val private = obj["private"]?.jsonPrimitive?.booleanOrNull ?: Detectors.hasPrivateAddress(raw)
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
        "dc-send", "dc-recv" -> "${obj.strOr("label", "")} ${obj.strOr("bytes", "")}B"
        "dc-created" -> "${obj.strOr("label", "")} ${obj.strOr("detail", "")} (${obj.strOr("state", "unknown")})"
        "dc-state", "pc-state", "tls-runtime", "tls-scan-start", "tls-scan-result", "tls-scan-error" -> obj.strOr("detail", "")
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
        this[key]?.jsonPrimitive?.contentOrNull ?: default

}
