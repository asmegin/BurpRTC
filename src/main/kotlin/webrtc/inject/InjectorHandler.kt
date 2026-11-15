package webrtc.inject

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.responses.HttpResponse
import webrtc.config.ConfigStore
import webrtc.config.WebRtcConfig
import webrtc.scope.ScopeGate
import webrtc.workflow.RequestCatalog
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * M1 — injects the browser agent before </head> on allow-listed, in-scope HTML
 * responses and strips CSP restrictions except frame-ancestors so the inline
 * agent runs without changing which parents may embed the page.
 */
class InjectorHandler(
    private val api: MontoyaApi,
    private val configStore: ConfigStore,
    private val scope: ScopeGate,
    private val requests: RequestCatalog? = null,
    private val capture: webrtc.workflow.RtcCapture? = null,
    private val sessions: webrtc.authz.SessionCatalog? = null,
    private val links: webrtc.authz.LinkCatalogs? = null,
    private val canaries: webrtc.canary.CanaryRegistry? = null
) : HttpHandler {

    private val metaCspRegex =
        Regex("(?is)<meta[^>]+http-equiv=[\"']?content-security-policy[\"']?[^>]*>")
    private val bundledAgentJs: String? by lazy {
        javaClass.getResourceAsStream("/agent/webrtc-agent.js")?.bufferedReader(StandardCharsets.UTF_8)?.use { it.readText() }
    }

    override fun handleHttpRequestToBeSent(req: HttpRequestToBeSent): RequestToBeSentAction {
        if (sessions != null && !req.toolSource().isFromTool(burp.api.montoya.core.ToolType.EXTENSIONS))
            runCatching { sessions?.observe(req) }
        return RequestToBeSentAction.continueWith(req)
    }

    override fun handleHttpResponseReceived(resp: HttpResponseReceived): ResponseReceivedAction {
        val cfg = configStore.config
        if ((sessions != null || requests != null || links != null) && !resp.toolSource().isFromTool(burp.api.montoya.core.ToolType.EXTENSIONS))
            runCatching {
                val req = resp.initiatingRequest()
                val sessionId = sessions?.observe(req, resp.headerValue("Content-Type").orEmpty(), resp.statusCode().toInt())
                links?.observe(req, resp.headerValue("Content-Type").orEmpty(), resp.statusCode().toInt(),
                    resp.headerValue("Content-Disposition").orEmpty(), sessionId)
                val host = java.net.URI(req.url()).host
                if (host != null && ScopeGate.hostAllowed(host, cfg.hostAllowList) && scope.inScope(req.url()))
                    requests?.observe(req, resp.headerValue("Content-Type").orEmpty(), resp.statusCode().toInt())
            }
        canaries?.let { registry -> runCatching {
            if (registry.all().isNotEmpty()) {
                val url = resp.initiatingRequest().url()
                val host = java.net.URI(url).host
                if (host != null && ScopeGate.hostAllowed(host, cfg.hostAllowList) && scope.inScope(url))
                    registry.scan(resp.bodyToString(), url, "HTTP response")
            }
        } }
        capture?.let { observer -> runCatching {
            // Decide before copying headers or decoding the body: this handler sees every response from every tool.
            if (!observer.allowed(resp.initiatingRequest().url())) return@runCatching
            val original = kotlinx.serialization.json.buildJsonArray {
                resp.headers().forEach { header -> add(kotlinx.serialization.json.buildJsonObject {
                    put("name", kotlinx.serialization.json.JsonPrimitive(header.name())); put("value", kotlinx.serialization.json.JsonPrimitive(header.value()))
                }) }
            }
            observer.http(resp.initiatingRequest().url(), resp.bodyToString().take(262145), resp.headerValue("Content-Type").orEmpty(), original)
        } }
        if (!cfg.injectionEnabled) return ResponseReceivedAction.continueWith(resp)
        // Only the browser's own traffic is instrumented. Repeater, Scanner, Intruder and
        // other extensions must see the application's real response and CSP.
        if (!resp.toolSource().isFromTool(burp.api.montoya.core.ToolType.PROXY)) return ResponseReceivedAction.continueWith(resp)

        val request = resp.initiatingRequest()
        val host = request.httpService().host()
        val url = request.url()

        if (!ScopeGate.hostAllowed(host, cfg.hostAllowList)) return ResponseReceivedAction.continueWith(resp)
        if (!scope.inScope(url)) return ResponseReceivedAction.continueWith(resp)

        val contentType = resp.headerValue("Content-Type") ?: ""
        if (!contentType.contains("text/html", ignoreCase = true)) {
            return ResponseReceivedAction.continueWith(resp)
        }

        var out: HttpResponse = resp
        if (cfg.stripCsp) {
            val policies = resp.headers().filter { it.name().equals("Content-Security-Policy", true) }
            val reportOnly = resp.headers().filter { it.name().equals("Content-Security-Policy-Report-Only", true) }
            out = out.withRemovedHeaders(policies + reportOnly)
            for (policy in policies) {
                // Enforced frame-ancestors overrides X-Frame-Options. Removing it
                // can activate SAMEORIGIN and break previously allowed embeds.
                val ancestors = retainedFrameAncestors(policy.value()) ?: continue
                out = out.withAddedHeader(policy.name(), ancestors)
            }
        }

        val agent = buildAgentScript(cfg, url) ?: return ResponseReceivedAction.continueWith(out)

        var bodyStr = out.bodyToString()
        if (cfg.stripCsp) bodyStr = metaCspRegex.replace(bodyStr, "")

        val idx = injectionPoint(bodyStr)
        val injected = if (idx >= 0) {
            bodyStr.substring(0, idx) + agent + bodyStr.substring(idx)
        } else {
            agent + bodyStr
        }
        out = out.withBody(injected)
        api.logging().logToOutput("[inject] agent injected into $url")
        return ResponseReceivedAction.continueWith(out)
    }

    private fun buildAgentScript(cfg: WebRtcConfig, frame: String): String? {
        val agentSrc = if (cfg.agentJsPath.isBlank()) {
            bundledAgentJs
                ?: run { api.logging().logToError("[inject] bundled agent missing; rebuild the jar"); return null }
        } else {
            val f = File(cfg.agentJsPath)
            if (!f.isFile) { api.logging().logToError("[inject] agent JS not found: ${cfg.agentJsPath}"); return null }
            f.readText(StandardCharsets.UTF_8)
        }
        val bridgeBase = "http://${cfg.bridgeHost}:${cfg.bridgePort}"
        val session = configStore.bridgeSessions.issue(frame)
        val cfgJs = """
            window.__WRTC_CFG__ = {
              collect: ${jsonStr(bridgeBase + cfg.collectPath + "?session=" + session)},
              command: ${jsonStr(bridgeBase + cfg.commandPath + "?session=" + session)}
            };
        """.trimIndent()
        return "\n<script>\n$cfgJs\n$agentSrc\n</script>\n"
    }

    private fun indexOfIgnoreCase(haystack: String, needle: String): Int =
        haystack.indexOf(needle, ignoreCase = true)

    /**
     * Before the first <script> inside <head>, so the agent hooks RTCPeerConnection,
     * createDataChannel and WebSocket before application code runs; otherwise before
     * </head>. Meta charset and other leading head elements stay ahead of the agent.
     */
    private fun injectionPoint(body: String): Int {
        val head = indexOfIgnoreCase(body, "</head>")
        if (head < 0) return -1
        val script = Regex("<script[\\s>]", RegexOption.IGNORE_CASE).find(body)?.range?.first ?: -1
        return if (script in 0 until head) script else head
    }

    private fun jsonStr(s: String): String =
        kotlinx.serialization.json.JsonPrimitive(s).toString().replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
}

/** Preserve the first frame-ancestors directive in each comma-separated policy. */
internal fun retainedFrameAncestors(value: String): String? = value.split(',').mapNotNull { policy ->
    policy.split(';').map { it.trim() }.firstOrNull { directive ->
        directive.substringBefore(' ').substringBefore('\t').equals("frame-ancestors", true)
    }
}.takeIf { it.isNotEmpty() }?.joinToString(", ")
