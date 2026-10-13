package webrtc.telemetry

import kotlinx.serialization.json.*

/**
 * Interprets browser-side evidence: stored-XSS canaries, Collaborator callbacks,
 * capture lifecycle (camera, microphone, screen), cross-window messaging and
 * device exposure. Only an executed canary or a received callback is a finding;
 * the rest are review leads with the evidence attached.
 */
object BrowserReview {
    enum class Level { FINDING, REVIEW, INFO }
    enum class Topic { XSS, CALLBACK, CAPTURE, MESSAGING, PERMISSIONS }
    data class Item(val title: String, val text: String, val level: Level, val topic: Topic, val events: List<TelemetryEvent>)

    private val json = Json { ignoreUnknownKeys = true }
    private fun obj(event: TelemetryEvent) = runCatching { json.parseToJsonElement(event.raw).jsonObject }.getOrNull()
    private fun JsonObject?.str(key: String) = (this?.get(key) as? JsonPrimitive)?.contentOrNull
    private val sensitive = Regex("(?i)token|jwt|session|password|secret|auth|iban|account|pesel|ssn")

    fun review(events: List<TelemetryEvent>): List<Item> {
        val items = mutableListOf<Item>()
        events.filter { it.type == "xss-canary-fired" }.groupBy { obj(it).str("canaryId") to obj(it).str("origin") }.forEach { (key, group) ->
            val o = obj(group.first())
            val cookies = o.str("readableCookies").orEmpty()
            items += Item("Stored XSS executed", "XSS canary ${key.first} (${o.str("context").orEmpty().ifBlank { "context not recorded" }}) executed JavaScript in ${key.second} at ${o.str("href")}. " +
                (if (cookies.isNotBlank()) "Script could read cookies: $cookies. " else "No script-readable cookies. ") +
                "Execution was reported by the instrumented page itself, so this is a confirmed script execution in that origin.", Level.FINDING, Topic.XSS, group)
        }
        events.filter { it.type == "xss-canary-reflected" }.groupBy { obj(it).str("canaryId") to obj(it).str("url") }.forEach { (key, group) ->
            val o = obj(group.first())
            val markup = o.str("markup") ?: if (o.str("encoded") == "false") "intact" else "encoded"
            val raw = markup == "intact"
            items += Item(if (raw) "Canary returned unencoded" else "Canary stored and returned",
                "Canary ${key.first} (${o.str("context").orEmpty()}) came back in ${o.str("channel") ?: "a response"} from ${key.second} " + when (markup) {
                    "intact" -> "with its HTML markup intact. JSON escaping is not HTML encoding: if a page renders this value as HTML, the payload executes. Watch for an executed-canary result."
                    "encoded" -> "HTML-encoded, which is the expected safe handling for that response."
                    else -> "as plain text (this variant carries no markup). This shows where the value is stored and returned."
                }, if (raw) Level.REVIEW else Level.INFO, Topic.XSS, group)
        }
        events.filter { it.type == "collaborator-interaction" }.groupBy { obj(it).str("canaryId") }.forEach { (id, group) ->
            val o = obj(group.first())
            val types = group.mapNotNull { obj(it).str("interactionType") }.distinct()
            val http = "HTTP" in types
            items += Item(if (o.str("purpose") == "callback") "Server fetched a callback URL" else "Out-of-band canary callback",
                "Burp Collaborator received ${types.joinToString("/")} interaction(s) for ${o.str("purpose") ?: "canary"} $id (${o.str("context").orEmpty()}) from ${group.mapNotNull { obj(it).str("clientIp") }.distinct().joinToString(", ")}. " +
                    if (o.str("purpose") == "callback") "The target, or a component it controls, contacted a URL you supplied (SSRF / unvalidated callback lead)."
                    else if (http) "The injected markup loaded a remote resource, so HTML was rendered unencoded where it was viewed."
                    else "A DNS lookup alone can come from link previews or scanners; confirm with an HTTP interaction or an executed canary.",
                if (http) Level.FINDING else Level.REVIEW, Topic.CALLBACK, group)
        }
        events.filter { it.type == "track-state" && obj(it).str("action") == "live-after-close" }.forEach { event ->
            val o = obj(event)
            items += Item("Capture stays live after hang-up",
                "${event.frame}: ${o.str("source")} ${o.str("kind")} capture was still live 3 s after the last peer connection closed. The device indicator stays on and the page can keep reading it. Confirm whether the application intends to keep the device open between calls.",
                Level.REVIEW, Topic.CAPTURE, listOf(event))
        }
        events.filter { it.type == "capture-result" && obj(it).str("outcome") == "resolved" }.forEach { event ->
            val surfaces = (obj(event)?.get("displaySurfaces") as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            items += Item("Screen share granted", "${event.frame}: screen sharing was granted${if (surfaces.isNotEmpty()) " (surface ${surfaces.joinToString(", ")})" else ""}. " +
                if ("monitor" in surfaces) "A whole monitor was shared; advisors may expose other customers' data. Consider limiting sharing to a tab or window (displaySurface / preferCurrentTab)." else "Observation only.",
                if ("monitor" in surfaces) Level.REVIEW else Level.INFO, Topic.CAPTURE, listOf(event))
        }
        events.filter { it.type == "message-listener" && obj(it).str("checksOrigin") == "false" }
            .distinctBy { it.frame + obj(it).str("source").orEmpty().take(200) }.forEach { event ->
                items += Item("Message listener without origin check",
                    "${event.frame}: a window message listener does not reference event.origin. If it acts on the message (for example navigation, HTML or call controls), any page that can frame or open this one can drive it. Inspect the listener source in the evidence.",
                    Level.REVIEW, Topic.MESSAGING, listOf(event))
            }
        events.filter { it.type == "message-sent" }.groupBy { it.frame }.forEach { (frame, group) ->
            val leaks = group.any { sensitive.containsMatchIn(obj(it).str("data").orEmpty()) }
            items += Item("postMessage to any origin", "$frame: ${group.size} message(s) were posted with target origin \"*\"" +
                (if (leaks) ", including token- or account-like data. Any page embedding this frame receives it." else ". Any embedding page can read them."),
                Level.REVIEW, Topic.MESSAGING, group)
        }
        events.filter { it.type == "message-received" && obj(it).str("sameOrigin") == "false" }.groupBy { obj(it).str("origin") }.forEach { (origin, group) ->
            items += Item("Cross-origin messages received", "${group.first().frame}: received ${group.size} message(s) from ${origin?.ifBlank { "an opaque origin" }}. Correlate with listener origin checks.",
                Level.INFO, Topic.MESSAGING, group)
        }
        events.filter { it.type == "enumerateDevices-result" && obj(it).str("labelsExposed") == "true" }.distinctBy { it.frame }.forEach { event ->
            items += Item("Device labels visible to the page", "${event.frame}: enumerateDevices returned device names. Browsers expose labels only after a capture permission; this is expected after joining a call.",
                Level.INFO, Topic.PERMISSIONS, listOf(event))
        }
        events.filter { it.type == "browser-capabilities" }.distinctBy { it.frame }.forEach { event ->
            items += Item("Browser permission snapshot", "${event.frame}: ${obj(event).str("detail")}", Level.INFO, Topic.PERMISSIONS, listOf(event))
        }
        return items
    }
}
