package webrtc.telemetry

import kotlinx.serialization.json.*
import java.net.URI

/**
 * Reviews response headers captured *before* injection changed them (the
 * "original-policy" events). Injection strips CSP, so CSP, framing and
 * permission-policy verdicts must come from these originals, never from the
 * instrumented page. Results are review items, not exploit confirmations.
 */
object PolicyAudit {
    enum class Level { INFO, REVIEW }
    data class Issue(
        val rule: String, val origin: String, val url: String, val title: String, val detail: String,
        val level: Level, val events: List<TelemetryEvent>, val webrtcSpecific: Boolean = false
    ) { val key: String get() = "$origin|$rule" }

    private val json = Json { ignoreUnknownKeys = true }
    private val sessionCookie = Regex("(?i)sess|auth|token|jwt|sid|login|remember")
    private val tokenParam = Regex("(?i)^(token|jwt|access_token|auth|invite|invitetoken|invite_token|key|code|sig|signature|meeting_token|room_token|t)$")
    private val mediaFeatures = listOf("camera", "microphone", "display-capture")

    private data class Response(val event: TelemetryEvent, val url: String, val origin: String, val https: Boolean,
                                val html: Boolean, val headers: List<Pair<String, String>>) {
        fun all(name: String) = headers.filter { it.first.equals(name, true) }.map { it.second }
        fun first(name: String) = all(name).firstOrNull()
    }

    private fun parse(event: TelemetryEvent): Response? = runCatching {
        val obj = json.parseToJsonElement(event.raw).jsonObject
        val url = (obj["frame"] as? JsonPrimitive)?.contentOrNull ?: event.frame
        val uri = URI(url)
        val scheme = uri.scheme?.lowercase() ?: return null
        val origin = "$scheme://${uri.host?.lowercase() ?: return null}${if (uri.port >= 0) ":${uri.port}" else ""}"
        val headers = (obj["headers"] as? JsonArray).orEmpty().mapNotNull { element ->
            val h = element as? JsonObject ?: return@mapNotNull null
            val name = (h["name"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null
            name to ((h["value"] as? JsonPrimitive)?.contentOrNull ?: "")
        }
        val contentType = (obj["contentType"] as? JsonPrimitive)?.contentOrNull.orEmpty()
        Response(event, url, origin, scheme == "https", contentType.contains("html", true), headers)
    }.getOrNull()

    /** Directive value of the first enforced policy that declares it (default-src fallback for scripts). */
    private fun directive(policies: List<String>, name: String): String? {
        for (policy in policies.flatMap { it.split(',') }) {
            val directives = policy.split(';').map { it.trim() }.filter { it.isNotEmpty() }
            directives.firstOrNull { it.substringBefore(' ').equals(name, true) }?.let { return it.substringAfter(' ', "").trim() }
        }
        return null
    }

    fun audit(events: List<TelemetryEvent>): List<Issue> {
        val responses = events.filter { it.type == "original-policy" }.mapNotNull(::parse)
        val found = LinkedHashMap<String, Issue>()
        fun add(rule: String, r: Response, title: String, detail: String, level: Level = Level.REVIEW, webrtc: Boolean = false) {
            val key = "${r.origin}|$rule"
            val previous = found[key]
            found[key] = if (previous == null) Issue(rule, r.origin, r.url, title, detail, level, listOf(r.event), webrtc)
                else previous.copy(events = (previous.events + r.event).takeLast(5))
        }
        for (r in responses) {
            if (r.html) {
                val csp = r.all("Content-Security-Policy")
                val ancestors = directive(csp, "frame-ancestors")
                val xfo = r.first("X-Frame-Options")?.trim()?.uppercase()
                if ((ancestors == null || ancestors.split(' ').any { it == "*" }) && (xfo == null || xfo == "ALLOWALL"))
                    add("framing", r, "Page can be framed by any site",
                        "${r.url} sets neither an enforced CSP frame-ancestors directive nor X-Frame-Options. A call or advisor page that can be framed is a clickjacking target (for example tricking a user into granting camera, microphone or screen sharing). Confirm whether embedding by third parties is intended.")
                if (csp.isEmpty()) add("csp-missing", r, "No enforced Content-Security-Policy",
                    "${r.url} has no enforced Content-Security-Policy in the original response (the extension strips CSP only after recording it). Without CSP, a stored XSS in chat, display names or file names runs unrestricted.")
                else {
                    val scripts = directive(csp, "script-src") ?: directive(csp, "default-src")
                    if (scripts != null) {
                        val tokens = scripts.split(Regex("\\s+")).map { it.lowercase() }
                        val strict = tokens.any { it.startsWith("'nonce-") || it.startsWith("'sha256-") || it.startsWith("'sha384-") || it.startsWith("'sha512-") || it == "'strict-dynamic'" }
                        if ("'unsafe-inline'" in tokens && !strict) add("csp-inline", r, "CSP allows inline script",
                            "${r.url}: script-src/default-src contains 'unsafe-inline' without a nonce, hash or 'strict-dynamic' ($scripts). CSP will not stop injected inline script.")
                        if (tokens.any { it == "*" || it == "https:" || it == "http:" || it == "data:" }) add("csp-wildcard", r, "CSP allows scripts from any host",
                            "${r.url}: script-src/default-src allows a wildcard source ($scripts).")
                        if ("'unsafe-eval'" in tokens) add("csp-eval", r, "CSP allows eval", "${r.url}: script-src/default-src contains 'unsafe-eval' ($scripts).", Level.INFO)
                    }
                }
                val permissions = r.first("Permissions-Policy").orEmpty()
                val unrestricted = mediaFeatures.filter { feature ->
                    val value = Regex("(?i)(?:^|,)\\s*${Regex.escape(feature)}\\s*=\\s*([^,]*)").find(permissions)?.groupValues?.get(1)?.trim()
                    value == null || value == "*"
                }
                if (unrestricted.isNotEmpty()) add("permissions-policy", r, "Permissions-Policy does not restrict media capture",
                    "${r.url}: Permissions-Policy does not limit ${unrestricted.joinToString(", ")} to trusted origins${if (permissions.isBlank()) " (header absent)" else " ($permissions)"}. Embedded third-party frames can then ask for camera, microphone or screen capture under this site's name. Restrict them, for example camera=(self), microphone=(self), display-capture=(self).",
                    Level.INFO, webrtc = true)
                val query = runCatching { URI(r.url).rawQuery }.getOrNull().orEmpty()
                val tokenNames = query.split('&').map { it.substringBefore('=') }.filter { tokenParam.matches(it) && it.isNotBlank() }
                val referrer = r.first("Referrer-Policy")?.lowercase()?.split(',')?.lastOrNull()?.trim()
                if (tokenNames.isNotEmpty() && referrer in setOf("unsafe-url", "no-referrer-when-downgrade"))
                    add("referrer-token", r, "Meeting token in URL leaks through Referer",
                        "${r.url} carries ${tokenNames.joinToString(", ")} in the URL and sets Referrer-Policy: $referrer, so the full link (including the token) is sent to every third-party resource the page loads. Use strict-origin-when-cross-origin or no-referrer, and avoid bearer tokens in URLs.",
                        webrtc = true)
            }
            if (r.https && r.html) {
                val hsts = r.first("Strict-Transport-Security")
                if (hsts == null) add("hsts-missing", r, "No HSTS on HTTPS page",
                    "${r.url}: no Strict-Transport-Security header. A first visit over plain HTTP can be intercepted before the redirect.")
                else Regex("(?i)max-age\\s*=\\s*(\\d+)").find(hsts)?.groupValues?.get(1)?.toLongOrNull()?.let { age ->
                    if (age < 15_552_000) add("hsts-short", r, "Short HSTS lifetime", "${r.url}: HSTS max-age=$age (less than 180 days).", Level.INFO)
                }
            }
            for (cookie in r.all("Set-Cookie")) {
                val name = cookie.substringBefore('=').trim()
                if (!sessionCookie.containsMatchIn(name)) continue
                val attributes = cookie.split(';').drop(1).map { it.trim().lowercase() }
                val missing = buildList {
                    if (r.https && attributes.none { it == "secure" }) add("Secure")
                    if (attributes.none { it == "httponly" }) add("HttpOnly")
                    val sameSite = attributes.firstOrNull { it.startsWith("samesite") }?.substringAfter('=', "")?.trim()
                    if (sameSite == null) add("SameSite") else if (sameSite == "none") add("SameSite (set to None)")
                }
                if (missing.isNotEmpty()) add("cookie-$name", r, "Session cookie $name lacks ${missing.joinToString(", ")}",
                    "${r.url} sets session-like cookie $name without ${missing.joinToString(", ")}. Without HttpOnly, an XSS can read it; without SameSite, cross-site requests (including WebSocket handshakes) carry it.")
            }
            val acao = r.first("Access-Control-Allow-Origin")?.trim()
            if (acao == "null" && r.first("Access-Control-Allow-Credentials")?.trim().equals("true", true))
                add("cors-null", r, "CORS trusts the null origin with credentials",
                    "${r.url} returns Access-Control-Allow-Origin: null with credentials. Sandboxed frames and local files use the null origin, so any site can read this credentialed response.")
        }
        return found.values.toList()
    }
}
