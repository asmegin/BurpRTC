package webrtc.telemetry

import kotlinx.serialization.json.*
import kotlin.test.*

class ClientSecurityTest {
    private var seq = 0L
    private fun event(type: String, frame: String, data: JsonObjectBuilder.() -> Unit) =
        buildJsonObject { put("type", type); put("frame", frame); data() }.let { TelemetryEvent(++seq, "t", type, frame, "", false, "", it.toString()) }
    private fun policy(url: String, contentType: String = "text/html", vararg headers: Pair<String, String>) = event("original-policy", url) {
        put("contentType", contentType)
        put("headers", buildJsonArray { headers.forEach { (n, v) -> add(buildJsonObject { put("name", n); put("value", v) }) } })
    }

    @Test fun `original headers drive framing CSP permissions HSTS and cookie review`() {
        val issues = PolicyAudit.audit(listOf(policy("https://bank.test/advisor", "text/html", "Set-Cookie" to "advisor_session=abc; Path=/")))
        val rules = issues.map { it.rule }.toSet()
        assertTrue(setOf("framing", "csp-missing", "permissions-policy", "hsts-missing", "cookie-advisor_session").all { it in rules }, rules.toString())
        assertTrue(issues.single { it.rule == "permissions-policy" }.webrtcSpecific)
        assertFalse(issues.single { it.rule == "framing" }.webrtcSpecific)
    }

    @Test fun `a hardened page produces no review items`() {
        val issues = PolicyAudit.audit(listOf(policy("https://bank.test/call",
            "text/html",
            "Content-Security-Policy" to "default-src 'self'; script-src 'nonce-abc' 'unsafe-inline'; frame-ancestors 'self'",
            "Permissions-Policy" to "camera=(self), microphone=(self), display-capture=(self)",
            "Strict-Transport-Security" to "max-age=31536000",
            "Set-Cookie" to "session=x; Secure; HttpOnly; SameSite=Lax")))
        assertEquals(emptyList(), issues.map { it.rule })
    }

    @Test fun `inline script without nonce and leaking meeting token are flagged`() {
        val issues = PolicyAudit.audit(listOf(policy("https://bank.test/join?token=abc123secret", "text/html",
            "Content-Security-Policy" to "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
            "Referrer-Policy" to "unsafe-url", "Strict-Transport-Security" to "max-age=31536000",
            "Permissions-Policy" to "camera=(self), microphone=(self), display-capture=(self)")))
        assertEquals(setOf("csp-inline", "referrer-token"), issues.map { it.rule }.toSet())
        assertTrue(issues.single { it.rule == "referrer-token" }.webrtcSpecific)
    }

    @Test fun `repeated responses from one origin collapse into one issue`() {
        val issues = PolicyAudit.audit((1..4).map { policy("https://bank.test/page$it") })
        assertEquals(1, issues.count { it.rule == "framing" })
        assertEquals(4, issues.single { it.rule == "framing" }.events.size)
    }

    @Test fun `executed canary is a finding while capture and messaging items are review leads`() {
        val items = BrowserReview.review(listOf(
            event("xss-canary-fired", "https://bank.test/advisor") { put("canaryId", "wrtcxabcdefghij"); put("origin", "https://bank.test"); put("context", "chat"); put("readableCookies", "sid=1") },
            event("track-state", "https://bank.test/call") { put("action", "live-after-close"); put("source", "camera/microphone"); put("kind", "video") },
            event("message-listener", "https://bank.test/widget") { put("checksOrigin", false); put("source", "function(e){x(e.data)}") },
            event("message-sent", "https://bank.test/widget") { put("data", "{\"token\":\"abc\"}") },
            event("xss-canary-reflected", "https://bank.test/api") { put("canaryId", "wrtcxabcdefghij"); put("url", "https://bank.test/api"); put("markup", "intact"); put("encoded", "false") }))
        assertEquals(BrowserReview.Level.FINDING, items.single { it.title == "Stored XSS executed" }.level)
        assertTrue(items.single { it.title == "Stored XSS executed" }.text.contains("sid=1"))
        assertEquals(BrowserReview.Level.REVIEW, items.single { it.title == "Capture stays live after hang-up" }.level)
        assertEquals(BrowserReview.Level.REVIEW, items.single { it.title == "Message listener without origin check" }.level)
        assertTrue(items.single { it.title == "postMessage to any origin" }.text.contains("token"))
        assertEquals(BrowserReview.Level.REVIEW, items.single { it.title == "Canary returned unencoded" }.level)
    }
}
