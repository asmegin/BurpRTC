package webrtc.canary

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import kotlinx.serialization.json.*
import webrtc.burp.IssueReporter
import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.lang.reflect.Proxy
import kotlin.test.*

class CanaryRegistryTest {
    private var stored: String? = null
    private val telemetry = TelemetryTableModel()
    private class FakeCollaborator : OutOfBand {
        val hits = mutableListOf<OutOfBandHit>()
        override fun payload(customData: String) = "$customData.oast.test"
        override fun poll(): List<OutOfBandHit> = hits.toList().also { hits.clear() }
        override fun secret() = "secret"
    }

    @Test fun `canaries persist, carry their marker in every payload and survive reload`() {
        val registry = CanaryRegistry({ stored }, { stored = it }, telemetry)
        val canary = registry.create("chat <message>")
        assertTrue(CanaryRegistry.MARKER.matches(canary.id))
        assertEquals("chat message", canary.context)
        assertTrue(registry.payloads(canary).all { it.value.contains(canary.id) })
        assertTrue(registry.payloads(canary).none { it.value.contains("oast") })
        assertNotNull(CanaryRegistry({ stored }, { stored = it }, telemetry).byId(canary.id))
        assertFailsWith<IllegalArgumentException> { registry.create("webhook", "callback") }
    }

    @Test fun `reflections are classified by surviving markup and reported once`() {
        val registry = CanaryRegistry({ stored }, { stored = it }, telemetry)
        val canary = registry.create("display name")
        val html = registry.payloads(canary).first().value
        registry.scan("{\"name\":\"${html.replace("\"", "\\\"").replace("<", "\\u003c")}\"}", "https://bank.test/api/participants", "HTTP response")
        registry.scan("{\"name\":\"${html.replace("\"", "\\\"").replace("<", "\\u003c")}\"}", "https://bank.test/api/participants?x=1", "HTTP response")
        registry.scan("<td>${html.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")}</td>", "https://bank.test/history", "HTTP response")
        val reflected = telemetry.snapshot().filter { it.type == "xss-canary-reflected" }
        assertEquals(2, reflected.size)
        assertTrue(reflected.first().raw.contains("\"markup\":\"intact\""))
        assertTrue(reflected.last().raw.contains("\"markup\":\"encoded\""))
        assertEquals("Returned unencoded", registry.status(canary))
        registry.scan("unknown wrtcxzzzzzzzzzz marker", "https://bank.test/x", "HTTP response")
        assertEquals(2, telemetry.snapshot().count { it.type == "xss-canary-reflected" })
    }

    @Test fun `collaborator payloads and interactions map back to their canary`() {
        val collaborator = FakeCollaborator()
        val registry = CanaryRegistry({ stored }, { stored = it }, telemetry) { collaborator }
        val canary = registry.create("recording export URL", "callback")
        assertEquals("${canary.id}.oast.test", canary.collaborator)
        assertTrue(registry.payloads(canary).first().value.startsWith("https://${canary.collaborator}/"))
        collaborator.hits += OutOfBandHit("i1", canary.id, "HTTP", "198.51.100.4", "now", "GET / HTTP/1.1")
        collaborator.hits += OutOfBandHit("i1", canary.id, "HTTP", "198.51.100.4", "now", "GET / HTTP/1.1")
        assertEquals(1, registry.pollOutOfBand())
        assertEquals("Callback (HTTP)", registry.status(canary))
        val xss = registry.create("chat")
        assertTrue(registry.payloads(xss).first().value.contains("${xss.id}.oast.test"))
    }

    @Test fun `executed canary becomes one Burp issue and the toggle disables issues`() {
        val persisted = mutableMapOf<String, String>()
        fun proxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            when {
                method.name == "getString" -> persisted[args!![0] as String]
                method.name == "setString" -> { persisted[args!![0] as String] = args[1] as String; null }
                method.returnType.isInterface -> proxy(method.returnType)
                else -> null
            }
        }
        val config = ConfigStore(proxy(MontoyaApi::class.java) as MontoyaApi)
        val issues = mutableListOf<IssueReporter.Spec>()
        IssueReporter({ issues += it }, config, telemetry).attach()
        val raw = buildJsonObject { put("type", "xss-canary-fired"); put("canaryId", "wrtcxabcdefghij"); put("origin", "https://bank.test")
            put("href", "https://bank.test/advisor"); put("context", "chat") }.toString()
        repeat(2) { telemetry.add(TelemetryEvent(telemetry.nextSeq(), "t", "xss-canary-fired", "https://bank.test/advisor", "", false, "", raw)) }
        assertEquals(1, issues.size)
        assertEquals(AuditIssueSeverity.HIGH, issues.single().severity)
        assertTrue(telemetry.snapshot().any { it.type == "burp-issue" })
        config.save(config.config.copy(burpIssues = false))
        val live = buildJsonObject { put("type", "track-state"); put("action", "live-after-close"); put("source", "screen") }.toString()
        telemetry.add(TelemetryEvent(telemetry.nextSeq(), "t", "track-state", "https://bank.test/call", "", false, "", live))
        assertEquals(1, issues.size)
    }
}
