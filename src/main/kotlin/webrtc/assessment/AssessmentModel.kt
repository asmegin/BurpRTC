package webrtc.assessment

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.UUID

@Serializable
data class TestDefinition(val id: String, val title: String, val priority: String, val modes: String, val contract: String)

object TestRegistry {
    val definitions: List<TestDefinition> = Json.decodeFromString(
        javaClass.getResourceAsStream("/assessment/catalog.json")!!.bufferedReader().use { it.readText() })
    val byId = definitions.associateBy { it.id }
    val protocolTests = setOf("TRN-01", "TRN-02", "TRN-04", "TRN-05", "TRN-07")
    val passiveTests = setOf("COR-01", "COR-02", "COR-03", "COR-04", "COR-05", "SIG-01", "WEB-01", "WEB-02", "WEB-03")
    // Checks needing only captured observations / discovered ICE listeners. Forwarding
    // checks use a second allocation as the peer when no echo destination is supplied.
    val automaticProtocolTests = setOf("TRN-01", "TRN-02", "TRN-04", "TRN-05", "TRN-07")
    val automaticTests: Set<String> = definitions.map { it.id }.filter { it in passiveTests || it in automaticProtocolTests }.toSet()
    val scenarioTests = definitions.filter { it.id.startsWith("SIG-") || it.id.startsWith("APP-") || it.id.startsWith("SFU-") ||
        it.id in setOf("TRN-03", "DCH-02", "WEB-03", "RES-01", "RES-03", "ICE-01", "ICE-05", "SDP-02", "SDP-03", "DTL-03", "MED-02", "SIP-02", "SIP-04") }.map { it.id }.toSet() - setOf("SIG-01", "APP-04", "WEB-03")
    /** Executed by the DataChannel runner (Tests → Data channel runner), which records their outcomes. */
    val dataChannelTests = setOf("DCH-01", "DCH-02", "DCH-03")
    fun capability(id: String, config: AssessmentConfig): String = when {
        id in dataChannelTests && config.scenarios.none { it.testId == id } -> "DataChannel runner"
        id in passiveTests -> "Passive analysis"
        id in protocolTests -> "Built-in TURN runner"
        id in scenarioTests && config.scenarios.any { it.testId == id } -> "Configured scenario"
        id in scenarioTests -> "Needs scenario / identities / receiver assertions"
        else -> "Manual / external — see contract"
    }

    /** Available execution adapters; prerequisites are reported by the controller. */
    fun executable(config: AssessmentConfig = AssessmentConfig()): Set<String> =
        passiveTests + protocolTests + config.scenarios.map { it.testId }.filter { it in scenarioTests }

    fun description(id: String): String = when (id) {
        "COR-01" -> "Review captured ICE addresses and relay-only privacy policy"
        "COR-02" -> "Review ICE credential rotation during deliberate restarts"
        "COR-03" -> "Review captured DTLS certificate and SDP fingerprint binding"
        "COR-04" -> "Review SDP media sections and BUNDLE semantics"
        "COR-05" -> "Review observed media crypto and SDP key exchange"
        "SIG-01" -> "Review captured HTTP / WebSocket signaling"
        "WEB-01" -> "Audit original CSP, framing, Permissions-Policy, HSTS and cookie headers captured before injection"
        "WEB-02" -> "Review camera, microphone and screen-share capture lifecycle and permission states"
        "WEB-03" -> "Review cross-window message listeners and wildcard postMessage use"
        "TRN-01" -> "Probe STUN / TURN listener and server information"
        "TRN-02" -> "Compare valid, absent and incorrect TURN credentials"
        "TRN-04" -> "Verify TURN forwarding (second allocation, or your UDP echo peer)"
        "TRN-05" -> "Compare TURN Send/Data and ChannelBind/ChannelData paths"
        "TRN-07" -> "Allocate, refresh and release a TURN allocation"
        else -> byId.getValue(id).title
    }
}

@Serializable
data class AssessmentConfig(
    val engagementId: String = UUID.randomUUID().toString(),
    val selectedTests: Set<String> = emptySet(),
    val scenarios: List<Scenario> = emptyList(),
    val profile: String = "standard"
) {
    fun validate() {
        require(profile in setOf("standard", "stress", "lab"))
        require(selectedTests.all { it in TestRegistry.byId }) { "Unknown selected test ID" }
        require(scenarios.size <= 100 && scenarios.map { it.id }.distinct().size == scenarios.size)
        scenarios.forEach(Scenario::validate)
    }
}

@Serializable
data class Assertion(val pointer: String, val equals: JsonElement, val meaning: String = "protected-effect")
@Serializable
data class ScenarioStep(
    val id: String,
    val url: String,
    val method: String = "GET",
    val identity: String = "",
    val headers: Map<String, String> = emptyMap(),
    val body: String = "",
    val expectStatus: Set<Int> = emptySet(),
    val assertion: Assertion? = null,
    val extract: Map<String, String> = emptyMap(),
    val transport: String = "http",
    val connection: String = "main"
)
@Serializable
data class ScenarioCase(val id: String, val steps: List<ScenarioStep>, val expectation: String = "rejected")
@Serializable
data class Scenario(
    val id: String,
    val testId: String,
    val title: String,
    val policy: String,
    val setup: List<ScenarioStep> = emptyList(),
    val control: List<ScenarioStep>,
    val cases: List<ScenarioCase>,
    val cleanup: List<ScenarioStep> = emptyList(),
    val timeoutSeconds: Int = 60,
    val intervalMs: Int = 250,
    val profile: String = "standard"
) {
    fun validate() {
        require(testId in TestRegistry.scenarioTests) { "No scenario adapter for $testId" }
        require(id.isNotBlank() && policy.isNotBlank() && control.any { it.assertion != null }) { "Supply a scenario ID, policy and a protected-effect positive control" }
        require(cases.size in 1..20 && timeoutSeconds in 5..300 && intervalMs in 100..5000)
        require(profile in setOf("standard", "stress", "lab"))
        val steps = setup + control + cases.flatMap { it.steps } + cleanup
        require(steps.size <= 100 && steps.all { it.body.toByteArray().size <= 65536 && it.headers.size <= 32 })
        require(steps.all { it.transport in setOf("http", "ws-open", "ws-send", "ws-receive", "ws-close") })
        require(cases.all { it.expectation in setOf("rejected", "allowed") && it.steps.any { s -> s.assertion != null } })
        require(steps.all { it.assertion?.meaning in setOf(null, "protected-effect", "explicit-rejection", "receiver-marker", "health-control") })
        require(steps.all { it.assertion == null || it.assertion.pointer.startsWith("/json/") || it.assertion.pointer == "/body" }) {
            "Security assertions must inspect protected response content; HTTP status, upgrade, and local sends are not effects"
        }
    }
}

@Serializable
data class TestEvidence(val stage: String, val timestamp: String = Instant.now().toString(),
                        val input: JsonObject = JsonObject(emptyMap()), val output: JsonObject = JsonObject(emptyMap()),
                        val observation: String = "")
@Serializable
data class TestOutcome(
    val schema: Int = 1,
    val engagementId: String,
    val runId: String = UUID.randomUUID().toString(),
    val testId: String,
    val target: String,
    val backend: String,
    val backendVersion: String = webrtc.BuildInfo.version,
    val startedAt: String = Instant.now().toString(),
    val endedAt: String = Instant.now().toString(),
    val execution: String,
    val security: String = "unknown",
    val confidence: String = "none",
    val severity: String = "information",
    val control: String = "not-run",
    val cleanup: String = "not-required",
    val evidence: List<TestEvidence> = emptyList(),
    val limitations: List<String> = emptyList(),
    val imported: Boolean = false
) {
    fun validate() {
        require(schema == 1 && testId in TestRegistry.byId && runId.isNotBlank() && engagementId.isNotBlank())
        require(execution in setOf("completed", "partial", "timeout", "cancelled", "blocked", "unsupported", "not-tested", "error", "observed"))
        require(security in setOf("unknown", "observed", "inconclusive", "demonstrated-rejection", "policy-violation"))
        require(confidence in setOf("none", "low", "medium", "high") && severity in setOf("information", "low", "medium", "high", "critical"))
        require(Instant.parse(endedAt) >= Instant.parse(startedAt))
        require(evidence.size <= 200 && evidence.sumOf { it.toString().length } <= 2_000_000)
        if (security in setOf("demonstrated-rejection", "policy-violation")) {
            require(execution == "completed" && control == "passed" && evidence.any { it.stage == "effect" }) { "A security verdict needs a successful control and observed effect" }
        }
    }
}

object JsonPointer {
    fun get(root: JsonElement, pointer: String): JsonElement? {
        if (pointer.isEmpty()) return root
        if (!pointer.startsWith('/')) return null
        var current: JsonElement? = root
        for (part in pointer.drop(1).split('/')) {
            val key = part.replace("~1", "/").replace("~0", "~")
            current = when (val node = current) { is JsonObject -> node[key]; is JsonArray -> key.toIntOrNull()?.let { node.getOrNull(it) }; else -> null }
        }
        return current
    }
}
