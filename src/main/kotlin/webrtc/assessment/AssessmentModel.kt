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
    val passiveTests = setOf("COR-01", "COR-02", "COR-03", "COR-04", "COR-05", "SIG-01", "WEB-01")
    val scenarioTests = definitions.filter { it.id.startsWith("SIG-") || it.id.startsWith("APP-") || it.id.startsWith("SFU-") ||
        it.id in setOf("TRN-03", "DCH-02", "WEB-03", "RES-01", "RES-03", "ICE-01", "ICE-05", "SDP-02", "SDP-03", "DTL-03", "MED-02", "SIP-02", "SIP-04") }.map { it.id }.toSet() - setOf("SIG-01", "APP-04")
    fun capability(id: String, config: AssessmentConfig): String = when {
        id in passiveTests -> "Passive analysis"
        id in protocolTests -> "Bundled TURN runner"
        id in scenarioTests && config.scenarios.any { it.testId == id } -> "Configured scenario"
        id in scenarioTests -> "Needs scenario / identities / receiver assertions"
        else -> "No execution adapter"
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
