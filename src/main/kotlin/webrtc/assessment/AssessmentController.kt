package webrtc.assessment

import webrtc.config.ConfigStore
import webrtc.protocol.ProtocolRunner
import webrtc.protocol.ProtocolTarget
import webrtc.telemetry.TelemetryTableModel

class AssessmentController(private val config: ConfigStore, val store: OutcomeStore,
                           private val runner: ProtocolRunner, private val telemetry: TelemetryTableModel) {
    @Volatile private var cancelled = false
    fun stop() { cancelled = true; runner.stop() }
    @Synchronized fun run(ids: Set<String> = config.config.assessment.selectedTests, retryIncomplete: Boolean = false,
                          emit: (String) -> Unit = {}) {
        cancelled = false
        val cfg = config.config
        cfg.assessment.validate()
        val finished = store.snapshot().filter { it.execution in setOf("completed", "observed") }.map { it.testId to it.target }.toSet()
        fun record(id: String, execution: String, reason: String, target: String = "Engagement") {
            store.add(TestOutcome(engagementId = cfg.assessment.engagementId, testId = id, target = target, backend = "registry",
                execution = execution, limitations = listOf(reason)))
            emit("$id: $execution — $reason")
        }
        for (definition in TestRegistry.definitions.filter { it.id in ids }) {
            if (cancelled) { record(definition.id, "cancelled", "Stopped before execution"); continue }
            val id = definition.id
            when {
                id in TestRegistry.protocolTests -> {
                    val endpoints = cfg.protocolScan.endpoints.mapNotNull { runCatching { ProtocolTarget.parse(it) }.getOrNull() }
                        .filter { it.scheme in if (id == "TRN-01") setOf("stun", "stuns", "turn", "turns") else setOf("turn", "turns") }.distinct()
                    if (endpoints.isEmpty()) record(id, "blocked", "Needs selected STUN/TURN listener")
                    else if (id in setOf("TRN-04", "TRN-05") && cfg.protocolScan.relayPeer.isBlank()) record(id, "blocked", "Needs controlled UDP echo destination")
                    else endpoints.forEach { target ->
                        if (!cancelled && (!retryIncomplete || id to target.input !in finished)) {
                            val result = runner.run(id, target) { cancelled }
                            emit("$id ${target.input}: ${result.execution}; ${result.security}; ${result.limitations.joinToString()}")
                        }
                    }
                }
                id in TestRegistry.scenarioTests -> {
                    val scenarios = cfg.assessment.scenarios.filter { it.testId == id }
                    if (scenarios.isEmpty()) record(id, "blocked", "Needs recorded scenario, scoped identities, policy and receiver/content assertions")
                    scenarios.forEach { scenario ->
                        if (!cancelled && (!retryIncomplete || id to scenario.id !in finished)) {
                            val outcome = runner.runScenario(scenario) { cancelled }
                            emit("$id ${scenario.title}: ${outcome.execution}; ${outcome.security}; ${outcome.limitations.joinToString()}")
                        }
                    }
                }
                id in TestRegistry.passiveTests -> {
                    val types = when (id) { "COR-01" -> setOf("ice"); "COR-02", "COR-04", "COR-05" -> setOf("sdp-local", "sdp-remote", "crypto"); "COR-03" -> setOf("dtls-cert"); "SIG-01" -> setOf("signaling-observation"); else -> setOf("original-policy") }
                    val evidence = telemetry.snapshot().filter { it.type in types }
                    record(id, if (evidence.isEmpty()) "not-tested" else "observed", if (evidence.isEmpty()) "No relevant observations captured" else "${evidence.size} observations available in M7; passive interpretation only")
                }
                else -> record(id, "unsupported", "Not automatable from Burp; test manually or with an external tool (see External Tests). ${definition.contract}")
            }
        }
    }
}
