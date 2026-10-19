package webrtc.assessment

import webrtc.config.ConfigStore
import webrtc.external.ExternalInputs
import webrtc.protocol.ProtocolRunner
import webrtc.protocol.ProtocolTarget
import webrtc.telemetry.TelemetryTableModel

class AssessmentController(private val config: ConfigStore, val store: OutcomeStore,
                           private val runner: ProtocolRunner, private val telemetry: TelemetryTableModel) {
    @Volatile private var cancelled = false
    fun stop() { cancelled = true; runner.stop() }
    fun checkRuntime(): String = runner.check()
    @Synchronized fun run(ids: Set<String> = TestRegistry.executable(config.config.assessment), retryIncomplete: Boolean = false,
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
                    val schemes = if (id == "TRN-01") setOf("stun", "stuns", "turn", "turns") else setOf("turn", "turns")
                    // Endpoints and credentials come from the ICE servers the agent observed on the
                    // application's peers, so nothing has to be configured in the tab. Any manually
                    // entered endpoints are still honored as a fallback.
                    val legs = LinkedHashMap<String, Triple<ProtocolTarget, String?, String?>>()
                    ExternalInputs.detect(cfg, telemetry.snapshot()).iceServers.asReversed().forEach { server ->
                        server.urls.forEach { url ->
                            runCatching { ProtocolTarget.parse(url) }.getOrNull()?.takeIf { it.scheme in schemes }
                                ?.let { legs.putIfAbsent(it.input, Triple(it, server.username.orEmpty(), server.credential.orEmpty())) }
                        }
                    }
                    cfg.protocolScan.endpoints.forEach { endpoint ->
                        runCatching { ProtocolTarget.parse(endpoint) }.getOrNull()?.takeIf { it.scheme in schemes }
                            ?.let { legs[it.input] = Triple(it, cfg.protocolScan.turnUsername, cfg.protocolScan.turnCredential) }
                    }
                    if (legs.isEmpty()) record(id, "blocked", "No STUN/TURN listener observed yet — join a call so the agent captures the app's ICE servers, and add the listener host to Burp Target scope")
                    else legs.values.take(20).forEach { (target, user, pass) ->
                        if (!cancelled && (!retryIncomplete || id to target.input !in finished)) {
                            val result = runner.run(id, target, { cancelled }, user, pass)
                            emit("$id ${target.input}: ${result.execution}; ${result.security}; ${result.limitations.joinToString()}")
                        }
                    }
                }
                id in TestRegistry.dataChannelTests && cfg.assessment.scenarios.none { it.testId == id } -> {
                    if (store.snapshot().none { it.testId == id && it.backend == "datachannel-runner" })
                        record(id, "not-tested", "Run Tests → Data channel runner (or select Data channel runner in Scan All) with at least two instrumented participants")
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
                    val types = when (id) { "COR-01" -> setOf("ice"); "COR-02", "COR-04", "COR-05" -> setOf("sdp-local", "sdp-remote", "crypto"); "COR-03" -> setOf("dtls-cert"); "SIG-01" -> setOf("signaling-observation")
                        "WEB-02" -> setOf("track-state", "capture-result", "getUserMedia-result", "browser-capabilities", "enumerateDevices-result")
                        "WEB-03" -> setOf("message-listener", "message-received", "message-sent"); else -> setOf("original-policy") }
                    val evidence = telemetry.snapshot().filter { it.type in types }
                    record(id, if (evidence.isEmpty()) "not-tested" else "observed", if (evidence.isEmpty()) "No relevant observations captured" else "${evidence.size} observations available in M7; passive interpretation only")
                }
                else -> record(id, "unsupported", "Not automatable from Burp; test manually or with an external tool (see External Tests). ${definition.contract}")
            }
        }
    }
}
