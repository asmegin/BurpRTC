package webrtc.protocol

import webrtc.assessment.*
import webrtc.config.ConfigStore
import java.time.Instant
import java.util.UUID

/**
 * Built-in protocol backends: the JVM STUN/TURN client and the Burp-routed
 * HTTP/WebSocket scenario runner. Nothing is installed or launched; scope is
 * re-checked before every connect, send and scenario step.
 */
class ProtocolRunner(private val config: ConfigStore, private val authorization: NetworkAuthorization,
                     private val store: OutcomeStore,
                     private val transport: ScenarioTransport? = null) : AutoCloseable {
    @Volatile private var stopped = false
    @Volatile private var closed = false
    fun stop() { stopped = true }
    override fun close() { closed = true; stop() }

    fun check(): String = "Built-in STUN/TURN and scenario runners are ready; no external runtime is required"

    @Synchronized fun runScenario(scenario: Scenario, cancelled: () -> Boolean = { false }): TestOutcome {
        stopped = false
        val cfg = config.config
        val id = UUID.randomUUID().toString(); val started = Instant.now().toString()
        val outcome = try {
            scenario.validate()
            require(scenario.profile == "standard" || scenario.profile == cfg.assessment.profile) { "Select the scenario's stress/lab profile" }
            if (closed || cancelled()) error("cancelled")
            val network = transport ?: error("Scenario transport unavailable")
            ScenarioRunner(network, authorization::allows) { closed || stopped || cancelled() }
                .run(scenario, id, cfg.assessment.engagementId, cfg.identities)
        } catch (e: Exception) {
            TestOutcome(engagementId = cfg.assessment.engagementId, runId = id, testId = scenario.testId, target = scenario.id,
                backend = "recorded-scenario", startedAt = started,
                execution = if (stopped || closed || cancelled()) "cancelled" else "error", limitations = listOf(e.message.orEmpty()))
        }
        store.add(outcome)
        return outcome
    }

    @Synchronized fun run(testId: String, target: ProtocolTarget, cancelled: () -> Boolean = { false },
                          username: String? = null, password: String? = null): TestOutcome {
        stopped = false
        val cfg = config.config
        val settings = cfg.protocolScan
        val runId = UUID.randomUUID().toString(); val started = Instant.now().toString()
        fun failed(execution: String, message: String) = TestOutcome(engagementId = cfg.assessment.engagementId, runId = runId,
            testId = testId, target = target.input, backend = "built-in-turn", startedAt = started, execution = execution,
            cleanup = "unconfirmed; run stopped, allocation may persist until its server lifetime expires", limitations = listOf(message))
        val result = try {
            settings.validate()
            require(testId in TestRegistry.protocolTests)
            if (closed || cancelled()) error("cancelled")
            if (!authorization.allows(target.scopeUrl)) throw SecurityException("Listener outside configured scope: ${target.scopeUrl}")
            // Prefer per-target credentials (the app's own observed TURN account); fall back to protocol settings.
            val turnUser = username ?: settings.turnUsername.ifEmpty { null }
            val turnPass = if (username != null) password.orEmpty() else settings.turnCredential
            val credentials = buildList {
                if (!turnUser.isNullOrEmpty()) add(TurnProbe.Credential("valid", turnUser, turnPass))
                if (testId == "TRN-02") {
                    add(TurnProbe.Credential("absent", "", ""))
                    if (!turnUser.isNullOrEmpty()) add(TurnProbe.Credential("incorrect", turnUser, UUID.randomUUID().toString()))
                    settings.credentialConditions.forEach { add(TurnProbe.Credential(it.condition, it.username, it.password)) }
                }
            }
            val peer = settings.relayPeer.takeIf { it.isNotBlank() }?.let(ProtocolTarget::parse)
            TurnProbe(authorization::allowsLeg) { closed || stopped || cancelled() }
                .run(testId, runId, cfg.assessment.engagementId, target, settings.timeoutSeconds, credentials, peer)
        } catch (e: Exception) {
            failed(when { stopped || closed || cancelled() -> "cancelled"; e is SecurityException -> "blocked"; else -> "error" }, e.message.orEmpty())
        }
        store.add(result)
        return result
    }
}
