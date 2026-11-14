package webrtc.assessment

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.time.Instant

/** One durable result per run/test/target. Import is passive and cannot trigger actions. */
class OutcomeStore(private val api: MontoyaApi, private val telemetry: TelemetryTableModel, private val engagement: () -> String) {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val outcomes = linkedMapOf<String, TestOutcome>()
    @Volatile private var cachedList: List<TestOutcome> = emptyList()
    private val key = "webrtc.assessment.results.v1"
    init {
        runCatching { api.persistence().extensionData().getString(key)?.let { json.decodeFromString<List<TestOutcome>>(it) } }
            .getOrNull().orEmpty().takeLast(1000).forEach { outcome ->
                runCatching { outcome.validate(); if (outcome.engagementId == engagement()) outcomes[resultKey(outcome)] = outcome }
            }
        cachedList = outcomes.values.toList()
    }
    private fun resultKey(o: TestOutcome) = listOf(o.engagementId, o.runId, o.testId, o.target).joinToString("\u0000")
    fun snapshot(): List<TestOutcome> {
        val currentEngagement = engagement()
        return cachedList.filter { it.engagementId == currentEngagement }
    }
    @Synchronized fun add(outcome: TestOutcome) {
        outcome.validate()
        require(outcome.engagementId == engagement()) { "Evidence belongs to another engagement" }
        outcomes[resultKey(outcome)] = outcome
        while (outcomes.size > 1000) outcomes.remove(outcomes.keys.first())
        // Enforce a project persistence budget without silently truncating individual evidence.
        var encoded = json.encodeToString(outcomes.values.toList())
        while (encoded.length > 16_000_000 && outcomes.size > 1) { outcomes.remove(outcomes.keys.first()); encoded = json.encodeToString(outcomes.values.toList()) }
        cachedList = outcomes.values.toList()
        api.persistence().extensionData().setString(key, encoded)
        val detail = "${outcome.testId}: ${outcome.execution}; security=${outcome.security}; ${outcome.target}"
        telemetry.add(TelemetryEvent(telemetry.nextSeq(), Instant.now().toString(), "assessment-result", outcome.target, "", false, detail,
            buildJsonObject { put("type", "assessment-result"); put("detail", detail); put("outcome", json.encodeToJsonElement(outcome)) }.toString()))
    }
    fun exportJson(): String = json.encodeToString(snapshot())
    fun importJson(text: String): Int {
        require(text.length <= 16_000_000 && webrtc.bridge.boundedJson(text)) { "Result import exceeds size/depth limit" }
        val incoming = json.decodeFromString<List<TestOutcome>>(text)
        require(incoming.size <= 1000)
        incoming.forEach { it.validate(); require(it.engagementId == engagement()) { "Wrong engagement ID" } }
        incoming.forEach { add(it.copy(imported = true)) }
        return incoming.size
    }
}
