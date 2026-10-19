package webrtc.datachannel

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import webrtc.assessment.OutcomeStore
import webrtc.assessment.TestEvidence
import webrtc.assessment.TestOutcome
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.io.File
import java.io.RandomAccessFile
import java.time.Instant
import java.time.LocalTime
import java.time.format.DateTimeFormatter

/**
 * DataChannel runner results. Each case result is also a "dc-case-result" telemetry event
 * (Evidence, Report, Burp issues) and each run rolls up into the DCH registry outcomes.
 * Full payloads, URLs and credentials are preserved; nothing is masked.
 */
class DcResultStore(
    private val telemetry: TelemetryTableModel,
    private val load: () -> String? = { null },
    private val save: (String) -> Unit = {},
    private val outcomes: () -> OutcomeStore? = { null },
    private val engagement: () -> String = { "" }
) {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = true }
    private val runs = mutableListOf<DcRun>()
    private val listeners = java.util.concurrent.CopyOnWriteArrayList<(DcRun) -> Unit>()

    init {
        runCatching { load()?.let { json.decodeFromString<List<DcRun>>(it) } }.getOrNull()?.takeLast(5)?.let(runs::addAll)
    }

    fun onRun(listener: (DcRun) -> Unit) { listeners += listener }
    @Synchronized fun runs(): List<DcRun> = runs.toList()
    @Synchronized fun latest(): DcRun? = runs.lastOrNull()

    fun record(result: DcCaseResult) {
        val detail = "${result.caseId} ${result.verdict.label}: ${result.title} — ${result.reasons.firstOrNull().orEmpty()}"
        val raw = buildJsonObject {
            put("type", "dc-case-result"); put("detail", detail); put("verdict", result.verdict.label); put("scope", result.scope)
            put("result", json.encodeToJsonElement(DcCaseResult.serializer(), result))
        }
        telemetry.add(TelemetryEvent(telemetry.nextSeq(), LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS")), "dc-case-result",
            result.target.ifBlank { "runner" }, "", false, detail, raw.toString()))
    }

    fun note(detail: String, extra: JsonObject = JsonObject(emptyMap())) {
        val raw = JsonObject(extra + mapOf("type" to JsonPrimitive("dc-runner"), "detail" to JsonPrimitive(detail)))
        telemetry.add(TelemetryEvent(telemetry.nextSeq(), LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS")), "dc-runner", "runner", "", false, detail, raw.toString()))
    }

    @Synchronized fun finish(run: DcRun) {
        runs += run
        while (runs.size > 5) runs.removeAt(0)
        var encoded = json.encodeToString(runs)
        while (encoded.length > 8_000_000 && runs.size > 1) { runs.removeAt(0); encoded = json.encodeToString(runs) }
        runCatching { save(encoded) }
        runCatching { rollUp(run) }
        listeners.forEach { runCatching { it(run) } }
    }

    fun exportJson(run: DcRun? = latest()): String = Json { prettyPrint = true; encodeDefaults = true }.encodeToString(run)

    /** DCH-01 (discovery/binary), DCH-02 (authorization/replay), DCH-03 (load/churn) registry outcomes. */
    private fun rollUp(run: DcRun) {
        val store = outcomes() ?: return
        val groups = mapOf(
            "DCH-01" to setOf(DcScope.DISCOVERY, DcScope.BINARY, DcScope.TRANSPORT, DcScope.FUZZ),
            "DCH-02" to setOf(DcScope.AUTHZ, DcScope.REPLAY),
            "DCH-03" to setOf(DcScope.LOAD))
        val control = run.results.firstOrNull { it.caseId.startsWith("control") }?.verdict == Verdict.PASS
        for ((testId, scopes) in groups) {
            val rows = run.results.filter { DcScope.byId(it.scope) in scopes }
            if (rows.isEmpty()) continue
            val executed = rows.filter { it.verdict in setOf(Verdict.PASS, Verdict.FAIL, Verdict.INCONCLUSIVE) }
            val security = when {
                !control -> "inconclusive"
                rows.any { it.verdict == Verdict.FAIL } -> "policy-violation"
                executed.isNotEmpty() && executed.all { it.verdict == Verdict.PASS } -> "demonstrated-rejection"
                else -> "inconclusive"
            }
            val evidence = rows.filter { it.verdict in setOf(Verdict.FAIL, Verdict.PASS) }.take(150).map { r ->
                TestEvidence("effect", Instant.ofEpochMilli(r.sentAt ?: run.startedAt).toString(),
                    buildJsonObject { put("caseId", r.caseId); put("payload", r.payload.take(2048)); put("transport", r.transport) },
                    buildJsonObject { put("verdict", r.verdict.label); put("receipts", r.receipts.size) }, r.reasons.joinToString("; ").take(2048))
            }
            val counts = Verdict.entries.joinToString(", ") { v -> "${v.label} ${rows.count { it.verdict == v }}" }
            // A registry security verdict needs a completed run; a stopped run stays inconclusive.
            val completed = run.stopReason.isBlank()
            store.add(TestOutcome(engagementId = engagement(), runId = run.runId, testId = testId, target = run.sender, backend = "datachannel-runner",
                startedAt = Instant.ofEpochMilli(run.startedAt).toString(), endedAt = Instant.ofEpochMilli(maxOf(run.startedAt, run.endedAt)).toString(),
                execution = if (completed) "completed" else "partial", security = if (completed) security else "inconclusive",
                confidence = if (security == "policy-violation") "medium" else "low", severity = if (security == "policy-violation") "medium" else "information",
                control = if (control) "passed" else "failed", evidence = evidence,
                limitations = listOf("Case verdicts: $counts") + run.coverage.filter { DcScope.byId(it.scope) in scopes }.flatMap { it.limitations }.distinct().take(20)))
        }
    }
}

/** Tails a local copy or mount of the bridge log and keeps lines that look like problems. */
class BridgeLog(private val path: String) {
    private val interesting = Regex("(?i)\\b(error|severe|exception|warn(ing)?|fail(ed|ure)?|refus|denied|invalid|malformed)\\b")
    val available: Boolean get() = path.isNotBlank() && File(path).isFile

    fun mark(): Long = if (available) File(path).length() else 0

    /** New problem lines since [mark], bounded to 256 KiB read and 200 lines. */
    fun since(mark: Long): List<String> {
        if (!available) return emptyList()
        return runCatching {
            RandomAccessFile(path, "r").use { file ->
                val start = if (file.length() < mark) 0 else mark
                val length = (file.length() - start).coerceAtMost(262144).toInt()
                val bytes = ByteArray(length)
                file.seek(start); file.readFully(bytes)
                String(bytes, Charsets.UTF_8).lines().filter { it.isNotBlank() && (interesting.containsMatchIn(it) || Markers.pattern.containsMatchIn(it)) }.take(200)
            }
        }.getOrDefault(emptyList())
    }
}
