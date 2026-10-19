package webrtc.datachannel

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/** Everything observed for one case; built by the runner from agent telemetry. */
data class CaseObservation(
    val case: DcCase,
    /** The sender agent's dc-case event, or null when the case never ran. */
    val sent: JsonObject?,
    /** Receipts from participants other than the sender (data, Colibri WebSocket, DOM, error). */
    val receipts: List<Receipt>,
    /** Page errors at any participant inside the case window that carry no marker. */
    val windowErrors: List<String> = emptyList(),
    /** Delivery probe after the case: true delivered, false failed, null not evaluated. */
    val probeAfter: Boolean?,
    val controlPassed: Boolean,
    /** Agent IDs that were live (heartbeat, open transport) while the case ran. */
    val live: Set<String>,
    /** Every other participant's agent ID. */
    val others: Set<String>
)

object DcClassifier {
    private val dataKinds = setOf("dc", "colibri-ws", "ws")

    private fun JsonObject.str(key: String) = (this[key] as? JsonPrimitive)?.contentOrNull

    fun classify(o: CaseObservation): Pair<Verdict, List<String>> {
        val c = o.case
        c.preVerdict?.let { return it to listOf(c.preReason) }
        val sent = o.sent ?: return Verdict.BLOCKED to listOf("Not executed: the target closed, a budget was exhausted or the run stopped before this case")
        val stage = sent.str("stage").orEmpty()
        val error = sent.str("error").orEmpty()
        if (stage == "blocked") return Verdict.BLOCKED to listOf("Not sent: $error")
        if (stage == "browser-rejected") return Verdict.INCONCLUSIVE to listOf(
            "The browser rejected the send before transmission ($error); server-side validation was not exercised")
        if (stage != "queued") return Verdict.INCONCLUSIVE to listOf("Unknown send stage '$stage'")

        val reasons = mutableListOf<String>()
        val intended = c.intended.ifEmpty { if (c.expect == Expect.DELIVER) o.others else emptySet() }
        val forbidden = c.forbidden.ifEmpty { if (c.expect == Expect.REJECT) o.others else emptySet() }
        val data = o.receipts.filter { it.kind in dataKinds || it.kind == "dom" }
        val errorReceipts = o.receipts.filter { it.kind == "error" }
        val gotIntended = data.filter { it.agentId in intended }
        val gotForbidden = data.filter { it.agentId in forbidden }
        val forbiddenLive = forbidden.any { it in o.live }
        val observersLive = (intended + forbidden + o.others).any { it in o.live }
        val senderClosed = (sent["stateAfter"] as? JsonObject)?.let { it.str("channel") == "closed" || it.str("socket") == "closed" } == true
        if (senderClosed) reasons += "The sending channel was closed by the remote side or page after this case"
        fun names(list: List<Receipt>) = list.map { it.participant }.distinct().joinToString(", ")
        fun kinds(list: List<Receipt>) = list.map { when (it.kind) { "dom" -> "rendered"; "colibri-ws" -> "Colibri WebSocket"; "dc" -> "DataChannel"; else -> it.kind } }.distinct().joinToString("/")

        if (c.spoofedFrom.isNotBlank()) {
            val spoofed = data.filter { it.kind in dataKinds && it.from == c.spoofedFrom }
            if (spoofed.isNotEmpty()) return Verdict.FAIL to listOf(
                "${names(spoofed)} received the message attributed to '${c.spoofedFrom}': the sender identity was not rewritten or rejected") + reasons
            data.firstOrNull { it.kind in dataKinds && it.from.isNotBlank() }?.let { reasons += "Recipients saw from='${it.from}' (rewritten from the spoofed '${c.spoofedFrom}')" }
        }
        if (errorReceipts.isNotEmpty() || o.windowErrors.isNotEmpty()) {
            val detail = (errorReceipts.map { "${it.participant}: ${it.detail}" } + o.windowErrors).distinct().take(3).joinToString("; ")
            if (errorReceipts.isNotEmpty()) return Verdict.FAIL to listOf("Application error carrying this case's marker: $detail") + reasons
            reasons += "Unattributed page error(s) during the case window: $detail"
        }

        when (c.expect) {
            Expect.DELIVER -> {
                if (gotForbidden.isNotEmpty()) return Verdict.FAIL to listOf("Delivered to unauthorized participant(s) ${names(gotForbidden)} (${kinds(gotForbidden)})") + reasons
                if (gotIntended.isEmpty()) {
                    if (intended.none { it in o.live }) return Verdict.INCONCLUSIVE to listOf("No live intended recipient was observing") + reasons
                    return Verdict.FAIL to listOf("The valid message was not delivered to the intended recipient(s); the positive control failed") + reasons
                }
                reasons.add(0, "Delivered to ${names(gotIntended)} (${kinds(gotIntended)})")
                if (c.forbidden.isNotEmpty() || c.scope == DcScope.AUTHZ) {
                    if (!forbiddenLive) return Verdict.INCONCLUSIVE to reasons + "No live unauthorized observer (for example a test-room session) could confirm isolation"
                    reasons += "Not delivered to ${forbidden.size} unauthorized observer(s)"
                }
                return Verdict.PASS to reasons
            }
            Expect.REJECT -> {
                if (gotForbidden.isNotEmpty()) return Verdict.FAIL to listOf(
                    "Delivered to ${names(gotForbidden)} (${kinds(gotForbidden)}) although it should have been rejected" +
                        gotForbidden.firstOrNull { it.colibriClass.isNotBlank() }?.let { " (relayed as ${it.colibriClass})" }.orEmpty()) + reasons
            }
            Expect.TOLERATE -> {
                if (data.isNotEmpty()) reasons.add(0, "Delivered to ${names(data)} (${kinds(data)}) without recipient errors")
                else reasons.add(0, "Not delivered to any observer")
            }
        }
        if (!o.controlPassed) return Verdict.INCONCLUSIVE to reasons + "The positive control did not pass, so non-delivery or silence cannot be attributed to the system under test"
        if (!observersLive) return Verdict.INCONCLUSIVE to reasons + "No live observer was available"
        if (c.expect == Expect.REJECT && !forbiddenLive) return Verdict.INCONCLUSIVE to reasons + "No live observer among the participants that must not receive it"
        return when (o.probeAfter) {
            true -> Verdict.PASS to (if (c.expect == Expect.REJECT) listOf("Not delivered to any participant") else emptyList()) + reasons +
                "The delivery probe after the case succeeded"
            false -> Verdict.INCONCLUSIVE to reasons + "The delivery probe after this case group failed; see the isolation result"
            null -> Verdict.INCONCLUSIVE to reasons + "No delivery probe could be evaluated after the case (no same-room observer)"
        }
    }

    /** Admission verdict for a fresh Colibri WebSocket attempt that should be refused. */
    fun admission(result: JsonObject?, controlOpen: Boolean): Pair<Verdict, String> {
        result ?: return Verdict.BLOCKED to "The admission attempt did not run"
        val opened = result.str("opened") == "true"
        val outcome = result.str("outcome").orEmpty()
        val firstClass = result.str("firstClass").orEmpty()
        return when {
            opened && (outcome == "message" || outcome == "open-timeout") -> Verdict.FAIL to
                "The bridge admitted the connection${if (firstClass.isNotBlank()) " and sent $firstClass" else " and kept it open"}"
            !opened && outcome == "closed" && controlOpen -> Verdict.PASS to
                "Refused before open (close code ${result.str("closeCode") ?: "none"}); the application's own Colibri socket to the same bridge was open"
            !opened && outcome == "closed" -> Verdict.INCONCLUSIVE to "Refused, but no open application socket proved the bridge was reachable"
            opened -> Verdict.PASS to "Opened then closed by the bridge without application data (close code ${result.str("closeCode") ?: "none"})"
            else -> Verdict.INCONCLUSIVE to "Connection attempt timed out ($outcome)"
        }
    }

    data class LoadMetrics(val sent: Int, val deliveryRatio: Double?, val p95LatencyMs: Long?, val lossIncreasePct: Double?, val healthLost: Boolean)

    /** Load-step verdict against the configured degradation thresholds. */
    fun load(m: LoadMetrics, config: DcSuiteConfig, observer: Boolean): Pair<Verdict, String> {
        val summary = "sent ${m.sent}; delivery ${m.deliveryRatio?.let { "%.0f%%".format(it * 100) } ?: "n/a"}; p95 latency ${m.p95LatencyMs?.let { "$it ms" } ?: "n/a"}; " +
            "packet-loss increase ${m.lossIncreasePct?.let { "%.1f%%".format(it) } ?: "n/a"}"
        return when {
            m.sent == 0 -> Verdict.BLOCKED to "No message was sent ($summary)"
            m.healthLost -> Verdict.FAIL to "Session health was lost under load; $summary"
            !observer || m.deliveryRatio == null -> Verdict.INCONCLUSIVE to "No recipient observed the load; $summary"
            m.deliveryRatio < config.minDeliveryRatio -> Verdict.FAIL to "Delivery fell below ${"%.0f%%".format(config.minDeliveryRatio * 100)}; $summary"
            (m.p95LatencyMs ?: 0) > config.maxP95LatencyMs -> Verdict.FAIL to "p95 latency exceeded ${config.maxP95LatencyMs} ms; $summary"
            (m.lossIncreasePct ?: 0.0) > config.maxPacketLossIncreasePct -> Verdict.FAIL to "Media packet loss rose by more than ${config.maxPacketLossIncreasePct}%; $summary"
            else -> Verdict.PASS to "Within thresholds; $summary"
        }
    }

    fun percentile(values: List<Long>, p: Double): Long? {
        if (values.isEmpty()) return null
        val sorted = values.sorted()
        return sorted[((sorted.size - 1) * p).toInt().coerceIn(0, sorted.size - 1)]
    }
}

/** Maps every RTCDataChannel scope item to executed cases and remaining limitations. */
object DcCoverage {
    val staticLimitations = mapOf(
        DcScope.DISCOVERY to listOf("Channels created before the agent loaded are invisible; the agent is injected ahead of page scripts, and runner sessions also tag pages before startup."),
        DcScope.FUZZ to listOf("Bridge-side validation is inferred from relay behaviour, recipient errors and session health; bridge internals are only visible through the optional bridge log.",
            "Mutations inside EndpointMessage msgPayload are application data the bridge relays by design; they test receiving clients."),
        DcScope.BINARY to listOf("A browser-side rejection (for example above maxMessageSize) is reported as INCONCLUSIVE, never as server-side validation.",
            "Payloads without a marker (empty or 1-byte) cannot be observed at recipients and are judged on errors and session health only."),
        DcScope.AUTHZ to listOf("Isolation needs a live observer in a separate test room; without one, isolation cases are INCONCLUSIVE.",
            "Application-level role rules (advisor-only commands) need protected-message definitions with a state probe in runner sessions."),
        DcScope.REPLAY to listOf("Exact replays carry no marker and are matched by payload hash; a bridge that re-serializes payloads can prevent matching.",
            "Lifecycle cases need runner sessions with join / leave / hang-up call controls. Token expiry alone need not end an established call."),
        DcScope.LOAD to listOf("Latency is estimated from the send schedule and recipient clocks; sessions on different machines need synchronized clocks.",
            "Channel churn runs only on a DataChannel peer with a connected SCTP association, so it never triggers renegotiation."),
        DcScope.TRANSPORT to listOf("Comparison runs only when the application exposes both an RTCDataChannel bridge channel and a Colibri WebSocket in the same session."),
        DcScope.NATIVE_SCTP to listOf("Not covered: browser JavaScript cannot craft SCTP chunks, fragmentation, stream resets or DCEP packets.",
            "Use a separate DTLS/SCTP-capable test peer with crash and log collection against controlled targets (registry test DCH-04); keep it separate from browser API and Colibri payload testing.")
    )

    fun compute(results: List<DcCaseResult>, dynamic: Map<DcScope, List<String>> = emptyMap()): List<CoverageRow> = DcScope.entries.map { scope ->
        val rows = results.filter { it.scope == scope.id }
        CoverageRow(scope.id, scope.title, scope.verification,
            Verdict.entries.associate { v -> v.label to rows.count { it.verdict == v } }.filterValues { it > 0 },
            rows.map { it.caseId }, dynamic[scope].orEmpty() + staticLimitations[scope].orEmpty() +
                if (rows.isEmpty() && scope != DcScope.NATIVE_SCTP) listOf("No case executed in this run") else emptyList())
    }

    fun text(coverage: List<CoverageRow>): String = coverage.joinToString("\n\n") { row ->
        val counts = row.counts.entries.joinToString(", ") { "${it.key} ${it.value}" }.ifEmpty { "no cases" }
        buildString {
            append("${row.title}: $counts\n")
            append("  Verification: ${row.verification}\n")
            if (row.caseIds.isNotEmpty()) append("  Cases: ${row.caseIds.take(40).joinToString(", ")}${if (row.caseIds.size > 40) " … (${row.caseIds.size})" else ""}\n")
            row.limitations.forEach { append("  Limitation: $it\n") }
        }.trimEnd()
    }
}
