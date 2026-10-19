package webrtc.datachannel

import kotlinx.serialization.json.*
import webrtc.bridge.ActiveTestController
import webrtc.config.ConfigStore
import webrtc.config.Roles
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.net.URI
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * DataChannel test runner. Uses live instrumented pages (and, when configured, integrated
 * runner sessions) to run cases one at a time from a sender, observe every other participant,
 * restore state, and classify each case PASS / FAIL / INCONCLUSIVE / BLOCKED / NOT APPLICABLE.
 * Every command goes through [ActiveTestController], so Burp scope, the host allow-list and
 * the agent switch are rechecked for every case.
 */
class DcSuiteRunner(
    private val configStore: ConfigStore,
    private val controller: ActiveTestController,
    private val telemetry: TelemetryTableModel,
    private val store: DcResultStore,
    private val browser: BrowserRunner? = null,
    private val sleeper: (Long) -> Unit = { Thread.sleep(it) },
    private val clock: () -> Long = System::currentTimeMillis
) {
    data class Options(
        val sender: String? = null,
        /** agentId → (role, room) assignments for pages not launched by the runner. */
        val assignments: Map<String, Pair<String, String>> = emptyMap(),
        val families: Set<String>? = null
    )

    @Volatile private var cancelled = false
    @Volatile var running = false
        private set
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val inbox = ConcurrentLinkedQueue<TelemetryEvent>()
    private val interesting = setOf("dc-case", "dc-markers", "page-error", "dc-health", "dc-load-step", "dc-churn-result", "dc-churn-summary",
        "ws-admission-result", "transport-action-result", "pc-state", "dc-state", "ws-colibri",
        "dc-suite-error", "dc-load-error", "dc-churn-error", "dc-health-error", "ws-admission-error", "transport-action-error")

    init { telemetry.onEvent { if (running && it.type in interesting) inbox.add(it) } }

    fun stop() { cancelled = true; controller.observing = false }

    // ---- telemetry index ----

    private class Index {
        val byCommand = HashMap<String, MutableList<JsonObject>>()
        val receipts = mutableListOf<Pair<String, JsonObject>>()
        val errors = mutableListOf<Pair<String, JsonObject>>()
    }
    private var index = Index()

    private fun refresh() {
        while (true) {
            val event = inbox.poll() ?: break
            val obj = runCatching { json.parseToJsonElement(event.raw).jsonObject }.getOrNull() ?: continue
            val agent = obj.str("agent").orEmpty()
            obj.str("commandId")?.let { index.byCommand.getOrPut(it) { mutableListOf() }.add(obj) }
            when (event.type) {
                "dc-markers" -> (obj["receipts"] as? JsonArray).orEmpty().forEach { r -> (r as? JsonObject)?.let { index.receipts += agent to it } }
                "page-error" -> index.errors += agent to obj
            }
        }
        while (index.receipts.size > 200000) index.receipts.removeAt(0)
    }

    private fun eventsFor(commandId: String?, type: String) = commandId?.let { index.byCommand[it] }.orEmpty().filter { it.str("type") == type }

    // ---- run state ----

    private inner class RunState(
        val runId: String, val seed: Long, val cfg: DcSuiteConfig, val gen: DcCaseGenerator,
        var sender: Participant, var target: DcTarget, val participants: List<Participant>, var ctx: DcContext
    ) {
        val started = clock()
        val deadline = started + cfg.maxDurationSeconds * 1000L
        var bytesUsed = 0L
        var controlPassed = false
        var stopReason = ""
        val results = mutableListOf<DcCaseResult>()
        val dropped = mutableMapOf<DcScope, Int>()
        val notes = mutableListOf<String>()
        val bridgeLog = BridgeLog(cfg.bridgeLogPath)
        var logMark = bridgeLog.mark()
        val logLines = mutableListOf<String>()
        val senderGroup: Set<String> get() = participants.filter { it.agentId == sender.agentId || (sender.session.isNotBlank() && it.session == sender.session) }.map { it.agentId }.toSet()
        val others: Set<String> get() = participants.map { it.agentId }.toSet() - senderGroup
        fun overBudget() = clock() > deadline || bytesUsed >= cfg.maxTotalBytes
        fun participant(agent: String) = participants.firstOrNull { it.agentId == agent }
    }

    // ---- participants and targets ----

    private fun JsonObject.str(key: String) = (this[key] as? JsonPrimitive)?.contentOrNull
    private fun JsonObject.long(key: String) = (this[key] as? JsonPrimitive)?.longOrNull
    private fun JsonObject.array(key: String) = (this[key] as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }

    fun participants(options: Options = Options()): List<Participant> {
        val sessions = configStore.config.browserRunner.sessions
        val parts = controller.agents().filter { controller.pageAllowed(it.frame) }.map { agent ->
            val tag = agent.state.str("runnerSession").orEmpty()
            val session = sessions.firstOrNull { it.name == tag && tag.isNotBlank() }
            val manual = options.assignments[agent.id]
            val socket = agent.state.array("sockets").firstOrNull { it.str("endpoint")?.isNotBlank() == true }
            val endpoint = agent.state.str("endpoint")?.takeIf { it.isNotBlank() } ?: socket?.str("endpoint").orEmpty()
            Participant(agent.id, agent.frame, tag, manual?.first ?: session?.role.orEmpty(), manual?.second ?: session?.room ?: "main",
                endpoint, socket?.str("conference").orEmpty())
        }
        // Runner sessions can name their endpoint; otherwise infer it from what the others received.
        val withExpr = parts.map { p ->
            val b = browser
            if (p.endpoint.isNotBlank() || p.session.isBlank() || b == null) p
            else b.endpointFor(p.session).takeIf { it.isNotBlank() }?.let { p.copy(endpoint = it) } ?: p
        }
        val hints = controller.agents().associate { a -> a.id to (a.state["endpointHints"] as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.toSet() }
        val inferred = withExpr.map { p ->
            if (p.endpoint.isNotBlank()) return@map p
            val peers = withExpr.filter { it.room == p.room && it.agentId != p.agentId && (p.session.isBlank() || it.session != p.session) }
            val known = peers.map { it.endpoint }.filter { it.isNotBlank() }.toSet()
            val candidates = peers.flatMap { hints[it.agentId].orEmpty() }.toSet() - hints[p.agentId].orEmpty() - known
            if (candidates.size == 1 && hints[p.agentId].orEmpty().isNotEmpty()) p.copy(endpoint = candidates.single()) else p
        }
        // Share an endpoint between the frames of one runner session.
        return inferred.map { p ->
            if (p.endpoint.isNotBlank() || p.session.isBlank()) p
            else inferred.firstOrNull { it.session == p.session && it.endpoint.isNotBlank() }?.let { p.copy(endpoint = it.endpoint, conference = it.conference) } ?: p
        }
    }

    fun targets(agentId: String): List<DcTarget> {
        val agent = controller.agents().firstOrNull { it.id == agentId } ?: return emptyList()
        val channels = agent.state.array("channels").filter { it.str("state") == "open" }.map { c ->
            DcTarget("datachannel", channelId = c.str("channelId").orEmpty(), label = c.str("label").orEmpty(), pcId = c.str("pc").orEmpty(),
                peerKind = c.str("peerKind") ?: "unknown", maxMessageSize = c.long("maxMessageSize"))
        }
        val sockets = agent.state.array("sockets").filter { it.str("state") == "open" }.map { s ->
            DcTarget("colibri-ws", socketId = s.str("socketId").orEmpty(), label = "colibri-ws", peerKind = "jvb", url = s.str("url").orEmpty())
        }
        val rank = { t: DcTarget -> when { t.peerKind == "jvb" && t.transport == "datachannel" -> 0; t.transport == "colibri-ws" -> 1; t.peerKind == "sfu" -> 2; else -> 3 } }
        return (channels + sockets).sortedBy(rank)
    }

    private fun live(): Set<String> = controller.agents().map { it.id }.toSet()

    // ---- execution ----

    private data class Job(val id: String?, val state: String, val error: String = "")

    private fun execute(agentId: String, type: String, config: JsonObject, budgetMs: Long, endpoint: String? = null): Job {
        val id = try { controller.queueRunnerCommand(agentId, type, config, endpoint, budgetMs + 30000) }
        catch (e: IllegalArgumentException) { return Job(null, "refused", e.message.orEmpty()) }
        val started = clock()
        var runningAt = 0L
        while (true) {
            if (cancelled) { controller.cancelJob(id); return Job(id, "cancelled") }
            val state = controller.jobState(id)
            if (state == null || state !in setOf("queued", "running")) { refresh(); return Job(id, state ?: "done") }
            if (state == "running" && runningAt == 0L) runningAt = clock()
            if (clock() > (if (runningAt > 0) runningAt + budgetMs else started + 15000)) { controller.cancelJob(id); refresh(); return Job(id, "timeout") }
            sleeper(200)
        }
    }

    /** Health snapshots from several pages at once (each page runs one job at a time). */
    private fun health(agents: Collection<String>): Map<String, JsonObject> {
        val queued = agents.distinct().mapNotNull { a -> runCatching { a to controller.queueRunnerCommand(a, "dc-health", JsonObject(emptyMap()), lifetimeMs = 30000) }.getOrNull() }
        val deadline = clock() + 15000
        while (!cancelled && clock() < deadline && queued.any { (_, id) -> controller.jobState(id) in setOf("queued", "running") }) sleeper(200)
        queued.forEach { (_, id) -> if (controller.jobState(id) in setOf("queued", "running")) controller.cancelJob(id) }
        refresh()
        return queued.mapNotNull { (a, id) -> eventsFor(id, "dc-health").lastOrNull()?.let { a to it } }.toMap()
    }

    private fun caseJson(c: DcCase) = buildJsonObject {
        put("id", c.id); put("marker", c.marker)
        put("payload", json.encodeToJsonElement(PayloadSpec.serializer(), c.payload))
        c.settleMs?.let { put("settleMs", it) }
        c.target?.commandFields()?.forEach { (k, v) -> put(k, v) }
    }

    /** Runs cases in order on the sender; returns each executed case's dc-case event. */
    private fun execSequence(rs: RunState, sequence: List<DcCase>, agentId: String = rs.sender.agentId): Map<String, JsonObject> {
        val sent = HashMap<String, JsonObject>()
        var position = 0
        var stalls = 0
        while (position < sequence.size && !cancelled) {
            if (rs.overBudget()) { if (rs.stopReason.isBlank()) rs.stopReason = if (clock() > rs.deadline) "Run duration budget reached" else "Run byte budget reached"; break }
            val chunk = mutableListOf<DcCase>()
            var size = 0
            while (position + chunk.size < sequence.size && chunk.size < 40) {
                val next = caseJson(sequence[position + chunk.size]).toString().length
                if (chunk.isNotEmpty() && size + next > 600_000) break
                chunk += sequence[position + chunk.size]; size += next
            }
            val config = buildJsonObject {
                rs.target.commandFields().forEach { (k, v) -> put(k, v) }
                put("settleMs", rs.cfg.settleMs); put("maxMessageBytes", rs.cfg.maxMessageBytes)
                put("maxTotalBytes", (rs.cfg.maxTotalBytes - rs.bytesUsed).coerceIn(1, 16777216).toInt()); put("maxBufferedAmount", rs.cfg.maxBufferedAmount)
                put("cases", JsonArray(chunk.map(::caseJson)))
            }
            val budget = chunk.sumOf { (it.settleMs ?: rs.cfg.settleMs) + 300L } + 10000L
            val job = execute(agentId, "dc-suite", config, budget)
            if (job.id == null) { rs.stopReason = "The sender page refused the runner command: ${job.error}"; break }
            sleeper(rs.cfg.receiptGraceMs.toLong()); refresh()
            val events = eventsFor(job.id, "dc-case")
            events.forEach { e -> e.str("caseId")?.let { sent[it] = e }; rs.bytesUsed += e.long("bytes") ?: 0 }
            val executed = chunk.indexOfLast { sent.containsKey(it.id) } + 1
            position += executed
            if (executed < chunk.size) {
                if (cancelled || job.state == "cancelled") break
                if (executed == 0 && ++stalls >= 2) { rs.stopReason = "The sender page did not run the runner cases (${job.state})"; break }
                if (!restoreTarget(rs)) { rs.stopReason = "The sending channel closed and was not re-established"; break }
            } else stalls = 0
        }
        if (cancelled && rs.stopReason.isBlank()) rs.stopReason = "Stopped by the tester"
        return sent
    }

    /** After the sending transport closes: wait for the application to reopen one, or re-join a runner session. */
    private fun restoreTarget(rs: RunState): Boolean {
        fun find(): Pair<String, DcTarget>? = rs.senderGroup.flatMap { a -> targets(a).map { a to it } }
            .firstOrNull { it.second.transport == rs.target.transport && it.second.id != rs.target.id }
            ?: rs.senderGroup.flatMap { a -> targets(a).map { a to it } }.firstOrNull { it.second.id == rs.target.id }
        fun await(ms: Long): Pair<String, DcTarget>? {
            val deadline = clock() + ms
            while (!cancelled && clock() < deadline) { find()?.let { return it }; sleeper(500) }
            return null
        }
        var found = await(20000)
        val b = browser
        if (found == null && b != null && rs.sender.session.isNotBlank() && b.isRunning(rs.sender.session)) {
            runCatching { b.runSteps(rs.sender.session, "join", { cancelled }) }
            found = await(configStore.config.browserRunner.joinTimeoutSeconds * 1000L)
        }
        val (agent, target) = found ?: return false
        if (agent != rs.sender.agentId) rs.sender = rs.participant(agent) ?: rs.sender.copy(agentId = agent)
        rs.notes += "Sending transport re-established as ${target.transport} ${target.id} at ${clock() - rs.started} ms"
        rs.target = target
        return true
    }

    private fun receiptsFor(rs: RunState, c: DcCase, sent: JsonObject?): List<Receipt> {
        val sentAt = sent?.long("sentAt") ?: 0
        val raw = if (c.marker.isNotBlank()) index.receipts.filter { it.second.str("marker") == c.marker }
            else {
                val hash = sent?.str("payloadHash") ?: sent?.str("textHash") ?: return emptyList()
                index.receipts.filter { (_, r) -> r.str("marker").isNullOrEmpty() && (r.str("payloadHash") == hash || r.str("textHash") == hash) && (r.long("t") ?: 0) >= sentAt - 500 }
            }
        val excluded = rs.senderGroup
        return raw.filter { it.first !in excluded }.map { (agent, r) ->
            val p = rs.participant(agent)
            val t = r.long("t") ?: 0
            Receipt(agent, p?.label ?: "page ${agent.takeLast(6)}", p?.role.orEmpty(), p?.room.orEmpty(), r.str("kind").orEmpty(), t, r.str("colibriClass").orEmpty(),
                r.str("from").orEmpty(), r.str("to").orEmpty(), r.long("bytes") ?: 0, if (sentAt > 0 && t > 0) t - sentAt else null, r.str("detail").orEmpty())
        }.distinctBy { listOf(it.agentId, it.kind, it.time) }
    }

    private fun windowErrors(rs: RunState, sent: JsonObject?): List<String> {
        val from = sent?.long("sentAt") ?: return emptyList()
        val to = (sent.long("settledAt") ?: from) + rs.cfg.receiptGraceMs
        return index.errors.filter { (agent, e) -> agent !in rs.senderGroup && (e.long("t") ?: 0) in from..to && (e["markers"] as? JsonArray).isNullOrEmpty() }
            .map { (agent, e) -> "${rs.participant(agent)?.label ?: agent.takeLast(6)}: ${e.str("message").orEmpty().take(200)}" }
    }

    private fun result(rs: RunState, c: DcCase, sent: JsonObject?, probe: Boolean?, override: Pair<Verdict, List<String>>? = null,
                       extra: List<String> = emptyList(), evidence: JsonObject? = null, recovery: String = ""): DcCaseResult {
        val receipts = receiptsFor(rs, c, sent)
        val (verdict, reasons) = override ?: DcClassifier.classify(CaseObservation(c, sent, receipts, windowErrors(rs, sent), probe, rs.controlPassed, live(), rs.others))
        val target = c.target ?: rs.target
        return DcCaseResult(rs.runId, c.id, c.scope.id, c.title, verdict, reasons + extra + c.notes, target.transport, c.direction, c.messageClass, c.mutation,
            c.expect.name.lowercase(), rs.sender.label, rs.sender.role, rs.sender.room, rs.sender.endpoint, "${target.transport} ${target.id} ${target.label}".trim(),
            c.payload.describe(), c.payload.kind, c.seed, c.marker, sent?.long("bytes") ?: c.payload.byteLength().takeIf { c.preVerdict == null }, rs.started,
            sent?.long("sentAt"), sent?.long("settledAt"), sent?.str("stage") ?: if (c.preVerdict != null) "not-run" else "", sent?.str("error").orEmpty(),
            sent?.long("bufferedBefore"), sent?.long("bufferedAfter"), sent?.get("stateBefore"), sent?.get("stateAfter"), receipts,
            index.errors.filter { (_, e) -> c.marker.isNotBlank() && (e["markers"] as? JsonArray)?.any { (it as? JsonPrimitive)?.contentOrNull == c.marker } == true }
                .map { (agent, e) -> "${rs.participant(agent)?.label ?: agent}: ${e.str("message")}" },
            when (probe) { true -> "delivered"; false -> "failed"; null -> "not evaluated" }, recovery,
            rs.logLines.filter { c.marker.isNotBlank() && it.contains(c.marker) }.take(20), evidence)
    }

    private fun synthetic(rs: RunState, id: String, scope: DcScope, title: String, verdict: Verdict, reasons: List<String>, evidence: JsonObject? = null,
                          transport: String = rs.target.transport): DcCaseResult =
        DcCaseResult(rs.runId, id, scope.id, title, verdict, reasons, transport, sender = rs.sender.label, senderRole = rs.sender.role, senderRoom = rs.sender.room,
            senderEndpoint = rs.sender.endpoint, target = "${rs.target.transport} ${rs.target.id}", queuedAt = rs.started, stage = "runner", evidence = evidence)

    private fun publish(rs: RunState, results: List<DcCaseResult>, emit: (String) -> Unit) {
        results.forEach { r -> rs.results += r; store.record(r); emit("${r.verdict.label.padEnd(14)} ${r.caseId}  ${r.title} — ${r.reasons.firstOrNull().orEmpty()}") }
    }

    private fun probeDelivered(rs: RunState, probe: DcCase, sent: JsonObject?): Boolean? {
        if (probe.intended.isEmpty()) return null
        if (sent == null) return null
        if (sent.str("stage") != "queued") return false
        return receiptsFor(rs, probe, sent).any { it.agentId in probe.intended }
    }

    /** One probe after every N cases. A failed probe triggers recovery and per-case isolation. */
    private fun runCases(rs: RunState, cases: List<DcCase>, emit: (String) -> Unit): List<DcCaseResult> {
        val ready = cases.filter { it.preVerdict == null }
        val sequence = mutableListOf<DcCase>()
        val probeOf = HashMap<String, DcCase>()
        ready.chunked(rs.cfg.probeEvery).forEach { group ->
            val probe = rs.gen.probe(rs.ctx, group.first().target)
            sequence += group; sequence += probe
            group.forEach { probeOf[it.id] = probe }
        }
        val sent = HashMap(execSequence(rs, sequence))
        val probeOk = sequence.filter { it.probe }.associate { it.id to probeDelivered(rs, it, sent[it.id]) }.toMutableMap()
        val overrides = HashMap<String, Pair<Pair<Verdict, List<String>>, String>>()
        for (probe in sequence.filter { it.probe && probeOk[it.id] == false }) {
            if (cancelled) break
            val group = ready.filter { probeOf[it.id]?.id == probe.id && sent.containsKey(it.id) }
            if (group.isEmpty()) continue
            emit("Delivery probe failed after ${group.first().id}…${group.last().id}; checking recovery")
            val (recovered, after) = recover(rs)
            if (!recovered) {
                group.forEach { overrides[it.id] = (Verdict.INCONCLUSIVE to listOf("Session health was lost in this case group and did not recover; the culprit could not be isolated")) to "not recovered" }
                publish(rs, listOf(synthetic(rs, "health-${probe.id}", group.first().scope, "Session health lost during ${group.first().id}…${group.last().id}", Verdict.FAIL,
                    listOf("A delivery probe after these cases failed and the session did not recover within the recovery window", "Cases: ${group.joinToString { it.id }}"))), emit)
                if (rs.stopReason.isBlank()) rs.stopReason = "Session health lost and not recovered"
                break
            }
            // Isolate: each case of the group alone, followed by its own probe.
            for (c in group) {
                if (cancelled || rs.overBudget()) break
                val single = rs.gen.probe(rs.ctx, c.target)
                val retry = execSequence(rs, listOf(c.copy(id = "${c.id}-isolated"), single))
                val delivered = probeDelivered(rs, single, retry[single.id])
                if (delivered == false) {
                    val (back, ms) = recover(rs)
                    overrides[c.id] = (Verdict.FAIL to listOf("Session health was lost immediately after this case (the delivery probe failed when it was re-run alone)",
                        if (back) "The session recovered after $ms ms" else "The session did not recover")) to (if (back) "recovered after $ms ms" else "not recovered")
                    if (!back) { rs.stopReason = "Session health lost and not recovered"; break }
                } else if (delivered == true) probeOk["isolated:${c.id}"] = true
            }
            emit("Recovery after $after ms; isolated ${group.size} case(s)")
        }
        return cases.map { c ->
            val override = overrides[c.id]
            val probe = if (probeOk["isolated:${c.id}"] == true) true else probeOf[c.id]?.let { probeOk[it.id] }
            result(rs, c, sent[c.id], probe, override?.first, recovery = override?.second.orEmpty())
        }
    }

    /** Wait for the path to recover: a fresh probe must be delivered (with one re-join attempt for runner sessions). */
    private fun recover(rs: RunState): Pair<Boolean, Long> {
        val started = clock()
        repeat(3) { attempt ->
            if (cancelled) return false to (clock() - started)
            sleeper(if (attempt == 0) 2000 else 4000)
            if (targets(rs.sender.agentId).none { it.id == rs.target.id } && !restoreTarget(rs)) return false to (clock() - started)
            val probe = rs.gen.probe(rs.ctx)
            val sent = execSequence(rs, listOf(probe))
            if (probeDelivered(rs, probe, sent[probe.id]) == true) return true to (clock() - started)
        }
        return false to (clock() - started)
    }

    // ---- families ----

    private fun learn(sender: Participant, target: DcTarget): Triple<Map<String, List<String>>, Map<String, List<String>>, Pair<String?, Set<String>>> {
        val outbound = LinkedHashMap<String, MutableList<String>>()
        val inbound = LinkedHashMap<String, MutableList<String>>()
        val classes = mutableSetOf<String>()
        var serverHello: String? = null
        for (event in telemetry.snapshot()) {
            if (event.type !in setOf("dc-send", "dc-recv", "ws-colibri-send", "ws-colibri-recv")) continue
            val obj = runCatching { json.parseToJsonElement(event.raw).jsonObject }.getOrNull() ?: continue
            obj.str("colibriClass")?.takeIf { it.isNotBlank() }?.let(classes::add)
            if (obj.str("agent") != sender.agentId) continue
            val text = obj.str("text") ?: continue
            val sameTarget = if (target.transport == "colibri-ws") event.type.startsWith("ws-colibri") else obj.str("channelId") == target.channelId || target.peerKind == "jvb"
            if (!sameTarget) continue
            val cls = obj.str("colibriClass").orEmpty()
            val bucket = if (event.type.endsWith("send")) outbound else inbound
            bucket.getOrPut(cls) { mutableListOf() }.let { if (it.size < 8 && text !in it) it += text }
            if (cls == "ServerHello") serverHello = ColibriSchemas.parseObject(text)?.str("version") ?: serverHello
        }
        return Triple(outbound, inbound, serverHello to classes)
    }

    private fun sourceNames(inbound: Map<String, List<String>>): Map<String, List<String>> {
        val names = LinkedHashMap<String, MutableList<String>>()
        inbound["VideoSourcesMap"].orEmpty().plus(inbound["AudioSourcesMap"].orEmpty()).forEach { text ->
            ColibriSchemas.parseObject(text)?.array("mappedSources")?.forEach { s ->
                val owner = s.str("owner") ?: return@forEach
                s.str("source")?.let { names.getOrPut(owner) { mutableListOf() }.add(it) }
            }
        }
        inbound["ForwardedSources"].orEmpty().forEach { text ->
            (ColibriSchemas.parseObject(text)?.get("forwardedSources") as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.forEach { source ->
                names.getOrPut(source.substringBeforeLast('-')) { mutableListOf() }.add(source)
            }
        }
        return names
    }

    fun run(options: Options = Options(), emit: (String) -> Unit = {}): DcRun? {
        val cfg = configStore.config.dataChannelSuite
        cfg.validate()
        synchronized(this) { check(!running) { "A DataChannel runner suite is already running" }; running = true }
        cancelled = false
        inbox.clear(); index = Index()
        try {
            return execute(cfg, options, emit)
        } finally {
            controller.observing = false
            running = false
        }
    }

    private fun execute(cfg: DcSuiteConfig, options: Options, emit: (String) -> Unit): DcRun? {
        val runId = UUID.randomUUID().toString()
        val seed = if (cfg.seed != 0L) cfg.seed else (System.nanoTime() and 0x7fffffffL)
        val families = (options.families ?: cfg.families).mapNotNull { DcScope.byId(it) }.toSet()
        var participants = participants(options)
        emit("Participants: ${participants.size} instrumented page(s): ${participants.joinToString("; ") { "${it.label}${if (it.endpoint.isNotBlank()) " endpoint ${it.endpoint}" else ""}" }}")
        val candidates = (options.sender?.let { id -> participants.filter { it.agentId == id } } ?: participants.sortedWith(compareBy({ if (it.room == "main") 0 else 1 }, { Roles.rank(it.role) ?: 1 })))
        val choice = candidates.firstNotNullOfOrNull { p -> targets(p.agentId).firstOrNull()?.let { p to it } }
        if (choice == null) {
            val rs = RunState(runId, seed, cfg, DcCaseGenerator(cfg, seed), participants.firstOrNull() ?: Participant("", ""), DcTarget("none"), participants,
                DcContext(Participant("", ""), DcTarget("none"), emptyList(), false, null))
            val reason = if (participants.isEmpty()) "No in-scope instrumented page is reporting. Browse the app through Burp (or launch runner sessions) and join a call."
                else "No open RTCDataChannel or Colibri WebSocket on any instrumented page. Wait for the call to connect; a channel that never reaches open cannot be tested."
            val blocked = DcScope.runnable.filter { it in families }.map { synthetic(rs, "${it.id}-blocked", it, it.title, Verdict.BLOCKED, listOf(reason)) }
            publish(rs, blocked, emit)
            return finish(rs, "No open channel")
        }
        val (sender, target) = choice
        // Observers poll faster and watch for rendered markers while the suite runs.
        controller.observing = true
        sleeper(4000)
        participants = participants(options)
        val (outbound, inbound, versionInfo) = learn(sender, target)
        val jitsi = target.peerKind == "jvb" || target.transport == "colibri-ws" || versionInfo.second.any(ColibriSchemas::known)
        val schema = if (jitsi) ColibriSchemas.select(cfg.jitsiVersion, versionInfo.first, versionInfo.second) else null
        val others = participants.filter { it.agentId != sender.agentId && (sender.session.isBlank() || it.session != sender.session) }
        val foreign = cfg.testRoomEndpoint.ifBlank { others.firstOrNull { it.room != sender.room && it.endpoint.isNotBlank() }?.endpoint.orEmpty() }
        val gen = DcCaseGenerator(cfg, seed)
        val ctx = DcContext(sender, target, others, jitsi, schema, outbound, inbound, sourceNames(inbound), foreign)
        val rs = RunState(runId, seed, cfg, gen, sender, target, participants, ctx)
        emit("Sender: ${sender.label} via ${target.transport} ${target.id} (${target.label}, ${target.peerKind}); seed $seed; ${schema?.label ?: "generic application messages (no Colibri envelope)"}")
        store.note("DataChannel runner $runId started: sender ${sender.label}, ${target.transport} ${target.id}, seed $seed",
            buildJsonObject { put("runId", runId); put("seed", seed); put("participants", json.encodeToJsonElement(participants)) })

        discovery(rs, emit)
        val generated = linkedMapOf<DcScope, List<DcCase>>()
        if (DcScope.FUZZ in families) generated[DcScope.FUZZ] = gen.fuzzCases(ctx)
        if (DcScope.BINARY in families) generated[DcScope.BINARY] = gen.binaryCases(ctx)
        if (DcScope.AUTHZ in families) generated[DcScope.AUTHZ] = gen.authzCases(ctx)
        if (DcScope.REPLAY in families) generated[DcScope.REPLAY] = gen.replayCases(ctx)
        val (kept, dropped) = DcCaseGenerator.allocate(generated, cfg.maxCases)
        rs.dropped += dropped.filterValues { it > 0 }
        for ((scope, cases) in kept) {
            if (cancelled || rs.stopReason.isNotBlank()) break
            emit("— ${scope.title}: ${cases.size} case(s)${dropped[scope]?.takeIf { it > 0 }?.let { ", $it more not run (case budget)" }.orEmpty()}")
            publish(rs, runCases(rs, cases, emit), emit)
            if (scope == DcScope.AUTHZ) { admission(rs, emit); protectedMessages(rs, emit); if (!jitsi) genericAuthzNote(rs, emit) }
            pullLog(rs)
        }
        if (DcScope.TRANSPORT in families && !cancelled && rs.stopReason.isBlank()) transport(rs, emit)
        if (DcScope.LOAD in families && !cancelled && rs.stopReason.isBlank()) load(rs, emit)
        if (DcScope.REPLAY in families && !cancelled && rs.stopReason.isBlank()) lifecycle(rs, emit)
        // Families that never produced a row are reported explicitly instead of disappearing.
        DcScope.runnable.filter { it in families && rs.results.none { r -> r.scope == it.id } }.forEach { scope ->
            publish(rs, listOf(synthetic(rs, "${scope.id}-not-run", scope, scope.title, Verdict.BLOCKED,
                listOf(rs.stopReason.ifBlank { "No case for this family could be generated for the observed application" }))), emit)
        }
        pullLog(rs)
        return finish(rs, rs.stopReason)
    }

    private fun pullLog(rs: RunState) {
        if (!rs.bridgeLog.available) return
        val lines = rs.bridgeLog.since(rs.logMark)
        rs.logMark = rs.bridgeLog.mark()
        if (lines.isEmpty()) return
        rs.logLines += lines
        store.note("Bridge log: ${lines.size} new problem line(s)", buildJsonObject { put("lines", JsonArray(lines.take(200).map(::JsonPrimitive))) })
    }

    private fun finish(rs: RunState, stopReason: String): DcRun {
        val dynamic = mutableMapOf<DcScope, MutableList<String>>()
        rs.dropped.forEach { (scope, n) -> dynamic.getOrPut(scope) { mutableListOf() } += "$n generated case(s) not run because of the case budget (maxCases ${rs.cfg.maxCases})" }
        if (rs.ctx.otherRoom.isEmpty()) dynamic.getOrPut(DcScope.AUTHZ) { mutableListOf() } += "No live test-room observer in this run"
        if (rs.ctx.sameRoom.isEmpty()) DcScope.runnable.forEach { dynamic.getOrPut(it) { mutableListOf() } += "No same-room observer: recipient receipt and delivery probes could not be evaluated" }
        rs.ctx.schema?.let { dynamic.getOrPut(DcScope.FUZZ) { mutableListOf() } += it.label }
        if (stopReason.isNotBlank()) DcScope.runnable.forEach { dynamic.getOrPut(it) { mutableListOf() } += "Run stopped: $stopReason" }
        if (rs.bridgeLog.available) dynamic.getOrPut(DcScope.FUZZ) { mutableListOf() } += "Bridge log attached: ${rs.logLines.size} problem line(s) captured"
        val coverage = DcCoverage.compute(rs.results, dynamic)
        val run = DcRun(rs.runId, rs.started, clock(), rs.seed, rs.ctx.schema?.label ?: "generic", rs.participants, rs.sender.label, rs.target.transport,
            rs.results.toList(), coverage, rs.notes.toList(), stopReason)
        store.finish(run)
        store.note("DataChannel runner ${rs.runId} finished: " + Verdict.entries.joinToString(", ") { v -> "${v.label} ${rs.results.count { it.verdict == v }}" } +
            if (stopReason.isNotBlank()) "; stopped: $stopReason" else "")
        return run
    }

    private fun discovery(rs: RunState, emit: (String) -> Unit) {
        val agents = controller.agents().filter { a -> rs.participants.any { it.agentId == a.id } }
        val inventory = buildJsonArray {
            agents.forEach { a ->
                val p = rs.participant(a.id)
                add(buildJsonObject {
                    put("participant", p?.label.orEmpty()); put("agent", a.id); put("frame", a.frame); put("endpoint", p?.endpoint.orEmpty())
                    put("channels", a.state["channels"] ?: JsonArray(emptyList())); put("sockets", a.state["sockets"] ?: JsonArray(emptyList()))
                    put("peers", a.state["pcs"] ?: JsonArray(emptyList()))
                })
            }
        }
        val channelText = agents.flatMap { a -> a.state.array("channels").map { c -> "${c.str("label")} [${c.str("peerKind")}, ${c.str("state")}, protocol=${c.str("protocol")?.ifBlank { "none" }}, ordered=${c.str("ordered")}, maxRetransmits=${c.str("maxRetransmits")}, maxMessageSize=${c.str("maxMessageSize")}]" } +
            a.state.array("sockets").map { s -> "colibri-ws ${s.str("socketId")} [${s.str("state")}, conference ${s.str("conference")}, endpoint ${s.str("endpoint")}]" } }
        val results = mutableListOf(synthetic(rs, "discovery-inventory", DcScope.DISCOVERY, "Channel inventory and JVB / participant classification", Verdict.PASS,
            listOf("Sender ${rs.sender.label} uses ${rs.target.transport} ${rs.target.id} (${rs.target.peerKind})", channelText.joinToString("; ").ifBlank { "no channel details" }),
            buildJsonObject { put("inventory", inventory) }))
        results += synthetic(rs, "discovery-observers", DcScope.DISCOVERY, "Recipient observers", if (rs.ctx.sameRoom.isEmpty()) Verdict.INCONCLUSIVE else Verdict.PASS,
            listOf("${rs.ctx.sameRoom.size} same-room and ${rs.ctx.otherRoom.size} test-room observer(s)") +
                if (rs.ctx.sameRoom.isEmpty()) listOf("Without a second instrumented participant no recipient can confirm delivery; most cases will be INCONCLUSIVE") else emptyList())
        val learned = rs.ctx.outbound.values.sumOf { it.size } + rs.ctx.inbound.values.sumOf { it.size }
        results += synthetic(rs, "discovery-baseline", DcScope.DISCOVERY, "Baseline application traffic", if (learned > 0) Verdict.PASS else Verdict.INCONCLUSIVE,
            listOf(if (learned > 0) "Learned ${rs.ctx.outbound.keys.joinToString { it.ifBlank { "untyped" } }} outbound and ${rs.ctx.inbound.keys.joinToString { it.ifBlank { "untyped" } }} inbound message type(s)"
                else "No application message was captured before testing; schema examples / synthetic templates are used"),
            buildJsonObject { put("outbound", json.encodeToJsonElement(rs.ctx.outbound)); put("inbound", json.encodeToJsonElement(rs.ctx.inbound)) })
        results += synthetic(rs, "discovery-schema", DcScope.DISCOVERY, "Message schema selection", if (rs.ctx.jitsi) Verdict.PASS else Verdict.NOT_APPLICABLE,
            listOf(rs.ctx.schema?.label ?: "Not a Jitsi / Colibri bridge channel; schemas are inferred from observed JSON messages"))
        val baseline = health(rs.participants.map { it.agentId })
        val unhealthy = baseline.filter { (_, h) -> h.array("peers").none { it.str("connectionState") == "connected" } && h.array("sockets").none { it.str("state") == "open" } }
        results += synthetic(rs, "discovery-health", DcScope.DISCOVERY, "Baseline connection health and getStats", when {
                baseline.isEmpty() -> Verdict.BLOCKED
                rs.sender.agentId in unhealthy -> Verdict.BLOCKED
                else -> Verdict.PASS },
            listOf("${baseline.size} health snapshot(s); ${unhealthy.size} page(s) without a connected peer or open bridge socket") +
                baseline.map { (a, h) -> "${rs.participant(a)?.label ?: a}: ${h.str("detail")}" },
            buildJsonObject { baseline.forEach { (a, h) -> put(a, h) } })
        publish(rs, results, emit)
        val control = rs.gen.control(rs.ctx)
        val sent = execSequence(rs, listOf(control))
        rs.controlPassed = true
        val controlResult = result(rs, control, sent[control.id], null)
        rs.controlPassed = controlResult.verdict == Verdict.PASS
        publish(rs, listOf(controlResult), emit)
        if (!rs.controlPassed) emit("Positive control did not pass; rejection-based verdicts will be INCONCLUSIVE")
    }

    private fun genericAuthzNote(rs: RunState, emit: (String) -> Unit) {
        publish(rs, listOf(synthetic(rs, "authz-envelope", DcScope.AUTHZ, "Sender / recipient / room envelope tampering", Verdict.NOT_APPLICABLE,
            listOf("The channel carries no Colibri envelope (to / from / conference); peer-to-peer data has no relay that could enforce them",
                "Define protected messages with state probes to test application role rules"))), emit)
    }

    private fun wsScopeUrl(url: String): String? = runCatching {
        val uri = URI(url)
        val secure = uri.scheme.equals("wss", true)
        "${if (secure) "https" else "http"}://${uri.host}:${if (uri.port > 0) uri.port else if (secure) 443 else 80}/"
    }.getOrNull()

    /** Fresh Colibri WebSocket admissions with tampered credentials or identifiers. */
    private fun admission(rs: RunState, emit: (String) -> Unit) {
        val socket = rs.senderGroup.flatMap(::targets).firstOrNull { it.transport == "colibri-ws" && it.url.isNotBlank() }
        if (socket == null) {
            publish(rs, listOf(synthetic(rs, "authz-ws-admission", DcScope.AUTHZ, "Colibri WebSocket admission with tampered URL", Verdict.NOT_APPLICABLE,
                listOf("The sender has no open Colibri WebSocket; the bridge channel uses SCTP, which is admitted through ICE/DTLS rather than a URL"))), emit)
            return
        }
        val hints = Regex("/colibri-ws/([^/?#]+)/([^/?#]+)/([^/?#]+)").find(socket.url)
        val foreignConference = rs.ctx.otherRoom.firstOrNull { it.conference.isNotBlank() }?.conference
        val recipient = rs.ctx.recipient?.endpoint
        fun replaceSegment(group: Int, value: String) = hints?.let { m -> socket.url.replaceRange(m.groups[group]!!.range, value) }
        val pwd = Regex("([?&]pwd=)([^&]*)")
        val attempts = listOf(
            Triple("authz-ws-wrong-pwd", "Wrong pwd", if (pwd.containsMatchIn(socket.url)) socket.url.replace(pwd, "$1wrtc${Markers.next().drop(4)}") else null),
            Triple("authz-ws-no-pwd", "No pwd", if (pwd.containsMatchIn(socket.url)) socket.url.replace(Regex("([?&])pwd=[^&]*&?"), "$1").trimEnd('?', '&') else null),
            Triple("authz-ws-foreign-conference", "Another conference (test room)", foreignConference?.let { replaceSegment(2, it) }),
            Triple("authz-ws-foreign-endpoint", "Another participant's endpoint with the sender's pwd", recipient?.let { replaceSegment(3, it) }))
        val results = attempts.map { (id, title, url) ->
            if (url == null) return@map synthetic(rs, id, DcScope.AUTHZ, "Colibri WebSocket admission: $title", Verdict.INCONCLUSIVE,
                listOf(if (id.contains("foreign")) "The identifier needed for this attempt is not known (start a test-room session / second participant)" else "The socket URL has no pwd parameter"), transport = "colibri-ws")
            val config = buildJsonObject { put("caseId", id); put("url", url); put("timeoutMs", 6000); put("send", "{\"colibriClass\":\"ClientHello\"}") }
            val job = execute(rs.sender.agentId, "ws-admission", config, 12000, wsScopeUrl(url))
            val event = eventsFor(job.id, "ws-admission-result").lastOrNull()
            val controlOpen = targets(rs.sender.agentId).any { it.id == socket.id }
            var (verdict, reason) = if (job.id == null) Verdict.BLOCKED to job.error else DcClassifier.admission(event, controlOpen)
            val extra = mutableListOf("URL: $url")
            if (id == "authz-ws-foreign-endpoint") {
                val victim = rs.ctx.recipient
                if (victim != null && targets(victim.agentId).none { it.transport == "colibri-ws" } &&
                    rs.participants.filter { it.session == victim.session || it.agentId == victim.agentId }.none { p -> targets(p.agentId).any { it.transport == "colibri-ws" } }) {
                    verdict = Verdict.FAIL; extra += "The victim participant lost its Colibri WebSocket after the attempt (bridge channel displaced)"
                }
            }
            synthetic(rs, id, DcScope.AUTHZ, "Colibri WebSocket admission: $title", verdict, listOf(reason) + extra, event, "colibri-ws")
        }
        publish(rs, results, emit)
    }

    /** Role rules for application commands: positive control from an allowed role, then an attempt from a denied role. */
    private fun protectedMessages(rs: RunState, emit: (String) -> Unit) {
        for (pm in rs.cfg.protectedMessages) {
            if (cancelled) return
            val id = "authz-protected-${pm.name.lowercase().replace(Regex("[^a-z0-9]+"), "-").take(32)}"
            fun blocked(reason: String) = publish(rs, listOf(synthetic(rs, id, DcScope.AUTHZ, "Protected message '${pm.name}'", Verdict.BLOCKED, listOf(reason))), emit)
            val b = browser
            if (b == null) { blocked("State probes need integrated runner sessions"); continue }
            if (pm.stateProbe.isBlank()) { blocked("No state probe is defined, so a protected effect cannot be verified"); continue }
            val sameRoom = rs.participants.filter { it.room == rs.sender.room && it.session.isNotBlank() && b.isRunning(it.session) }
            val recipient = sameRoom.firstOrNull { it.role.equals(pm.recipientRole, true) }
            val allowed = sameRoom.firstOrNull { it.role in pm.allowedRoles && it.session != recipient?.session && targets(it.agentId).isNotEmpty() }
            val denied = sameRoom.firstOrNull { it.role !in pm.allowedRoles && it.session != recipient?.session && targets(it.agentId).isNotEmpty() }
            if (recipient == null || allowed == null || denied == null) { blocked("Needs live runner sessions for the recipient role (${pm.recipientRole}), an allowed role (${pm.allowedRoles.joinToString()}) and a role that is not allowed"); continue }
            fun probe(): String = runCatching { b.evaluate(recipient.session, pm.stateProbe).toString() }.getOrElse { "error: ${it.message}" }
            fun send(from: Participant): Pair<DcCase, JsonObject?> {
                val m = Markers.next()
                val text = pm.template.replace("{marker}", m).replace("{to}", recipient.endpoint)
                val target = targets(from.agentId).first()
                val c = DcCase("$id-${from.role}", DcScope.AUTHZ, "Protected message '${pm.name}' from ${from.role}", PayloadSpec.text(text), m, Expect.TOLERATE, pm.name, "protected-role",
                    intended = setOf(recipient.agentId), target = target)
                val config = buildJsonObject { target.commandFields().forEach { (k, v) -> put(k, v) }; put("settleMs", rs.cfg.settleMs); put("maxMessageBytes", rs.cfg.maxMessageBytes)
                    put("maxTotalBytes", rs.cfg.maxMessageBytes); put("maxBufferedAmount", rs.cfg.maxBufferedAmount); put("cases", buildJsonArray { add(caseJson(c)) }) }
                val job = execute(from.agentId, "dc-suite", config, rs.cfg.settleMs + 10000L)
                sleeper(rs.cfg.receiptGraceMs.toLong()); refresh()
                return c to eventsFor(job.id, "dc-case").lastOrNull()
            }
            val before = probe()
            val (controlCase, controlSent) = send(allowed)
            val afterControl = probe()
            val controlChanged = afterControl != before
            publish(rs, listOf(result(rs, controlCase, controlSent, null, if (controlChanged) Verdict.PASS to listOf("Allowed role ${allowed.role} changed the protected state ($before → $afterControl)")
                else Verdict.INCONCLUSIVE to listOf("The allowed role's message did not change the protected state ($before); the probe or template may not match the application"))), emit)
            if (!controlChanged) continue
            if (pm.restore.isNotBlank()) runCatching { b.runSteps(recipient.session, "restore", { cancelled }, pm.restore) }
            val restored = probe()
            if (restored != before) {
                publish(rs, listOf(synthetic(rs, "$id-denied", DcScope.AUTHZ, "Protected message '${pm.name}' from ${denied.role}", Verdict.INCONCLUSIVE,
                    listOf("Protected state could not be restored ($restored, expected $before); add restore steps"))), emit); continue
            }
            val (deniedCase, deniedSent) = send(denied)
            val after = probe()
            publish(rs, listOf(result(rs, deniedCase, deniedSent, null, if (after != before) Verdict.FAIL to listOf("Role ${denied.role} changed the protected state ($before → $after) with a message only ${pm.allowedRoles.joinToString()} may send")
                else Verdict.PASS to listOf("Role ${denied.role}'s message did not change the protected state ($before); the allowed-role control did"))), emit)
        }
    }

    private fun transport(rs: RunState, emit: (String) -> Unit) {
        emit("— ${DcScope.TRANSPORT.title}")
        val available = rs.senderGroup.flatMap(::targets)
        val dc = available.firstOrNull { it.transport == "datachannel" && it.peerKind in setOf("jvb", "sfu") }
        val ws = available.firstOrNull { it.transport == "colibri-ws" }
        if (dc == null || ws == null) {
            publish(rs, listOf(synthetic(rs, "transport-compare", DcScope.TRANSPORT, "RTCDataChannel vs Colibri WebSocket", Verdict.NOT_APPLICABLE,
                listOf("Only ${if (ws != null) "a Colibri WebSocket" else if (dc != null) "an RTCDataChannel" else "a non-bridge channel"} carries bridge messages in this session; there is no second transport to compare"))), emit)
        } else {
            val secondary = if (rs.target.transport == "datachannel") ws else dc
            val results = runCases(rs, rs.gen.transportCases(rs.ctx, secondary), emit)
            publish(rs, results, emit)
            val primary = rs.results.filter { it.scope in setOf(DcScope.FUZZ.id, DcScope.AUTHZ.id) && it.transport == rs.target.transport }.associateBy { it.mutation + "|" + it.messageClass }
            val differences = results.mapNotNull { r -> primary[r.mutation + "|" + r.messageClass]?.takeIf { it.verdict != r.verdict }?.let { "${r.mutation}: ${it.transport} ${it.verdict.label} vs ${r.transport} ${r.verdict.label}" } }
            publish(rs, listOf(synthetic(rs, "transport-compare", DcScope.TRANSPORT, "RTCDataChannel vs Colibri WebSocket handling", if (differences.isEmpty()) Verdict.PASS else Verdict.INCONCLUSIVE,
                if (differences.isEmpty()) listOf("Equivalent cases were classified the same on both transports") else listOf("Transports handled equivalent cases differently; review:") + differences)), emit)
        }
        if (ws != null && !cancelled) {
            val job = execute(rs.sender.agentId, "transport-action", buildJsonObject { put("action", "close-ws"); put("socketId", ws.socketId); put("waitMs", 15000); put("caseId", "transport-reconnect") }, 25000)
            val event = eventsFor(job.id, "transport-action-result").lastOrNull()
            val reopened = event?.str("reopened").orEmpty()
            val verdict: Pair<Verdict, List<String>> = when {
                event == null -> Verdict.BLOCKED to listOf("The reconnect action did not run: ${job.error.ifBlank { job.state }}")
                reopened.isBlank() -> Verdict.FAIL to listOf("The application did not re-establish its Colibri WebSocket within 15 s of the socket closing")
                else -> {
                    val newTarget = targets(rs.sender.agentId).firstOrNull { it.socketId == reopened }
                    if (rs.target.transport == "colibri-ws" && newTarget != null) rs.target = newTarget
                    val probe = rs.gen.probe(rs.ctx, newTarget)
                    val ok = probeDelivered(rs, probe, execSequence(rs, listOf(probe))[probe.id])
                    when (ok) {
                        true -> Verdict.PASS to listOf("Reconnected as $reopened after ${event.str("reopenMs")} ms and delivered a probe")
                        false -> Verdict.FAIL to listOf("Reconnected as $reopened but a probe through it was not delivered")
                        null -> Verdict.INCONCLUSIVE to listOf("Reconnected as $reopened; no same-room observer to confirm delivery")
                    }
                }
            }
            publish(rs, listOf(synthetic(rs, "transport-reconnect", DcScope.TRANSPORT, "Colibri WebSocket reconnect", verdict.first, verdict.second, event, "colibri-ws")), emit)
        }
    }

    private fun lossPct(h: JsonObject?): Pair<Long, Long> = h?.array("peers")?.fold(0L to 0L) { acc, p ->
        val m = p["media"] as? JsonObject ?: return@fold acc
        (acc.first + (m.long("packetsLost") ?: 0)) to (acc.second + (m.long("packetsReceived") ?: 0))
    } ?: (0L to 0L)

    private fun healthLost(rs: RunState, before: Map<String, JsonObject>, after: Map<String, JsonObject>): Boolean {
        if (targets(rs.sender.agentId).none { it.id == rs.target.id }) return true
        return before.any { (agent, h) ->
            val connected = h.array("peers").filter { it.str("connectionState") == "connected" }.mapNotNull { it.str("pcId") }.toSet()
            val now = after[agent] ?: return@any agent in live()
            connected.any { pc -> now.array("peers").firstOrNull { it.str("pcId") == pc }?.str("connectionState") in setOf("failed", "closed", "disconnected") }
        }
    }

    private fun load(rs: RunState, emit: (String) -> Unit) {
        emit("— ${DcScope.LOAD.title}")
        val (prefix, suffix) = rs.gen.loadFrame(rs.ctx)
        val intended = rs.ctx.sameRoom.map { it.agentId }.toSet()
        val everyone = rs.participants.map { it.agentId }
        val steps = rs.cfg.loadRates.map { "rate" to it } + if (rs.cfg.burstSize > 0) listOf("burst" to rs.cfg.burstSize) else emptyList()
        var stopped = ""
        for ((stepIndex, step) in steps.withIndex()) {
            val (mode, value) = step
            val id = if (mode == "rate") "load-rate-$value" else "load-burst-$value"
            val title = if (mode == "rate") "$value messages/s for ${rs.cfg.loadStepSeconds} s" else "Burst of $value messages"
            if (stopped.isNotBlank() || cancelled || rs.overBudget()) {
                publish(rs, listOf(synthetic(rs, id, DcScope.LOAD, title, Verdict.BLOCKED, listOf(stopped.ifBlank { "Run stopped or budget reached" }))), emit); continue
            }
            val before = health(everyone)
            val stem = Markers.stem()
            val config = buildJsonObject {
                rs.target.commandFields().forEach { (k, v) -> put(k, v) }
                put("mode", mode); put("markerStem", stem); put("prefix", prefix); put("suffix", suffix); put("maxBufferedAmount", rs.cfg.maxBufferedAmount)
                put("maxBytes", (rs.cfg.maxTotalBytes - rs.bytesUsed).coerceIn(1, 16777216).toInt())
                if (mode == "rate") { put("rate", value); put("durationMs", rs.cfg.loadStepSeconds * 1000); put("maxMessages", minOf(10000, value * rs.cfg.loadStepSeconds * 2)) }
                else { put("count", value); put("maxMessages", value) }
            }
            val job = execute(rs.sender.agentId, "dc-load", config, rs.cfg.loadStepSeconds * 1000L + 15000)
            sleeper(rs.cfg.receiptGraceMs + 1000L); refresh()
            val event = eventsFor(job.id, "dc-load-step").lastOrNull()
            val after = health(everyone)
            val sent = event?.long("sent")?.toInt() ?: 0
            rs.bytesUsed += event?.long("bytes") ?: 0
            val started = event?.long("startedAt") ?: 0
            val first = event?.long("firstSeq") ?: 0
            val receipts = index.receipts.filter { (agent, r) -> agent in intended && r.str("marker")?.startsWith(stem) == true }
            val perAgent = receipts.groupBy { it.first }.mapValues { (_, list) -> list.mapNotNull { it.second.str("marker") }.toSet().size }
            val ratio = if (intended.isEmpty() || sent == 0) null else intended.filter { it in live() }.minOfOrNull { (perAgent[it] ?: 0).toDouble() / sent }
            val interval = if (mode == "rate") 1000.0 / value else 0.0
            val latencies = receipts.mapNotNull { (_, r) ->
                val seq = r.str("marker")?.takeLast(4)?.toLongOrNull(36) ?: return@mapNotNull null
                r.long("t")?.let { it - (started + ((seq - first) * interval).toLong()) }?.coerceAtLeast(0)
            }
            val lossIncrease = intended.mapNotNull { a ->
                val (l0, r0) = lossPct(before[a]); val (l1, r1) = lossPct(after[a])
                val dl = l1 - l0; val dr = r1 - r0
                if (dl + dr <= 0) null else (dl * 100.0 / (dl + dr)) - (if (l0 + r0 > 0) l0 * 100.0 / (l0 + r0) else 0.0)
            }.maxOrNull()
            val metrics = DcClassifier.LoadMetrics(sent, ratio, DcClassifier.percentile(latencies, 0.95), lossIncrease, healthLost(rs, before, after))
            var (verdict, reason) = if (event == null) Verdict.BLOCKED to "The load step did not run: ${job.error.ifBlank { job.state }}" else DcClassifier.load(metrics, rs.cfg, intended.isNotEmpty())
            val extra = mutableListOf<String>()
            event?.str("stopReason")?.takeIf { it.isNotBlank() }?.let { extra += "Agent stopped the step: $it (max bufferedAmount ${event.long("maxBuffered")})" }
            if (verdict == Verdict.FAIL) {
                stopped = "Stopped after degradation at step ${stepIndex + 1} ($title)"
                val (back, ms) = recover(rs)
                extra += if (back) "Recovered after $ms ms" else "Did not recover"
                if (!back) rs.stopReason = "Session did not recover after load"
            }
            publish(rs, listOf(synthetic(rs, id, DcScope.LOAD, title, verdict, listOf(reason) + extra, buildJsonObject {
                event?.let { put("step", it) }; put("receivedPerAgent", json.encodeToJsonElement(perAgent)); put("latencySamples", latencies.size)
                put("healthBefore", JsonObject(before)); put("healthAfter", JsonObject(after))
            })), emit)
        }
        churn(rs, emit)
    }

    private fun churn(rs: RunState, emit: (String) -> Unit) {
        val channel = targets(rs.sender.agentId).firstOrNull { it.transport == "datachannel" }
        val agent = controller.agents().firstOrNull { it.id == rs.sender.agentId }
        val sctp = agent?.state?.array("channels")?.firstOrNull { it.str("channelId") == channel?.channelId }?.str("sctpState")
        if (channel == null || sctp != "connected") {
            publish(rs, listOf(synthetic(rs, "churn", DcScope.LOAD, "Channel churn and reliability variants", Verdict.NOT_APPLICABLE,
                listOf(if (channel == null) "The sender has no RTCDataChannel (a Colibri WebSocket has no SCTP streams to churn)" else "The SCTP association is $sctp; churn would trigger renegotiation"))), emit)
            return
        }
        val variants = buildJsonArray {
            add(buildJsonObject { put("name", "reliable-ordered") })
            add(buildJsonObject { put("name", "unordered"); put("ordered", false) })
            add(buildJsonObject { put("name", "maxRetransmits-0"); put("maxRetransmits", 0) })
            add(buildJsonObject { put("name", "maxPacketLifeTime-100"); put("maxPacketLifeTime", 100) })
            add(buildJsonObject { put("name", "negotiated-id"); put("negotiated", true); put("id", 1000) })
            add(buildJsonObject { put("name", "long-protocol"); put("protocol", "p".repeat(1024)) })
            add(buildJsonObject { put("name", "long-label"); put("label", "l".repeat(1024)) })
            add(buildJsonObject { put("name", "invalid-both-limits"); put("maxRetransmits", 0); put("maxPacketLifeTime", 100) })
        }
        for ((mode, iterations) in listOf("sequential" to rs.cfg.churnIterations, "concurrent" to rs.cfg.maxChannels)) {
            if (cancelled) return
            val before = health(rs.participants.map { it.agentId })
            val job = execute(rs.sender.agentId, "dc-churn", buildJsonObject {
                put("pcId", channel.pcId); put("mode", mode); put("iterations", iterations); put("openTimeoutMs", 5000)
                put("variants", if (mode == "sequential") variants else buildJsonArray { add(buildJsonObject { put("name", "reliable-ordered") }) })
            }, iterations * 6000L + 10000)
            val results = eventsFor(job.id, "dc-churn-result")
            val summary = eventsFor(job.id, "dc-churn-summary").lastOrNull()
            val after = health(rs.participants.map { it.agentId })
            val probe = rs.gen.probe(rs.ctx)
            val delivered = probeDelivered(rs, probe, execSequence(rs, listOf(probe))[probe.id])
            val outcomes = results.groupBy { it.str("variant").orEmpty() }.map { (v, list) -> "$v: ${list.map { it.str("outcome") }.distinct().joinToString("/")}" }
            val local = results.filter { it.str("outcome") == "create-rejected" }.map { "${it.str("variant")}: browser rejected locally (${it.str("error")})" }
            val lost = healthLost(rs, before, after)
            val verdict = when {
                summary == null -> Verdict.BLOCKED to listOf("Churn did not run: ${eventsFor(job.id, "dc-churn-error").lastOrNull()?.str("detail") ?: job.error.ifBlank { job.state }}")
                lost || delivered == false -> Verdict.FAIL to listOf("Session health was lost after $mode channel churn")
                delivered == null -> Verdict.INCONCLUSIVE to listOf("Churn completed; no same-room observer to confirm the application channel still delivers")
                else -> Verdict.PASS to listOf("Application channel still delivered after $mode churn (${summary.str("detail")})")
            }
            publish(rs, listOf(synthetic(rs, "churn-$mode", DcScope.LOAD, "Channel churn ($mode, $iterations channel(s))", verdict.first, verdict.second + outcomes + local +
                listOfNotNull(summary?.long("maxChannels")?.let { "SCTP maxChannels $it" }), buildJsonObject { put("results", JsonArray(results)); summary?.let { put("summary", it) } })), emit)
        }
    }

    // ---- lifecycle (integrated runner) ----

    private fun lifecycle(rs: RunState, emit: (String) -> Unit) {
        emit("— Lifecycle (${DcScope.REPLAY.title})")
        val titles = listOf("lifecycle-leave" to "Customer leave closes the old channel", "lifecycle-rejoin-replay" to "Stale messages replayed after re-join",
            "lifecycle-reconnect" to "Network interruption and reconnect", "lifecycle-hangup" to "Advisor hang-up ends the customer session",
            "lifecycle-admission" to "Fresh admission after the call ended", "lifecycle-removal" to "Removed participant cannot keep or regain access")
        val b = browser
        val customer = rs.sender.session.takeIf { it.isNotBlank() && b?.isRunning(it) == true }?.let { name -> configStore.config.browserRunner.sessions.firstOrNull { it.name == name } }
        val advisor = configStore.config.browserRunner.sessions.firstOrNull { s -> s.name != customer?.name && s.room == (customer?.room ?: "main") &&
            b?.isRunning(s.name) == true && (s.role.equals("advisor", true) || s.hangup.isNotBlank()) }
        if (b == null || customer == null) {
            publish(rs, titles.map { (id, title) -> synthetic(rs, id, DcScope.REPLAY, title, Verdict.BLOCKED,
                listOf("Needs the sender to be an integrated runner session with call controls (Tests → Data channel runner → Sessions)")) }, emit)
            return
        }
        val results = mutableListOf<DcCaseResult>()
        fun blocked(id: String, reason: String) = synthetic(rs, id, DcScope.REPLAY, titles.first { it.first == id }.second, Verdict.BLOCKED, listOf(reason))
        fun sessionTargets(name: String) = b.agentsFor(name).flatMap { a -> targets(a.id).map { a.id to it } }
        fun awaitTargets(name: String, ms: Long): List<Pair<String, DcTarget>> {
            val deadline = clock() + ms
            while (!cancelled && clock() < deadline) { sessionTargets(name).takeIf { it.isNotEmpty() }?.let { return it }; sleeper(500) }
            return emptyList()
        }
        fun awaitClosed(old: List<Pair<String, DcTarget>>, ms: Long): Long? {
            val started = clock(); val deadline = started + ms
            while (!cancelled && clock() < deadline) {
                if (old.none { (agent, t) -> targets(agent).any { it.id == t.id } }) return clock() - started
                sleeper(250)
            }
            return null
        }
        fun probeVia(agent: String, target: DcTarget): Boolean? {
            val probe = rs.gen.probe(rs.ctx, target)
            return probeDelivered(rs, probe, execSequence(rs, listOf(probe), agent)[probe.id])
        }
        fun step(name: String, which: String): String? = runCatching { b.runSteps(name, which, { cancelled }); null }.getOrElse { it.message ?: "failed" }
        val joinMs = configStore.config.browserRunner.joinTimeoutSeconds * 1000L
        val oldUrl = sessionTargets(customer.name).map { it.second }.firstOrNull { it.transport == "colibri-ws" }?.url

        // Leave.
        val beforeLeave = sessionTargets(customer.name)
        if (customer.leave.isBlank()) results += blocked("lifecycle-leave", "Session '${customer.name}' has no Leave steps")
        else {
            val started = clock()
            val error = step(customer.name, "leave")
            val closedAfter = awaitClosed(beforeLeave, 10000)
            results += when {
                error != null -> blocked("lifecycle-leave", "Leave steps failed: $error")
                closedAfter != null -> synthetic(rs, "lifecycle-leave", DcScope.REPLAY, titles[0].second, Verdict.PASS,
                    listOf("The customer's channel(s) closed ${closedAfter} ms after the leave action (action at +${started - rs.started} ms)"))
                else -> {
                    val (agent, old) = beforeLeave.first()
                    when (probeVia(agent, old)) {
                        true -> synthetic(rs, "lifecycle-leave", DcScope.REPLAY, titles[0].second, Verdict.FAIL, listOf("The old channel stayed open 10 s after leaving and still delivered a message to the call"))
                        false -> synthetic(rs, "lifecycle-leave", DcScope.REPLAY, titles[0].second, Verdict.PASS, listOf("The old channel stayed open but the bridge no longer relayed its messages"))
                        null -> synthetic(rs, "lifecycle-leave", DcScope.REPLAY, titles[0].second, Verdict.INCONCLUSIVE, listOf("The old channel stayed open; no same-room observer to check delivery"))
                    }
                }
            }
        }
        // Re-join and stale replay.
        val rejoinError = if (customer.join.isBlank()) "Session '${customer.name}' has no Join steps" else step(customer.name, "join")
        val fresh = if (rejoinError == null) awaitTargets(customer.name, joinMs) else emptyList()
        if (fresh.isEmpty()) results += blocked("lifecycle-rejoin-replay", rejoinError ?: "The customer did not re-join within ${joinMs / 1000} s")
        else {
            val (agent, target) = fresh.first()
            rs.sender = rs.participant(agent) ?: rs.sender.copy(agentId = agent)
            rs.target = target
            val stale = rs.ctx.outbound.values.flatten().distinct().take(5).map { text ->
                DcCase("lifecycle-stale-${text.hashCode().toUInt().toString(36)}", DcScope.REPLAY, "Stale ${ColibriSchemas.colibriClass(text) ?: "message"} from the previous session",
                    PayloadSpec.text(text), "", Expect.TOLERATE, ColibriSchemas.colibriClass(text).orEmpty(), "stale-replay")
            }
            if (stale.isEmpty()) results += synthetic(rs, "lifecycle-rejoin-replay", DcScope.REPLAY, titles[1].second, Verdict.INCONCLUSIVE, listOf("Nothing was captured before leaving to replay"))
            else results += runCases(rs, stale, emit)
            if (oldUrl != null) {
                val job = execute(agent, "ws-admission", buildJsonObject { put("caseId", "lifecycle-old-url"); put("url", oldUrl); put("timeoutMs", 6000); put("send", "{\"colibriClass\":\"ClientHello\"}") }, 12000, wsScopeUrl(oldUrl))
                val (v, reason) = if (job.id == null) Verdict.BLOCKED to job.error else DcClassifier.admission(eventsFor(job.id, "ws-admission-result").lastOrNull(), target.transport == "colibri-ws")
                results += synthetic(rs, "lifecycle-old-url", DcScope.REPLAY, "Old Colibri WebSocket URL after leaving", v, listOf(reason, "URL: $oldUrl"), transport = "colibri-ws")
            }
        }
        // Network interruption.
        if (fresh.isEmpty()) results += blocked("lifecycle-reconnect", "The customer is not in the call")
        else {
            b.setOffline(customer.name, true); sleeper(5000); b.setOffline(customer.name, false)
            val back = awaitTargets(customer.name, 20000)
            val delivered = back.firstOrNull()?.let { (a, t) -> rs.target = t; probeVia(a, t) }
            results += synthetic(rs, "lifecycle-reconnect", DcScope.REPLAY, titles[2].second, when { back.isEmpty() -> Verdict.FAIL; delivered == true -> Verdict.PASS; delivered == false -> Verdict.FAIL; else -> Verdict.INCONCLUSIVE },
                listOf(if (back.isEmpty()) "No open channel within 20 s after a 5 s HTTP/WebSocket outage" else "Channel open after the outage; probe ${when (delivered) { true -> "delivered"; false -> "not delivered"; null -> "not observable" }}",
                    "DevTools network emulation interrupts HTTP and WebSocket traffic, not established UDP media"))
        }
        // Advisor hang-up and fresh admission.
        if (advisor == null || advisor.hangup.isBlank()) {
            results += blocked("lifecycle-hangup", "Needs a live advisor runner session with Hang up steps")
            results += blocked("lifecycle-admission", "Needs the advisor hang-up to run first")
        } else {
            val before = sessionTargets(customer.name)
            val started = clock()
            val error = step(advisor.name, "hangup")
            val closedAfter = if (error == null) awaitClosed(before, 15000) else null
            results += when {
                error != null -> blocked("lifecycle-hangup", "Hang up steps failed: $error")
                !rs.cfg.expectDisconnectOnHangup -> synthetic(rs, "lifecycle-hangup", DcScope.REPLAY, titles[3].second, Verdict.NOT_APPLICABLE,
                    listOf("Configured as not expected to disconnect; observed ${if (closedAfter != null) "closure after $closedAfter ms" else "no closure within 15 s"}"))
                closedAfter != null -> synthetic(rs, "lifecycle-hangup", DcScope.REPLAY, titles[3].second, Verdict.PASS,
                    listOf("The customer's channel(s) closed $closedAfter ms after the advisor's hang-up (action at +${started - rs.started} ms)"))
                else -> synthetic(rs, "lifecycle-hangup", DcScope.REPLAY, titles[3].second, Verdict.FAIL, listOf("The customer stayed connected 15 s after the advisor ended the call"))
            }
            val urlBefore = before.map { it.second }.firstOrNull { it.transport == "colibri-ws" }?.url
            val joinError = step(customer.name, "join")
            val admitted = awaitTargets(customer.name, joinMs).isNotEmpty()
            results += synthetic(rs, "lifecycle-admission", DcScope.REPLAY, titles[4].second, when (rs.cfg.rejoinAfterHangup) {
                    "denied" -> if (admitted) Verdict.FAIL else Verdict.PASS
                    "allowed" -> if (admitted) Verdict.PASS else Verdict.INCONCLUSIVE
                    else -> Verdict.NOT_APPLICABLE },
                listOf("Customer re-join after hang-up was ${if (admitted) "admitted (open channel)" else "not admitted within ${joinMs / 1000} s"}; expected: ${rs.cfg.rejoinAfterHangup}") +
                    listOfNotNull(joinError?.let { "Join steps reported: $it" }))
            if (urlBefore != null) {
                val agent = b.agentFor(customer.name)?.id ?: rs.sender.agentId
                val job = execute(agent, "ws-admission", buildJsonObject { put("caseId", "lifecycle-ended-url"); put("url", urlBefore); put("timeoutMs", 6000); put("send", "{\"colibriClass\":\"ClientHello\"}") }, 12000, wsScopeUrl(urlBefore))
                val (v, reason) = if (job.id == null) Verdict.BLOCKED to job.error else DcClassifier.admission(eventsFor(job.id, "ws-admission-result").lastOrNull(), true)
                results += synthetic(rs, "lifecycle-ended-url", DcScope.REPLAY, "Colibri WebSocket URL from the ended call", v, listOf(reason, "URL: $urlBefore"), transport = "colibri-ws")
            }
        }
        // Removal.
        if (advisor == null || advisor.remove.isBlank()) results += blocked("lifecycle-removal", "Needs a live advisor runner session with Remove participant steps")
        else {
            step(advisor.name, "join"); step(customer.name, "join")
            val inCall = awaitTargets(customer.name, joinMs)
            if (inCall.isEmpty()) results += blocked("lifecycle-removal", "The customer could not re-join before the removal test")
            else {
                val error = step(advisor.name, "remove")
                val closedAfter = if (error == null) awaitClosed(inCall, 15000) else null
                val oldStillDelivers = if (error == null && closedAfter == null) probeVia(inCall.first().first, inCall.first().second) else null
                step(customer.name, "join")
                val regained = awaitTargets(customer.name, joinMs).isNotEmpty()
                val (verdict, reasons) = when {
                    error != null -> Verdict.BLOCKED to listOf("Remove steps failed: $error")
                    oldStillDelivers == true -> Verdict.FAIL to listOf("The removed customer's channel stayed open and still delivered messages")
                    rs.cfg.rejoinAfterRemoval == "denied" && regained -> Verdict.FAIL to listOf("The removed customer re-joined the call")
                    closedAfter == null && oldStillDelivers == null -> Verdict.INCONCLUSIVE to listOf("The channel stayed open; no observer to check delivery")
                    else -> Verdict.PASS to listOf(if (closedAfter != null) "Removed customer's channel closed after $closedAfter ms" else "Old channel no longer delivered",
                        "Re-join ${if (regained) "admitted" else "refused"} (expected ${rs.cfg.rejoinAfterRemoval})")
                }
                results += synthetic(rs, "lifecycle-removal", DcScope.REPLAY, titles[5].second, verdict, reasons)
            }
        }
        // Restore the call for later runs.
        advisor?.let { if (it.join.isNotBlank()) step(it.name, "join") }
        if (customer.join.isNotBlank() && sessionTargets(customer.name).isEmpty()) step(customer.name, "join")
        publish(rs, results, emit)
    }
}
