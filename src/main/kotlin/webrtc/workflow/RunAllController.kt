package webrtc.workflow

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import webrtc.bridge.ActiveTestController
import webrtc.config.ConfigStore
import webrtc.config.Detectors
import webrtc.config.IdentityProfile
import webrtc.config.IpAddresses
import webrtc.internals.InternalsComparator
import webrtc.telemetry.EvidenceAnalysis
import webrtc.telemetry.CertificateAnalyzer
import webrtc.telemetry.StatsSnapshot
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import webrtc.tls.TlsScanRunner
import webrtc.authz.AuthzResult
import webrtc.report.SecurityTestReport
import webrtc.report.CoverageSupport

/**
 * The beginner-friendly "Run all" orchestration. It runs the checks that can be
 * run safely and automatically, in order, and reports everything in plain
 * English — including what it deliberately skipped and why.
 *
 * What it can do on its own: review the passive telemetry already collected
 * (M1/M2), and drive the live active checks (M6 ICE gather, M4 DataChannel fuzz)
 * against any browser page the agent is live on. What it cannot do on its own,
 * and therefore only guides: M3 needs a fresh negotiation started in the browser,
 * and M5 needs the tester to pick a request to replay. Nothing here invents a
 * finding — it reports what the modules actually observed.
 */
class RunAllController(
    private val configStore: ConfigStore,
    private val controller: ActiveTestController,
    private val telemetry: TelemetryTableModel,
    private val tlsRunner: TlsScanRunner? = null,
    private val authzResults: () -> List<AuthzResult> = { emptyList() },
    private val signalingEndpoints: () -> List<SignalingMetadata.Endpoint> = { emptyList() },
    private val assessments: webrtc.assessment.AssessmentController? = null
) {
    /** One line of the run report, tagged so the UI can format it. */
    enum class Level { HEAD, OK, INFO, WARN, FINDING, FAIL, SKIP }
    data class Line(val level: Level, val text: String)

    @Volatile private var cancelled = false
    private val json = Json { ignoreUnknownKeys = true }

    /** Already-captured metadata for the report; never queues a request. */
    fun observedSignalingEndpoints(): List<SignalingMetadata.Endpoint> = runCatching { signalingEndpoints() }.getOrDefault(emptyList())

    fun requestStop() { cancelled = true; tlsRunner?.stop(); assessments?.stop(); controller.cancelAll() }
    fun reset() { cancelled = false }

    /** Runs the whole sequence, emitting report lines through [emit]. Call off the EDT. */
    fun run(emit: (Line) -> Unit) {
        reset()
        val cfg = configStore.config

        emit(Line(Level.HEAD, "1. Configuration (M0)"))
        val configReady = checkConfig(emit)

        emit(Line(Level.HEAD, "2. Passive telemetry review (M1 injection / M2 telemetry)"))
        reviewTelemetry(emit)

        emit(Line(Level.HEAD, "2b. Signaling endpoint metadata (T7, passive)"))
        reviewSignaling(emit)

        emit(Line(Level.HEAD, "3. Live active checks (M6 TURN/STUN, T1 stats capture, M4 DataChannel fuzz, M3+ SDP fuzz)"))
        val liveAgents = controller.agents()
        var iceRuns = 0
        var fuzzRuns = 0
        var sdpFuzzRuns = 0
        var statsCaptures = 0
        if (!configReady) {
            emit(Line(Level.SKIP, "Configuration is not ready, so live checks were skipped. Fix the items above and run again."))
        } else if (liveAgents.isEmpty()) {
            emit(Line(Level.SKIP, "No live in-scope browser page is reporting. Browse the app through Burp and join a call, then run this again."))
        } else {
            emit(Line(Level.INFO, "${liveAgents.size} live page(s) responding; running one check at a time per page."))
            if (!cfg.signalingFlood.confirm)
                emit(Line(Level.SKIP, "T8 signaling/ICE-restart flood is opt-in and currently off; Run All will not start it automatically. Enable it in the Signaling Flood tab if required."))
            for (agent in liveAgents) {
                if (cancelled) break
                val label = agent.id.takeLast(8)

                // M6 — ICE gather (host candidates only when no server is configured).
                if (!cancelled) {
                    runOne(emit, "M6 ICE gather on page $label",
                        start = { controller.queueIce(agent.id, cfg.iceProbe) },
                        budgetMs = (cfg.iceProbe.timeoutSeconds + 8) * 1000L
                    )?.let { iceRuns++ }
                }

                // T1 — force a fresh getStats snapshot for the page's live peers.
                if (!cancelled) {
                    runOne(emit, "T1 getStats capture on page $label",
                        start = { controller.queueCaptureStats(agent.id) },
                        budgetMs = 12000L
                    )?.let { statsCaptures++ }
                }

                // M4 — DataChannel fuzz on each open channel.
                val openChannels = agent.channels.filter { it.state == "open" }
                if (openChannels.isEmpty()) {
                    emit(Line(Level.SKIP, "M4 on page $label: no open DataChannel. Open/join a call that uses a DataChannel."))
                }
                val fuzzCfg = cfg.dataChannelFuzz
                val fuzzBudget = (fuzzCfg.count.toLong() * fuzzCfg.intervalMs) + 8000L
                for (channel in openChannels) {
                    if (cancelled) break
                    runOne(emit, "M4 fuzz on page $label channel ${channel.pc}/${channel.id}",
                        start = { controller.queueFuzz(agent.id, channel.id, fuzzCfg) },
                        budgetMs = fuzzBudget
                    )?.let { fuzzRuns++ }
                }

                // M3+ — malformed-SDP parser fuzz (local, no packets sent).
                if (!cancelled) {
                    var sdpCommandId: String? = null
                    val state = runOne(emit, "M3+ SDP fuzz on page $label",
                        start = { controller.queueSdpFuzz(agent.id, cfg.sdpFuzz).also { sdpCommandId = it } },
                        budgetMs = cfg.sdpFuzz.maxCases * 400L + 8000L
                    )
                    if (state == "completed") sdpFuzzRuns++
                    sdpCommandId?.let { reportSdpCases(it, emit) }
                }

                // T8 — opt-in only; never started unless explicitly confirmed.
                if (!cancelled && cfg.signalingFlood.confirm) {
                    runOne(emit, "T8 signaling/ICE-restart flood on page $label",
                        start = { controller.queueSignalingFlood(agent.id, cfg.signalingFlood) },
                        budgetMs = (cfg.signalingFlood.count.toLong() * cfg.signalingFlood.intervalMs) + 10000L
                    )
                }
            }
        }

        emit(Line(Level.HEAD, "3b. TLS listener tests (Python / SSLyze)"))
        if (!cancelled && cfg.tlsScan.includeInRunAll && tlsRunner != null) {
            val firstSeq = telemetry.snapshot().maxOfOrNull { it.seq } ?: 0
            val result = tlsRunner.scan(cfg.tlsScan) { cancelled }
            emit(Line(if (result.status == "completed") Level.INFO else Level.WARN, result.detail))
            reviewTls(telemetry.snapshot().filter { it.seq > firstSeq }, emit)
        } else emit(Line(Level.SKIP, "TLS scans are opt-in. Select an endpoint and enable inclusion in Run All in TLS Tests."))

        emit(Line(Level.HEAD, "4. SDP mutation (M3)"))
        if (cfg.sdpMutation.enabled) {
            emit(Line(Level.INFO, "M3 is enabled and will rewrite the next negotiation. Start a fresh call/renegotiation in the browser, then check SDP Mutation (M3) for before/after evidence."))
        } else {
            emit(Line(Level.SKIP, "M3 is disabled. Configure and enable a rule in SDP Mutation (M3), then start a new call — mutation cannot be triggered from here."))
        }

        emit(Line(Level.HEAD, "5. Authorization matrix (M5)"))
        val identities = runCatching { configStore.config.identities }.getOrDefault(emptyList())
        emit(authzGuidance(identities))
        reviewIdentifiers(emit)

        emit(Line(Level.HEAD, "Security checklist coverage"))
        if (!cancelled) assessments?.let { a ->
            // "Everything automatic": when the tester has not curated a selection in
            // the Assessment tests tab, Run All executes every test that has a ready
            // automated backend (passive, TURN runner, configured scenarios) instead
            // of running nothing. An explicit selection is still honored as-is.
            val selected = cfg.assessment.selectedTests
            val ids = selected.ifEmpty { webrtc.assessment.TestRegistry.executable(cfg.assessment) }
            if (selected.isEmpty())
                emit(Line(Level.INFO, "No assessment tests selected; auto-running ${ids.size} with a ready automated backend. Curate in the Assessment tests tab to change this."))
            a.run(ids = ids) { emit(Line(Level.INFO, it)) }
        }
        val sections = SecurityTestReport.sections(cfg, telemetry.snapshot(), authzResults(), observedSignalingEndpoints())
        SecurityTestReport.checklist(sections).forEach { summary ->
            val level = when {
                summary.results.any { it.status == SecurityTestReport.Status.FINDING } -> Level.FINDING
                summary.results.any { it.status in setOf(SecurityTestReport.Status.REVIEW, SecurityTestReport.Status.ERROR, SecurityTestReport.Status.PARTIAL) } -> Level.WARN
                summary.check.support == CoverageSupport.EXTERNAL -> Level.SKIP
                summary.results.all { it.status == SecurityTestReport.Status.NOT_TESTED } -> Level.SKIP
                else -> Level.INFO
            }
            emit(Line(level, SecurityTestReport.summaryText(summary)))
        }

        emit(Line(Level.HEAD, "Summary"))
        emit(Line(if (configReady) Level.OK else Level.WARN,
            "Config ${if (configReady) "ready" else "needs attention"} · ICE gathers: $iceRuns · Stats captures: $statsCaptures · DataChannel fuzz: $fuzzRuns · SDP fuzz: $sdpFuzzRuns"))
        emit(Line(Level.INFO, "Review the Telemetry (M2) and per-module tabs for full evidence. Export a report from the Findings (M7) tab."))
        if (cancelled) emit(Line(Level.WARN, "Run was stopped before finishing."))
        else emit(Line(Level.OK, "Run all complete."))
    }

    /**
     * Passive report used by the Findings (M7) tab. Same config check, telemetry
     * review and M3/M5 guidance as [run], but it never queues an active job — so a
     * report can be generated at any time without touching the target.
     */
    fun passiveReport(events: List<TelemetryEvent> = telemetry.snapshot(), emit: (Line) -> Unit) {
        reset()
        val cfg = configStore.config
        emit(Line(Level.HEAD, "1. Configuration (M0)"))
        checkConfig(emit)
        emit(Line(Level.HEAD, "2. Passive telemetry review (M1 injection / M2 telemetry)"))
        reviewTelemetry(emit, events)
        emit(Line(Level.HEAD, "2b. Signaling endpoint metadata (T7, passive)"))
        reviewSignaling(emit)
        emit(Line(Level.HEAD, "3. SDP mutation (M3)"))
        if (cfg.sdpMutation.enabled)
            emit(Line(Level.INFO, "M3 is enabled; it rewrites the next negotiation. See SDP Mutation (M3) for before/after evidence."))
        else
            emit(Line(Level.SKIP, "M3 is disabled."))
        emit(Line(Level.HEAD, "4. Authorization matrix (M5)"))
        emit(authzGuidance(cfg.identities))
        reviewIdentifiers(emit)
    }

    // ---- steps ----------------------------------------------------------

    private fun checkConfig(emit: (Line) -> Unit): Boolean {
        val cfg = configStore.config
        var ready = true
        if (!cfg.injectionEnabled) {
            emit(Line(Level.WARN, "Agent injection is OFF. Turn on 'Enable agent injection' in Config (M0)."))
            ready = false
        }
        if (cfg.hostAllowList.isEmpty()) {
            emit(Line(Level.WARN, "Host allow-list is empty — nothing will be injected. Add the app's hostname (or 'all')."))
            ready = false
        }
        if (cfg.bridgePort !in 1..65535) {
            emit(Line(Level.WARN, "Bridge port ${cfg.bridgePort} is invalid; expected 1–65535."))
            ready = false
        }
        if (cfg.hostAllowList.any { it.equals("all", ignoreCase = true) }) {
            emit(Line(Level.INFO, "Allow-list is 'all' — every in-scope host may be injected."))
        }
        if (ready) emit(Line(Level.OK, "Configuration looks ready."))
        return ready
    }

    private fun reviewTelemetry(emit: (Line) -> Unit, events: List<TelemetryEvent> = telemetry.snapshot()) {
        if (events.isEmpty()) {
            emit(Line(Level.SKIP, "No telemetry collected yet. With injection on and the app in scope, browse it and join a call; the agent then reports SDP, ICE, ciphers and DataChannels here."))
            return
        }
        val byType = events.groupingBy { it.type }.eachCount()
        val installed = byType["installed"] ?: 0
        if (installed > 0) emit(Line(Level.OK, "Agent installed and reporting from $installed page load(s) (M1 injection working)."))
        else emit(Line(Level.WARN, "No 'installed' beacon seen — the agent may not be loading. Check injection and CSP settings."))

        reviewPrivacy(events, emit)
        reviewTls(events, emit)

        val sdp = (byType["sdp-local"] ?: 0) + (byType["sdp-remote"] ?: 0)
        if (sdp > 0) emit(Line(Level.INFO, "Observed $sdp SDP offer/answer message(s)."))

        // Use the latest sample per agent/peer/transport; early ICE stats may
        // precede DTLS. Unknown values must never become weak-crypto findings.
        fun peerKey(event: TelemetryEvent) = listOf(field(event, "agent"), event.frame, event.pcId)
        val crypto = events.filter { it.type == "crypto" }
            .groupBy { peerKey(it) + field(it, "transportId") }.values.map { group -> group.maxBy { it.seq } }
        for (event in crypto) {
            val detail = field(event, "detail") ?: event.summary
            val label = "${event.frame} ${event.pcId} ${field(event, "transportId").orEmpty()}".trim()
            val descriptions = events.filter { peerKey(it) == peerKey(event) && it.type in setOf("sdp-local", "sdp-remote") }
                .mapNotNull { field(it, "sdp") }
            val hasRtp = descriptions.any { Regex("(?m)^m=(audio|video)\\s").containsMatchIn(it) }
            val dataOnly = !hasRtp && descriptions.any { Regex("(?m)^m=application\\s").containsMatchIn(it) }
            val findings = Detectors.analyzeTransportSecurity(detail)
            findings.forEach { emit(Line(Level.FINDING, "Transport $label: $it")) }
            val missing = buildList {
                if (Detectors.transportValue(detail, "dtls") == null) add("DTLS cipher")
                if (!dataOnly && Detectors.transportValue(detail, "srtp") == null) add("SRTP profile")
            }
            if (missing.isNotEmpty()) emit(Line(Level.WARN,
                "Transport $label: ${missing.joinToString(" and ")} not captured; encryption status is unknown. Missing stats do not prove missing encryption."))
            else if (findings.isEmpty()) emit(Line(Level.OK, "Transport $label: captured cipher values $detail; no weak cipher identified."))
            if (dataOnly) emit(Line(Level.INFO, "Peer ${event.pcId}: DataChannel-only SDP; SRTP media checks are not applicable. DataChannels use DTLS."))
        }
        if (crypto.isEmpty() && sdp > 0) emit(Line(Level.WARN, "No transport cipher stats captured; encryption status is unknown."))

        // SDES cleartext keys, missing DTLS fingerprint, and codec enumeration from SDP.
        val sdpTexts = events.filter { it.type == "sdp-local" || it.type == "sdp-remote" }
            .mapNotNull { field(it, "sdp") }
        if (sdpTexts.any { Detectors.usesSdesKeys(it) })
            emit(Line(Level.WARN, "SDES key exchange (a=crypto) seen in SDP — media keys are carried in cleartext signaling; DTLS-SRTP should be used instead."))
        if (sdpTexts.any { Detectors.hasMedia(it) && !Detectors.hasDtlsFingerprint(it) })
            emit(Line(Level.WARN, "An SDP with media had no DTLS a=fingerprint — check that DTLS-SRTP is actually in use."))
        val codecs = sdpTexts.flatMap { Detectors.enumerateCodecs(it) }.distinct()
        if (codecs.isNotEmpty())
            emit(Line(Level.INFO, "Codecs advertised: ${codecs.joinToString(", ")}."))

        // T5 — SDP attribute + codec audit, and T4 — ICE credential hygiene.
        reviewSdpAttributes(events, sdpTexts, emit)

        // T1 — deeper getStats evidence, and T2 — DTLS certificate binding.
        reviewStats(events, sdpTexts, emit)

        (byType["dc-created"] ?: 0).let { if (it > 0) emit(Line(Level.INFO, "Observed $it DataChannel(s) — candidates for M4 fuzzing.")) }
        events.filter { it.type == "dc-state" && field(it, "state") == "closed" }
            .distinctBy { listOf(field(it, "agent"), it.frame, it.pcId, field(it, "channelId")) }.forEach { event ->
                val channel = field(event, "channelId").orEmpty()
                val lifetime = field(event, "elapsedMs")?.let { " after ${it}ms" }.orEmpty()
                val states = "peer=${field(event, "connectionState")} ICE=${field(event, "iceConnectionState")} signaling=${field(event, "signalingState")} SCTP=${field(event, "sctpState")}"
                when (field(event, "everOpened")) {
                    "false" -> emit(Line(Level.WARN, "DataChannel ${event.pcId}/$channel closed before reaching open$lifetime ($states). Local creation is not an open channel; M4 cannot send until open. Review SDP errors, ICE/DTLS states and close() call telemetry."))
                    "true" -> emit(Line(Level.INFO, "DataChannel ${event.pcId}/$channel opened, then closed$lifetime ($states)."))
                }
            }
        events.filter { it.type == "pc-state" }
            .groupBy { listOf(field(it, "agent"), it.frame, it.pcId) }.values.forEach { history ->
                val latest = history.maxByOrNull { it.seq }!!
                emit(Line(Level.INFO, "Peer ${latest.pcId}: connection=${field(latest, "connectionState")}, ICE=${field(latest, "iceConnectionState")}, signaling=${field(latest, "signalingState")}, SCTP=${field(latest, "sctpState")}."))
                if (history.any { field(it, "connectionState") == "failed" || field(it, "iceConnectionState") == "failed" })
                    emit(Line(Level.WARN, "Peer ${latest.pcId} reported an ICE or connection failure. This is a connectivity diagnostic, not a vulnerability."))
                if (history.any { field(it, "action") == "close-called" })
                    emit(Line(Level.INFO, "Peer ${latest.pcId}: the page called RTCPeerConnection.close(); inspect the pc-state stack for the caller."))
            }
        (byType["getUserMedia"] ?: 0).let { if (it > 0) emit(Line(Level.INFO, "Observed $it getUserMedia (camera/mic) request(s).")) }
        events.filter { it.type == "getUserMedia-result" }.forEach { result ->
            val error = field(result, "error")
            if (field(result, "outcome") == "rejected") {
                emit(Line(Level.INFO, "Camera/microphone request was rejected by the browser${error?.let { ": $it" } ?: ""}."))
            } else if (field(result, "outcome") == "resolved") {
                emit(Line(Level.INFO, "Camera/microphone request was granted by the browser."))
            }
        }

        // Keep completed totals separate from newer queued/running/aborted jobs.
        val latestFuzzSummary = events.filter { it.type == "sdp-fuzz-summary" }.maxByOrNull { it.seq }
        val fuzzCommandId = latestFuzzSummary?.let { field(it, "commandId") }
        val fuzzResults = events.filter { event ->
            event.type == "sdp-fuzz-result" && fuzzCommandId != null && field(event, "commandId") == fuzzCommandId
        }
        val mutations = fuzzResults.filter { field(it, "label") != "baseline-observed" }
        val acceptedFuzz = mutations.count { field(it, "outcome") == "accepted" }
        val rejectedFuzz = mutations.count { field(it, "outcome") == "rejected" }
        val offersProcessed = mutations.count { field(it, "followupOutcome") == "answer-generated" }
        if (latestFuzzSummary != null) {
            emit(Line(Level.INFO, "Latest completed SDP fuzz run ${fuzzCommandId?.take(8)} at ${latestFuzzSummary.time}: $acceptedFuzz mutations accepted, $rejectedFuzz rejected; $offersProcessed accepted mutations also produced an answer. Baseline controls are excluded; acceptance alone is not a vulnerability."))
            val baseline = fuzzResults.firstOrNull { field(it, "label") == "baseline-observed" }
            emit(Line(if (baseline?.let { field(it, "outcome") } == "accepted") Level.OK else Level.WARN,
                "SDP baseline control: ${baseline?.let { field(it, "outcome") } ?: "not recorded"}."))
            val expected = field(latestFuzzSummary, "cases")?.toIntOrNull()
            if (expected != null && expected != fuzzResults.size)
                emit(Line(Level.WARN, "Completed summary declares $expected cases, but ${fuzzResults.size} per-case records were captured. Reported mutation totals cover captured records only."))
        }
        val completedIds = events.filter { it.type == "sdp-fuzz-summary" }.mapNotNull { field(it, "commandId") }.toSet()
        events.filter { (it.type == "test-job" && field(it, "module") == "sdp-fuzz") ||
            it.type in setOf("sdp-fuzz-result", "sdp-fuzz-error") }
            .groupBy { field(it, "commandId") }.forEach { (id, history) ->
                if (id != null && id !in completedIds) {
                    val latest = history.filter { it.type == "test-job" }.maxByOrNull { it.seq }
                    val count = events.count { it.type == "sdp-fuzz-result" && field(it, "commandId") == id }
                    emit(Line(Level.WARN, "SDP fuzz run ${id.take(8)}: ${latest?.let { field(it, "status") } ?: "incomplete"}; $count case result(s), no completed summary. These partial results are excluded from completed totals."))
                }
            }

        // TURN relay allocation issued for supplied creds — the Ghost Calls precondition.
        val relayIssued = events.filter { it.type == "ice-probe-result" }.any { relayCount(it) > 0 }
        if (relayIssued)
            emit(Line(Level.INFO, "A TURN relay allocation was issued for the supplied credentials. This demonstrates allocation capability, not an authorization vulnerability; relay destination restrictions require further testing."))

        if (sdp == 0 && installed > 0)
            emit(Line(Level.INFO, "No SDP seen yet — join or start a call so a negotiation happens."))

        // Imported chrome://webrtc-internals dump comparison (manual import in Telemetry (M2)).
        events.filter { it.type == "internals-comparison" }.maxByOrNull { it.seq }?.let { comparison ->
            InternalsComparator.decodeLines(comparison.raw).forEach { line ->
                val level = when (line.level) {
                    InternalsComparator.Level.FINDING -> Level.FINDING
                    InternalsComparator.Level.WARN -> Level.WARN
                    InternalsComparator.Level.OK -> Level.OK
                    InternalsComparator.Level.INFO -> Level.INFO
                }
                emit(Line(level, "Chrome webrtc-internals: ${line.text}"))
            }
        }
    }

    /**
     * T3 — a dedicated IP-location privacy section. Application ICE candidates
     * (type "ice") are parsed; probe candidates and import records are excluded.
     * A public address is the meaningful exposure; mDNS names conceal the address.
     */
    private fun reviewTls(events: List<TelemetryEvent>, emit: (Line) -> Unit) {
        val scans = events.filter { it.type in setOf("tls-scan-result", "tls-scan-error") }
        for (event in scans) {
            val obj = runCatching { json.parseToJsonElement(event.raw).jsonObject }.getOrNull()
            val result = obj?.get("result") as? JsonObject
            fun value(obj: JsonObject?, name: String) = (obj?.get(name) as? JsonPrimitive)?.contentOrNull
            val status = value(result, "status") ?: "failed"
            val target = value(obj, "target") ?: event.frame
            emit(Line(if (status == "completed") Level.INFO else Level.WARN, "TLS $target: $status. ${event.summary}"))
            (result?.get("checks") as? JsonArray)?.forEach { element ->
                val check = element as? JsonObject ?: return@forEach
                emit(Line(if (value(check, "status") == "completed") Level.INFO else Level.WARN,
                    "TLS $target: ${value(check, "summary") ?: value(check, "name")}."))
            }
            (result?.get("findings") as? JsonArray)?.forEach { element ->
                val finding = element as? JsonObject ?: return@forEach
                emit(Line(if (value(finding, "level") == "finding") Level.FINDING else Level.WARN,
                    "TLS $target: ${value(finding, "text") ?: "Inspect scanner evidence"}."))
            }
        }
        if (scans.isNotEmpty()) emit(Line(Level.INFO,
            "TLS results cover the selected TCP listener; they do not test TURN authentication/allocation, media DTLS or SRTP. Complete means the scanner completed, not that the listener is secure. Full SSLyze evidence is in TLS Tests / telemetry."))
    }

    private fun reviewPrivacy(events: List<TelemetryEvent>, emit: (Line) -> Unit) {
        EvidenceAnalysis.privacy(events).forEach {
            emit(Line(if (it.policyMismatch) Level.WARN else Level.INFO, it.text))
        }
    }

    /**
     * T1 — summary of the browser's own getStats() snapshots, and T2 — DTLS
     * certificate/fingerprint binding. Evidence only: it reports what the local
     * engine measured, never that media reached the peer.
     */
    private fun reviewStats(events: List<TelemetryEvent>, sdpTexts: List<String>, emit: (Line) -> Unit) {
        val snapshots = events.filter { it.type == "stats-snapshot" }
        if (snapshots.isNotEmpty()) {
            val latest = snapshots.groupBy { listOf(field(it, "agent"), it.frame, it.pcId) }
                .values.map { group -> group.maxBy { it.seq } }
            val parsed = latest.mapNotNull { StatsSnapshot.parse(it.raw) }
            val streams = parsed.flatMap { it.rtp }
            val payloadTypes = streams.mapNotNull { it.payloadType }.distinct().sorted()
            if (payloadTypes.isNotEmpty())
                emit(Line(Level.INFO, "getStats reported ${streams.size} RTP stream(s) in use; payload type(s): ${payloadTypes.joinToString(", ")}; codec(s): ${streams.map { it.codec }.filter { it.isNotBlank() }.distinct().joinToString(", ").ifBlank { "(not resolved)" }}."))
            val inbound = streams.filter { it.direction == "inbound" }
            val lost = inbound.sumOf { it.packetsLost ?: 0L }
            val received = inbound.sumOf { it.packets ?: 0L }
            if (received + lost > 0) {
                val pct = lost * 100.0 / (received + lost)
                val text = "Inbound RTP loss is ${"%.2f".format(pct)}% ($lost lost of ${received + lost} packets)."
                emit(Line(if (pct >= 5.0) Level.WARN else Level.INFO, text + if (pct >= 5.0) " Investigate network quality; this is not a target finding." else ""))
            }
            inbound.mapNotNull { it.jitter }.maxOrNull()?.let { emit(Line(Level.INFO, "Maximum inbound RTP jitter observed: ${"%.4f".format(it)} s.")) }
            parsed.forEach { snap ->
                val roles = buildList {
                    if (snap.dtlsRole.isNotBlank()) add("DTLS role ${snap.dtlsRole}")
                    if (snap.iceRole.isNotBlank()) add("ICE role ${snap.iceRole}")
                }
                if (roles.isNotEmpty()) emit(Line(Level.INFO, "Peer ${snap.pcId}: ${roles.joinToString(", ")}."))
                if (snap.pair.isNotBlank()) emit(Line(Level.INFO, "Peer ${snap.pcId}: chosen candidate pair ${snap.pair}."))
                if (snap.truncated) emit(Line(Level.INFO, "Peer ${snap.pcId}: the stats snapshot was truncated at the capture bound; a manual capture shows the same bound."))
            }
        }

        events.filter { it.type == "dtls-cert" }.forEach { ev ->
            val cert = CertificateAnalyzer.parse(field(ev, "role").orEmpty(), field(ev, "algorithm").orEmpty(),
                field(ev, "fingerprint").orEmpty(), field(ev, "base64").orEmpty())
            val binding = EvidenceAnalysis.binding(ev, events)
            val results = CertificateAnalyzer.analyze(listOf(cert), binding.fingerprints)
            if (results.isEmpty()) emit(Line(Level.INFO, "${ev.frame} ${ev.pcId}: certificate binding observed. ${binding.limitation}"))
            else results.forEach { (text, finding) -> emit(Line(if (finding) Level.FINDING else Level.WARN,
                "${ev.frame} ${ev.pcId}: $text ${binding.limitation}")) }
        }
    }

    /** T5 — SDP attribute + codec audit; T4 — ICE credential hygiene (SDP ufrag/pwd). */
    private fun reviewSdpAttributes(events: List<TelemetryEvent>, sdpTexts: List<String>, emit: (Line) -> Unit) {
        if (sdpTexts.isEmpty()) return

        sdpTexts.distinct().flatMap { Detectors.auditSdpAttributes(it) }.distinct().forEach { finding ->
            emit(Line(if (finding.finding) Level.FINDING else Level.WARN, "SDP attribute review: ${finding.text}"))
        }

        val details = sdpTexts.flatMap { Detectors.codecDetails(it) }.distinct()
        val fmtp = details.filter { it.fmtp != null }
        if (fmtp.isNotEmpty())
            emit(Line(Level.INFO, "Codec parameters: " + fmtp.joinToString("; ") { "pt ${it.payloadType} ${it.name} fmtp=${it.fmtp}" }))
        val setups = sdpTexts.flatMap { Detectors.setupRoles(it) }.distinct()
        if (setups.isNotEmpty()) emit(Line(Level.INFO, "DTLS setup role(s) advertised: ${setups.joinToString(", ")}."))

        val credentials = sdpTexts.flatMap { Detectors.iceCredentials(it) }.distinct()
        credentials.mapNotNull { Detectors.auditIceCredential(it) }.distinct()
            .forEach { emit(Line(Level.WARN, "ICE credential hygiene (SDP): $it Credentials are preserved in full; this is separate from TURN account credentials.")) }

        EvidenceAnalysis.restartIssues(events).forEach { emit(Line(Level.WARN, it)) }
    }

    /**
     * T7 — passive signaling endpoint metadata from Burp Proxy history. No new
     * request is made; only origins and HSTS presence are reported.
     */
    private fun reviewSignaling(emit: (Line) -> Unit) {
        val endpoints = observedSignalingEndpoints()
        if (endpoints.isEmpty()) {
            emit(Line(Level.SKIP, "No HTTP(S) signaling origins observed in Burp Proxy history yet. Browse the app through Burp; this is a passive read only."))
            return
        }
        emit(Line(Level.INFO, "Signaling origin(s) observed in proxy history: " + endpoints.joinToString(", ") {
            "${it.origin} (${if (it.secure) "https" else "http"}, ${it.requests} request(s))"
        }))
        SignalingMetadata.findings(endpoints).forEach { emit(Line(Level.WARN, it)) }
    }

    /** Config-based guessability check over the identifier values across identities. */
    private fun reviewIdentifiers(emit: (Line) -> Unit) {
        val cfg = configStore.config
        cfg.identifierKeys.forEach { key ->
            val values = cfg.identities.mapNotNull { it.identifiers[key] }.filter { it.isNotBlank() }
            Detectors.guessableIdentifiers(values)?.let {
                emit(Line(Level.WARN, "Identifier '$key': $it"))
            }
        }
    }

    private fun field(ev: TelemetryEvent, key: String): String? =
        runCatching { (json.parseToJsonElement(ev.raw).jsonObject[key] as? JsonPrimitive)?.contentOrNull }.getOrNull()

    private fun relayCount(ev: TelemetryEvent): Int = runCatching {
        val counts = json.parseToJsonElement(ev.raw).jsonObject["counts"]?.jsonObject ?: return 0
        (counts["relay"] as? JsonPrimitive)?.content?.toIntOrNull() ?: 0
    }.getOrDefault(0)

    private fun authzGuidance(identities: List<IdentityProfile>): Line {
        if (identities.size < 2)
            return Line(Level.SKIP, "M5 needs at least two identities. Add them in Config (M0), then right-click a request → 'WebRTC: Run authz matrix'. This step cannot pick a request for you.")
        return Line(Level.INFO, "${identities.size} identities configured. Right-click a captured request → 'WebRTC: Run authz matrix' to replay it across them; a cross-principal 2xx is flagged in Authz Matrix (M5).")
    }

    /**
     * Queues one active job, then polls its state to a terminal result within a
     * budget, cancelling on timeout or stop. Returns the terminal state, or null
     * if the job could not even be queued (reason is reported).
     */
    private fun runOne(emit: (Line) -> Unit, label: String, start: () -> String, budgetMs: Long): String? {
        val id = try {
            start()
        } catch (e: Exception) {
            emit(Line(Level.SKIP, "$label skipped: ${e.message}"))
            return null
        }
        emit(Line(Level.INFO, "$label — queued ${id.take(8)}; waiting for the page to run it…"))

        val graceMs = 12000L
        val startedAt = System.currentTimeMillis()
        var runningAt = 0L
        while (true) {
            if (cancelled) { controller.cancelJob(id); emit(Line(Level.WARN, "$label — stopped.")); return "cancelled" }
            val state = controller.jobState(id)
            if (state == null || state !in setOf("queued", "running")) {
                val summary = latestSummaryFor(id)
                val level = if (state == "completed") Level.OK else Level.WARN
                emit(Line(level, "$label — ${state ?: "done"}${summary?.let { ": $it" } ?: ""}."))
                return state ?: "done"
            }
            if (state == "running" && runningAt == 0L) runningAt = System.currentTimeMillis()
            val deadline = if (runningAt > 0L) runningAt + budgetMs else startedAt + graceMs
            if (System.currentTimeMillis() > deadline) {
                controller.cancelJob(id)
                val why = if (runningAt == 0L) "the page never picked it up (still open and in a call, in scope?)" else "it ran past its time budget"
                emit(Line(Level.WARN, "$label — timed out; $why."))
                return "timeout"
            }
            try { Thread.sleep(400) } catch (_: InterruptedException) { controller.cancelJob(id); return "cancelled" }
        }
    }

    /** Newest telemetry summary carrying this commandId, for a human-readable result. */
    private fun latestSummaryFor(commandId: String): String? =
        telemetry.snapshot().asReversed().firstOrNull { ev ->
            val obj = runCatching { json.parseToJsonElement(ev.raw).jsonObject }.getOrNull() ?: return@firstOrNull false
            (obj["commandId"] as? JsonPrimitive)?.contentOrNull == commandId && ev.type != "test-job"
        }?.summary

    private fun reportSdpCases(commandId: String, emit: (Line) -> Unit) {
        val events = telemetry.snapshot().filter { event ->
            event.type in setOf("sdp-fuzz-result", "sdp-fuzz-error") && field(event, "commandId") == commandId
        }
        if (events.isEmpty()) {
            emit(Line(Level.FAIL, "No per-case SDP fuzz result was recorded for command ${commandId.take(8)}."))
            return
        }
        for (event in events) {
            if (event.type == "sdp-fuzz-error") {
                emit(Line(Level.FAIL, "SDP fuzz could not complete: ${field(event, "detail") ?: event.summary}"))
                continue
            }
            val label = field(event, "label") ?: "case ${field(event, "index") ?: "?"}"
            val bytes = field(event, "bytes")?.let { " ($it bytes)" }.orEmpty()
            if (label == "baseline-observed") {
                val accepted = field(event, "outcome") == "accepted"
                emit(Line(if (accepted) Level.OK else Level.FAIL,
                    "Scanned the baseline SDP control$bytes: ${if (accepted) "accepted as expected; excluded from mutation findings" else "rejected; the run cannot assess mutations reliably: ${field(event, "error")}"}."))
                continue
            }
            when (field(event, "outcome")) {
                "rejected" -> {
                    val error = field(event, "error") ?: field(event, "detail") ?: "browser rejected the description"
                    emit(Line(Level.OK, "Scanned SDP case '$label'$bytes: setRemoteDescription rejected it with $error."))
                }
                "accepted" -> {
                    val followup = field(event, "followupOutcome")
                    val result = when (followup) {
                        "answer-generated" -> "the browser accepted it and createAnswer succeeded"
                        "answer-rejected" -> "the browser accepted it, then createAnswer failed: ${field(event, "followupError") ?: "unknown error"}"
                        else -> "the browser accepted it; no follow-up negotiation was run for answer mode"
                    }
                    emit(Line(Level.FAIL, "Scanned SDP case '$label'$bytes: $result. Review it as a triage lead, not a confirmed vulnerability."))
                }
                "setup-error" -> emit(Line(Level.FAIL, "SDP case '$label' could not be tested: peer setup failed with ${field(event, "error")}."))
                else -> emit(Line(Level.FAIL, "Scanned SDP case '$label'$bytes: no parser result was recorded."))
            }
        }
    }
}
