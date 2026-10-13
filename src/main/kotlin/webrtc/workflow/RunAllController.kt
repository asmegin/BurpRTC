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
import webrtc.config.ScanModule
import webrtc.config.ScanPlan
import webrtc.external.ExternalInputs
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
 * Runs the saved Scan All selection and reports real execution and missing inputs.
 * Browser jobs, managed TLS/protocol runners and captured-request authorization
 * replays share the same workflow. M3 arms saved rules for the next negotiation.
 */
class RunAllController(
    private val configStore: ConfigStore,
    private val controller: ActiveTestController,
    private val telemetry: TelemetryTableModel,
    private val tlsRunner: TlsScanRunner? = null,
    private val authzResults: () -> List<AuthzResult> = { emptyList() },
    private val signalingEndpoints: () -> List<SignalingMetadata.Endpoint> = { emptyList() },
    private val assessments: webrtc.assessment.AssessmentController? = null,
    private val automaticAuthz: (((() -> Boolean), (AuthzResult) -> Unit) -> Int)? = null,
    private val automaticInvites: (((() -> Boolean), (AuthzResult) -> Unit) -> Int)? = null,
    private val automaticArtifacts: (((() -> Boolean), (AuthzResult) -> Unit) -> Int)? = null
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
    fun run(plan: ScanPlan = configStore.config.scanPlan, emit: (Line) -> Unit) {
        reset()
        val cfg = configStore.config
        val currentAuthzResults = mutableListOf<AuthzResult>()
        val selected = ScanModule.entries.filter { plan.includes(it) }
        if (selected.isEmpty()) {
            emit(Line(Level.SKIP, "No scans selected. Select scans in Scan All before running."))
            return
        }
        emit(Line(Level.HEAD, "Selected scans"))
        emit(Line(Level.INFO, selected.joinToString(" · ") { it.title }))
        ScanModule.entries.filterNot { plan.includes(it) }.forEach {
            emit(Line(Level.SKIP, "${it.title}: unchecked in Scan All; will not run."))
        }

        emit(Line(Level.HEAD, "1. Setup"))
        val configReady = checkConfig(emit)

        if (!cancelled && plan.includes(ScanModule.PASSIVE)) {
            emit(Line(Level.HEAD, "2. Captured evidence review"))
            reviewTelemetry(emit)
            emit(Line(Level.HEAD, "2b. Signaling endpoints"))
            reviewSignaling(emit)
            emit(Line(Level.HEAD, "2c. Browser & client security (original headers, canaries, capture, messaging)"))
            reviewClient(telemetry.snapshot(), emit)
        }

        emit(Line(Level.HEAD, "3. Browser tests"))
        val liveAgents = controller.agents()
        var iceRuns = 0
        var fuzzRuns = 0
        var sdpFuzzRuns = 0
        var statsCaptures = 0
        var browserChecks = 0
        val browserSelected = listOf(ScanModule.ICE, ScanModule.STATS, ScanModule.BROWSER, ScanModule.DATA, ScanModule.SDP, ScanModule.LOCAL_FLOOD).any { plan.includes(it) }
        if (!browserSelected) {
            emit(Line(Level.SKIP, "No browser scans selected."))
        } else if (!configReady) {
            emit(Line(Level.SKIP, "Configuration is not ready, so live checks were skipped. Fix the items above and run again."))
        } else if (liveAgents.isEmpty()) {
            emit(Line(Level.SKIP, "No live in-scope browser page is reporting. Browse the app through Burp and join a call, then run this again."))
        } else {
            emit(Line(Level.INFO, "${liveAgents.size} live page(s) responding; running one check at a time per page."))
            for (agent in liveAgents) {
                if (cancelled) break
                val label = agent.id.takeLast(8)

                // M6 — ICE gather (host candidates only when no server is configured).
                if (!cancelled && plan.includes(ScanModule.ICE)) {
                    val probes = if (cfg.iceProbe.url.isNotBlank()) listOf(cfg.iceProbe) else
                        ExternalInputs.detect(cfg, telemetry.snapshot()).iceServers.asReversed()
                            .filter { it.frame == agent.frame || it.frame.isBlank() }
                            .flatMap { server -> server.urls.map { url -> cfg.iceProbe.copy(url = url,
                                username = server.username.orEmpty(), credential = server.credential.orEmpty(), useObservedCredentials = false) } }
                            .distinctBy { it.url }.take(5).ifEmpty { listOf(cfg.iceProbe) }
                    for (probe in probes) {
                        if (cancelled) break
                        runOne(emit, "M6 ICE gather on page $label (${probe.url.ifBlank { "host candidates" }})",
                            start = { controller.queueIce(agent.id, probe) },
                            budgetMs = (probe.timeoutSeconds + 8) * 1000L
                        )?.let { if (it == "completed") iceRuns++ }
                    }
                }

                // T1 — force a fresh getStats snapshot for the page's live peers.
                if (!cancelled && plan.includes(ScanModule.STATS)) {
                    runOne(emit, "T1 getStats capture on page $label",
                        start = { controller.queueCaptureStats(agent.id) },
                        budgetMs = 12000L
                    )?.let { statsCaptures++ }
                }

                // Browser permission / capture snapshot; no media is captured.
                if (!cancelled && plan.includes(ScanModule.BROWSER)) {
                    runOne(emit, "Browser & capture checks on page $label",
                        start = { controller.queueBrowserChecks(agent.id) },
                        budgetMs = 10000L
                    )?.let { if (it == "completed") browserChecks++ }
                }

                // M4 — DataChannel fuzz on each open channel.
                val openChannels = agent.channels.filter { plan.includes(ScanModule.DATA) && it.state == "open" }
                if (plan.includes(ScanModule.DATA) && openChannels.isEmpty()) {
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
                if (!cancelled && plan.includes(ScanModule.SDP)) {
                    var sdpCommandId: String? = null
                    val state = runOne(emit, "M3+ SDP fuzz on page $label",
                        start = { controller.queueSdpFuzz(agent.id, cfg.sdpFuzz).also { sdpCommandId = it } },
                        budgetMs = cfg.sdpFuzz.maxCases * 400L + 8000L
                    )
                    if (state == "completed") sdpFuzzRuns++
                    sdpCommandId?.let { reportSdpCases(it, emit) }
                }

                // Scan All selection authorizes the bounded local loop without a second tab switch.
                if (!cancelled && plan.includes(ScanModule.LOCAL_FLOOD)) {
                    runOne(emit, "T8 local negotiation / ICE-restart loop on page $label",
                        start = { controller.queueSignalingFlood(agent.id, cfg.signalingFlood.copy(confirm = true)) },
                        budgetMs = (cfg.signalingFlood.count.toLong() * cfg.signalingFlood.intervalMs) + 10000L
                    )
                }
            }
        }

        if (!cancelled && plan.includes(ScanModule.TLS)) {
            emit(Line(Level.HEAD, "3b. TLS listener tests (${if (cfg.tlsScan.engine == "sslyze") "SSLyze" else "built-in engine"})"))
            when {
                tlsRunner == null -> emit(Line(Level.SKIP, "TLS runner is unavailable."))
                cfg.tlsScan.endpoint.isBlank() -> emit(Line(Level.SKIP, "Select a TLS endpoint in TLS tests and save it. The built-in engine needs no setup."))
                else -> {
                    val firstSeq = telemetry.snapshot().maxOfOrNull { it.seq } ?: 0
                    val result = tlsRunner.scan(cfg.tlsScan) { cancelled }
                    emit(Line(if (result.status == "completed") Level.INFO else Level.WARN, result.detail))
                    reviewTls(telemetry.snapshot().filter { it.seq > firstSeq }, emit)
                }
            }
        }

        if (!cancelled) {
            val rules = cfg.sdpMutation
            val hasRules = rules.removeFingerprint || rules.removeCandidates || rules.mediaDirection != "unchanged" || rules.effectiveRules().any { it.find.isNotEmpty() }
            val enabled = plan.includes(ScanModule.MUTATION) && hasRules && configReady
            val current = configStore.config
            if (current.sdpMutation.enabled != enabled) configStore.save(current.copy(sdpMutation = current.sdpMutation.copy(enabled = enabled)))
            if (plan.includes(ScanModule.MUTATION)) {
                emit(Line(Level.HEAD, "4. SDP rules"))
                emit(Line(if (enabled) Level.INFO else Level.SKIP, if (enabled)
                    "Saved M3 rules enabled. Start a fresh call / renegotiation to capture before/after evidence."
                    else "M3 needs saved rewrite rules and ready configuration. Add rules in SDP rules; Scan All enables them."))
            }
        }

        if (!cancelled && plan.includes(ScanModule.AUTHZ)) {
            emit(Line(Level.HEAD, "5. Access control"))
            reviewIdentifiers(emit)
            if (configReady && automaticAuthz != null) {
                val count = automaticAuthz.invoke({ !cancelled }) { result ->
                    currentAuthzResults += result
                    emit(authzLine("M5", result))
                }
                emit(Line(if (count == 0) Level.SKIP else Level.INFO, if (count == 0)
                    "No eligible scoped captured GET/HEAD request could run. Browse the app through Burp; select captured sessions in Access control or configure identities in Setup."
                    else "M5 replayed $count captured request(s); full results are in Access control. Label sessions Customer / Advisor there to turn matching responses into likely violations."))
            } else emit(authzGuidance(cfg.identities))
        }

        if (!cancelled && plan.includes(ScanModule.INVITES)) {
            emit(Line(Level.HEAD, "5b. Meeting links"))
            if (!configReady || automaticInvites == null) emit(Line(Level.SKIP, "Meeting-link replays need ready configuration (agent enabled, allowed hosts)."))
            else {
                val count = automaticInvites.invoke({ !cancelled }) { result -> currentAuthzResults += result; emit(authzLine("Link", result)) }
                emit(Line(if (count == 0) Level.SKIP else Level.INFO, if (count == 0)
                    "No meeting / invite link captured yet. Open an invite link (for example from the SMS or e-mail) in a browser routed through Burp."
                    else "Tested $count meeting link(s). After the meeting ends, use Recheck links in Access control → Meeting links to test reuse and expiry."))
            }
        }

        if (!cancelled && plan.includes(ScanModule.ARTIFACTS)) {
            emit(Line(Level.HEAD, "5c. Documents & recordings"))
            if (!configReady || automaticArtifacts == null) emit(Line(Level.SKIP, "Document replays need ready configuration (agent enabled, allowed hosts)."))
            else {
                val count = automaticArtifacts.invoke({ !cancelled }) { result -> currentAuthzResults += result; emit(authzLine("Document", result)) }
                emit(Line(if (count == 0) Level.SKIP else Level.INFO, if (count == 0)
                    "No document, attachment or recording download captured yet. Exchange a document in the call and download it through Burp."
                    else "Tested $count document / recording download(s) across sessions and without credentials."))
            }
        }

        if (!cancelled && plan.includes(ScanModule.SECURITY)) assessments?.let { a ->
            emit(Line(Level.HEAD, "6. Security checks"))
            val ids = webrtc.assessment.TestRegistry.executable(cfg.assessment)
            emit(Line(Level.INFO, "Running ${ids.size} security check(s) with extension backends. Missing inputs are reported in Security checks."))
            a.run(ids = ids) { emit(Line(Level.INFO, it)) }
        }
        emit(Line(Level.HEAD, "Recorded evidence coverage (does not start additional scans)"))
        val sections = SecurityTestReport.sections(cfg, telemetry.snapshot(), (authzResults() + currentAuthzResults).distinct(), observedSignalingEndpoints())
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
            "Config ${if (configReady) "ready" else "needs attention"} · ICE gathers: $iceRuns · Stats captures: $statsCaptures · Browser checks: $browserChecks · DataChannel fuzz: $fuzzRuns · SDP fuzz: $sdpFuzzRuns · Likely access violations: ${currentAuthzResults.count { it.verdict == AuthzResult.LIKELY_VIOLATION }}"))
        emit(Line(Level.INFO, "Review the Evidence and per-module tabs for full evidence. Export a report from the Report tab."))
        if (cancelled) emit(Line(Level.WARN, "Run was stopped before finishing."))
        else emit(Line(Level.OK, "Run all complete. Selected scans finished; review skips and incomplete results above."))
    }

    /**
     * Passive report used by the Report tab. Same config check, telemetry
     * review and M3/M5 guidance as [run], but it never queues an active job — so a
     * report can be generated at any time without touching the target.
     */
    fun passiveReport(events: List<TelemetryEvent> = telemetry.snapshot(), emit: (Line) -> Unit) {
        val cfg = configStore.config
        emit(Line(Level.HEAD, "1. Setup"))
        checkConfig(emit)
        emit(Line(Level.HEAD, "2. Captured evidence review"))
        reviewTelemetry(emit, events)
        emit(Line(Level.HEAD, "2b. Signaling endpoints"))
        reviewSignaling(emit)
        emit(Line(Level.HEAD, "2c. Browser & client security"))
        reviewClient(events, emit)
        emit(Line(Level.HEAD, "3. SDP rules"))
        if (cfg.sdpMutation.enabled)
            emit(Line(Level.INFO, "M3 is enabled; it rewrites the next negotiation. See SDP rules for before/after evidence."))
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
            emit(Line(Level.WARN, "Agent injection is OFF. Turn on 'Enable agent injection' in Setup."))
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

        // Imported chrome://webrtc-internals dump comparison (manual import in Evidence).
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
            "TLS results cover the selected TCP listener; they do not test TURN authentication/allocation, media DTLS or SRTP. Complete means the scanner completed, not that the listener is secure. Full SSLyze evidence is in TLS tests / telemetry."))
    }

    private fun authzLine(prefix: String, result: AuthzResult): Line {
        val level = when (result.verdict) {
            AuthzResult.LIKELY_VIOLATION -> Level.FINDING
            AuthzResult.LEAD -> Level.WARN
            else -> if (result.flagged) Level.WARN else Level.INFO
        }
        val verdict = result.verdict.takeIf { it.isNotEmpty() }?.let { " [$it]" }.orEmpty()
        return Line(level, "$prefix ${result.variant}$verdict: ${result.baselineUrl} → HTTP ${result.status}; ${result.note}")
    }

    /** Original response policy (before injection), canaries, capture lifecycle and cross-window messaging. */
    private fun reviewClient(events: List<TelemetryEvent>, emit: (Line) -> Unit) {
        val policy = webrtc.telemetry.PolicyAudit.audit(events)
        val browser = webrtc.telemetry.BrowserReview.review(events)
        if (policy.isEmpty() && browser.isEmpty()) {
            emit(Line(Level.SKIP, "No original response headers or browser security events captured yet. Browse the app (customer and advisor pages) through Burp; generate XSS canaries in the XSS canaries screen to test stored injection."))
            return
        }
        policy.forEach { issue ->
            emit(Line(if (issue.level == webrtc.telemetry.PolicyAudit.Level.REVIEW) Level.WARN else Level.INFO,
                "${issue.origin}: ${issue.title}. ${issue.detail}" + if (issue.events.size > 1) " (${issue.events.size} responses)" else ""))
        }
        browser.forEach { item ->
            emit(Line(when (item.level) {
                webrtc.telemetry.BrowserReview.Level.FINDING -> Level.FINDING
                webrtc.telemetry.BrowserReview.Level.REVIEW -> Level.WARN
                webrtc.telemetry.BrowserReview.Level.INFO -> Level.INFO
            }, "${item.title}: ${item.text}"))
        }
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
            return Line(Level.SKIP, "M5 needs at least two identities and captured requests. Select sessions in Access control or add identities in Setup, then use the Burp context menu.")
        return Line(Level.INFO, "${identities.size} identities configured. Right-click a captured request → 'WebRTC: Run authz matrix' to replay it across them; a cross-principal 2xx is flagged in Access control.")
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
