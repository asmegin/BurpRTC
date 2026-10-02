package webrtc.report

import kotlinx.serialization.json.*
import webrtc.authz.AuthzResult
import webrtc.config.Detectors
import webrtc.config.IpAddresses
import webrtc.config.WebRtcConfig
import webrtc.telemetry.StatsSnapshot
import webrtc.telemetry.EvidenceAnalysis
import webrtc.telemetry.CertificateAnalyzer
import webrtc.telemetry.TelemetryEvent
import webrtc.workflow.SignalingMetadata

/** Fixed engagement taxonomy. Evidence is recorded separately from security conclusions. */
enum class SecurityArea(val title: String) {
    SIGNALING("Signaling Channel Security (WebSocket / HTTP-SSE)"),
    SDP("Session Description Protocol (SDP) Manipulation"),
    NAT("NAT Traversal Infrastructure (STUN / TURN)"),
    ICE("Interactive Connectivity Establishment (ICE) & Candidate Harvesting"),
    MEDIA("Media Transport & Encryption (SRTP / SRTCP)"),
    DTLS("Key Exchange & Handshake (DTLS)"),
    DATA("DataChannel Security (SCTP)"),
    ARCHITECTURE("Media Server Architecture (SFU / MCU / Gateway)"),
    AUTH("Authentication, Session Management & Access Control"),
    CLIENT("Client-Side Security (Browser APIs, Permissions, XSS/Origin)"),
    STORAGE("Recording, Storage & Regulatory Compliance (Media Archival)"),
    DOS("Denial of Service (DoS / Resource Exhaustion)")
}

object SecurityTestReport {
    enum class Status(val label: String) {
        OBSERVED("Observed"), COMPLETED("Completed"), REVIEW("Review required"), FINDING("Finding"),
        ERROR("Error"), PARTIAL("Partial / unknown"), CANCELLED("Cancelled"), PENDING("Queued / running"),
        SKIPPED("Skipped / blocked"), CONFIGURED("Configured only"), NOT_TESTED("Not tested"), UNSUPPORTED("Not supported"), NOT_APPLICABLE("Not applicable")
    }
    data class Result(val test: String, val status: Status, val detail: String, val evidence: List<Long> = emptyList(), val authzIndex: Int? = null,
                      val checks: Set<CoverageCheck> = emptySet())
    data class Section(val area: SecurityArea, val results: List<Result>)
    data class CheckSummary(val check: CoverageCheck, val results: List<Result>) {
        val statuses: String get() = if (results.size == 1) results.single().status.label else
            results.groupingBy { it.status }.eachCount().entries.joinToString(", ") { "${it.key.label}: ${it.value}" }
        // Keep both problems and incomplete work visible instead of collapsing them to a pass/fail.
        val observation: String? get() = results.firstOrNull { it.status in setOf(Status.FINDING, Status.REVIEW, Status.ERROR, Status.PARTIAL) }
            ?.detail ?: results.lastOrNull { it.status in setOf(Status.OBSERVED, Status.COMPLETED) }?.detail
    }
    private val json = Json { ignoreUnknownKeys = true }
    private fun objectOf(event: TelemetryEvent) = runCatching { json.parseToJsonElement(event.raw).jsonObject }.getOrNull()
    private fun JsonObject?.str(key: String) = (this?.get(key) as? JsonPrimitive)?.contentOrNull
    private fun isTurnProbe(obj: JsonObject?): Boolean = obj.str("url")?.let { Regex("^turns?:", RegexOption.IGNORE_CASE).containsMatchIn(it) } == true ||
        obj.str("expected") == "relay" || obj.str("candidateType") == "relay" ||
        (obj?.get("counts") as? JsonObject).str("relay")?.toIntOrNull()?.let { it > 0 } == true
    private fun state(value: String?): Status = when (value?.lowercase()) {
        "completed", "complete" -> Status.COMPLETED
        "failed", "error", "expired", "timeout" -> Status.ERROR
        "cancelled" -> Status.CANCELLED
        "blocked", "skipped" -> Status.SKIPPED
        "queued", "running" -> Status.PENDING
        "partial" -> Status.PARTIAL
        else -> Status.PARTIAL
    }

    fun sections(config: WebRtcConfig, events: List<TelemetryEvent>, authz: List<AuthzResult>,
                 endpoints: List<SignalingMetadata.Endpoint> = emptyList()): List<Section> {
        val rows = SecurityArea.entries.associateWith { mutableListOf<Result>() }
        fun add(area: SecurityArea, test: String, status: Status, detail: String, source: List<TelemetryEvent> = emptyList(), authzIndex: Int? = null,
                checks: Set<CoverageCheck> = emptySet()) {
            rows.getValue(area).add(Result(test, status, detail, source.map { it.seq }.distinct(), authzIndex, checks))
        }
        fun unsupported(area: SecurityArea, test: String, detail: String) = add(area, test, Status.UNSUPPORTED, detail)
        fun absent(area: SecurityArea, test: String, present: Boolean, detail: String) {
            if (!present) add(area, test, Status.NOT_TESTED, detail)
        }
        fun source(event: TelemetryEvent) = "${event.frame} ${event.pcId}".trim()
        fun detail(event: TelemetryEvent) = objectOf(event).str("detail") ?: event.summary

        endpoints.forEach { endpoint ->
            add(SecurityArea.SIGNALING, "Captured HTTP transport / HSTS", if (!endpoint.secure || !endpoint.hsts) Status.REVIEW else Status.OBSERVED,
                "${endpoint.origin}: ${endpoint.requests} captured request(s), secure=${endpoint.secure}, HSTS observed=${endpoint.hsts}. Origin metadata does not identify WebSocket or SSE application authorization.", checks = setOf(CoverageCheck.TRANSPORT))
        }
        absent(SecurityArea.SIGNALING, "HTTP transport / HSTS review", endpoints.isNotEmpty(), "No captured HTTP origin metadata available.")
        unsupported(SecurityArea.SIGNALING, "WebSocket / HTTP-SSE message security", "WebSocket origin/auth checks, SSE access control, message tampering and reconnect/session behavior require application-specific tests.")

        val sdpEvents = events.filter { it.type in setOf("sdp-local", "sdp-remote") && objectOf(it).str("sdp") != null }
        for (event in sdpEvents) {
            val sdp = objectOf(event).str("sdp")!!
            val audits = Detectors.auditSdpAttributes(sdp)
            val codecs = Detectors.enumerateCodecs(sdp)
            add(SecurityArea.SDP, "Codec enumeration (advertised)", if (codecs.isEmpty()) Status.PARTIAL else Status.OBSERVED,
                "${source(event)}: advertised codecs=${codecs.joinToString(", ").ifEmpty { "none captured" }}. SDP advertisement does not establish the codec actually used.",
                listOf(event), checks = setOf(CoverageCheck.CODEC_ENUM))
            add(SecurityArea.SDP, "Passive SDP attribute / codec audit", if (audits.any { it.finding }) Status.FINDING else if (audits.isNotEmpty()) Status.REVIEW else Status.OBSERVED,
                "${source(event)}: ${event.type}; codecs=${Detectors.enumerateCodecs(sdp).joinToString(", ").ifEmpty { "not captured" }}. " +
                    audits.joinToString(" ") { it.text }.ifEmpty { "No attribute issue identified in the captured description; this is a passive review." }, listOf(event))
            val hasRtp = Regex("(?m)^m=(audio|video)\\s").containsMatchIn(sdp)
            if (hasRtp) add(SecurityArea.MEDIA, "SDP media keying", if (Detectors.usesSdesKeys(sdp)) Status.REVIEW else Status.OBSERVED,
                "${source(event)}: ${if (Detectors.usesSdesKeys(sdp)) "SDES a=crypto keys available to signaling participants; HTTPS may protect them in transit" else "No SDES a=crypto keys in this description"}. This does not prove negotiated SRTP or SRTCP protection.", listOf(event), checks = setOf(CoverageCheck.SRTP_SECURITY))
            if (hasRtp || sdp.contains("m=application")) add(SecurityArea.DTLS, "Advertised fingerprint / DTLS setup", if (!Detectors.hasDtlsFingerprint(sdp)) Status.REVIEW else Status.OBSERVED,
                "${source(event)}: fingerprint present=${Detectors.hasDtlsFingerprint(sdp)}; setup=${Detectors.setupRoles(sdp).joinToString(", ").ifEmpty { "not captured" }}. Advertisement is separate from handshake validation.", listOf(event))
            val creds = Detectors.iceCredentials(sdp)
            if (creds.isNotEmpty()) {
                val issues = creds.mapNotNull { Detectors.auditIceCredential(it) }
                add(SecurityArea.ICE, "ICE credential hygiene", if (issues.isEmpty()) Status.OBSERVED else Status.REVIEW,
                    "${source(event)}: " + issues.joinToString(" ").ifEmpty { "No length/character-diversity issue identified in captured ICE credentials." }, listOf(event), checks = setOf(CoverageCheck.ICE_CREDS))
            }
        }
        absent(SecurityArea.SDP, "Passive SDP attribute / codec audit", sdpEvents.isNotEmpty(), "No SDP description captured.")

        events.filter { it.type in setOf("sdp-mutation", "sdp-result", "sdp-error", "sdp-fuzz-result", "sdp-fuzz-error", "sdp-fuzz-summary") }.forEach { event ->
            val obj = objectOf(event)
            val baseline = obj.str("label") == "baseline-observed"
            val outcome = obj.str("outcome")
            val status = when {
                event.type.endsWith("error") || outcome == "setup-error" -> Status.ERROR
                baseline && outcome == "rejected" -> Status.ERROR
                event.type == "sdp-fuzz-result" && !baseline && outcome == "accepted" -> Status.REVIEW
                event.type == "sdp-fuzz-result" && outcome !in setOf("accepted", "rejected") -> Status.PARTIAL
                event.type == "sdp-fuzz-summary" -> if (obj.str("cases")?.toIntOrNull()?.let { expected ->
                    expected != events.count { it.type == "sdp-fuzz-result" && objectOf(it).str("commandId") == obj.str("commandId") }
                } == true) Status.PARTIAL else Status.COMPLETED
                else -> Status.OBSERVED
            }
            add(SecurityArea.SDP, if (baseline) "SDP parser baseline control" else "${event.type}: ${obj.str("label") ?: obj.str("kind") ?: "case"}", status,
                "${source(event)}: ${detail(event)}; outcome=${outcome ?: obj.str("accepted") ?: "see evidence"}; follow-up=${obj.str("followupOutcome") ?: "not recorded"}; error=${obj.str("error") ?: "none recorded"}. " +
                    if (baseline) "Baseline controls are excluded from mutation findings." else "Browser parser acceptance/rejection alone does not prove peer processing or a vulnerability.", listOf(event),
                checks = if (baseline) emptySet() else buildSet {
                    add(CoverageCheck.INJECTION); add(CoverageCheck.SIGNALING_FUZZ)
                    if (event.type == "sdp-fuzz-result" && obj.str("label")?.contains("codec-") == true) add(CoverageCheck.CODEC_FUZZ)
                })
        }
        absent(SecurityArea.SDP, "Active SDP mutation / parser fuzz", events.any { it.type in setOf("sdp-mutation", "sdp-result", "sdp-error", "sdp-fuzz-result", "sdp-fuzz-error", "sdp-fuzz-summary") }, "No recorded mutation or fuzz case. Enabled rules and generated payloads are not test results.")

        val inputs = webrtc.external.ExternalInputs.detect(config, events)
        if (inputs.iceServers.isNotEmpty()) add(SecurityArea.NAT, "ICE server configuration", Status.CONFIGURED,
            inputs.iceServers.joinToString("; ") { "urls=${it.urls.joinToString(",")} username=${it.username} credential=${it.credential}" })
        val probes = events.filter { it.type in setOf("ice-probe-candidate", "ice-probe-result", "ice-probe-error") }
        probes.forEach { event ->
            val obj = objectOf(event)
            val reason = obj.str("reason")
            val status = when {
                event.type == "ice-probe-error" -> Status.ERROR
                reason in setOf("timeout", "cancelled") -> state(reason)
                event.type == "ice-probe-result" && obj.str("observed") != "true" -> Status.PARTIAL
                else -> Status.OBSERVED
            }
            add(SecurityArea.NAT, "STUN/TURN gather / allocation", status,
                "${detail(event)}; url=${obj.str("url") ?: "not captured"}; username=${obj.str("username") ?: "not captured"}; credential=${obj.str("credential") ?: "not captured"}; counts=${obj?.get("counts") ?: "not supplied"}; errors=${obj.str("errors") ?: "not supplied"}. A relay candidate proves allocation was observed; it does not establish unauthorized access or unrestricted relay destinations.", listOf(event),
                checks = if (isTurnProbe(obj) && (event.type != "ice-probe-candidate" || obj.str("candidateType") == "relay")) setOf(CoverageCheck.TURN_AUTH, CoverageCheck.TURN_ABUSE) else emptySet())
        }
        absent(SecurityArea.NAT, "STUN/TURN gather / allocation", probes.isNotEmpty(), "No active gather/allocation evidence recorded.")
        unsupported(SecurityArea.NAT, "TURN relay destination restrictions / tunneling", "Arbitrary-destination relay, C2 tunneling and server-side credential policy are not tested by ICE gathering.")

        val candidates = events.filter { it.type == "ice" }
        EvidenceAnalysis.privacy(events).forEach { review ->
            add(SecurityArea.ICE, "Application candidate privacy review", if (review.policyMismatch) Status.REVIEW else Status.OBSERVED,
                review.text, listOf(review.event), checks = setOf(CoverageCheck.ICE_PRIVACY))
        }
        EvidenceAnalysis.restartIssues(events).forEach { issue ->
            add(SecurityArea.ICE, "Deliberate ICE restart", Status.REVIEW, issue, checks = setOf(CoverageCheck.ICE_CREDS))
        }
        absent(SecurityArea.ICE, "Application candidate harvesting / IP disclosure", candidates.isNotEmpty(), "No application ICE candidate captured; missing candidates do not establish privacy protection.")
        events.filter { it.type in setOf("selected-pair", "pc-state") }.forEach { event ->
            add(SecurityArea.ICE, "Selected path / peer connectivity", if (objectOf(event).str("iceConnectionState") == "failed" || objectOf(event).str("connectionState") == "failed") Status.REVIEW else Status.OBSERVED,
                "${source(event)}: ${detail(event)}. Connection failure/closure is a diagnostic, not proof of a DTLS attack or DoS.", listOf(event))
        }
        val latestCrypto = events.filter { it.type == "crypto" }.groupBy { listOf(it.frame, it.pcId, objectOf(it).str("agent"), objectOf(it).str("transportId")) }.values.map { it.maxBy { e -> e.seq } }
        latestCrypto.forEach { event ->
            val text = detail(event)
            for ((area, keys) in listOf(SecurityArea.MEDIA to listOf("srtp"), SecurityArea.DTLS to listOf("dtls", "tls"))) {
                val descriptions = sdpEvents.filter { it.frame == event.frame && it.pcId == event.pcId && objectOf(it).str("agent") == objectOf(event).str("agent") }.mapNotNull { objectOf(it).str("sdp") }
                val dataOnly = descriptions.any { it.contains("m=application") } && descriptions.none { Regex("(?m)^m=(audio|video)\\s").containsMatchIn(it) }
                val values = keys.mapNotNull { key -> Detectors.transportValue(text, key)?.let { "$key=$it" } }.joinToString(" ")
                val findings = Detectors.analyzeTransportSecurity(values)
                add(area, if (area == SecurityArea.MEDIA) "Negotiated SRTP profile" else "Negotiated DTLS cipher / version",
                    if (area == SecurityArea.MEDIA && dataOnly) Status.NOT_APPLICABLE else if (values.isEmpty()) Status.PARTIAL else if (findings.isNotEmpty()) Status.FINDING else Status.OBSERVED,
                    if (area == SecurityArea.MEDIA && dataOnly) "${source(event)}: captured descriptions are DataChannel-only; SRTP media profiles do not apply." else
                        "${source(event)}: ${values.ifEmpty { "value not captured; encryption status unknown" }}. " + findings.joinToString(" ").ifEmpty { "Captured values describe this transport only." }, listOf(event),
                    checks = setOf(if (area == SecurityArea.MEDIA) CoverageCheck.SRTP_SECURITY else CoverageCheck.DTLS_CIPHER))
            }
        }
        absent(SecurityArea.MEDIA, "Negotiated SRTP profile", latestCrypto.isNotEmpty(), "No crypto transport event captured; encryption status unknown.")
        absent(SecurityArea.DTLS, "Negotiated DTLS cipher / version", latestCrypto.isNotEmpty(), "No crypto transport event captured; handshake security unknown.")
        events.filter { it.type == "stats-snapshot" }.groupBy { listOf(it.frame, it.pcId, objectOf(it).str("agent")) }.values.forEach { history ->
            val event = history.maxBy { it.seq }
            val snapshot = StatsSnapshot.parse(event.raw)
            val usedCodecs = snapshot?.rtp?.map { it.codec }?.filter { it.isNotBlank() }?.distinct().orEmpty()
            if (usedCodecs.isNotEmpty()) add(SecurityArea.SDP, "Codec enumeration (in use)", if (snapshot?.truncated == true) Status.PARTIAL else Status.OBSERVED,
                "${source(event)}: in-use codecs=${usedCodecs.joinToString(", ")}; browser RTP stats only.", listOf(event), checks = setOf(CoverageCheck.CODEC_ENUM))
            add(SecurityArea.MEDIA, "Browser RTP transport statistics", if (snapshot == null || snapshot.truncated) Status.PARTIAL else Status.OBSERVED,
                "${source(event)}: streams=${snapshot?.rtp?.size ?: "unknown"}; ${snapshot?.rtp?.joinToString("; ") { "${it.direction} ${it.kind} codec=${it.codec} packets=${it.packets} lost=${it.packetsLost} jitter=${it.jitter}" }.orEmpty()}. Browser statistics do not test SRTP/SRTCP packet authentication, replay resistance or end-to-end encryption.", listOf(event))
            add(SecurityArea.ICE, "Browser ICE role / selected pair", if (snapshot == null || snapshot.pair.isBlank() || snapshot.truncated) Status.PARTIAL else Status.OBSERVED,
                "${source(event)}: role=${snapshot?.iceRole}; pair=${snapshot?.pair}; candidates=${snapshot?.candidates?.size ?: "unknown"}; truncated=${snapshot?.truncated}.", listOf(event))
        }
        unsupported(SecurityArea.MEDIA, "SRTP / SRTCP packet security", "Authentication tags, replay protection, SRTCP integrity, key lifecycle and media confidentiality require packet-level testing. Transport encryption does not establish end-to-end encryption.")
        val certificates = events.filter { it.type == "dtls-cert" }
        certificates.forEach { event ->
            val obj = objectOf(event)
            val role = obj.str("role").orEmpty()
            val certificate = CertificateAnalyzer.parse(role, obj.str("algorithm").orEmpty(), obj.str("fingerprint").orEmpty(), obj.str("base64").orEmpty())
            val binding = EvidenceAnalysis.binding(event, events)
            val descriptions = binding.descriptions
            val fingerprints = binding.fingerprints
            val issues = CertificateAnalyzer.analyze(listOf(certificate), fingerprints)
            val bindingUnknown = fingerprints.isEmpty() || issues.any { it.first.contains("binding is unknown") }
            add(SecurityArea.DTLS, "DTLS certificate validity / key / fingerprint review", when {
                certificate.parseError != null -> Status.ERROR
                issues.any { it.second } -> Status.FINDING
                bindingUnknown -> Status.PARTIAL
                issues.isNotEmpty() -> Status.REVIEW
                else -> Status.OBSERVED
            }, "${source(event)}: role=$role; algorithm=${obj.str("algorithm")}; fingerprint=${obj.str("fingerprint")}; key=${certificate.keyAlgorithm}/${certificate.keySize}; expires=${certificate.notAfter}. " +
                issues.joinToString(" ") { it.first } + if (bindingUnknown) " No matching peer/role/generation/transport description captured; binding is unknown." else " Review uses captured descriptions from this peer/direction; it does not prove remote handshake rejection.", listOf(event) + descriptions, checks = setOf(CoverageCheck.DTLS_CERT))
        }
        absent(SecurityArea.DTLS, "DTLS certificate capture", certificates.isNotEmpty(), "No DTLS certificate captured.")
        unsupported(SecurityArea.DTLS, "Raw DTLS handshake / malicious peer testing", "Raw UDP handshake, replay, downgrade/race and server fingerprint enforcement are not tested by the TCP TLS runner or local SDP parser.")

        val dcEvents = events.filter { it.type in setOf("dc-created", "dc-state", "dc-send", "dc-recv", "fuzz-result", "fuzz-error") }
        dcEvents.forEach { event ->
            val obj = objectOf(event)
            val status = when {
                event.type == "fuzz-error" || obj.str("accepted") == "false" -> Status.ERROR
                event.type == "dc-state" && obj.str("state") == "closed" && obj.str("everOpened") == "false" -> Status.REVIEW
                else -> Status.OBSERVED
            }
            add(SecurityArea.DATA, if (event.type.startsWith("fuzz")) "DataChannel payload fuzz" else "DataChannel lifecycle / traffic", status,
                "${source(event)}: ${detail(event)}; channel=${obj.str("channelId")}; state=${obj.str("state") ?: "not supplied"}; accepted=${obj.str("accepted") ?: "not supplied"}; bytes=${obj.str("bytes") ?: "not supplied"}. Local creation differs from open; send() acceptance does not prove remote parsing, processing or authorization.", listOf(event), checks = setOf(CoverageCheck.DATA_CHANNEL))
        }
        absent(SecurityArea.DATA, "DataChannel lifecycle / payload fuzz", dcEvents.isNotEmpty(), "No DataChannel result captured.")
        unsupported(SecurityArea.DATA, "SCTP packet / application authorization testing", "Native SCTP parser/reliability attacks and application message authorization need separate protocol/application tests.")
        unsupported(SecurityArea.ARCHITECTURE, "SFU / MCU / Gateway identification and isolation", "Architecture is not established by the current captures. Tenant isolation, routing, transcoding, gateway trust and media access require server-side/application evidence.")

        authz.forEachIndexed { index, result ->
            add(SecurityArea.AUTH, "HTTP authorization replay: ${result.variant}", when {
                result.variant == "SKIPPED" -> Status.SKIPPED
                result.status == 0 -> Status.ERROR
                result.flagged -> Status.REVIEW
                else -> Status.OBSERVED
            }, "${result.baselineUrl}: HTTP ${result.status}; length=${result.length}; body hash=${result.bodyHash}; same as baseline=${result.sameAsBaseline}; flagged=${result.flagged}; ${result.note}. A non-baseline 2xx is a review lead; resource ownership and intended permissions must be verified.", authzIndex = index + 1,
                checks = if (result.variant == "baseline") emptySet() else setOf(CoverageCheck.SIGNALING_AUTH, CoverageCheck.API_SECURITY))
        }
        absent(SecurityArea.AUTH, "HTTP authorization matrix", authz.isNotEmpty(), "No replay results recorded. Configured identities are not executed tests.")
        config.identifierKeys.forEach { key ->
            val values = config.identities.mapNotNull { it.identifiers[key] }.filter { it.isNotBlank() }
            Detectors.guessableIdentifiers(values)?.let { add(SecurityArea.AUTH, "Configured identifier guessability", Status.REVIEW, "$key: $it (configuration review only; no identifier enumeration performed)") }
        }
        unsupported(SecurityArea.AUTH, "Session / token lifecycle and room access", "Token expiry, revocation, logout, fixation, room membership and media/data authorization are not established by HTTP status codes alone.")

        add(SecurityArea.CLIENT, "Test instrumentation configuration", Status.CONFIGURED,
            "injectionEnabled=${config.injectionEnabled}, stripCsp=${config.stripCsp}. When CSP stripping is enabled, observed page behavior reflects modified CSP; enforced frame-ancestors is preserved. This is not an XSS/origin protection test.")
        val browserEvents = events.filter { it.type in setOf("installed", "getUserMedia", "getUserMedia-result") }
        browserEvents.forEach { event ->
            add(SecurityArea.CLIENT, if (event.type == "installed") "Browser agent installation" else "Camera / microphone permission observation", Status.OBSERVED,
                "${event.frame}: ${detail(event)}; outcome=${objectOf(event).str("outcome") ?: "not supplied"}; error=${objectOf(event).str("error") ?: "none supplied"}. Permission grant/rejection is an observation, not a bypass test.", listOf(event),
                checks = if (event.type == "getUserMedia-result") setOf(CoverageCheck.PERMISSIONS) else emptySet())
        }
        absent(SecurityArea.CLIENT, "Browser API / permission observations", browserEvents.isNotEmpty(), "No installation or media-permission event recorded.")
        unsupported(SecurityArea.CLIENT, "XSS / origin / iframe / Permissions Policy enforcement", "Agent injection is not an XSS finding. These controls require dedicated tests against original responses and page behavior.")
        unsupported(SecurityArea.STORAGE, "Recording / archival / regulatory compliance", "No recording-storage or compliance tests implemented. Access controls, retention/deletion, encryption at rest, consent, residency and regulatory requirements require application and policy evidence.")

        val floodEvents = events.filter { it.type in setOf("flood-result", "signaling-flood-summary", "signaling-flood-error") }
        floodEvents.forEach { event ->
            add(SecurityArea.DOS, "Bounded local renegotiation / ICE restart", if (event.type.endsWith("error")) Status.ERROR else if (event.type.endsWith("summary")) Status.COMPLETED else Status.OBSERVED,
                "${detail(event)}; attempts=${objectOf(event).str("attempts") ?: objectOf(event).str("index")}; reused=${objectOf(event).str("reusedCredentials") ?: objectOf(event).str("reused")}. Local browser operations send no signaling flood to the server and do not establish server DoS resistance.", listOf(event), checks = setOf(CoverageCheck.SIGNALING_DOS))
        }
        absent(SecurityArea.DOS, "Bounded local renegotiation / ICE restart", floodEvents.isNotEmpty(), "No local flood-test result captured; an enabled checkbox is not a run.")
        unsupported(SecurityArea.DOS, "Server / media resource exhaustion", "Server saturation, connection/room quotas, TURN bandwidth exhaustion, RTP floods and sustained recovery/resource measurements are not tested here.")

        // Preserve every run's latest state, including jobs that never produced case results.
        val jobAreas = mapOf("sdp-fuzz" to SecurityArea.SDP, "dc-fuzz" to SecurityArea.DATA,
            "ice-probe" to SecurityArea.NAT, "capture-stats" to SecurityArea.MEDIA, "signaling-flood" to SecurityArea.DOS)
        events.filter { it.type == "test-job" }.groupBy { objectOf(it).str("commandId") ?: "event-${it.seq}" }.values.forEach { history ->
            val latest = history.maxBy { it.seq }; val obj = objectOf(latest)
            jobAreas[obj.str("module")]?.let { area ->
                add(area, "Active run ${obj.str("module")} / ${obj.str("commandId")}", state(obj.str("status")),
                    "Latest recorded job state=${obj.str("status")}. Completion describes execution; individual payload/response evidence determines the result.", history,
                    checks = when (obj.str("module")) {
                        "sdp-fuzz" -> setOf(CoverageCheck.INJECTION, CoverageCheck.SIGNALING_FUZZ)
                        "dc-fuzz" -> setOf(CoverageCheck.DATA_CHANNEL)
                        "signaling-flood" -> setOf(CoverageCheck.SIGNALING_DOS)
                        else -> emptySet()
                    })
            }
        }
        events.filter { it.type in setOf("tls-scan-start", "tls-scan-result", "tls-scan-error") }.forEach { event ->
            val obj = objectOf(event); val target = obj.str("target").orEmpty()
            if (event.type == "tls-scan-start") {
                val next = events.filter { it.seq > event.seq && it.type in setOf("tls-scan-start", "tls-scan-result", "tls-scan-error") && objectOf(it).str("target") == target }.minByOrNull { it.seq }
                if (next != null && next.type != "tls-scan-start") return@forEach
            }
            val area = if (target.startsWith("turns:", true)) SecurityArea.NAT else SecurityArea.SIGNALING
            val result = obj?.get("result") as? JsonObject
            val tlsChecks = setOf(CoverageCheck.TLS_VERSION, CoverageCheck.TLS_CIPHER)
            add(area, "TCP TLS listener scan: $target", if (event.type == "tls-scan-start") Status.PENDING else state(result.str("status")),
                "${detail(event)}; ${result.str("error").orEmpty()}. This is the TCP listener, not media DTLS/SRTP.", listOf(event),
                checks = if (event.type == "tls-scan-start" || event.type == "tls-scan-error") tlsChecks else emptySet())
            (result?.get("checks") as? JsonArray)?.forEach { element ->
                val check = element as? JsonObject ?: return@forEach
                add(area, "TLS $target / ${check.str("name")}", state(check.str("status")), check.str("summary") ?: "No per-check summary", listOf(event),
                    checks = if (check.str("name") in tlsProtocolChecks) tlsChecks else emptySet())
            }
            (result?.get("findings") as? JsonArray)?.forEach { element ->
                val finding = element as? JsonObject ?: return@forEach
                add(area, "TLS $target / scanner observation", if (finding.str("level") == "finding") Status.FINDING else Status.REVIEW,
                    finding.str("text") ?: "No finding text", listOf(event), checks = when {
                        finding.str("check") in tlsProtocolChecks && finding.str("text")?.startsWith("Weak cipher suite(s) accepted:") == true -> setOf(CoverageCheck.TLS_CIPHER)
                        finding.str("check") in tlsProtocolChecks -> setOf(CoverageCheck.TLS_VERSION)
                        // Compatibility with the 1.0.3/1.0.4 runner's untagged observations.
                        finding.str("text")?.startsWith("Weak cipher suite(s) accepted:") == true -> setOf(CoverageCheck.TLS_CIPHER)
                        Regex("^(ssl [23] 0|tls 1 [01]) accepted by the listener$", RegexOption.IGNORE_CASE).matches(finding.str("text").orEmpty()) -> setOf(CoverageCheck.TLS_VERSION)
                        else -> emptySet()
                    })
            }
        }
        for (area in listOf(SecurityArea.SIGNALING, SecurityArea.NAT)) absent(area, "TCP TLS listener scan",
            rows.getValue(area).any { it.test.startsWith("TCP TLS listener scan:") }, "No selected listener TLS scan recorded. Generated external commands are not executed tests.")
        // Every methodology item remains visible, even with an empty engagement or only unrelated evidence.
        for (check in CoverageCheck.entries) {
            if (check.support == CoverageSupport.EXTERNAL) {
                add(check.area, check.title, Status.UNSUPPORTED, "${check.scope} ${check.nextStep}", checks = setOf(check))
            } else if (rows.values.flatten().none { check in it.checks }) {
                add(check.area, check.title, Status.NOT_TESTED, "No matching result captured. ${check.scope} ${check.nextStep}", checks = setOf(check))
            }
        }
        return SecurityArea.entries.map { Section(it, rows.getValue(it).toList()) }
    }

    private val tlsProtocolChecks = setOf("ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites", "tls_1_0_cipher_suites",
        "tls_1_1_cipher_suites", "tls_1_2_cipher_suites", "tls_1_3_cipher_suites")

    fun checklist(sections: List<Section>): List<CheckSummary> = CoverageCheck.entries.map { check ->
        CheckSummary(check, sections.flatMap { it.results }.filter { check in it.checks })
    }

    /** One line per check; support and execution state remain separate. Full values live in the evidence tables. */
    fun summaryText(summary: CheckSummary): String = buildString {
        append("${summary.check.title} — ${summary.check.support.label}; ${summary.statuses}. ${summary.check.scope}")
        summary.observation?.let { append(" Result: ${it.replace(Regex("\\s+"), " ").take(200)}${if (it.length > 200) "…" else ""}") }
    }

    fun summaryMarkdown(sections: List<Section>): String = buildString {
        appendLine("## Security checklist — concise summary"); appendLine()
        appendLine("Every requested test is listed below. Coverage describes what the extension can do; result states describe captured evidence, never an overall security pass. External/manual checks have not run here. Repeated checks across groups refer to the same evidence.")
        appendLine()
        val summaries = checklist(sections)
        for (group in CoverageGroup.entries) {
            appendLine("### ${group.title}"); appendLine()
            val ordered = if (group == CoverageGroup.RESILIENCE) {
                listOf(CoverageCheck.SIGNALING_FUZZ, CoverageCheck.SIGNALING_DOS, CoverageCheck.API_FLOOD, CoverageCheck.RTP_FUZZ, CoverageCheck.CODEC_FUZZ)
                    .map { check -> summaries.single { it.check == check } }
            } else summaries.filter { group in it.check.groups }
            for (summary in ordered) {
                val check = summary.check
                append("- **${check.title}** — ${check.support.label}; ${summary.statuses}. ${check.scope}")
                summary.observation?.let {
                    val text = it.replace(Regex("\\s+"), " ")
                    append(" Result: ${cell(text.take(200))}${if (text.length > 200) "…" else ""}")
                }
                appendLine(" [Details / next step](#check-${check.name.lowercase()}).")
            }
            appendLine()
        }
    }

    /** Escape values in Markdown tables; raw evidence remains byte-for-byte text in fenced blocks. */
    private fun cell(value: String): String = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\\", "&#92;").replace("|", "&#124;").replace("`", "&#96;").replace("*", "&#42;")
        .replace("_", "&#95;").replace("[", "&#91;").replace("]", "&#93;").replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")

    fun markdown(config: WebRtcConfig, events: List<TelemetryEvent>, authz: List<AuthzResult>, endpoints: List<SignalingMetadata.Endpoint> = emptyList(),
                 includeSummary: Boolean = true): String {
        val sections = sections(config, events, authz, endpoints)
        return buildString {
            if (includeSummary) append(summaryMarkdown(sections))
            appendLine("## Security test results")
            appendLine()
            appendLine("Results reflect recorded evidence only. Observed means passive evidence; Completed means execution finished. Neither is an overall security pass. Review required is a triage lead. Not tested means no result was captured; Not supported identifies a coverage gap. Queued/running, partial, cancelled and errors are incomplete.")
            appendLine()
            appendLine("Counts below are result rows, not unique tests or a coverage percentage; one check can have several observations and remaining gaps.")
            appendLine()
            appendLine("| Area | Recorded results | Incomplete / pending | Missing / unsupported rows |")
            appendLine("| --- | ---: | ---: | ---: |")
            sections.forEachIndexed { index, section ->
                val results = section.results
                appendLine("| ${index + 1}. ${cell(section.area.title)} | ${results.count { it.status in setOf(Status.OBSERVED, Status.COMPLETED, Status.REVIEW, Status.FINDING) }} | ${results.count { it.status in setOf(Status.ERROR, Status.PARTIAL, Status.CANCELLED, Status.PENDING, Status.SKIPPED) }} | ${results.count { it.status in setOf(Status.NOT_TESTED, Status.UNSUPPORTED) }} |")
            }
            appendLine()
            sections.forEachIndexed { index, section ->
                appendLine("## ${index + 1}. ${section.area.title}")
                appendLine()
                for (check in CoverageCheck.entries.filter { it.area == section.area }) {
                    appendLine("<a id=\"check-${check.name.lowercase()}\"></a>"); appendLine()
                    appendLine("- **${check.title} (${check.support.label}):** ${check.scope} Next: ${check.nextStep}")
                    appendLine()
                }
                appendLine("| Test / check | Result | Details / limitations | Evidence |")
                appendLine("| --- | --- | --- | --- |")
                section.results.forEach { result ->
                    val refs = result.evidence.joinToString(", ") { "[#$it](#event-$it)" } +
                        (result.authzIndex?.let { "[Authz $it](#authz-$it)" } ?: "")
                    appendLine("| ${cell(result.test)} | ${result.status.label} | ${cell(result.detail)} | ${refs.ifEmpty { "—" }} |")
                }
                appendLine()
            }
            appendLine("## Test evidence")
            appendLine()
            val used = sections.flatMap { it.results }.flatMap { it.evidence }.toSet()
            events.filter { it.seq in used }.forEach { event ->
                appendLine("<a id=\"event-${event.seq}\"></a>")
                appendLine()
                appendLine("### Event #${event.seq}: ${cell(event.type)}")
                appendLine()
                appendLine("Time: ${cell(event.time)} · Frame: ${cell(event.frame)} · Peer: ${cell(event.pcId)}")
                appendLine()
                val fence = "`".repeat(maxOf(3, (Regex("`+").findAll(event.raw).maxOfOrNull { it.value.length } ?: 0) + 1))
                appendLine("${fence}json"); appendLine(event.raw); appendLine(fence); appendLine()
            }
            authz.forEachIndexed { index, result ->
                appendLine("<a id=\"authz-${index + 1}\"></a>"); appendLine()
                appendLine("### Authz ${index + 1}: ${cell(result.variant)}"); appendLine()
                appendLine("URL: ${cell(result.baselineUrl)} · HTTP ${result.status} · Length: ${result.length} · Body hash: ${cell(result.bodyHash)} · Same as baseline: ${result.sameAsBaseline} · Flagged: ${result.flagged}")
                appendLine(); appendLine(cell(result.note)); appendLine()
            }
        }
    }
}
