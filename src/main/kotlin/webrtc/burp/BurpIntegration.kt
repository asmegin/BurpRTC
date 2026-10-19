package webrtc.burp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.SecretKey
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.intruder.AttackConfiguration
import burp.api.montoya.intruder.GeneratedPayload
import burp.api.montoya.intruder.IntruderInsertionPoint
import burp.api.montoya.intruder.PayloadGenerator
import burp.api.montoya.intruder.PayloadGeneratorProvider
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import kotlinx.serialization.json.*
import webrtc.authz.AuthzResult
import webrtc.canary.CanaryRegistry
import webrtc.canary.OutOfBand
import webrtc.canary.OutOfBandHit
import webrtc.config.ConfigStore
import webrtc.telemetry.PolicyAudit
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.net.URI
import java.time.Instant

/** Burp Collaborator (Professional only). The client key is persisted so callbacks survive reloads. */
class BurpCollaborator(private val api: MontoyaApi, private val loadSecret: () -> String?, private val saveSecret: (String) -> Unit) : OutOfBand {
    @Volatile private var client: CollaboratorClient? = null
    @Volatile private var unavailable = false
    @Synchronized private fun client(): CollaboratorClient? {
        if (unavailable) return null
        client?.let { return it }
        return runCatching {
            val existing = loadSecret()?.takeIf { it.isNotBlank() }
            val created = existing?.let { runCatching { api.collaborator().restoreClient(SecretKey.secretKey(it)) }.getOrNull() }
                ?: api.collaborator().createClient()
            saveSecret(created.getSecretKey().toString())
            created
        }.onFailure { unavailable = true }.getOrNull().also { client = it }
    }
    fun available(): Boolean = client() != null
    override fun payload(customData: String): String = client()?.generatePayload(customData)?.toString()
        ?: error("Burp Collaborator is unavailable (Burp Suite Professional required)")
    override fun poll(): List<OutOfBandHit> = client()?.getAllInteractions().orEmpty().map { interaction ->
        val detail = interaction.httpDetails().map { it.requestResponse().request().toString() }.orElse(null)
            ?: interaction.dnsDetails().map { "DNS ${it.queryType()} query" }.orElse(null)
            ?: interaction.smtpDetails().map { it.conversation() }.orElse("")
        OutOfBandHit(interaction.id().toString(), interaction.customData().orElse(null), interaction.type().name,
            interaction.clientIp().hostAddress, interaction.timeStamp().toString(), detail)
    }
    override fun secret(): String? = client?.getSecretKey()?.toString()
}

/**
 * Adds deduplicated, WebRTC-specific issues to Burp's Issues list so findings flow
 * into Burp's own reporting. Generic header issues that Burp's passive scanner
 * already raises (HSTS, cookie flags, framing) are left to Burp to avoid duplicates.
 */
class IssueReporter(private val sink: (Spec) -> Unit, private val config: ConfigStore, private val telemetry: TelemetryTableModel) {
    data class Spec(val key: String, val name: String, val detail: String, val remediation: String, val baseUrl: String,
                    val severity: AuditIssueSeverity, val confidence: AuditIssueConfidence, val background: String,
                    val evidence: List<HttpRequestResponse> = emptyList())
    private val reported = java.util.Collections.synchronizedSet(HashSet<String>())
    private val json = Json { ignoreUnknownKeys = true }

    fun attach() = telemetry.onEvent { runCatching { onEvent(it) } }

    fun report(spec: Spec): Boolean {
        if (!config.config.burpIssues || !reported.add(spec.key)) return false
        val baseUrl = httpUrl(spec.baseUrl) ?: return false
        sink(spec.copy(baseUrl = baseUrl))
        val raw = buildJsonObject { put("type", "burp-issue"); put("frame", baseUrl); put("detail", "Burp issue added: ${spec.name}"); put("severity", spec.severity.name); put("key", spec.key) }
        telemetry.add(TelemetryEvent(telemetry.nextSeq(), Instant.now().toString(), "burp-issue", baseUrl, "", false, "Burp issue added: ${spec.name}", raw.toString()))
        return true
    }

    fun reportAuthz(result: AuthzResult) {
        if (result.verdict != AuthzResult.LIKELY_VIOLATION) return
        report(Spec("authz|${result.variant}|${result.baselineUrl.substringBefore('?')}",
            "Broken access control (WebRTC session comparison)",
            "${result.baselineUrl} returned the baseline principal's data to ${result.variant}. ${result.note}",
            "Enforce server-side authorization on every request using the authenticated principal, role and resource ownership. Do not rely on unguessable identifiers or client-side role checks.",
            result.baselineUrl, AuditIssueSeverity.HIGH, AuditIssueConfidence.TENTATIVE,
            "The extension replayed a captured request with another captured session or role, or without credentials. The response matched the baseline and contained the baseline owner's identifying values.",
            listOfNotNull(result.baselineRequestResponse, result.requestResponse)))
    }

    private fun obj(event: TelemetryEvent) = runCatching { json.parseToJsonElement(event.raw).jsonObject }.getOrNull()
    private fun JsonObject?.str(key: String) = (this?.get(key) as? JsonPrimitive)?.contentOrNull

    private fun onEvent(event: TelemetryEvent) {
        val o = obj(event)
        when (event.type) {
            "xss-canary-fired" -> report(Spec("canary-fired|${o.str("canaryId")}|${o.str("origin")}", "Stored cross-site scripting (WebRTC canary executed)",
                "XSS canary ${o.str("canaryId")} placed in '${o.str("context")}' executed in ${o.str("href")}. Script-readable cookies: ${o.str("readableCookies").orEmpty().ifBlank { "none" }}.",
                "HTML-encode user-controlled values (chat messages, display names, file names, room metadata) for the context where they are rendered, and deploy a strict Content-Security-Policy.",
                o.str("href") ?: event.frame, AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN,
                "The canary payload calls a hook defined only by the extension's agent. The agent in the rendering page reported the call, which proves script execution in that page."))
            "collaborator-interaction" -> {
                val callback = o.str("purpose") == "callback"
                val http = o.str("interactionType") == "HTTP"
                report(Spec("oob|${o.str("canaryId")}|${o.str("interactionType")}", if (callback) "Out-of-band callback from target (WebRTC canary)" else "HTML injection (WebRTC canary loaded Collaborator)",
                    "Burp Collaborator received a ${o.str("interactionType")} interaction for canary ${o.str("canaryId")} ('${o.str("context")}') from ${o.str("clientIp")}.\n\n${o.str("interaction").orEmpty().take(4000)}",
                    if (callback) "Validate and allow-list outbound URLs (webhooks, recording/export targets, avatars, document imports). Block internal and metadata addresses."
                    else "Encode user-controlled values before rendering them as HTML.",
                    o.str("frame") ?: event.frame, if (callback || http) AuditIssueSeverity.MEDIUM else AuditIssueSeverity.LOW,
                    if (http) AuditIssueConfidence.FIRM else AuditIssueConfidence.TENTATIVE,
                    "Collaborator payloads are unique per canary. A DNS-only interaction can come from link previews or scanners."))
            }
            "track-state" -> if (o.str("action") == "live-after-close") report(Spec("capture-live|${event.frame.substringBefore('?')}|${o.str("source")}",
                "Media capture remains active after call ends",
                "${event.frame}: ${o.str("detail")}.", "Stop every captured MediaStreamTrack (track.stop()) when a call ends or screen sharing stops.",
                event.frame, AuditIssueSeverity.LOW, AuditIssueConfidence.FIRM,
                "The agent checked the capture tracks 3 seconds after the last RTCPeerConnection on the page closed."))
            "message-sent" -> if (Regex("(?i)token|jwt|session|password|secret|auth").containsMatchIn(o.str("data").orEmpty()))
                report(Spec("postmessage-star|${event.frame.substringBefore('?')}", "Sensitive data sent with postMessage to any origin",
                    "${event.frame} posted a message with target origin \"*\" containing token-like data:\n${o.str("data")}",
                    "Always pass the exact expected target origin to postMessage.", event.frame, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.TENTATIVE,
                    "A wildcard target origin delivers the message to whatever page currently embeds or opened the frame."))
            "original-policy" -> PolicyAudit.audit(listOf(event)).filter { it.webrtcSpecific }.forEach { issue ->
                report(Spec("policy|${issue.key}", issue.title + " (WebRTC)", issue.detail,
                    "Restrict camera, microphone and display-capture with Permissions-Policy and keep bearer tokens out of URLs.",
                    issue.url, if (issue.level == PolicyAudit.Level.REVIEW) AuditIssueSeverity.LOW else AuditIssueSeverity.INFORMATION,
                    AuditIssueConfidence.FIRM, "Evaluated on the original response headers, before the extension's agent injection changed them."))
            }
            "assessment-result" -> {
                val outcome = o?.get("outcome") as? JsonObject
                if (outcome.str("security") == "policy-violation") report(Spec("assessment|${outcome.str("testId")}|${outcome.str("target")}",
                    "WebRTC security check failed: ${outcome.str("testId")}",
                    "${outcome.str("testId")} against ${outcome.str("target")} demonstrated a policy violation (confidence ${outcome.str("confidence")}). Limitations: ${(outcome?.get("limitations") as? JsonArray)?.joinToString("; ") { (it as? JsonPrimitive)?.content.orEmpty() }}",
                    "Review the full evidence in the extension's Security checks tab and restrict the demonstrated behaviour.",
                    scopeUrl(outcome.str("target").orEmpty()) ?: event.frame, severity(outcome.str("severity")), AuditIssueConfidence.FIRM,
                    "Recorded by the extension's built-in protocol or scenario runner with a passing positive control."))
            }
            "dc-case-result" -> {
                val element = o?.get("result") ?: return
                val result = runCatching { json.decodeFromJsonElement(webrtc.datachannel.DcCaseResult.serializer(), element) }.getOrNull() ?: return
                val issue = webrtc.datachannel.DcIssues.classify(result) ?: return
                val origin = webrtc.bridge.BridgeSessions.originOf(result.senderFrame)
                val receipts = result.receipts.take(5).joinToString("\n") { "  - ${it.participant} (${it.kind}${if (it.from.isNotBlank()) ", from=${it.from}" else ""})" }
                // One issue per failure category and site; the detail names the first failing case.
                report(Spec("dc|${issue.category}|$origin", issue.name,
                    "Case ${result.caseId}: ${result.title}\nTransport: ${result.transport}; sender ${result.sender} (endpoint ${result.senderEndpoint.ifBlank { "unknown" }})\n" +
                        "Result: ${result.reasons.joinToString("; ")}\n" + (if (receipts.isNotBlank()) "Recipient observations:\n$receipts\n" else "") +
                        "Payload: ${result.payload.take(2000)}\nRun ${result.runId}; see Tests → Data channel runner for the full evidence and other failing cases.",
                    issue.remediation, result.senderFrame.ifBlank { event.frame },
                    when (issue.severity) { "high" -> AuditIssueSeverity.HIGH; "medium" -> AuditIssueSeverity.MEDIUM; "low" -> AuditIssueSeverity.LOW; else -> AuditIssueSeverity.INFORMATION },
                    when (issue.confidence) { "certain" -> AuditIssueConfidence.CERTAIN; "firm" -> AuditIssueConfidence.FIRM; else -> AuditIssueConfidence.TENTATIVE },
                    issue.background))
            }
            "tls-scan-result" -> {
                val result = o?.get("result") as? JsonObject
                val target = o.str("scopeUrl") ?: return
                (result?.get("findings") as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }.filter { it.str("level") == "finding" }.forEach { finding ->
                    report(Spec("tls|$target|${finding.str("text")}", "TLS listener weakness (WebRTC TLS scan)",
                        "${o.str("target")}: ${finding.str("text")}", "Disable legacy protocol versions and weak cipher suites on the listener.",
                        target, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM, "Direct TCP TLS handshake probes against the selected listener."))
                }
            }
        }
    }

    private fun severity(value: String?) = when (value) {
        "critical", "high" -> AuditIssueSeverity.HIGH; "medium" -> AuditIssueSeverity.MEDIUM
        "low" -> AuditIssueSeverity.LOW; else -> AuditIssueSeverity.INFORMATION
    }
    private fun scopeUrl(target: String): String? = runCatching { webrtc.protocol.ProtocolTarget.parse(target).scopeUrl }.getOrNull()
    private fun httpUrl(value: String): String? = runCatching {
        val uri = URI(value)
        when (uri.scheme?.lowercase()) {
            "http", "https" -> value
            "ws" -> "http" + value.substring(2)
            "wss" -> "https" + value.substring(3)
            else -> null
        }
    }.getOrNull()
    companion object {
        private fun html(text: String) = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
        /** Builds the Burp issue; only callable inside Burp, where Montoya's factories exist. */
        fun toAuditIssue(spec: Spec): AuditIssue = AuditIssue.auditIssue(spec.name, html(spec.detail), html(spec.remediation), spec.baseUrl,
            spec.severity, spec.confidence, html(spec.background), null, spec.severity, spec.evidence)
    }
}

/** Intruder payload source: one fresh canary per attack, all variants in turn. */
class CanaryPayloadGeneratorProvider(private val registry: CanaryRegistry) : PayloadGeneratorProvider {
    override fun displayName() = "WebRTC XSS canaries"
    override fun providePayloadGenerator(attack: AttackConfiguration): PayloadGenerator {
        val label = "Intruder " + runCatching { attack.httpService().map { it.host() }.orElse("") + " " + attack.requestTemplate().content().toString().lineSequence().first().take(60) }.getOrDefault("")
        val payloads = registry.payloads(registry.create(label))
        var index = 0
        return PayloadGenerator { _: IntruderInsertionPoint ->
            if (index < payloads.size) GeneratedPayload.payload(payloads[index++].value) else GeneratedPayload.end()
        }
    }
}
