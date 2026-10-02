package webrtc.ui

import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryTableModel
import webrtc.workflow.RunAllController
import webrtc.report.SecurityTestReport
import webrtc.BuildInfo
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.io.File
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import javax.swing.*

/**
 * M7 — findings + report export. Compiles a plain-text / Markdown report from the
 * passive analysis (config, telemetry findings, M3/M5 guidance) plus a telemetry
 * summary, and saves it to a file. It never runs an active test, so a report can
 * be generated at any point in the engagement without touching the target.
 * Credentials (identity headers, TURN usernames/passwords) are preserved in full:
 * the tester decides what to remove from the final report evidence.
 */
class FindingsPanel(
    private val orchestrator: RunAllController,
    private val configStore: ConfigStore,
    private val telemetry: TelemetryTableModel,
    private val authzResults: AuthzResultTableModel
) : JPanel(BorderLayout()) {

    private val report = JTextArea().apply {
        isEditable = false
        lineWrap = false
        font = java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12)
    }
    private val status = JLabel(" ")

    init {
        val intro = JTextArea(
            "Findings (M7) — generate a point-form checklist for authentication, media/RTP, " +
                "resilience, signaling protocols and other security categories, followed by " +
                "configuration (credentials preserved in full) and results across 12 areas: SDP, ICE, " +
                "STUN/TURN, DTLS/SRTP, DataChannels, TLS and authorization replays. " +
                "Missing results and unsupported checks are explicit. Generate it any " +
                "time; it is passive and does not touch the target. Linked raw evidence " +
                "and SDP before/after are included in the report. " +
                "Export all telemetry and authorization-matrix results to CSV for analysis."
        ).apply {
            isEditable = false; lineWrap = true; wrapStyleWord = true; isOpaque = false
            border = BorderFactory.createEmptyBorder(8, 10, 4, 10)
            font = UIManager.getFont("Label.font")
        }

        val buttons = JPanel(FlowLayout(FlowLayout.LEFT)).apply {
            add(JButton("Generate report").apply { addActionListener { generate() } })
            add(JButton("Export all data (CSV)…").apply { addActionListener { exportCsv() } })
            add(JButton("Save report…").apply { addActionListener { save() } })
            add(JButton("Clear").apply { addActionListener { report.text = ""; status.text = " " } })
            add(status)
        }
        add(JPanel(BorderLayout()).apply {
            add(intro, BorderLayout.NORTH)
            add(buttons, BorderLayout.SOUTH)
        }, BorderLayout.NORTH)
        add(JScrollPane(report), BorderLayout.CENTER)
    }

    private fun generate() {
        report.text = buildReport()
        report.caretPosition = 0
        status.text = "report generated"
    }

    private fun save() {
        if (report.text.isBlank()) generate()
        val stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
        val chooser = JFileChooser().apply {
            selectedFile = File("webrtc-findings-$stamp.md")
            dialogTitle = "Save findings report"
        }
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return
        try {
            chooser.selectedFile.writeText(report.text)
            status.text = "saved ${chooser.selectedFile.name}"
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(this, e.message, "Could not save report", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun exportCsv() {
        val stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
        val chooser = JFileChooser().apply {
            selectedFile = File("webrtc-telemetry-$stamp.csv")
            dialogTitle = "Export all WebRTC telemetry"
        }
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return
        try {
            val rows = buildList {
                add(listOf("record_type", "sequence", "time", "type", "frame", "peer", "private", "summary", "raw_json",
                    "url", "variant", "status", "response_length", "body_hash", "same_as_baseline", "flagged", "note"))
                telemetry.snapshot().forEach { event ->
                    add(listOf("telemetry", event.seq.toString(), event.time, event.type, event.frame, event.pcId,
                        event.private.toString(), event.summary, event.raw, "", "", "", "", "", "", "", ""))
                }
                authzResults.snapshot().forEach { result ->
                    add(listOf("authz", "", "", "authz-matrix", "", "", "", "", "", result.baselineUrl,
                        result.variant, result.status.toString(), result.length.toString(), result.bodyHash,
                        result.sameAsBaseline.toString(), result.flagged.toString(), result.note))
                }
            }
            chooser.selectedFile.writeText(
                rows.joinToString("\r\n") { row -> row.joinToString(",", transform = ::csvField) },
                Charsets.UTF_8
            )
            status.text = "exported ${rows.size - 1} records to ${chooser.selectedFile.name}"
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(this, e.message, "Could not export telemetry CSV", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun csvField(value: String): String = "\"${value.replace("\"", "\"\"")}\""

    private fun buildReport(): String {
        val cfg = configStore.config
        val events = telemetry.snapshot()
        val authz = authzResults.snapshot()
        val endpoints = orchestrator.observedSignalingEndpoints()
        val sb = StringBuilder()
        sb.appendLine("# WebRTC Test Suite — findings report")
        sb.appendLine()
        sb.appendLine("Generated: ${LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)}")
        sb.appendLine("Extension version: ${BuildInfo.version}")
        sb.appendLine()

        sb.appendLine(SecurityTestReport.summaryMarkdown(SecurityTestReport.sections(cfg, events, authz, endpoints)))

        sb.appendLine("## Configuration (M0)")
        sb.appendLine("- Injection enabled: ${cfg.injectionEnabled}")
        sb.appendLine("- Strip CSP: ${cfg.stripCsp}")
        sb.appendLine("- Host allow-list: ${cfg.hostAllowList.joinToString(", ").ifBlank { "(empty)" }}")
        sb.appendLine("- Bridge: ${cfg.bridgeHost}:${cfg.bridgePort}")
        sb.appendLine("- Identities: ${cfg.identities.size} (credentials preserved in full)")
        cfg.identities.forEach { identity ->
            val headers = identity.headers.entries.joinToString("; ") { "${it.key}: ${it.value}" }.ifBlank { "(none)" }
            val identifiers = identity.identifiers.entries.joinToString("; ") { "${it.key}=${it.value}" }.ifBlank { "(none)" }
            sb.appendLine("  - ${identity.name}: headers [${headers}]; identifiers [${identifiers}]")
        }
        sb.appendLine("- Identifier keys: ${cfg.identifierKeys.joinToString(", ").ifBlank { "(none)" }}")
        sb.appendLine("- TURN/STUN probe: url=${cfg.iceProbe.url.ifBlank { "(none)" }} username=${cfg.iceProbe.username.ifBlank { "(none)" }} credential=${cfg.iceProbe.credential.ifBlank { "(none)" }} policy=${cfg.iceProbe.policy}")
        sb.appendLine()

        sb.appendLine(SecurityTestReport.markdown(cfg, events, authz, endpoints, includeSummary = false))
        sb.appendLine("## Module analysis & guidance")
        orchestrator.passiveReport(events) { line ->
            sb.appendLine(markdown(line))
        }
        sb.appendLine()

        sb.appendLine("## Telemetry summary (M2)")
        if (events.isEmpty()) {
            sb.appendLine("- No telemetry collected.")
        } else {
            sb.appendLine("- Total events: ${events.size}")
            sb.appendLine("- PRIVATE-flagged events: ${events.count { it.private }}")
            events.groupingBy { it.type }.eachCount().toSortedMap().forEach { (type, n) ->
                sb.appendLine("  - $type: $n")
            }
        }
        sb.appendLine()

        sb.appendLine("## Scope of this report")
        sb.appendLine("- Reachable surface: signaling-visible / WebRTC JS-API (SDP, ICE, DataChannel) + HTTP(S), plus explicitly selected TLS-over-TCP listeners scanned by the integrated Python runner.")
        sb.appendLine("- Out of scope (see README): RTP/RTCP/SRTP media plane, native-parser memory-safety/RCE,")
        sb.appendLine("  signaling/SIP fuzzing, and full TURN-as-C2 relay tunnelling.")
        return sb.toString()
    }

    private fun markdown(line: RunAllController.Line): String = when (line.level) {
        RunAllController.Level.HEAD -> "\n### ${line.text}"
        RunAllController.Level.FINDING -> "- **[FINDING]** ${line.text}"
        RunAllController.Level.FAIL -> "- **[REVIEW]** ${line.text}"
        RunAllController.Level.WARN -> "- **[warn]** ${line.text}"
        RunAllController.Level.OK -> "- [ok] ${line.text}"
        RunAllController.Level.SKIP -> "- [skip] ${line.text}"
        RunAllController.Level.INFO -> "- ${line.text}"
    }
}
