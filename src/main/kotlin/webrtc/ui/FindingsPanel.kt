package webrtc.ui

import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryTableModel
import webrtc.workflow.RunAllController
import webrtc.report.PentestReport
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
    private val authzResults: AuthzResultTableModel,
    private val outcomeStore: webrtc.assessment.OutcomeStore? = null
) : JPanel(BorderLayout()) {

    private val report = SearchableTextPane("Report preview").apply { text = "Click Generate report to review the current findings and test outcomes.\n\nUse the target filter to limit the report to a specific host or URL." }
    private var generated = false
    private val status = JLabel(" ")
    private val targetFilter = JTextField(24)
    private val fullEvidence = JCheckBox("Include full evidence and configuration", true)

    init {
        val options = UiKit.toolbar(JLabel("Target contains:"), targetFilter, fullEvidence)
        targetFilter.toolTipText = "Blank includes all targets. Enter part of a host or URL to filter."
        val buttons = UiKit.toolbar(UiKit.primary(JButton("Generate report").apply { addActionListener { generate() } }),
            JButton("Save Markdown…").apply { addActionListener { save() } },
            JButton("Export summary CSV…").apply { addActionListener { exportCsv() } },
            UiKit.quiet(JButton("Clear preview").apply { addActionListener { report.text = ""; generated = false; status.text = " " } }))
        add(JPanel(BorderLayout()).apply {
            add(options, BorderLayout.NORTH)
            add(buttons, BorderLayout.SOUTH)
        }, BorderLayout.NORTH)
        add(report, BorderLayout.CENTER)
        status.putClientProperty("webrtc.role", "muted"); status.preferredSize = java.awt.Dimension(0, 30)
        add(status, BorderLayout.SOUTH)
    }

    private fun generate() {
        report.text = buildReport()
        generated = true
        status.text = "report generated"
    }

    private fun save() {
        if (!generated || report.text.isBlank()) generate()
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
            selectedFile = File("webrtc-summary-$stamp.csv")
            dialogTitle = "Export concise pentest summary"
        }
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return
        try {
            val concise = summary()
            chooser.selectedFile.writeText(concise.csv(), Charsets.UTF_8)
            status.text = "exported ${concise.facts.size} concise items"
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(this, e.message, "Could not export telemetry CSV", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun summary() = PentestReport.build(configStore.config, telemetry.snapshot(), authzResults.snapshot(), targetFilter.text.trim())

    private fun buildReport(): String = buildString {
        append(summary().markdown())
        val outcomes = outcomeStore?.snapshot().orEmpty().filter { targetFilter.text.isBlank() || it.target.contains(targetFilter.text, true) }
        append(webrtc.report.AssessmentReport.markdown(configStore.config.assessment, outcomes, fullEvidence.isSelected))
        if (fullEvidence.isSelected) {
            appendLine("\n## Configuration (credentials preserved)\n")
            append(webrtc.report.EvidenceFormatting.code(configStore.toJson(configStore.config)))
            append(webrtc.report.SecurityTestReport.markdown(configStore.config, telemetry.snapshot().filter {
                targetFilter.text.isBlank() || it.frame.contains(targetFilter.text, true)
            }, authzResults.snapshot().filter { targetFilter.text.isBlank() || it.baselineUrl.contains(targetFilter.text, true) }, orchestrator.observedSignalingEndpoints()))
        }
    }
}
