package webrtc.ui

import webrtc.workflow.RunAllController
import webrtc.config.ConfigStore
import java.awt.BorderLayout
import java.awt.Color
import java.awt.FlowLayout
import javax.swing.*
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants

/**
 * The one-click "Run all" beginner workflow. It runs the checks that can be run
 * safely and automatically and prints a plain-English report of what it did,
 * what it found, and what still needs a manual step.
 */
class RunAllPanel(private val orchestrator: RunAllController, private val store: ConfigStore) : JPanel(BorderLayout()) {

    private val report = JTextPane().apply { isEditable = false; text = "Your scan results will appear here.\n\nSelect scans above, then click Scan selected. Each result explains what ran, what was found, and any input still needed." }
    private val runButton = UiKit.primary(JButton("Scan selected"))
    private val selection = ScanSelectionPanel(store)
    private val stopButton = JButton("Stop").apply { isEnabled = false }
    private val status = JLabel("Ready to scan").apply { putClientProperty("webrtc.role", "muted") }
    @Volatile private var worker: Thread? = null

    init {
        val buttons = UiKit.toolbar(runButton, stopButton,
            UiKit.quiet(JButton("Clear results").apply { addActionListener { report.text = "" } }), status)
        val preset = JComboBox(arrayOf("Generic WebRTC app", "Video banking (advisor ↔ customer)")).apply {
            selectedIndex = if (store.config.preset == "banking") 1 else 0
        }
        val guide = UiKit.note(presetGuide(store.config.preset))
        val apply = JButton("Apply preset").apply { addActionListener {
            val banking = preset.selectedIndex == 1
            val current = store.config
            store.save(current.copy(preset = if (banking) "banking" else "generic", scanPlan = webrtc.config.ScanPlan(),
                burpIssues = true, tlsScan = current.tlsScan.copy(engine = "builtin")))
            guide.text = presetGuide(store.config.preset)
            status.text = "Preset applied: all scans selected, built-in TLS engine, Burp issues on"
        } }
        val top = JPanel(BorderLayout(0, 6)).apply {
            add(UiKit.stack(
                UiKit.note("For active scans: enable the agent in Setup, allow the target host, and add it to Burp Target scope. Individual test screens hold saved inputs."),
                UiKit.toolbar(JLabel("Preset:"), preset, apply), guide), BorderLayout.NORTH)
            add(selection, BorderLayout.CENTER)
            add(buttons, BorderLayout.SOUTH)
        }

        runButton.addActionListener { start() }
        stopButton.addActionListener { orchestrator.requestStop(); status.text = "stopping…" }

        add(JSplitPane(JSplitPane.VERTICAL_SPLIT, top, UiKit.section("Run output", JScrollPane(report))).apply {
            resizeWeight = 0.62
            top.minimumSize = java.awt.Dimension(0, 180)
            bottomComponent.minimumSize = java.awt.Dimension(0, 120)
        }, BorderLayout.CENTER)
    }

    private fun presetGuide(preset: String): String = if (preset == "banking")
        "Video banking checklist: 1. Use two browser profiles through Burp: a customer (profile A) and an advisor (profile B). " +
            "2. In Access control, tick both sessions and set their Role (customer / advisor); log in a second customer if you can. " +
            "3. Open the meeting invite link from the SMS or e-mail in profile A so Meeting links captures it. " +
            "4. In XSS canaries, generate canaries for chat, display name and file name; send them as the customer, then view them as the advisor. " +
            "5. During the call share a screen and exchange a document; download it in both profiles. 6. End the call, then click Scan selected. " +
            "7. After the meeting, use Recheck links in Access control → Meeting links."
    else "Tip: choose the video banking preset for advisor / customer applications (roles, meeting links, documents, XSS canaries)."

    private fun start() {
        if (worker?.isAlive == true) return
        selection.setRunning(true)
        val plan = store.config.scanPlan
        report.text = ""
        runButton.isEnabled = false
        stopButton.isEnabled = true
        status.text = "running…"
        worker = Thread({
            try {
                orchestrator.run(plan) { line -> SwingUtilities.invokeLater { append(line) } }
            } catch (t: Throwable) {
                SwingUtilities.invokeLater { append(RunAllController.Line(RunAllController.Level.WARN, "Run failed: ${t.message}")) }
            } finally {
                SwingUtilities.invokeLater {
                    runButton.isEnabled = true
                    selection.setRunning(false)
                    stopButton.isEnabled = false
                    status.text = "done"
                }
            }
        }, "webrtc-run-all").apply { isDaemon = true; start() }
    }

    private fun append(line: RunAllController.Line) {
        val doc = report.styledDocument
        val attrs = SimpleAttributeSet()
        val (prefix, color, bold) = when (line.level) {
            RunAllController.Level.HEAD -> Triple("", UiKit.accent, true)
            RunAllController.Level.OK -> Triple("[ok]   ", UiKit.success, false)
            RunAllController.Level.INFO -> Triple("[info] ", UiKit.ink, false)
            RunAllController.Level.WARN -> Triple("[warn] ", UiKit.warning, false)
            RunAllController.Level.FINDING -> Triple("[find] ", UiKit.danger, true)
            RunAllController.Level.FAIL -> Triple("[review] ", UiKit.danger, true)
            RunAllController.Level.SKIP -> Triple("[skip] ", UiKit.muted, false)
        }
        StyleConstants.setForeground(attrs, color)
        StyleConstants.setBold(attrs, bold)
        val text = if (line.level == RunAllController.Level.HEAD) "\n$prefix${line.text}\n" else "$prefix${line.text}\n"
        doc.insertString(doc.length, text, attrs)
        report.caretPosition = doc.length
    }
}
