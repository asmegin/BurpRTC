package webrtc.ui

import webrtc.workflow.RunAllController
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
class RunAllPanel(private val orchestrator: RunAllController) : JPanel(BorderLayout()) {

    private val report = JTextPane().apply { isEditable = false }
    private val runButton = JButton("Run all checks")
    private val stopButton = JButton("Stop").apply { isEnabled = false }
    private val status = JLabel(" ")
    @Volatile private var worker: Thread? = null

    init {
        val intro = JTextArea(
            "Run all checks — the guided path. It reviews the telemetry already " +
                "collected (M1/M2), then runs the live active checks it safely can " +
                "(M6 ICE gather and M4 DataChannel fuzz) on every page the agent is on. " +
                "M3 and M5 need a manual step, so it tells you exactly what to do. " +
                "Nothing target-specific runs unless the page is allow-listed and in Burp Target scope."
        ).apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
            isOpaque = false
            border = BorderFactory.createEmptyBorder(8, 10, 4, 10)
            font = UIManager.getFont("Label.font")
        }

        val buttons = JPanel(FlowLayout(FlowLayout.LEFT)).apply {
            add(runButton); add(stopButton)
            add(JButton("Clear").apply { addActionListener { report.text = "" } })
            add(status)
        }
        val top = JPanel(BorderLayout()).apply {
            add(intro, BorderLayout.NORTH)
            add(buttons, BorderLayout.SOUTH)
        }

        runButton.addActionListener { start() }
        stopButton.addActionListener { orchestrator.requestStop(); status.text = "stopping…" }

        add(top, BorderLayout.NORTH)
        add(JScrollPane(report), BorderLayout.CENTER)
    }

    private fun start() {
        if (worker?.isAlive == true) return
        report.text = ""
        runButton.isEnabled = false
        stopButton.isEnabled = true
        status.text = "running…"
        worker = Thread({
            try {
                orchestrator.run { line -> SwingUtilities.invokeLater { append(line) } }
            } catch (t: Throwable) {
                SwingUtilities.invokeLater { append(RunAllController.Line(RunAllController.Level.WARN, "Run failed: ${t.message}")) }
            } finally {
                SwingUtilities.invokeLater {
                    runButton.isEnabled = true
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
            RunAllController.Level.HEAD -> Triple("", Color(0x1a, 0x4d, 0x8f), true)
            RunAllController.Level.OK -> Triple("[ok]   ", Color(0x1b, 0x7a, 0x2f), false)
            RunAllController.Level.INFO -> Triple("[info] ", Color(0x33, 0x33, 0x33), false)
            RunAllController.Level.WARN -> Triple("[warn] ", Color(0xb0, 0x6a, 0x00), false)
            RunAllController.Level.FINDING -> Triple("[find] ", Color(0xb0, 0x1c, 0x1c), true)
            RunAllController.Level.FAIL -> Triple("[review] ", Color(0xd0, 0x00, 0x00), true)
            RunAllController.Level.SKIP -> Triple("[skip] ", Color(0x66, 0x66, 0x66), false)
        }
        StyleConstants.setForeground(attrs, color)
        StyleConstants.setBold(attrs, bold)
        val text = if (line.level == RunAllController.Level.HEAD) "\n$prefix${line.text}\n" else "$prefix${line.text}\n"
        doc.insertString(doc.length, text, attrs)
        report.caretPosition = doc.length
    }
}
