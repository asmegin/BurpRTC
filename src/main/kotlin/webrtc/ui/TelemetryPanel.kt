package webrtc.ui

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import webrtc.bridge.ActiveTestController
import webrtc.internals.InternalsComparator
import webrtc.internals.InternalsDump
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import javax.swing.*
import javax.swing.event.ListSelectionEvent
import javax.swing.table.TableRowSorter

/** M2 view — live telemetry table, type filter, raw-event detail, and a dump comparator. */
class TelemetryPanel(
    private val model: TelemetryTableModel,
    private val controller: ActiveTestController? = null
) : JPanel(BorderLayout()) {

    private val table = JTable(model)
    private val sorter = TableRowSorter(model)
    private val detail = JTextArea(8, 80).apply { isEditable = false; lineWrap = true; wrapStyleWord = true }
    private val filterField = JTextField(20)
    private val timeFmt: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS")

    init {
        table.rowSorter = sorter
        TableCopyUi.install(table)

        val top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel("Filter (type/frame/summary):"))
        top.add(filterField)
        top.add(JButton("Import webrtc-internals dump…").apply { addActionListener { importDump() } })
        controller?.let { active ->
            top.add(JButton("Capture stats (T1)").apply { addActionListener { captureStats(active) } })
        }
        val clear = JButton("Clear").also { it.addActionListener { model.clearAll(); detail.text = "" } }
        top.add(clear)

        filterField.document.addUndoableEditListener { applyFilter() }
        filterField.addActionListener { applyFilter() }
        filterField.addCaretListener { applyFilter() }

        table.selectionModel.addListSelectionListener { e: ListSelectionEvent ->
            if (!e.valueIsAdjusting) {
                val viewRow = table.selectedRow
                if (viewRow >= 0) {
                    val modelRow = table.convertRowIndexToModel(viewRow)
                    detail.text = model.eventAt(modelRow)?.raw ?: ""
                    detail.caretPosition = 0
                }
            }
        }

        val split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(table),
            JScrollPane(detail)
        ).apply { resizeWeight = 0.7 }

        add(top, BorderLayout.NORTH)
        add(split, BorderLayout.CENTER)
    }

    /** T1 — queue a fresh getStats() snapshot for the most recently seen live page. */
    private fun captureStats(active: ActiveTestController) {
        val agent = active.agents().lastOrNull()
        if (agent == null) {
            JOptionPane.showMessageDialog(this, "No live browser page is reporting. Browse the app through Burp and join a call first.", "Capture stats", JOptionPane.INFORMATION_MESSAGE)
            return
        }
        try {
            val id = active.queueCaptureStats(agent.id)
            detail.text = "Queued getStats capture ${id.take(8)} for ${agent.frame}; results arrive as stats-snapshot / dtls-cert events."
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(this, e.message, "Capture stats", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun applyFilter() {
        val text = filterField.text
        sorter.rowFilter = if (text.isNullOrBlank()) null
        else RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(text))
    }

    /**
     * Import a user-exported `chrome://webrtc-internals` dump, compare it with the
     * telemetry captured so far, and record the result as telemetry events so the
     * Run All workflow and the M7 report include it. Passive: the file is read
     * locally and nothing is sent to the target.
     */
    private fun importDump() {
        val chooser = JFileChooser().apply { dialogTitle = "Import chrome://webrtc-internals dump (.gz, JSON or text)" }
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return
        val file = chooser.selectedFile
        val dump = try {
            InternalsDump.read(file)
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(this, e.message, "Could not read dump", JOptionPane.ERROR_MESSAGE)
            return
        }

        val lines = InternalsComparator.compare(dump, model.snapshot())
        val time = LocalTime.now().format(timeFmt)

        val importSummary = "imported ${file.name}: ${dump.candidates.size} candidate(s), " +
            "${dump.codecs.size} codec(s), ${dump.dtlsCiphers.size + dump.srtpCiphers.size} cipher(s)"
        model.add(
            TelemetryEvent(
                seq = model.nextSeq(), time = time, type = "internals-import", frame = "import",
                pcId = "", private = false, summary = importSummary,
                raw = buildJsonObject { put("type", "internals-import"); put("source", file.name) }.toString()
            )
        )
        val summary = lines.firstOrNull { it.level == InternalsComparator.Level.FINDING }
            ?: lines.firstOrNull { it.level == InternalsComparator.Level.WARN }
            ?: InternalsComparator.Line(InternalsComparator.Level.OK, "no discrepancies")
        model.add(
            TelemetryEvent(
                seq = model.nextSeq(), time = time, type = "internals-comparison", frame = "import",
                pcId = "", private = false, summary = summary.text,
                raw = InternalsComparator.encodeLines(lines)
            )
        )

        val area = JTextArea(lines.joinToString("\n") { "[${it.level}] ${it.text}" }, 18, 96).apply {
            isEditable = false; lineWrap = true; wrapStyleWord = true; caretPosition = 0
        }
        JOptionPane.showMessageDialog(
            this, JScrollPane(area),
            "chrome://webrtc-internals comparison — ${file.name}",
            JOptionPane.INFORMATION_MESSAGE
        )
    }
}
