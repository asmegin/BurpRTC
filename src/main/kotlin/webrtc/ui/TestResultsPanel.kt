package webrtc.ui

import webrtc.telemetry.TelemetryTableModel
import java.awt.BorderLayout
import javax.swing.*
import javax.swing.table.TableRowSorter

/** Module-specific event history with searchable raw evidence. */
class TestResultsPanel(model: TelemetryTableModel, types: String, module: String) : JPanel(BorderLayout()) {
    init {
        val detail = SearchableTextPane(wrap = true)
        val table = JTable(model).apply {
            TableCopyUi.install(this)
            rowSorter = TableRowSorter(model).apply {
                rowFilter = object : RowFilter<TelemetryTableModel, Int>() {
                    private val pattern = Regex(types)
                    override fun include(entry: Entry<out TelemetryTableModel, out Int>): Boolean {
                        val event = model.eventAt(entry.identifier) ?: return false
                        return pattern.matches(event.type) || (event.type in setOf("test-job", "command-result") && event.raw.contains("\"module\":\"$module\""))
                    }
                }
            }
        }
        table.selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting) detail.text = if (table.selectedRow >= 0) model.eventAt(table.convertRowIndexToModel(table.selectedRow))?.raw.orEmpty() else ""
        }
        add(JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(table), detail).apply { resizeWeight = 0.55 }, BorderLayout.CENTER)
    }
}
