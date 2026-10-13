package webrtc.ui

import webrtc.config.ConfigStore
import webrtc.config.ScanModule
import webrtc.config.ScanPlan
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import javax.swing.*
import javax.swing.table.AbstractTableModel

/** The single persisted selection used by Scan All; every row has a working backend. */
class ScanSelectionPanel(private val store: ConfigStore) : JPanel(BorderLayout()) {
    private val model: AbstractTableModel = object : AbstractTableModel() {
        override fun getRowCount() = ScanModule.entries.size
        override fun getColumnCount() = 3
        override fun getColumnName(c: Int) = listOf("Run", "Scan", "What runs / required inputs")[c]
        override fun getColumnClass(c: Int): Class<*> = if (c == 0) java.lang.Boolean::class.java else String::class.java
        override fun isCellEditable(r: Int, c: Int) = c == 0 && table.isEnabled
        override fun getValueAt(r: Int, c: Int): Any {
            val module = ScanModule.entries[r]
            return when (c) { 0 -> store.config.scanPlan.includes(module); 1 -> module.title; else -> module.detail }
        }
        override fun setValueAt(value: Any?, r: Int, c: Int) {
            if (c == 0) save(store.config.scanPlan.with(ScanModule.entries[r], value == true))
        }
    }
    private val table: JTable = JTable(model).apply { rowHeight = 24 }
    private val all = JButton("Select all").apply { addActionListener { save(ScanPlan()) } }
    private val none = JButton("Clear selection").apply { addActionListener { save(ScanPlan(emptySet())) } }
    private val count = JLabel().apply { putClientProperty("webrtc.role", "muted") }

    init {
        table.columnModel.getColumn(0).apply { maxWidth = 52; preferredWidth = 52 }
        table.columnModel.getColumn(1).preferredWidth = 200
        table.columnModel.getColumn(2).preferredWidth = 650
        table.putClientProperty("webrtc.wrapColumns", listOf(2))
        table.putClientProperty("webrtc.rowHeight", 48)
        add(JScrollPane(table).apply { preferredSize = Dimension(850, 517) }, BorderLayout.CENTER)
        add(UiKit.toolbar(UiKit.quiet(all), UiKit.quiet(none), count), BorderLayout.SOUTH)
        updateCount()
        store.onChange { SwingUtilities.invokeLater { model.fireTableDataChanged(); updateCount() } }
    }
    private fun save(plan: ScanPlan) {
        val current = store.config
        store.save(current.copy(scanPlan = plan, sdpMutation = if (!plan.includes(ScanModule.MUTATION))
            current.sdpMutation.copy(enabled = false) else current.sdpMutation))
        model.fireTableDataChanged()
        updateCount()
    }
    private fun updateCount() { count.text = "${ScanModule.entries.count { store.config.scanPlan.includes(it) }} of ${ScanModule.entries.size} scans selected · Saved automatically" }
    fun setRunning(running: Boolean) {
        if (table.isEditing) table.cellEditor.stopCellEditing()
        table.isEnabled = !running; all.isEnabled = !running; none.isEnabled = !running
    }
}
