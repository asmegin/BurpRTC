package webrtc.ui

import webrtc.authz.AuthzResult
import javax.swing.SwingUtilities
import javax.swing.table.AbstractTableModel

class AuthzResultTableModel : AbstractTableModel() {
    private val cols = arrayOf("Flag", "Variant", "Status", "Length", "Same body", "URL", "Note")
    private val rows = ArrayList<AuthzResult>()

    fun add(result: AuthzResult) {
        SwingUtilities.invokeLater {
            rows.add(result)
            fireTableRowsInserted(rows.size - 1, rows.size - 1)
        }
    }

    fun resultAt(index: Int): AuthzResult? = rows.getOrNull(index)

    fun snapshot(): List<AuthzResult> = rows.toList()

    fun clearAll() {
        SwingUtilities.invokeLater {
            val n = rows.size
            rows.clear()
            if (n > 0) fireTableRowsDeleted(0, n - 1)
        }
    }

    override fun getRowCount(): Int = rows.size
    override fun getColumnCount(): Int = cols.size
    override fun getColumnName(c: Int): String = cols[c]
    override fun isCellEditable(r: Int, c: Int): Boolean = false

    override fun getValueAt(r: Int, c: Int): Any {
        val e = rows[r]
        return when (c) {
            0 -> if (e.flagged) "⚠" else ""
            1 -> e.variant
            2 -> e.status
            3 -> e.length
            4 -> if (e.sameAsBaseline) "yes" else ""
            5 -> e.baselineUrl
            else -> e.note
        }
    }
}
