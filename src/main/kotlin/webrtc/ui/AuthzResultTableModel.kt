package webrtc.ui

import webrtc.authz.AuthzResult
import javax.swing.SwingUtilities
import javax.swing.table.AbstractTableModel

class AuthzResultTableModel : AbstractTableModel() {
    private val cols = arrayOf("Flag", "Verdict", "Variant", "Status", "Length", "Same body", "URL", "Note")
    private val rows = ArrayList<AuthzResult>()

    fun add(result: AuthzResult) {
        SwingUtilities.invokeLater {
            synchronized(rows) {
                while (rows.size >= MAX_RESULTS) {
                    rows.removeAt(0)
                    fireTableRowsDeleted(0, 0)
                }
                rows.add(result)
                val index = rows.size - 1
                fireTableRowsInserted(index, index)
            }
        }
    }

    fun resultAt(index: Int): AuthzResult? = synchronized(rows) { rows.getOrNull(index) }

    fun snapshot(): List<AuthzResult> = synchronized(rows) { rows.toList() }

    fun clearAll() {
        SwingUtilities.invokeLater {
            val n = synchronized(rows) { val count = rows.size; rows.clear(); count }
            if (n > 0) fireTableRowsDeleted(0, n - 1)
        }
    }

    override fun getRowCount(): Int = synchronized(rows) { rows.size }
    override fun getColumnCount(): Int = cols.size
    override fun getColumnName(c: Int): String = cols[c]
    override fun getColumnClass(c: Int): Class<*> = if (c in 3..4) java.lang.Integer::class.java else String::class.java
    override fun isCellEditable(r: Int, c: Int): Boolean = false

    override fun getValueAt(r: Int, c: Int): Any {
        val e = synchronized(rows) { rows[r] }
        return when (c) {
            0 -> if (e.verdict == AuthzResult.LIKELY_VIOLATION) "⛔" else if (e.flagged) "⚠" else ""
            1 -> e.verdict
            2 -> e.variant
            3 -> e.status
            4 -> e.length
            5 -> if (e.sameAsBaseline) "yes" else ""
            6 -> e.baselineUrl
            else -> e.note
        }
    }

    companion object {
        const val MAX_RESULTS = 2_000
    }
}
