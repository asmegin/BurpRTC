package webrtc.ui

import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.InputEvent
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.*

/** Adds spreadsheet-friendly multi-row copy behavior to result tables. */
object TableCopyUi {
    fun install(table: JTable) {
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        table.toolTipText = "Select one or more rows, then press Ctrl+C or right-click and choose Copy selected rows."

        val copy = object : AbstractAction("Copy selected rows") {
            override fun actionPerformed(event: java.awt.event.ActionEvent?) {
                val selected = table.selectedRows
                if (selected.isEmpty()) return
                val text = selected.joinToString("\n") { viewRow ->
                    val modelRow = table.convertRowIndexToModel(viewRow)
                    (0 until table.columnCount).joinToString("\t") { viewColumn ->
                        val modelColumn = table.convertColumnIndexToModel(viewColumn)
                        table.model.getValueAt(modelRow, modelColumn).toString()
                            .replace("\t", " ").replace("\r", " ").replace("\n", " ")
                    }
                }
                runCatching { Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null) }
            }
        }
        table.actionMap.put("copy-selected-rows", copy)
        table.inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK), "copy-selected-rows")

        val menu = JPopupMenu().apply { add(JMenuItem(copy)) }
        table.addMouseListener(object : MouseAdapter() {
            private fun showPopup(event: MouseEvent) {
                if (!event.isPopupTrigger) return
                val row = table.rowAtPoint(event.point)
                if (row >= 0 && !table.isRowSelected(row)) table.setRowSelectionInterval(row, row)
                menu.show(table, event.x, event.y)
            }

            override fun mousePressed(event: MouseEvent) = showPopup(event)
            override fun mouseReleased(event: MouseEvent) = showPopup(event)
        })
    }
}
