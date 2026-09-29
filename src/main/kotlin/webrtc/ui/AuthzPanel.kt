package webrtc.ui

import burp.api.montoya.MontoyaApi
import webrtc.authz.AuthzResult
import java.awt.BorderLayout
import java.awt.FlowLayout
import javax.swing.*

/** M5 view — results of the authz matrix, with send-to-Repeater. */
class AuthzPanel(private val api: MontoyaApi) : JPanel(BorderLayout()) {

    val model = AuthzResultTableModel()
    private val table = JTable(model)

    init {
        table.autoCreateRowSorter = true
        TableCopyUi.install(table)

        val top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel("Right-click a request in any Burp tool -> \"WebRTC: Run authz matrix\". Flagged rows returned 2xx under another principal."))

        val bottom = JPanel(FlowLayout(FlowLayout.LEFT))
        bottom.add(JButton("Send selected to Repeater").apply { addActionListener { sendToRepeater() } })
        bottom.add(JButton("Clear").also { it.addActionListener { model.clearAll() } })

        add(top, BorderLayout.NORTH)
        add(JScrollPane(table), BorderLayout.CENTER)
        add(bottom, BorderLayout.SOUTH)
    }

    fun addResult(result: AuthzResult) = model.add(result)

    private fun sendToRepeater() {
        val viewRow = table.selectedRow
        if (viewRow < 0) return
        val modelRow = table.convertRowIndexToModel(viewRow)
        val rr = model.resultAt(modelRow)?.requestResponse ?: return
        api.repeater().sendToRepeater(rr.request())
    }
}
