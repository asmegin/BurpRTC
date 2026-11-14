package webrtc.ui

import webrtc.bridge.ActiveTestController
import webrtc.canary.Canary
import webrtc.canary.CanaryPayload
import webrtc.canary.CanaryRegistry
import webrtc.config.ConfigStore
import webrtc.config.DataChannelFuzzConfig
import webrtc.telemetry.TelemetryTableModel
import java.awt.BorderLayout
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import javax.swing.*
import javax.swing.table.AbstractTableModel

/**
 * Stored-XSS and callback canaries. Paste payloads into chat messages, display
 * names, file names, room titles or callback/webhook fields; when an advisor or
 * other user views them, an executed canary reports itself from that page.
 */
class CanaryPanel(
    private val registry: CanaryRegistry,
    private val activeTests: ActiveTestController,
    private val telemetry: TelemetryTableModel,
    private val collaboratorAvailable: () -> Boolean
) : JPanel(BorderLayout(0, 8)) {
    constructor(
        config: ConfigStore,
        registry: CanaryRegistry,
        activeTests: ActiveTestController,
        telemetry: TelemetryTableModel,
        collaboratorAvailable: () -> Boolean
    ) : this(registry, activeTests, telemetry, collaboratorAvailable)
    private val context = JTextField("chat message", 24)
    private val purpose = JComboBox(arrayOf("XSS markup", "Callback URL (Collaborator)"))
    private val payloads = DefaultListModel<CanaryPayload>()
    private val payloadList = JList(payloads).apply {
        cellRenderer = object : DefaultListCellRenderer() {
            override fun getListCellRendererComponent(list: JList<*>?, value: Any?, index: Int, selected: Boolean, focus: Boolean) =
                super.getListCellRendererComponent(list, (value as? CanaryPayload)?.let { "${it.label}:   ${it.value}" }, index, selected, focus)
        }
        selectionMode = ListSelectionModel.SINGLE_SELECTION
    }
    private val channels = JComboBox<String>()
    private val status = JLabel(" ").apply { putClientProperty("webrtc.role", "muted") }
    private val evidence = SearchableTextPane("Canary evidence", wrap = true)
    private var rows: List<Canary> = registry.all()
    private var statusMap: Map<String, String> = emptyMap()
    private val model = object : AbstractTableModel() {
        override fun getRowCount() = rows.size
        override fun getColumnCount() = 5
        override fun getColumnName(c: Int) = listOf("Canary", "Placed in", "Type", "Created", "Status")[c]
        override fun getValueAt(r: Int, c: Int): Any = rows[r].let { canary -> when (c) {
            0 -> canary.id; 1 -> canary.context; 2 -> canary.purpose; 3 -> canary.createdAt.take(19).replace('T', ' ')
            else -> statusMap[canary.id] ?: "Waiting"
        } }
    }
    private val table = JTable(model).apply { autoCreateRowSorter = true; setSelectionMode(ListSelectionModel.SINGLE_SELECTION) }

    init {
        TableCopyUi.install(table)
        val generate = UiKit.primary(JButton("Generate canary").apply { addActionListener { generate() } })
        val copy = JButton("Copy selected payload").apply { addActionListener {
            payloadList.selectedValue?.let { copy(it.value); status.text = "Copied ${it.label}" } ?: run { status.text = "Select a payload first" }
        } }
        val copyAll = JButton("Copy all").apply { addActionListener { copy(payloads.elements().toList().joinToString("\n") { it.value }); status.text = "Copied ${payloads.size()} payloads" } }
        val send = JButton("Send via data channel").apply { addActionListener { sendViaChannel() } }
        val poll = JButton("Check Collaborator now").apply { addActionListener {
            Thread({
                try {
                    val n = registry.pollOutOfBand()
                    SwingUtilities.invokeLater { status.text = "$n new Collaborator interaction(s)"; refresh() }
                } catch (t: Throwable) {
                    UiKit.logError(t)
                }
            }, "webrtc-canary-poll").apply { isDaemon = true; start() }
        } }
        val clear = UiKit.quiet(JButton("Forget canaries").apply { addActionListener { registry.clear(); payloads.clear(); refresh() } })
        val top = UiKit.stack(
            UiKit.note("1. Name where the canary goes (for example: chat message, display name, uploaded file name, room title).  2. Generate and paste a payload there as the customer.  " +
                "3. Open the same item as the advisor through Burp. An executed canary appears as EXECUTED here, in Scan All and as a Burp issue. " +
                "Pages the agent does not instrument are covered by Burp Collaborator when available (Burp Suite Professional)."),
            UiKit.form("Placed in:" to context, "Type:" to purpose, "Live data channel:" to channels),
            UiKit.toolbar(generate, copy, copyAll, send, poll, clear, status))
        table.selectionModel.addListSelectionListener { if (!it.valueIsAdjusting) showSelected() }
        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
            JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(payloadList), UiKit.emptyTable(table, "No canaries yet", "Generate a canary for each place you inject.")).apply { resizeWeight = 0.5 },
            evidence).apply { resizeWeight = 0.6 }
        add(top, BorderLayout.NORTH); add(split, BorderLayout.CENTER)
        UiKit.refreshWhileShowing(this) { refresh() }
        refresh()
    }

    private fun generate() {
        val type = if (purpose.selectedIndex == 1) "callback" else "xss"
        runCatching { registry.create(context.text, type) }.onSuccess { canary ->
            payloads.clear(); registry.payloads(canary).forEach(payloads::addElement); payloadList.selectedIndex = 0
            status.text = "Canary ${canary.id} created" + if (canary.collaborator.isBlank()) " (agent-only detection; Collaborator unavailable)" else " with Collaborator ${canary.collaborator}"
            refresh()
        }.onFailure { status.text = it.message }
    }

    private fun sendViaChannel() {
        val selected = channels.selectedItem as? String ?: run { status.text = "No open data channel; join a call first"; return }
        val (agentId, channelId) = selected.substringAfter("[").substringBefore("]").split("|").let { it.getOrNull(0).orEmpty() to it.getOrNull(1).orEmpty() }
        val list = payloads.elements().toList().filter { !it.label.startsWith("Callback") }.map { it.value }
        if (list.isEmpty()) { status.text = "Generate an XSS canary first"; return }
        runCatching {
            activeTests.queueFuzz(agentId, channelId, DataChannelFuzzConfig(mode = "list", payloads = list, count = list.size, intervalMs = 250, maxBytes = 4096, stopOnError = false))
        }.onSuccess { status.text = "Queued ${list.size} canary payload(s) on $channelId; check the receiving side" }.onFailure { status.text = it.message }
    }

    private fun refresh() {
        val selected = table.selectedRow.takeIf { it >= 0 }?.let { rows.getOrNull(table.convertRowIndexToModel(it))?.id }
        val currentRows = registry.all()
        val snap = telemetry.snapshot()
        rows = currentRows
        statusMap = currentRows.associate { it.id to registry.status(it, snap) }
        model.fireTableDataChanged()
        rows.indexOfFirst { it.id == selected }.takeIf { it >= 0 }?.let { val view = table.convertRowIndexToView(it); table.setRowSelectionInterval(view, view) }
        val previous = channels.selectedItem
        val options = activeTests.agents().flatMap { agent -> agent.channels.filter { it.state == "open" }.map { "${it.label.ifBlank { it.id }} on ${agent.frame.take(60)} [${agent.id}|${it.id}]" } }
        if (options != (0 until channels.itemCount).map { channels.getItemAt(it) }) {
            channels.removeAllItems(); options.forEach(channels::addItem); if (previous in options) channels.selectedItem = previous
        }
        purpose.isEnabled = true
        if (!collaboratorAvailable() && purpose.selectedIndex == 1) status.text = "Callback canaries need Burp Collaborator (Burp Suite Professional)"
    }

    private fun showSelected() {
        val canary = table.selectedRow.takeIf { it >= 0 }?.let { rows.getOrNull(table.convertRowIndexToModel(it)) } ?: return
        payloads.clear(); registry.payloads(canary).forEach(payloads::addElement)
        val related = telemetry.snapshot().filter { it.raw.contains("\"canaryId\":\"${canary.id}\"") }
        evidence.text = "${canary.id} — placed in ${canary.context} (${canary.purpose}), created ${canary.createdAt}\nStatus: ${registry.status(canary, related)}\n\n" +
            related.joinToString("\n\n") { "#${it.seq} ${it.type} ${it.frame}\n${it.raw}" }.ifEmpty { "No evidence yet." }
    }

    private fun copy(value: String) { if (value.isNotEmpty()) Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(value), null) }
}
