package webrtc.ui

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import webrtc.assessment.*
import webrtc.config.ConfigStore
import webrtc.protocol.ProtocolTarget
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.GridLayout
import java.io.File
import javax.swing.*
import javax.swing.table.AbstractTableModel

/** Execution controls and evidence for real backends; the methodology backlog is not a scan list. */
class AssessmentPanel(private val config: ConfigStore, private val controller: AssessmentController) : JPanel(BorderLayout()) {
    private val json = Json { prettyPrint = true; encodeDefaults = true }
    private var shown = definitions()
    private val results = SearchableTextPane("Check details", wrap = true).apply { text = "Select a check to see its execution history and full evidence.\n\nRun checks reviews captured evidence and tests observed STUN / TURN listeners. Optional server overrides are in Server inputs." }
    private val endpoints = JTextArea(config.config.protocolScan.endpoints.joinToString("\n"), 4, 60)
    private val username = JTextField(config.config.protocolScan.turnUsername)
    private val credential = JTextField(config.config.protocolScan.turnCredential)
    private val peer = JTextField(config.config.protocolScan.relayPeer)
    private val timeout = JSpinner(SpinnerNumberModel(config.config.protocolScan.timeoutSeconds, 15, 300, 15))
    private val scenarios = JTextArea(json.encodeToString(config.config.assessment.scenarios), 18, 90)
    private val status = JLabel("Observed ICE servers and credentials are used automatically. Optional overrides are in Server inputs.")
    private val runButton = UiKit.primary(JButton("Run checks"))
    private val resumeButton = JButton("Resume incomplete")
    @Volatile private var worker: Thread? = null
    private val model = object : AbstractTableModel() {
        override fun getRowCount() = shown.size
        override fun getColumnCount() = 4
        override fun getColumnName(c: Int) = listOf("Check", "What runs", "Backend / inputs", "Latest execution")[c]
        override fun getValueAt(r: Int, c: Int): Any {
            val d = shown[r]
            return when (c) {
                0 -> d.id
                1 -> TestRegistry.description(d.id)
                2 -> when {
                    d.id in TestRegistry.passiveTests -> "Captured telemetry"
                    d.id in setOf("TRN-04", "TRN-05") -> "Built in: TURN account; second allocation as peer, or your UDP echo peer"
                    d.id == "TRN-01" -> "Built in: observed / entered STUN or TURN listener"
                    d.id in TestRegistry.protocolTests -> "Built in: TURN listener and account"
                    else -> "Saved HTTP / WebSocket scenario (sent through Burp)"
                }
                else -> controller.store.snapshot().lastOrNull { it.testId == d.id }?.let {
                    "${it.execution}: ${it.limitations.joinToString("; ")}"
                } ?: "Not run"
            }
        }
    }
    private fun definitions() = TestRegistry.definitions.filter { it.id in TestRegistry.executable(config.config.assessment) }

    init {
        val table = JTable(model).apply { autoCreateRowSorter = true; rowHeight = 24 }
        TableCopyUi.install(table)
        table.columnModel.getColumn(0).apply { minWidth = 80; maxWidth = 90; preferredWidth = 80 }
        table.putClientProperty("webrtc.wrapColumns", listOf(1, 2, 3))
        table.columnModel.getColumn(1).preferredWidth = 390
        table.columnModel.getColumn(2).preferredWidth = 290
        table.columnModel.getColumn(3).preferredWidth = 400
        table.selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting && table.selectedRow >= 0) {
                val d = shown[table.convertRowIndexToModel(table.selectedRow)]
                results.text = "${d.id}: ${TestRegistry.description(d.id)}\n\n" + controller.store.snapshot()
                    .filter { o -> o.testId == d.id }.joinToString("\n\n") { o -> json.encodeToString(o) }
            }
        }
        val inputs = UiKit.stack(
            UiKit.note("Observed servers and credentials are used automatically, and every check runs inside Burp with nothing to install. Forwarding checks use a second allocation on the same server as the receiving peer. Enter a controlled UDP echo peer (for example udp://192.0.2.10:9000) only to test delivery to a specific destination."),
            UiKit.section("Server overrides", UiKit.form(
                "STUN / TURN listeners:" to JScrollPane(endpoints), "TURN username:" to username,
                "TURN credential:" to credential, "UDP echo peer (optional):" to peer, "Timeout (seconds):" to timeout)),
            UiKit.toolbar(UiKit.primary(JButton("Save inputs").apply { addActionListener { save() } })))
        val scenarioSettings = JPanel(BorderLayout()).apply {
            add(UiKit.note("Optional HTTP / WebSocket scenarios require a valid control, policy, and response assertions. Save scenarios to add runnable checks."), BorderLayout.NORTH)
            add(JScrollPane(scenarios), BorderLayout.CENTER)
            add(UiKit.toolbar(UiKit.primary(JButton("Save scenarios").apply { addActionListener { save() } })), BorderLayout.SOUTH)
        }
        val tabs = JTabbedPane().apply {
            addTab("Checks", JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(table), results).apply { resizeWeight = 0.65 })
            addTab("Server inputs", UiKit.scroll(JPanel(BorderLayout()).apply { add(inputs, BorderLayout.NORTH) }))
            addTab("HTTP / WebSocket scenarios", scenarioSettings)
        }
        runButton.addActionListener { run(false) }
        resumeButton.addActionListener { run(true) }
        val buttons = UiKit.toolbar(runButton, resumeButton, JButton("Stop").apply { addActionListener { controller.stop() } },
            UiKit.more("Import / export", "Export results JSON…" to { export() }, "Import results JSON…" to { import() }))
        add(buttons, BorderLayout.NORTH); add(tabs, BorderLayout.CENTER); add(status, BorderLayout.SOUTH)
        status.putClientProperty("webrtc.role", "muted")
        status.preferredSize = java.awt.Dimension(0, 30)
        config.onChange { SwingUtilities.invokeLater { shown = definitions(); model.fireTableDataChanged() } }
    }
    private fun save(): Boolean = try {
        val cfg = config.config
        val protocol = cfg.protocolScan.copy(endpoints = endpoints.text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList(),
            turnUsername = username.text, turnCredential = credential.text, relayPeer = peer.text.trim(), timeoutSeconds = (timeout.value as Number).toInt())
        protocol.validate(); protocol.endpoints.forEach { require(ProtocolTarget.parse(it).scheme in setOf("stun", "stuns", "turn", "turns")) { "Listener overrides must be STUN / TURN URIs" } }
        require(scenarios.text.length <= 2_000_000 && webrtc.bridge.boundedJson(scenarios.text)) { "Scenarios exceed size/depth limit" }
        val assessment = cfg.assessment.copy(scenarios = json.decodeFromString<List<Scenario>>(scenarios.text))
        assessment.validate()
        config.save(cfg.copy(protocolScan = protocol, assessment = assessment))
        shown = definitions(); model.fireTableDataChanged(); status.text = "Inputs saved. ${shown.size} checks have extension backends."; true
    } catch (e: Exception) { status.text = "Inputs not saved: ${e.message}"; false }
    private fun append(line: String) = SwingUtilities.invokeLater { results.text += "$line\n"; status.text = line; status.toolTipText = line; model.fireTableDataChanged() }
    private fun run(resume: Boolean) = background {
        controller.run(retryIncomplete = resume) { append(it) }
    }
    private fun background(action: () -> Unit) {
        if (worker?.isAlive == true || !save()) return
        listOf(runButton, resumeButton).forEach { it.isEnabled = false }
        worker = Thread({
            runCatching(action).onFailure { append(it.message.orEmpty()) }
            SwingUtilities.invokeLater { listOf(runButton, resumeButton).forEach { it.isEnabled = true } }
        }, "webrtc-security-checks").apply { isDaemon = true; start() }
    }
    private fun export() {
        val chooser = JFileChooser().apply { selectedFile = File("rtc-results.json") }
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION)
            runCatching { chooser.selectedFile.writeText(controller.store.exportJson(), Charsets.UTF_8); status.text = "Exported results with full evidence and credentials" }.onFailure { status.text = it.message }
    }
    private fun import() {
        val chooser = JFileChooser()
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) runCatching {
            require(chooser.selectedFile.length() <= 16_000_000) { "Import exceeds 16 MB" }
            val count = controller.store.importJson(chooser.selectedFile.readText(Charsets.UTF_8))
            status.text = "Imported $count results; no tests were executed by import"; model.fireTableDataChanged()
        }.onFailure { status.text = it.message }
    }
}
