package webrtc.ui

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import webrtc.assessment.*
import webrtc.config.ConfigStore
import webrtc.protocol.ProtocolScanConfig
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.io.File
import javax.swing.*
import javax.swing.table.AbstractTableModel

/** Registry, reusable prerequisites, durable results and passive companion import in one place. */
class AssessmentPanel(private val config: ConfigStore, private val controller: AssessmentController) : JPanel(BorderLayout()) {
    @Serializable data class Settings(val assessment: AssessmentConfig, val protocol: ProtocolScanConfig)
    private val json = Json { prettyPrint = true; encodeDefaults = true }
    private val editor = JTextArea(18, 100)
    private val results = JTextArea().apply { isEditable = false }
    private val status = JLabel("Select tests; configure accounts and scenarios once. Changes save with Validate / save.")
    private var worker: Thread? = null
    private val model = object : AbstractTableModel() {
        override fun getRowCount() = TestRegistry.definitions.size
        override fun getColumnCount() = 4
        override fun getColumnName(c: Int) = listOf("Selected", "Test", "Requirement", "Execution path")[c]
        override fun getColumnClass(c: Int): Class<*> = if (c == 0) java.lang.Boolean::class.java else String::class.java
        override fun isCellEditable(r: Int, c: Int) = c == 0
        override fun getValueAt(r: Int, c: Int): Any {
            val d = TestRegistry.definitions[r]
            return when (c) { 0 -> d.id in config.config.assessment.selectedTests; 1 -> d.id; 2 -> d.title; else -> TestRegistry.capability(d.id, config.config.assessment) }
        }
        override fun setValueAt(value: Any?, r: Int, c: Int) {
            if (c != 0) return
            val cfg = config.config; val id = TestRegistry.definitions[r].id
            val selection = cfg.assessment.selectedTests.toMutableSet().apply { if (value == true) add(id) else remove(id) }
            config.save(cfg.copy(assessment = cfg.assessment.copy(selectedTests = selection)))
            fireTableRowsUpdated(r, r)
            // Do not replace the scenario editor while a tester is editing it.
        }
    }
    init {
        val table = JTable(model).apply { autoCreateRowSorter = true }
        table.columnModel.getColumn(0).preferredWidth = 60
        table.columnModel.getColumn(2).preferredWidth = 420
        table.selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting && table.selectedRow >= 0) {
                val d = TestRegistry.definitions[table.convertRowIndexToModel(table.selectedRow)]
                results.text = "${d.id}: ${d.title}\n${d.contract}\n\n" + controller.store.snapshot().filter { o -> o.testId == d.id }
                    .joinToString("\n\n") { o -> json.encodeToString(o) }
            }
        }
        val tabs = JTabbedPane().apply {
            addTab("Registry", JScrollPane(table)); addTab("Prerequisites / scenarios", JScrollPane(editor)); addTab("Evidence", JScrollPane(results))
        }
        val buttons = JPanel(FlowLayout(FlowLayout.LEFT)).apply {
            add(JButton("Validate / save settings").apply { addActionListener { save() } })
            add(JButton("Reload settings").apply { addActionListener { load() } })
            add(JButton("Run selected").apply { addActionListener { run(false) } })
            add(JButton("Resume incomplete").apply { addActionListener { run(true) } })
            add(JButton("Stop").apply { addActionListener { controller.stop() } })
            add(JButton("Export results JSON").apply { addActionListener { export() } })
            add(JButton("Import results JSON").apply { addActionListener { import() } })
        }
        add(buttons, BorderLayout.NORTH); add(tabs, BorderLayout.CENTER); add(status, BorderLayout.SOUTH)
        load()
    }
    private fun load() { editor.text = json.encodeToString(Settings(config.config.assessment, config.config.protocolScan)) }
    private fun save(): Boolean = try {
        require(editor.text.length <= 2_000_000 && webrtc.bridge.boundedJson(editor.text)) { "Settings exceed size/depth limit" }
        val parsed = json.decodeFromString<Settings>(editor.text)
        parsed.assessment.validate(); parsed.protocol.validate(); parsed.protocol.endpoints.forEach { webrtc.protocol.ProtocolTarget.parse(it) }
        require(parsed.assessment.engagementId == config.config.assessment.engagementId) { "Engagement ID is immutable; use a separate Burp project" }
        config.save(config.config.copy(assessment = parsed.assessment.copy(selectedTests = config.config.assessment.selectedTests), protocolScan = parsed.protocol))
        model.fireTableDataChanged(); status.text = "Saved. Python uses the executable configured in TLS Tests. Hostname and resolved IP both need scope/allow-list entries."; true
    } catch (e: Exception) { status.text = "Not saved: ${e.message}"; false }
    private fun run(resume: Boolean) {
        if (worker?.isAlive == true || !save()) return
        worker = Thread({
            runCatching { controller.run(retryIncomplete = resume) { line -> SwingUtilities.invokeLater { results.append("$line\n"); status.text = line } } }
                .onFailure { SwingUtilities.invokeLater { status.text = it.message } }
        }, "webrtc-assessment").apply { isDaemon = true; start() }
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
            status.text = "Imported $count results; no tests were executed by import"
        }.onFailure { status.text = it.message }
    }
}
