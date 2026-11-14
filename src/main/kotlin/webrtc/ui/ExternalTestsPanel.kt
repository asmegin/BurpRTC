package webrtc.ui

import webrtc.config.ConfigStore
import webrtc.external.ExternalInputs
import webrtc.external.ExternalTools
import webrtc.external.Recipe
import webrtc.telemetry.TelemetryTableModel
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.io.File
import javax.swing.*
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.AbstractTableModel
import javax.swing.table.TableRowSorter

/**
 * External Tests — generates complete Linux/Bash commands for ten external RTC
 * testing tools from passively observed telemetry and Config.
 *
 * It generates text only: it never installs or executes a tool, and a "Ready to
 * copy" recipe is not a completed scan. Manual edits are preserved until **Reset
 * to detected**; credentials are shown and copied in full.
 */
class ExternalTestsPanel(
    private val store: ConfigStore,
    private val telemetry: TelemetryTableModel
) : JPanel(BorderLayout()) {

    private class RecipeTableModel : AbstractTableModel() {
        private val cols = arrayOf("Status", "Tool", "Recipe", "Missing inputs / applicability")
        var rows: List<Recipe> = emptyList()
            private set

        fun setRows(value: List<Recipe>) {
            rows = value
            fireTableDataChanged()
        }

        override fun getRowCount() = rows.size
        override fun getColumnCount() = cols.size
        override fun getColumnName(c: Int) = cols[c]
        override fun isCellEditable(r: Int, c: Int) = false
        override fun getValueAt(r: Int, c: Int): Any {
            val recipe = rows[r]
            return when (c) {
                0 -> recipe.status
                1 -> recipe.tool
                2 -> recipe.title
                else -> recipe.notApplicableReason ?: recipe.missing.joinToString(", ") { ExternalTools.describe(it) }
            }
        }
    }

    private val tableModel = RecipeTableModel()
    private val table = JTable(tableModel)
    private val info = JTextArea().apply {
        isEditable = false; lineWrap = true; wrapStyleWord = true
        font = UIManager.getFont("Label.font")
    }
    private val commandArea = JTextArea().apply {
        font = Font(Font.MONOSPACED, Font.PLAIN, 12); lineWrap = false
    }
    private val manualArea = JTextArea(
        "# Manual inputs (KEY=value, one per line) for values that cannot be detected.\n" +
            "# Examples:\n" +
            "# TEST_PEER_IP=203.0.113.10\n" +
            "# CAPTURE_INTERFACE=eth0\n" +
            "# SIP_HOST=sip.example.test\n", 5, 40
    ).apply { font = Font(Font.MONOSPACED, Font.PLAIN, 12) }
    private val status = JLabel(" ")

    private val overrides = LinkedHashMap<String, String>()
    private var lastSignature: String? = null
    private var currentId: String? = null
    private var loadingCommand = false
    private var values: Map<String, String> = emptyMap()

    init {
        table.rowSorter = TableRowSorter(tableModel)
        table.columnModel.getColumn(0).preferredWidth = 115
        table.columnModel.getColumn(1).preferredWidth = 105
        table.columnModel.getColumn(2).preferredWidth = 220
        table.columnModel.getColumn(3).preferredWidth = 220
        table.putClientProperty("webrtc.wrapColumns", listOf(0, 2, 3))
        table.putClientProperty("webrtc.rowHeight", 56)
        TableCopyUi.install(table)
        table.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting) showSelected()
        }
        commandArea.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = captureEdit()
            override fun removeUpdate(e: DocumentEvent) = captureEdit()
            override fun changedUpdate(e: DocumentEvent) = captureEdit()
        })
        manualArea.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) { lastSignature = null; refresh() }
            override fun removeUpdate(e: DocumentEvent) { lastSignature = null; refresh() }
            override fun changedUpdate(e: DocumentEvent) { lastSignature = null; refresh() }
        })

        val intro = UiKit.note("Select a recipe, review the editable command, and copy it to your terminal. Suggestions update from captured evidence. Commands execute outside Burp's scope enforcement; credentials are included in full.")

        val buttons = JPanel(FlowLayout(FlowLayout.LEFT)).apply {
            add(UiKit.primary(JButton("Copy command").apply { addActionListener { copyCommand() } }))
            add(UiKit.quiet(JButton("Reset edits").apply { addActionListener { resetToDetected() } }))
            add(UiKit.more("More", "Copy selected recipes" to { copySelected() }, "Copy all ready recipes" to { copyAllReady() },
                "Export guide (Markdown)…" to { exportGuide() }, "Export TURNt config…" to { exportTurntConfig() }))
        }

        val north = JPanel(BorderLayout()).apply {
            add(intro, BorderLayout.NORTH)
            add(buttons, BorderLayout.SOUTH)
        }

        val right = JTabbedPane().apply {
            addTab("Command · editable", JScrollPane(commandArea))
            addTab("Recipe details", JScrollPane(info))
        }

        val centre = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(table), right).apply { resizeWeight = 0.5; dividerLocation = 530 }
        val south = UiKit.disclosure("Manual inputs · KEY=value", JScrollPane(manualArea).apply { preferredSize = java.awt.Dimension(0, 140) })

        add(north, BorderLayout.NORTH)
        add(centre, BorderLayout.CENTER)
        add(JPanel(BorderLayout(0, 8)).apply { add(south, BorderLayout.CENTER); add(status, BorderLayout.SOUTH) }, BorderLayout.SOUTH)
        status.putClientProperty("webrtc.role", "muted"); status.preferredSize = java.awt.Dimension(0, 30)

        UiKit.refreshWhileShowing(this) { refresh() }
        refresh()
    }

    private fun parseManual(text: String): Map<String, String> =
        text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") && it.contains('=') }
            .associate { line -> line.substringBefore('=').trim().uppercase() to line.substringAfter('=').trim() }
            .filterValues { it.isNotEmpty() }

    private fun refresh() {
        val inputs: ExternalInputs = ExternalInputs.detect(store.config, telemetry.snapshot())
        val manual = parseManual(manualArea.text)
        val signature = inputs.toString() + "|" + manual
        if (signature == lastSignature) return
        lastSignature = signature
        val recipes = ExternalTools.catalogue(inputs, manual)
        values = ExternalTools.buildValues(inputs, manual)
        tableModel.setRows(recipes)
        restoreSelection()
        status.text = "${recipes.count { it.ready }} of ${recipes.size} recipe(s) ready"
    }

    private fun selectById(id: String?) {
        if (id == null) return
        for (viewRow in 0 until table.rowCount) {
            if (table.convertRowIndexToModel(viewRow).let { tableModel.rows[it].id } == id) {
                table.selectionModel.setSelectionInterval(viewRow, viewRow)
                return
            }
        }
    }

    private fun restoreSelection() {
        if (currentId != null) selectById(currentId) else if (table.rowCount > 0) table.selectionModel.setSelectionInterval(0, 0)
        showSelected()
    }

    private fun selectedRecipes(): List<Recipe> =
        table.selectedRows.map { tableModel.rows[table.convertRowIndexToModel(it)] }

    private fun effectiveCommand(recipe: Recipe): String = overrides[recipe.id] ?: recipe.command

    private fun showSelected() {
        val recipe = selectedRecipes().firstOrNull() ?: return
        currentId = recipe.id
        info.text = buildString {
            appendLine("Status: ${recipe.status} (not executed)")
            recipe.notApplicableReason?.let { appendLine(it) }
            if (recipe.missing.isNotEmpty()) appendLine("Missing inputs: ${recipe.missing.joinToString(", ") { ExternalTools.describe(it) }}")
            appendLine("Tool: ${recipe.tool}")
            appendLine("Purpose: ${recipe.purpose}")
            appendLine("Coverage: ${recipe.coverage}")
            appendLine("Prerequisites: ${recipe.prerequisites}")
            appendLine("Evidence to look for: ${recipe.evidence}")
            appendLine("Effects: ${recipe.effects}")
            appendLine("Limitations: ${recipe.limitations}")
            appendLine("Setup: ${recipe.setupUrl}")
            appendLine("Reference: ${recipe.sourceUrl}")
        }
        info.caretPosition = 0
        loadingCommand = true
        commandArea.text = effectiveCommand(recipe)
        loadingCommand = false
    }

    private fun captureEdit() {
        if (loadingCommand) return
        currentId?.let { overrides[it] = commandArea.text }
    }

    private fun resetToDetected() {
        overrides.clear()
        lastSignature = null
        refresh()
        showSelected()
        status.text = "reset to detected values"
    }

    private fun copy(text: String, message: String) {
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
        status.text = message
    }

    private fun copyCommand() {
        val recipe = selectedRecipes().firstOrNull() ?: return
        copy(effectiveCommand(recipe), "copied ${recipe.title}")
    }

    private fun copySelected() {
        val selected = selectedRecipes()
        if (selected.isEmpty()) return
        copy(selected.joinToString("\n\n") { "# ${it.tool} — ${it.title}\n${effectiveCommand(it)}" },
            "copied ${selected.size} recipe(s)")
    }

    private fun copyAllReady() {
        val ready = tableModel.rows.filter { it.ready }
        if (ready.isEmpty()) { status.text = "no ready recipes"; return }
        copy(ready.joinToString("\n\n") { "# ${it.tool} — ${it.title}\n${effectiveCommand(it)}" },
            "copied ${ready.size} ready recipe(s)")
    }

    private fun exportGuide() {
        val stamp = java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
        val chooser = JFileChooser().apply {
            selectedFile = File("burprtc-external-tests-$stamp.md")
            dialogTitle = "Export external tests guide"
        }
        if (chooser.showSaveDialog(UiKit.parentWindow(this)) != JFileChooser.APPROVE_OPTION) return
        try {
            val withEdits = tableModel.rows.map { if (overrides.containsKey(it.id)) it.copy(command = effectiveCommand(it)) else it }
            chooser.selectedFile.writeText(ExternalTools.toMarkdown(withEdits), Charsets.UTF_8)
            status.text = "saved ${chooser.selectedFile.name}"
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(UiKit.parentWindow(this), e.message, "Could not export guide", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun exportTurntConfig() {
        val yaml = ExternalTools.turntConfig(values)
        if (yaml == null) {
            JOptionPane.showMessageDialog(UiKit.parentWindow(this), "TURNt configuration needs a valid turn:/turns: URL, username and password. Supply the missing values in Config or manual inputs (TURNT_ICE_URL, TURN_USER, TURN_PASSWORD).", "TURNt config", JOptionPane.INFORMATION_MESSAGE)
            return
        }
        val chooser = JFileChooser().apply {
            selectedFile = File("turnt-config.yaml")
            dialogTitle = "Export TURNt configuration"
        }
        if (chooser.showSaveDialog(UiKit.parentWindow(this)) != JFileChooser.APPROVE_OPTION) return
        try {
            chooser.selectedFile.writeText(yaml, Charsets.UTF_8)
            status.text = "saved ${chooser.selectedFile.name}"
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(UiKit.parentWindow(this), e.message, "Could not export TURNt config", JOptionPane.ERROR_MESSAGE)
        }
    }
}
