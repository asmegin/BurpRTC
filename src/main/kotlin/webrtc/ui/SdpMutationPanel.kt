package webrtc.ui

import kotlinx.serialization.json.*
import webrtc.config.ConfigStore
import webrtc.config.SdpMutationConfig
import webrtc.config.SdpTextRule
import webrtc.telemetry.TelemetryTableModel
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.GridLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.*
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.TableRowSorter

/** Persisted mutation controls and before/after evidence from the browser. */
class SdpMutationPanel(private val store: ConfigStore, telemetry: TelemetryTableModel) : JPanel(BorderLayout()) {
    private data class RuleEditor(val find: JTextArea, val replacement: JTextArea, val panel: JPanel)
    private val enabled = JCheckBox("Enable SDP mutation")
    private val target = JComboBox(arrayOf("Incoming: setRemoteDescription", "Outgoing: createOffer / createAnswer", "Both"))
    private val targets = listOf("remote", "local", "both")
    private val pcId = JTextField(12)
    private val fingerprint = JCheckBox("Remove a=fingerprint attributes")
    private val candidates = JCheckBox("Remove embedded ICE candidates and end-of-candidates")
    private val direction = JComboBox(arrayOf("unchanged", "sendrecv", "sendonly", "recvonly", "inactive"))
    private val rulesPanel = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
    private val ruleEditors = mutableListOf<RuleEditor>()
    private val status = JLabel(" ")
    private val before = SearchableTextPane("Before")
    private val after = SearchableTextPane("After")
    private val detail = SearchableTextPane(wrap = true)
    private var loading = false
    private val saveDebounce = Timer(350) { save() }.apply { isRepeats = false }

    init {
        store.onChange { cfg -> SwingUtilities.invokeLater { enabled.isSelected = cfg.sdpMutation.enabled } }
        val form = JPanel(GridBagLayout())
        val advanced = JPanel(GridBagLayout())
        val c = GridBagConstraints().apply {
            insets = Insets(7, 6, 7, 6)
            anchor = GridBagConstraints.WEST
            fill = GridBagConstraints.HORIZONTAL
        }
        var row = 0
        fun field(label: String, component: JComponent, help: JButton? = null) {
            val panel = if (label in setOf("Peer ID (blank = all):", "DTLS:", "ICE:", "Audio/video direction:")) advanced else form
            c.gridx = 0; c.gridy = row; c.weightx = 0.0; c.fill = GridBagConstraints.HORIZONTAL
            if (label.isEmpty() && component is JLabel) {
                c.gridwidth = 3; c.weightx = 1.0
                panel.add(UiKit.note(component.text), c); c.gridwidth = 1; row++; return
            }
            panel.add(JLabel(label).apply { labelFor = component }, c)
            c.gridx = 1; c.weightx = 1.0
            panel.add(component, c)
            c.gridx = 2; c.weightx = 0.0; c.fill = GridBagConstraints.NONE
            panel.add(help ?: JLabel(" "), c)
            row++
        }
        field("State:", enabled, HelpUi.button(
            "Enable SDP mutation",
            "Turns the SDP rewrite rules below on or off. When on, the agent rewrites the session description (SDP) of the next WebRTC negotiation on in-scope, allow-listed pages. SDP is the text blob peers exchange to agree on media, codecs, encryption fingerprints and ICE candidates.",
            "Leave off while you edit the rules, then enable and start a fresh call to exercise them."
        ))
        field("Apply to:", target, HelpUi.button(
            "Apply to",
            "Which side of the exchange to rewrite. Incoming edits the remote description the browser receives (setRemoteDescription) — the safest and default choice. Outgoing edits your own offer/answer (createOffer/createAnswer), which the browser may reject before it is ever sent. Both edits each.",
            "Tampering with the remote answer (Incoming) to strip encryption is the classic downgrade test."
        ))
        field("Peer ID (blank = all):", pcId, HelpUi.button(
            "Peer ID",
            "Optional filter to target one RTCPeerConnection on a page instead of all of them. The agent numbers connections per page as pc1, pc2, … in creation order (numbering restarts in each frame/page). Blank applies the rule to every connection.",
            "pc1"
        ))
        field("DTLS:", fingerprint, HelpUi.button(
            "Remove a=fingerprint",
            "Strips the DTLS certificate fingerprint lines from the SDP. The fingerprint binds the media encryption to the signaling channel; removing it tests whether the peer still proceeds without that binding (a downgrade / MITM-enabling condition). This often makes negotiation fail — that itself is a useful result.",
            "Enable this with find/replace cleared, then start a fresh connection and watch for an sdp-error (rejected) vs. a completed call."
        ))
        field("ICE:", candidates, HelpUi.button(
            "Remove embedded ICE candidates",
            "Removes a=candidate lines and the end-of-candidates marker that are embedded in the SDP. Tests how the app behaves with no in-SDP transport addresses. Note this does not stop trickle ICE, where candidates are sent separately after the SDP.",
            "Use to check whether a call still connects purely via trickled candidates."
        ))
        field("Audio/video direction:", direction, HelpUi.button(
            "Audio/video direction",
            "Rewrites the media direction attribute (sendrecv / sendonly / recvonly / inactive) on each audio and video section. Tests whether the app enforces the media direction it expects, or can be coerced into receiving-only or sending-only.",
            "Set recvonly on an outgoing offer to test whether the peer will still send you media while you send none."
        ))
        field("Text rules:", rulesPanel, HelpUi.button(
            "Text match and replace rules",
            "Each rule replaces every occurrence of a literal substring anywhere in the SDP; you do not need to match a whole line. Rules run in order, so you can add several with + Add text rule. Click a line in the Before pane to copy that line into the next empty Match box, then shorten it to a substring if useful. Each rule may match or replace multiline text.",
            "Match: actpass\nReplace: passive\n\nThis changes that substring wherever it appears."
        ))
        field("", JLabel("Rules affect the next SDP operation on in-scope, allow-listed pages. Start a new call to test."))
        field("", JLabel("Outgoing edits may be rejected by the browser. Removing embedded candidates does not stop trickle ICE."))
        val saved = store.config.sdpMutation
        form.add(UiKit.disclosure("Built-in edits & peer filter", advanced,
            saved.removeFingerprint || saved.removeCandidates || saved.mediaDirection != "unchanged" || saved.pcId.isNotBlank()),
            GridBagConstraints().apply { gridy = row; gridwidth = 3; weightx = 1.0; fill = GridBagConstraints.HORIZONTAL; insets = Insets(10, 6, 6, 6) })

        val buttons = JPanel(FlowLayout(FlowLayout.LEFT)).apply {
            add(JLabel("Saved automatically · applies to the next SDP operation").apply { putClientProperty("webrtc.role", "muted") })
            add(status)
        }
        val controls = JPanel(BorderLayout()).apply {
            preferredSize = java.awt.Dimension(800, 415)
            add(UiKit.scroll(form), BorderLayout.CENTER)
            add(buttons, BorderLayout.SOUTH)
        }
        val table = JTable(telemetry).apply {
            rowSorter = TableRowSorter(telemetry).apply {
                rowFilter = RowFilter.regexFilter("^sdp-(mutation|result|error|mutation-status)$", 2)
            }
            TableCopyUi.install(this)
        }
        table.selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting) {
                val event = if (table.selectedRow >= 0) telemetry.eventAt(table.convertRowIndexToModel(table.selectedRow)) else null
                val obj = event?.let { runCatching { Json.parseToJsonElement(it.raw).jsonObject }.getOrNull() }
                before.text = (obj?.get("before") as? JsonPrimitive)?.contentOrNull.orEmpty()
                after.text = (obj?.get("after") as? JsonPrimitive)?.contentOrNull.orEmpty()
                detail.text = event?.raw.orEmpty()
            }
        }
        val comparison = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, before, after).apply {
            resizeWeight = 0.5
        }
        val details = JTabbedPane().apply {
            addTab("SDP comparison", comparison)
            addTab("Event / browser result", detail)
        }
        val evidence = JSplitPane(JSplitPane.VERTICAL_SPLIT,
            UiKit.emptyTable(table, "No SDP rule results yet", "Enable a saved rule and start a fresh call to collect before / after evidence."), details).apply { resizeWeight = 0.5 }
        add(JSplitPane(JSplitPane.VERTICAL_SPLIT, controls, evidence).apply { resizeWeight = 0.35; dividerLocation = 415 }, BorderLayout.CENTER)
        before.onLineClick { line -> addClickedLineAsRule(line) }
        val schedule = { scheduleSave() }
        listOf(enabled, fingerprint, candidates).forEach { it.addActionListener { schedule() } }
        listOf(target, direction).forEach { it.addActionListener { schedule() } }
        pcId.document.addDocumentListener(documentListener(schedule))
        load()
    }

    private fun scheduleSave() {
        if (!loading) {
            status.text = "Saving changes…"
            saveDebounce.restart()
        }
    }

    private fun addClickedLineAsRule(line: String) {
        if (line.isBlank()) return
        val editor = ruleEditors.firstOrNull { it.find.text.isBlank() }
            ?: addRuleEditor(schedule = false)
            ?: run { status.text = "Maximum of 20 text rules reached"; return }
        editor.find.text = line
        editor.replacement.requestFocusInWindow()
        status.text = "Added clicked SDP line as a match; edit it to target a substring."
        scheduleSave()
    }

    private fun addRuleEditor(rule: SdpTextRule = SdpTextRule(), schedule: Boolean = true): RuleEditor? {
        if (ruleEditors.size >= 20) return null
        val match = JTextArea(rule.find, 2, 28).apply { lineWrap = true; wrapStyleWord = true }
        val replacement = JTextArea(rule.replacement, 2, 28).apply { lineWrap = true; wrapStyleWord = true }
        val pair = JPanel(GridLayout(1, 2, 6, 0)).apply {
            add(JPanel(BorderLayout(0, 2)).apply {
                add(JLabel("Match substring"), BorderLayout.NORTH)
                add(JScrollPane(match), BorderLayout.CENTER)
            })
            add(JPanel(BorderLayout(0, 2)).apply {
                add(JLabel("Replace with"), BorderLayout.NORTH)
                add(JScrollPane(replacement), BorderLayout.CENTER)
            })
        }
        val panel = JPanel(BorderLayout(6, 0)).apply { add(pair, BorderLayout.CENTER) }
        val editor = RuleEditor(match, replacement, panel)
        panel.add(JPanel(java.awt.GridBagLayout()).apply {
            add(UiKit.quiet(JButton("Remove").apply { addActionListener { removeRuleEditor(editor) } }))
        }, BorderLayout.EAST)
        ruleEditors.add(editor)
        match.document.addDocumentListener(documentListener { scheduleSave() })
        replacement.document.addDocumentListener(documentListener { scheduleSave() })
        rebuildRulesPanel()
        if (schedule) scheduleSave()
        return editor
    }

    private fun removeRuleEditor(editor: RuleEditor) {
        ruleEditors.remove(editor)
        if (ruleEditors.isEmpty()) addRuleEditor(schedule = false)
        rebuildRulesPanel()
        scheduleSave()
    }

    private fun rebuildRulesPanel() {
        rulesPanel.removeAll()
        ruleEditors.forEachIndexed { index, editor ->
            editor.panel.border = BorderFactory.createTitledBorder("Rule ${index + 1}")
            editor.panel.alignmentX = LEFT_ALIGNMENT
            rulesPanel.add(editor.panel)
        }
        rulesPanel.add(JButton("+ Add text rule").apply {
            isEnabled = ruleEditors.size < 20
            alignmentX = LEFT_ALIGNMENT
            addActionListener { addRuleEditor() }
        })
        UiKit.style(rulesPanel)
        rulesPanel.revalidate()
        rulesPanel.repaint()
    }

    private fun documentListener(onChange: () -> Unit) = object : DocumentListener {
        override fun insertUpdate(e: DocumentEvent) = onChange()
        override fun removeUpdate(e: DocumentEvent) = onChange()
        override fun changedUpdate(e: DocumentEvent) = onChange()
    }

    private fun load() {
        loading = true
        val cfg = store.config.sdpMutation
        enabled.isSelected = cfg.enabled
        target.selectedIndex = targets.indexOf(cfg.target)
        pcId.text = cfg.pcId
        fingerprint.isSelected = cfg.removeFingerprint
        candidates.isSelected = cfg.removeCandidates
        direction.selectedItem = cfg.mediaDirection
        ruleEditors.clear()
        (cfg.effectiveRules().ifEmpty { listOf(SdpTextRule()) }).forEach { addRuleEditor(it, schedule = false) }
        status.text = if (cfg.enabled) "Enabled" else "Disabled"
        loading = false
    }

    private fun save() {
        try {
            val mutation = SdpMutationConfig(
                enabled = enabled.isSelected,
                target = targets[target.selectedIndex],
                pcId = pcId.text.trim(),
                removeFingerprint = fingerprint.isSelected,
                removeCandidates = candidates.isSelected,
                mediaDirection = direction.selectedItem as String,
                rules = ruleEditors.map { SdpTextRule(it.find.text, it.replacement.text) }
            )
            store.save(store.config.copy(sdpMutation = mutation))
            status.text = if (mutation.enabled) "Saved · enabled" else "Saved · disabled"
        } catch (e: Exception) {
            status.text = "Not saved: ${e.message ?: "invalid settings"}"
        }
    }
}
