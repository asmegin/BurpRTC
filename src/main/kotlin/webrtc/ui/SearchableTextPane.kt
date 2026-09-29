package webrtc.ui

import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.event.ActionEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.*
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.text.DefaultHighlighter

/** Independent literal search for a read-only text pane. All positions use document offsets. */
class SearchableTextPane(title: String? = null, wrap: Boolean = false) : JPanel(BorderLayout()) {
    private val area = JTextArea().apply { isEditable = false; lineWrap = wrap; wrapStyleWord = wrap }
    private val query = JTextField(12).apply {
        toolTipText = "Find literal text. Enter: next; Shift+Enter: previous; Escape: clear."
        accessibleContext.accessibleName = "${title ?: "Event / browser result"} search"
    }
    private val matchCase = JCheckBox("Match case")
    private val count = JLabel("0 / 0")
    private val previous = JButton("Previous")
    private val next = JButton("Next")
    private val matches = ArrayList<Int>()
    private var current = -1
    private var highlight: Any? = null
    private val painter = DefaultHighlighter.DefaultHighlightPainter(java.awt.Color(255, 180, 0, 120))

    var text: String
        get() = area.text
        set(value) {
            area.text = value
            area.caretPosition = 0
            refreshSearch()
        }

    /** Invokes [listener] with the full SDP line under a mouse click. */
    fun onLineClick(listener: (String) -> Unit) {
        area.toolTipText = "Click a line to use it as an SDP match rule."
        area.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(event: MouseEvent) {
                if (!SwingUtilities.isLeftMouseButton(event)) return
                val content = area.text
                if (content.isEmpty()) return
                val offset = area.viewToModel2D(event.point).coerceIn(0, content.length)
                val start = content.lastIndexOf('\n', (offset - 1).coerceAtLeast(0)).let { it + 1 }
                val end = content.indexOf('\n', offset).let { if (it < 0) content.length else it }
                listener(content.substring(start, end).trimEnd('\r'))
            }
        })
    }

    init {
        if (title != null) border = BorderFactory.createTitledBorder(title)
        // Two short rows keep each comparison pane usable at half the tab width.
        val fieldRow = JPanel(BorderLayout(5, 0)).apply {
            add(JLabel("Find:"), BorderLayout.WEST)
            add(query, BorderLayout.CENTER)
            add(matchCase, BorderLayout.EAST)
        }
        val navigation = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0)).apply {
            add(previous); add(next); add(count)
            add(JButton("Clear").apply { addActionListener { query.text = ""; query.requestFocusInWindow() } })
        }
        add(JPanel(BorderLayout(0, 3)).apply {
            add(fieldRow, BorderLayout.NORTH)
            add(navigation, BorderLayout.SOUTH)
        }, BorderLayout.NORTH)
        add(JScrollPane(area), BorderLayout.CENTER)
        minimumSize = Dimension(220, 100)
        previous.addActionListener { navigate(-1) }
        next.addActionListener { navigate(1) }
        matchCase.addActionListener { refreshSearch() }
        query.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = refreshSearch()
            override fun removeUpdate(e: DocumentEvent) = refreshSearch()
            override fun changedUpdate(e: DocumentEvent) = refreshSearch()
        })
        fun bind(component: JComponent, key: String, name: String, action: () -> Unit) {
            component.getInputMap(WHEN_FOCUSED).put(KeyStroke.getKeyStroke(key), name)
            component.actionMap.put(name, object : AbstractAction() {
                override fun actionPerformed(e: ActionEvent) = action()
            })
        }
        for (component in listOf(query, area)) {
            bind(component, "control F", "find") { query.requestFocusInWindow(); query.selectAll() }
            bind(component, "F3", "nextMatch") { navigate(1) }
            bind(component, "shift F3", "previousMatch") { navigate(-1) }
        }
        bind(query, "ENTER", "nextMatch") { navigate(1) }
        bind(query, "shift ENTER", "previousMatch") { navigate(-1) }
        bind(query, "ESCAPE", "clearSearch") { query.text = "" }
        refreshSearch()
    }

    private fun refreshSearch() {
        matches.clear()
        val needle = query.text
        if (needle.isNotEmpty()) {
            val content = area.text
            var from = 0
            while (from <= content.length - needle.length) {
                val offset = content.indexOf(needle, from, ignoreCase = !matchCase.isSelected)
                if (offset < 0) break
                matches.add(offset)
                from = offset + needle.length
            }
        }
        current = if (matches.isEmpty()) -1 else 0
        showMatch()
    }

    private fun navigate(step: Int) {
        if (matches.isEmpty()) return
        current = Math.floorMod(current + step, matches.size)
        showMatch()
    }

    private fun showMatch() {
        highlight?.let { area.highlighter.removeHighlight(it) }
        highlight = null
        val found = current >= 0
        previous.isEnabled = found
        next.isEnabled = found
        count.text = if (query.text.isNotEmpty() && !found) "No matches" else "${current + 1} / ${matches.size}"
        if (found) {
            val start = matches[current]
            area.caretPosition = start
            highlight = area.highlighter.addHighlight(start, start + query.text.length, painter)
            area.modelToView2D(start)?.bounds?.let { area.scrollRectToVisible(it) }
        }
    }
}
