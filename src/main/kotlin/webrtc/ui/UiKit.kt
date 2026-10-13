package webrtc.ui

import java.awt.*
import java.awt.event.HierarchyEvent
import javax.swing.*
import javax.swing.border.AbstractBorder
import javax.swing.border.TitledBorder
import javax.swing.plaf.basic.BasicButtonUI
import javax.swing.plaf.basic.BasicTabbedPaneUI
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.text.JTextComponent

/** Local styling only: never changes Burp's global look-and-feel or UI defaults. */
object UiKit {
    private val base get() = UIManager.getColor("Panel.background") ?: Color.WHITE
    val dark get() = base.red + base.green + base.blue < 390
    val canvas get() = if (dark) Color(0x242932) else Color(0xF4F6FA)
    val surface get() = if (dark) Color(0x2C333E) else Color.WHITE
    val ink get() = if (dark) Color(0xECF0F6) else Color(0x243044)
    val muted get() = if (dark) Color(0xADB8CA) else Color(0x617087)
    val line get() = if (dark) Color(0x465164) else Color(0xDEE5EF)
    val accent get() = if (dark) Color(0x94B9FF) else Color(0x245FCB)
    val tint get() = if (dark) Color(0x344969) else Color(0xEAF1FF)
    val success get() = if (dark) Color(0x8CDBAF) else Color(0x247347)
    val warning get() = if (dark) Color(0xF7C875) else Color(0x926000)
    val danger get() = if (dark) Color(0xFFADB0) else Color(0xAD303D)
    private val font get() = (UIManager.getFont("Label.font") ?: Font("Dialog", Font.PLAIN, 13)).deriveFont(Font.PLAIN, 13f)

    fun primary(button: JButton) = button.apply { putClientProperty("webrtc.role", "primary") }
    fun quiet(button: JButton) = button.apply { putClientProperty("webrtc.role", "quiet") }
    fun note(text: String) = JTextArea(text).apply {
        isEditable = false; lineWrap = true; wrapStyleWord = true; isOpaque = false
        putClientProperty("webrtc.role", "note")
        border = BorderFactory.createEmptyBorder(4, 0, 8, 0)
    }
    fun header(title: String, description: String) = JPanel(BorderLayout(0, 4)).apply {
        putClientProperty("webrtc.role", "canvas")
        border = BorderFactory.createEmptyBorder(0, 0, 18, 0)
        add(JLabel(title).apply { putClientProperty("webrtc.role", "heading") }, BorderLayout.NORTH)
        add(note(description), BorderLayout.CENTER)
    }
    fun toolbar(vararg components: Component) = JPanel(WrapLayout(FlowLayout.LEFT, 8, 6)).apply {
        components.forEach { add(it) }
    }
    fun form(vararg fields: Pair<String, JComponent>) = JPanel(GridBagLayout()).apply {
        fields.forEachIndexed { row, (label, field) ->
            val c = GridBagConstraints().apply {
                gridy = row; anchor = GridBagConstraints.WEST; fill = GridBagConstraints.HORIZONTAL
                insets = Insets(8, 4, 8, 12)
            }
            add(JLabel(label).apply { labelFor = field }, c)
            c.gridx = 1; c.weightx = 1.0; c.insets = Insets(8, 4, 8, 4)
            field.accessibleContext.accessibleName = label
            add(field, c)
        }
    }
    fun section(title: String, body: JComponent) = JPanel(BorderLayout(0, 8)).apply {
        border = BorderFactory.createCompoundBorder(RoundBorder(), BorderFactory.createEmptyBorder(14, 16, 14, 16))
        add(JLabel(title).apply { putClientProperty("webrtc.role", "section") }, BorderLayout.NORTH)
        add(body, BorderLayout.CENTER)
    }
    fun disclosure(title: String, body: JComponent, open: Boolean = false) = JPanel(BorderLayout(0, 4)).apply {
        border = BorderFactory.createCompoundBorder(RoundBorder(), BorderFactory.createEmptyBorder(3, 10, 3, 10))
        val toggle = quiet(JButton()).apply {
            horizontalAlignment = SwingConstants.LEFT
            accessibleContext.accessibleName = title
        }
        fun update() { toggle.text = (if (body.isVisible) "▾  " else "▸  ") + title }
        body.isVisible = open; update()
        toggle.addActionListener { body.isVisible = !body.isVisible; update(); revalidate(); repaint() }
        add(toggle, BorderLayout.NORTH); add(body, BorderLayout.CENTER)
    }
    fun stack(vararg components: JComponent) = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        components.forEachIndexed { i, component ->
            component.alignmentX = Component.LEFT_ALIGNMENT
            component.maximumSize = Dimension(Int.MAX_VALUE, component.preferredSize.height)
            // Disclosures need to grow after being opened.
            if (component is JPanel) component.maximumSize = Dimension(Int.MAX_VALUE, Int.MAX_VALUE)
            if (i > 0) add(Box.createVerticalStrut(12))
            add(component)
        }
    }
    fun scroll(body: Component) = JScrollPane(if (body is Scrollable) body else WidthTrackingPanel(body)).apply {
        border = BorderFactory.createEmptyBorder(); verticalScrollBar.unitIncrement = 18
    }
    fun more(label: String = "More", vararg actions: Pair<String, () -> Unit>) = JButton(label).apply {
        val menu = JPopupMenu()
        actions.forEach { (title, action) -> menu.add(JMenuItem(title).apply { addActionListener { action() } }) }
        addActionListener { menu.show(this, 0, height) }
    }
    fun refreshWhileShowing(panel: JPanel, refresh: () -> Unit) {
        val timer = Timer(2000) { refresh() }
        panel.addHierarchyListener { event ->
            if (event.changeFlags and HierarchyEvent.SHOWING_CHANGED.toLong() != 0L) {
                if (panel.isShowing) { refresh(); timer.start() } else timer.stop()
            }
        }
        if (panel.isShowing) timer.start()
    }
    fun emptyTable(table: JTable, title: String, detail: String): JPanel {
        val cards = CardLayout()
        val panel = JPanel(cards)
        panel.add(JScrollPane(table), "rows")
        val message = JPanel(GridBagLayout()).apply {
            add(JPanel(BorderLayout(0, 8)).apply {
                add(JLabel(title, SwingConstants.CENTER).apply { putClientProperty("webrtc.role", "section") }, BorderLayout.NORTH)
                add(JLabel(detail, SwingConstants.CENTER).apply { putClientProperty("webrtc.role", "muted") }, BorderLayout.CENTER)
            })
        }
        panel.add(message, "empty")
        fun update() = cards.show(panel, if (table.rowCount == 0) "empty" else "rows")
        table.model.addTableModelListener { SwingUtilities.invokeLater { update() } }
        table.rowSorter?.addRowSorterListener { SwingUtilities.invokeLater { update() } }
        update()
        return panel
    }

    fun style(root: Component) {
        if (root is javax.swing.plaf.basic.BasicSplitPaneDivider) { root.border = null; root.background = canvas }
        if (root is JComponent) {
            root.font = font
            root.foreground = ink
            when (root) {
                is JPanel -> {
                    root.background = if (root.getClientProperty("webrtc.role") == "canvas") canvas else surface
                    val layout = root.layout
                    if (layout is FlowLayout && layout !is WrapLayout) root.layout = WrapLayout(FlowLayout.LEFT, 8, 6)
                }
                is JLabel -> when (root.getClientProperty("webrtc.role")) {
                    "heading" -> root.font = font.deriveFont(Font.BOLD, 25f)
                    "section" -> root.font = font.deriveFont(Font.BOLD, 14f)
                    "muted" -> root.foreground = muted
                }
                is JTextComponent -> {
                    root.background = surface; root.caretColor = ink
                    root.selectionColor = tint; root.selectedTextColor = ink
                    if (root is JTextArea || root is JTextPane) {
                        root.border = BorderFactory.createEmptyBorder(10, 12, 10, 12)
                        root.font = Font(Font.MONOSPACED, Font.PLAIN, 13)
                        if (root is JTextArea && root.lineWrap) root.font = font
                        if (root.getClientProperty("webrtc.role") == "note") {
                            root.font = font; root.foreground = muted
                            root.border = BorderFactory.createEmptyBorder(4, 0, 8, 0)
                        }
                    } else root.border = BorderFactory.createCompoundBorder(RoundBorder(), BorderFactory.createEmptyBorder(7, 9, 7, 9))
                }
                is JButton -> {
                    root.setUI(FlatButtonUi()); root.isOpaque = false; root.isContentAreaFilled = false
                    root.isRolloverEnabled = true; root.border = BorderFactory.createEmptyBorder(8, 12, 8, 12)
                    root.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                    if (root.getClientProperty("webrtc.role") == "primary") root.font = font.deriveFont(Font.BOLD)
                }
                is JCheckBox -> { root.isOpaque = false; root.iconTextGap = 8 }
                is JComboBox<*> -> {
                    root.background = surface; root.maximumRowCount = 12
                    root.renderer = object : DefaultListCellRenderer() {
                        override fun getListCellRendererComponent(list: JList<*>?, value: Any?, index: Int, selected: Boolean, focus: Boolean): Component {
                            super.getListCellRendererComponent(list, value, index, selected, focus)
                            if (value == null) text = root.getClientProperty("webrtc.emptyText")?.toString().orEmpty()
                            font = this@UiKit.font; foreground = ink; background = if (selected) tint else surface
                            border = BorderFactory.createEmptyBorder(5, 8, 5, 8); toolTipText = value?.toString()
                            return this
                        }
                    }
                }
                is JScrollPane -> {
                    if (root.border !is TitledBorder) root.border = RoundBorder()
                    val canvasView = (root.viewport.view as? JComponent)?.getClientProperty("webrtc.role") == "canvas"
                    root.viewport.background = if (canvasView) canvas else surface
                    if (canvasView) root.border = BorderFactory.createEmptyBorder()
                    root.verticalScrollBar.unitIncrement = 18
                }
                is JSplitPane -> {
                    root.border = null; root.dividerSize = 8; root.isContinuousLayout = true
                    listOfNotNull(root.leftComponent, root.rightComponent).forEach {
                        it.minimumSize = if (root.orientation == JSplitPane.VERTICAL_SPLIT) Dimension(100, 120) else Dimension(180, 100)
                    }
                }
                is JTabbedPane -> { root.setUI(FlatTabsUi()); root.background = surface; root.tabLayoutPolicy = JTabbedPane.SCROLL_TAB_LAYOUT }
                is JTable -> styleTable(root)
            }
            (root.border as? TitledBorder)?.let { it.titleFont = font.deriveFont(Font.BOLD, 14f); it.titleColor = muted; it.border = RoundBorder() }
        }
        if (root is Container) root.components.forEach { style(it) }
    }

    private fun styleTable(table: JTable) {
        table.rowHeight = 36; table.showHorizontalLines = false; table.showVerticalLines = false
        table.intercellSpacing = Dimension(0, 0); table.fillsViewportHeight = true
        table.background = surface; table.selectionBackground = tint; table.selectionForeground = ink
        table.tableHeader.apply { font = this@UiKit.font.deriveFont(Font.BOLD, 12f); background = canvas; foreground = muted; preferredSize = Dimension(0, 36) }
        val heading = JLabel().apply { isOpaque = true; font = this@UiKit.font.deriveFont(Font.BOLD, 12f) }
        table.tableHeader.defaultRenderer = javax.swing.table.TableCellRenderer { _, value, _, _, _, column ->
            heading.apply {
                text = value?.toString().orEmpty(); background = canvas; foreground = muted
                border = BorderFactory.createCompoundBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, line), BorderFactory.createEmptyBorder(0, 10, 0, 10))
                val key = table.rowSorter?.sortKeys?.firstOrNull { it.column == table.convertColumnIndexToModel(column) }
                icon = when (key?.sortOrder) { SortOrder.ASCENDING -> UIManager.getIcon("Table.ascendingSortIcon"); SortOrder.DESCENDING -> UIManager.getIcon("Table.descendingSortIcon"); else -> null }
                horizontalTextPosition = SwingConstants.LEFT; toolTipText = text
            }
        }
        val renderer = object : DefaultTableCellRenderer() {
            override fun getTableCellRendererComponent(t: JTable, value: Any?, selected: Boolean, focus: Boolean, row: Int, col: Int): Component {
                super.getTableCellRendererComponent(t, value, selected, focus, row, col)
                border = BorderFactory.createEmptyBorder(0, 10, 0, 10)
                background = if (selected) tint else if (row % 2 == 0) surface else canvas
                foreground = ink; toolTipText = value?.toString()
                return this
            }
        }
        table.setDefaultRenderer(Any::class.java, renderer)
        table.setDefaultRenderer(String::class.java, renderer)
        table.setDefaultRenderer(java.lang.Boolean::class.java, javax.swing.table.TableCellRenderer { _, value, selected, _, row, _ ->
            JCheckBox().apply {
                isSelected = value == true; horizontalAlignment = SwingConstants.CENTER
                background = if (selected) tint else if (row % 2 == 0) surface else canvas
                isOpaque = true; isEnabled = table.isEnabled
            }
        })
        val wrapped = table.getClientProperty("webrtc.wrapColumns") as? List<*>
        if (wrapped != null) {
            table.rowHeight = (table.getClientProperty("webrtc.rowHeight") as? Int) ?: 64
            val wrap = JTextArea().apply { lineWrap = true; wrapStyleWord = true; font = this@UiKit.font; border = BorderFactory.createEmptyBorder(7, 10, 7, 10) }
            val wrapRenderer = javax.swing.table.TableCellRenderer { _, value, selected, _, row, _ ->
                wrap.apply { text = value?.toString().orEmpty(); foreground = ink; background = if (selected) tint else if (row % 2 == 0) surface else canvas; toolTipText = text }
            }
            wrapped.filterIsInstance<Int>().forEach { table.columnModel.getColumn(it).cellRenderer = wrapRenderer }
        }
        table.preferredScrollableViewportSize = Dimension(600, 250)
    }

    private class RoundBorder : AbstractBorder() {
        override fun getBorderInsets(c: Component) = Insets(1, 1, 1, 1)
        override fun paintBorder(c: Component, g: Graphics, x: Int, y: Int, width: Int, height: Int) {
            (g.create() as Graphics2D).apply {
                setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                color = line; drawRoundRect(x, y, width - 1, height - 1, 10, 10); dispose()
            }
        }
    }
    private class FlatButtonUi : BasicButtonUI() {
        override fun paint(g: Graphics, c: JComponent) {
            val button = c as AbstractButton
            val primary = c.getClientProperty("webrtc.role") == "primary"
            val quiet = c.getClientProperty("webrtc.role") == "quiet"
            val nav = c.getClientProperty("webrtc.role") == "nav"
            val active = button.model.isRollover || button.model.isPressed || (nav && button.isSelected)
            val bg = when { !button.isEnabled -> canvas; primary -> Color(0x245FCB); active -> tint; quiet || nav -> c.parent?.background ?: surface; else -> surface }
            button.foreground = when { !button.isEnabled -> muted; primary -> Color.WHITE; nav && button.isSelected -> accent; else -> ink }
            (g.create() as Graphics2D).apply {
                setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                color = bg; fillRoundRect(0, 0, c.width, c.height, 10, 10)
                if ((!quiet && !nav) || button.hasFocus()) {
                    color = if (button.hasFocus()) accent else if (primary) bg else line
                    drawRoundRect(0, 0, c.width - 1, c.height - 1, 10, 10)
                }
                if (nav && button.isSelected) { color = accent; fillRoundRect(0, 7, 3, c.height - 14, 3, 3) }
                dispose()
            }
            super.paint(g, c)
        }
        override fun paintFocus(g: Graphics, b: AbstractButton, view: Rectangle, text: Rectangle, icon: Rectangle) = Unit
    }
    private class FlatTabsUi : BasicTabbedPaneUI() {
        override fun installDefaults() { super.installDefaults(); tabInsets = Insets(9, 14, 9, 14); contentBorderInsets = Insets(4, 0, 0, 0); tabAreaInsets = Insets(0, 0, 0, 0) }
        override fun paintTabBackground(g: Graphics, placement: Int, index: Int, x: Int, y: Int, w: Int, h: Int, selected: Boolean) {
            g.color = if (selected) surface else canvas; g.fillRect(x, y, w, h)
        }
        override fun paintTabBorder(g: Graphics, placement: Int, index: Int, x: Int, y: Int, w: Int, h: Int, selected: Boolean) {
            if (selected) { g.color = accent; g.fillRect(x + 8, y + h - 3, w - 16, 3) }
        }
        override fun paintContentBorder(g: Graphics, placement: Int, selected: Int) = Unit
    }
}

private class WidthTrackingPanel(body: Component) : JPanel(BorderLayout()), Scrollable {
    init { add(body, BorderLayout.NORTH); if (body is JComponent) putClientProperty("webrtc.role", body.getClientProperty("webrtc.role")) }
    override fun getPreferredScrollableViewportSize(): Dimension = preferredSize
    override fun getScrollableTracksViewportWidth() = true
    override fun getScrollableTracksViewportHeight() = false
    override fun getScrollableUnitIncrement(visible: Rectangle, orientation: Int, direction: Int) = 18
    override fun getScrollableBlockIncrement(visible: Rectangle, orientation: Int, direction: Int) = maxOf(18, visible.height - 30)
}

/** Toolbars wrap at their actual width instead of silently clipping actions. */
private class WrapLayout(align: Int, hgap: Int, vgap: Int) : FlowLayout(align, hgap, vgap) {
    override fun preferredLayoutSize(target: Container): Dimension = size(target, false)
    override fun minimumLayoutSize(target: Container): Dimension = size(target, true)
    private fun size(target: Container, minimum: Boolean): Dimension {
        synchronized(target.treeLock) {
            val available = (if (target.width > 0) target.width else target.parent?.width ?: 900).coerceAtLeast(100)
            val insets = target.insets
            val max = available - insets.left - insets.right - hgap * 2
            var width = 0; var height = 0; var rowWidth = 0; var rowHeight = 0
            target.components.filter { it.isVisible }.forEach {
                val d = if (minimum) it.minimumSize else it.preferredSize
                if (rowWidth > 0 && rowWidth + hgap + d.width > max) {
                    width = maxOf(width, rowWidth); height += rowHeight + vgap; rowWidth = 0; rowHeight = 0
                }
                rowWidth += (if (rowWidth > 0) hgap else 0) + d.width
                rowHeight = maxOf(rowHeight, d.height)
            }
            width = maxOf(width, rowWidth); height += rowHeight
            return Dimension(width + insets.left + insets.right + hgap * 2, height + insets.top + insets.bottom + vgap * 2)
        }
    }
}
