package webrtc.ui

import java.awt.Component
import java.awt.Dimension
import java.awt.Insets
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JOptionPane
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.ScrollPaneConstants
import javax.swing.UIManager

/**
 * Small "?" help buttons. Each explains one setting in plain English and, where
 * useful, shows an example pentest payload — so a tester who has never touched
 * WebRTC can tell what a field does and what to type in it.
 */
object HelpUi {

    /** A compact "?" button that opens a readable explanation for one setting. */
    fun button(title: String, plain: String, example: String? = null): JButton =
        JButton("?").apply {
            margin = Insets(0, 5, 0, 5)
            toolTipText = "What is \"$title\"?"
            accessibleContext.accessibleName = "Help: $title"
            UiKit.quiet(this)
            addActionListener { show(this, title, plain, example) }
        }

    private fun show(parent: Component, title: String, plain: String, example: String?) {
        val body = buildString {
            append(plain)
            if (!example.isNullOrBlank()) {
                append("\n\nExample:\n")
                append(example)
            }
        }
        val area = JTextArea(body).apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
            border = BorderFactory.createEmptyBorder(4, 4, 4, 4)
            background = UIManager.getColor("Panel.background")
            font = UIManager.getFont("Label.font")
            caretPosition = 0
        }
        val scroll = JScrollPane(
            area,
            ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER
        ).apply {
            preferredSize = Dimension(480, 300)
            border = null
        }
        JOptionPane.showMessageDialog(parent, scroll, title, JOptionPane.INFORMATION_MESSAGE)
    }
}
