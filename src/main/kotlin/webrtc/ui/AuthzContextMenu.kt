package webrtc.ui

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import java.awt.Component
import javax.swing.JMenuItem

/** Right-click -> "WebRTC: Run authz matrix" on any request(s). */
class AuthzContextMenu(
    private val onRun: (List<HttpRequestResponse>) -> Unit
) : ContextMenuItemsProvider {

    override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
        val selected = collect(event)
        if (selected.isEmpty()) return emptyList()
        val item = JMenuItem("WebRTC: Run authz matrix (${selected.size})")
        item.addActionListener { onRun(selected) }
        return listOf(item)
    }

    private fun collect(event: ContextMenuEvent): List<HttpRequestResponse> {
        val list = ArrayList<HttpRequestResponse>()
        list.addAll(event.selectedRequestResponses())
        event.messageEditorRequestResponse().ifPresent { list.add(it.requestResponse()) }
        return list.distinct()
    }
}
