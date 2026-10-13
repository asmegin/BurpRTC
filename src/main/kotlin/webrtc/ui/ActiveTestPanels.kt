package webrtc.ui

import kotlinx.serialization.json.*
import webrtc.bridge.ActiveTestController
import webrtc.config.*
import webrtc.telemetry.TelemetryTableModel
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.*
import javax.swing.event.TableModelEvent
import javax.swing.Timer

private fun followJobStatus(telemetry: TelemetryTableModel, status: JLabel, currentId: () -> String?) {
    telemetry.addTableModelListener { update ->
        if (update.type == TableModelEvent.INSERT) {
            for (index in update.firstRow..minOf(update.lastRow, telemetry.rowCount - 1)) {
                val event = telemetry.eventAt(index) ?: continue
                if (event.type !in setOf("test-job", "command-result")) continue
                val id = runCatching { Json.parseToJsonElement(event.raw).jsonObject["commandId"]?.jsonPrimitive?.content }.getOrNull()
                if (id != null && id == currentId()) status.text = event.summary
            }
        }
    }
}

private class TestForm : JPanel(GridBagLayout()) {
    private var row = 0
    private var advancedRow = 0
    private val advanced = JPanel(GridBagLayout())
    fun field(label: String, component: JComponent, help: JButton? = null) {
        addField(this, row++, label, component, help)
    }
    fun advancedField(label: String, component: JComponent, help: JButton? = null) = addField(advanced, advancedRow++, label, component, help)
    fun finishAdvanced(title: String) {
        if (advancedRow == 0) return
        add(UiKit.disclosure(title, advanced), GridBagConstraints().apply {
            gridy = row++; gridx = 0; gridwidth = 3; weightx = 1.0; fill = GridBagConstraints.HORIZONTAL; insets = Insets(10, 6, 6, 6)
        })
    }
    private fun addField(panel: JPanel, r: Int, label: String, component: JComponent, help: JButton?) {
        val c = GridBagConstraints().apply { insets = Insets(7, 6, 7, 6); fill = GridBagConstraints.HORIZONTAL; anchor = GridBagConstraints.WEST; gridy = r }
        if (label.isEmpty() && component is JLabel) {
            c.gridwidth = 3; c.weightx = 1.0
            panel.add(UiKit.note(component.text), c); return
        }
        panel.add(JLabel(label).apply { labelFor = component }, c)
        c.gridx = 1; c.weightx = 1.0
        component.accessibleContext.accessibleName = label.ifBlank { component.accessibleContext.accessibleName }
        if (component is JComboBox<*>) component.minimumSize = java.awt.Dimension(160, 32)
        panel.add(component, c)
        c.gridx = 2; c.weightx = 0.0; c.fill = GridBagConstraints.NONE
        panel.add(help ?: JLabel(" "), c)
    }
}

private fun statusBar(status: JLabel) = JPanel(BorderLayout()).apply {
    status.putClientProperty("webrtc.role", "muted")
    status.preferredSize = java.awt.Dimension(0, 30)
    add(status)
}

private fun saveSettings(parent: JPanel, status: JLabel, save: () -> Unit) = JButton("Save settings").apply {
    toolTipText = "Save these inputs for manual runs and Scan All."
    addActionListener {
        runCatching(save).onSuccess { status.text = "Settings saved for Scan All and manual runs" }
            .onFailure { JOptionPane.showMessageDialog(parent, it.message, "Settings not saved", JOptionPane.ERROR_MESSAGE) }
    }
}

class DataChannelFuzzPanel(
    private val store: ConfigStore, private val controller: ActiveTestController, telemetry: TelemetryTableModel
) : JPanel(BorderLayout()) {
    private data class Target(val agent: String, val channel: String, val text: String) { override fun toString() = text }
    private val target = JComboBox<Target>().apply { putClientProperty("webrtc.emptyText", "No open channels · start a call on an injected page") }
    private val modes = listOf("text", "hex", "json", "boundary")
    private val mode = JComboBox(arrayOf("Custom text (UTF-8)", "Custom binary (hex)", "JSON edge cases", "Text size boundaries"))
    private val payload = JTextArea(3, 40)
    private val count = JSpinner(SpinnerNumberModel(1, 1, 50, 1))
    private val interval = JSpinner(SpinnerNumberModel(250, 100, 1000, 50))
    private val maxBytes = JSpinner(SpinnerNumberModel(4096, 1, 65536, 1))
    private val stopOnError = JCheckBox("Stop on first send error", true)
    private val nextOpen = JCheckBox("Run on next DataChannel open (once, this session)")
    private var updatingArm = false
    private var lastAutomaticJob: String? = null
    private val status = JLabel("Start a DataChannel in the browser, then refresh the list.")
    private val runButton = UiKit.primary(JButton("Run payloads").apply { addActionListener { runTest() } })
    private var currentJob: String? = null

    init {
        followJobStatus(telemetry, status) { currentJob ?: controller.automaticFuzzJob() }
        val saved = store.config.dataChannelFuzz
        mode.selectedIndex = modes.indexOf(saved.mode).coerceAtLeast(0)
        payload.text = saved.payload; count.value = saved.count; interval.value = saved.intervalMs
        maxBytes.value = saved.maxBytes; stopOnError.isSelected = saved.stopOnError
        val form = TestForm().apply {
            field("Open DataChannel:", target, HelpUi.button(
                "Open DataChannel",
                "The live WebRTC DataChannel to send test payloads into. DataChannels are the app's peer-to-peer data pipe (chat, file transfer, game state, signaling). The list updates automatically while a call is open; each entry shows the page, the connection/channel, and the channel label."
            ))
            field("Payload mode:", mode, HelpUi.button(
                "Payload mode",
                "How the payload is built. Custom text sends your UTF-8 string as-is. Custom binary sends the bytes you type as hex. JSON edge cases sends a set of tricky JSON values (deep nesting, big numbers, unicode) to probe parser handling. Text size boundaries sends messages sized around common limits to probe buffering/fragmentation.",
                "Binary (hex) example — an all-zero then all-ones byte:\n00 ff\n\nText example — a JSON injection probe the peer might mis-handle:\n{\"type\":\"admin\",\"cmd\":\"promote\"}"
            ))
            field("Custom payload:", JScrollPane(payload), HelpUi.button(
                "Custom payload",
                "The message body used by the Custom text and Custom binary modes (ignored by the JSON and boundary modes, which generate their own). Text is sent as UTF-8; binary is entered as pairs of hex digits, whitespace allowed.",
                "Text: hello from the test suite\nHex:  48 65 6c 6c 6f"
            ))
            advancedField("Messages:", count, HelpUi.button(
                "Messages",
                "How many messages to send in this run (1–50). Combined with Interval, this controls burst size and rate — useful for flood / rate-limit testing without overwhelming the browser."
            ))
            advancedField("Interval (ms):", interval, HelpUi.button(
                "Interval (ms)",
                "Delay between messages, 100–1000 ms. Larger values are gentler; smaller values approximate a burst. The whole run is still capped at 1 MiB total."
            ))
            advancedField("Maximum bytes/message:", maxBytes, HelpUi.button(
                "Maximum bytes per message",
                "Per-message size cap (1–65,536 bytes). The suite refuses payloads larger than this and caps each run at 1 MiB total, so a fuzz run can't hang the browser. Use a large value to probe how the peer handles oversized frames."
            ))
            field("", stopOnError, HelpUi.button(
                "Stop on first send error",
                "When on, the run halts as soon as a send fails (for example the channel closed). When off, it keeps trying the remaining messages. A send succeeding only means the local browser accepted it for sending — it does not prove the remote peer processed it."
            ))
            advancedField("", nextOpen, HelpUi.button(
                "Run on next DataChannel open",
                "Arm one automatic M4 run using the settings currently shown. The next channel that actually reaches open on any allow-listed, in-scope page requests the run immediately, without waiting for the three-second poll. Local means created locally, not open. Channels that close while connecting cannot send test messages.",
                "Set the payload and limits, tick this option, then start a fresh call. It disarms after one run is queued. A busy page leaves it armed for another open event. Uncheck or press Stop to disarm and cancel the automatic run. Reload the browser page after updating the extension."
            ))
            field("", JLabel("Each run is limited to 1 MiB. Send acceptance does not prove peer processing."))
            finishAdvanced("Limits & run on next open")
        }
        val controls = JPanel(BorderLayout()).apply {
            preferredSize = java.awt.Dimension(800, 400)
            add(UiKit.scroll(form), BorderLayout.CENTER)
            add(JPanel(FlowLayout(FlowLayout.LEFT)).apply {
                add(runButton)
                add(JButton("Stop").apply { addActionListener {
                    controller.disarmNextOpenFuzz()
                    controller.cancelJob(currentJob.orEmpty())
                    refresh()
                    status.text = "Automatic run disarmed; stop requested for any current test"
                } })
                add(saveSettings(this@DataChannelFuzzPanel, status) {
                    val cfg = settings(); cfg.validate(); store.save(store.config.copy(dataChannelFuzz = cfg))
                })
                add(UiKit.quiet(JButton("Refresh channels").apply { addActionListener { refresh() } }))
            }, BorderLayout.SOUTH)
        }
        nextOpen.addActionListener {
            if (!updatingArm) try {
                if (nextOpen.isSelected) {
                    val cfg = settings()
                    cfg.validate()
                    store.save(store.config.copy(dataChannelFuzz = cfg))
                    controller.armNextOpenFuzz(cfg)
                    status.text = "Armed for the next open channel on an in-scope page"
                } else {
                    controller.disarmNextOpenFuzz()
                    status.text = "Automatic run disarmed"
                }
            } catch (e: Exception) {
                controller.disarmNextOpenFuzz()
                nextOpen.isSelected = false
                JOptionPane.showMessageDialog(this, e.message, "DataChannel test", JOptionPane.ERROR_MESSAGE)
            }
        }
        add(JSplitPane(JSplitPane.VERTICAL_SPLIT, controls, TestResultsPanel(telemetry, "fuzz-.*|pc-state|sdp-error|dc-(created|state|send|recv)", "dc-fuzz")).apply { resizeWeight = 0.35; dividerLocation = 400 })
        add(statusBar(status), BorderLayout.SOUTH)
        refresh()
        UiKit.refreshWhileShowing(this) { refresh() }
    }

    private fun refresh() {
        if (target.isPopupVisible) return
        updatingArm = true
        nextOpen.isSelected = controller.nextOpenFuzzArmed()
        updatingArm = false
        controller.automaticFuzzJob()?.let { id ->
            if (id != lastAutomaticJob) { lastAutomaticJob = id; currentJob = id }
            if (currentJob == id) status.text = "Automatic dc-fuzz ${id.take(8)} ${controller.jobState(id).orEmpty()}"
        }
        val previous = target.selectedItem as? Target
        target.removeAllItems()
        controller.agents().forEach { agent -> agent.channels.filter { it.state == "open" }.forEach { channel ->
            target.addItem(Target(agent.id, channel.id, "${agent.id.takeLast(8)} ${channel.pc}/${channel.id} ${channel.label} | ${agent.frame}"))
        } }
        (0 until target.itemCount).firstOrNull { target.getItemAt(it).let { item -> item.agent == previous?.agent && item.channel == previous?.channel } }?.let { target.selectedIndex = it }
        runButton.isEnabled = target.itemCount > 0
        runButton.toolTipText = if (target.itemCount == 0) "Open a data channel on an injected page to run payloads." else "Send the selected payloads."
        if (controller.nextOpenFuzzArmed()) status.text = "Armed for the next open channel · ${target.itemCount} open now"
        else if (currentJob == null) status.text = "${target.itemCount} open channel(s) · local creation does not mean open"
    }

    private fun settings() = DataChannelFuzzConfig(modes[mode.selectedIndex], payload.text, count.value as Int,
        interval.value as Int, maxBytes.value as Int, stopOnError.isSelected)

    private fun runTest() {
        try {
            val selected = target.selectedItem as? Target ?: error("Refresh and select an open DataChannel")
            val cfg = settings()
            cfg.validate()
            store.save(store.config.copy(dataChannelFuzz = cfg))
            val id = controller.queueFuzz(selected.agent, selected.channel, cfg)
            currentJob = id
            status.text = "Queued ${id.take(8)}; waiting for browser poll"
        } catch (e: Exception) { JOptionPane.showMessageDialog(this, e.message, "DataChannel test", JOptionPane.ERROR_MESSAGE) }
    }
}

class SdpFuzzPanel(
    private val store: ConfigStore, private val controller: ActiveTestController, telemetry: TelemetryTableModel
) : JPanel(BorderLayout()) {
    private val target = JComboBox<ActiveTestController.Agent>().apply { putClientProperty("webrtc.emptyText", "No live pages · enable the agent and browse the target") }
    private val descriptionType = JComboBox(arrayOf("offer", "answer"))
    private val maxCases = JSpinner(SpinnerNumberModel(300, 1, 500, 1))
    private val status = JLabel("Live pages update automatically.")
    private val runButton = UiKit.primary(JButton("Run SDP fuzzing").apply { addActionListener { runTest() } })
    private var currentJob: String? = null

    init {
        followJobStatus(telemetry, status) { currentJob }
        val saved = store.config.sdpFuzz
        descriptionType.selectedItem = saved.descriptionType
        maxCases.value = saved.maxCases
        val form = TestForm().apply {
            field("Browser page:", target, HelpUi.button(
                "Browser page",
                "The live agent (browser page) that runs the fuzz. Each case is fed to a throwaway RTCPeerConnection inside that page, so it exercises the real browser's SDP parser (libwebrtc) on the machine under test. The list updates automatically."
            ))
            field("Description type:", descriptionType, HelpUi.button(
                "Description type",
                "Whether each malformed SDP is submitted as an 'offer' or an 'answer' to setRemoteDescription(). Offer is the usual choice; answer additionally exercises the state machine's answer path."
            ))
            field("Max cases:", maxCases, HelpUi.button(
                "Max cases",
                "Maximum cases (1–500). The fuzzer uses the latest observed application SDP when available and mutates each line with known SDP attributes, malformed values, numeric overflow strings, and bounded large values. A small cap can stop before every line has been exercised.",
                "Each case and the overall number of cases are bounded. A parser accepting an input is evidence to investigate, not by itself a vulnerability."
            ))
            field("", JLabel("No packets are sent. Accepted offers also run createAnswer as a follow-up; this is stronger triage, not proof of a vulnerability. A timeout or agent disconnect needs manual browser review."))
        }
        val controls = JPanel(BorderLayout()).apply {
            preferredSize = java.awt.Dimension(800, 245)
            add(UiKit.scroll(form), BorderLayout.CENTER)
            add(JPanel(FlowLayout(FlowLayout.LEFT)).apply {
                add(runButton)
                add(JButton("Stop").apply { addActionListener {
                    status.text = if (controller.cancelJob(currentJob.orEmpty())) "Stop requested" else "No active test from this panel"
                } })
                add(saveSettings(this@SdpFuzzPanel, status) {
                    val cfg = SdpFuzzConfig(descriptionType.selectedItem as String, maxCases.value as Int)
                    cfg.validate(); store.save(store.config.copy(sdpFuzz = cfg))
                })
            }, BorderLayout.SOUTH)
        }
        add(JSplitPane(JSplitPane.VERTICAL_SPLIT, controls, TestResultsPanel(telemetry, "sdp-fuzz-.*", "sdp-fuzz")).apply { resizeWeight = 0.35; dividerLocation = 245 })
        add(statusBar(status), BorderLayout.SOUTH)
        refresh()
        UiKit.refreshWhileShowing(this) { refresh() }
    }

    private fun refresh() {
        if (target.isPopupVisible) return
        val previous = (target.selectedItem as? ActiveTestController.Agent)?.id
        target.removeAllItems()
        controller.agents().forEach { target.addItem(it) }
        (0 until target.itemCount).firstOrNull { target.getItemAt(it).id == previous }?.let { target.selectedIndex = it }
        runButton.isEnabled = target.itemCount > 0
        runButton.toolTipText = if (target.itemCount == 0) "Enable the agent in Setup, then load an allowed page through Burp." else "Run parser tests on this page."
        if (currentJob == null) status.text = "${target.itemCount} live page(s) · updating automatically"
    }

    private fun runTest() {
        try {
            val selected = target.selectedItem as? ActiveTestController.Agent ?: error("Refresh and select a live browser page")
            val cfg = SdpFuzzConfig(descriptionType.selectedItem as String, maxCases.value as Int)
            cfg.validate()
            store.save(store.config.copy(sdpFuzz = cfg))
            val id = controller.queueSdpFuzz(selected.id, cfg)
            currentJob = id
            status.text = "Queued ${id.take(8)}; waiting for browser poll"
        } catch (e: Exception) { JOptionPane.showMessageDialog(this, e.message, "SDP fuzz", JOptionPane.ERROR_MESSAGE) }
    }
}

class IceProbePanel(
    private val store: ConfigStore, private val controller: ActiveTestController, telemetry: TelemetryTableModel
) : JPanel(BorderLayout()) {
    private val target = JComboBox<ActiveTestController.Agent>().apply { putClientProperty("webrtc.emptyText", "No live pages · enable the agent and browse the target") }
    private val url = JTextField(40)
    private val username = JTextField(24)
    private val credential = JTextField(24)
    private val policy = JComboBox(arrayOf("all", "relay"))
    private val timeout = JSpinner(SpinnerNumberModel(10, 3, 30, 1))
    private val status = JLabel("Live pages update automatically.")
    private val runButton = UiKit.primary(JButton("Gather candidates").apply { addActionListener { runTest() } })
    private var currentJob: String? = null

    init {
        followJobStatus(telemetry, status) { currentJob }
        val saved = store.config.iceProbe
        url.text = saved.url; username.text = saved.username; credential.text = saved.credential
        policy.selectedItem = saved.policy; timeout.value = saved.timeoutSeconds
        val form = TestForm().apply {
            field("Browser page:", target, HelpUi.button(
                "Browser page",
                "The live agent (browser page) that will run the ICE gather. The probe uses a throwaway RTCPeerConnection inside that page, so it exercises the real browser and network path the target app uses. The list updates automatically."
            ))
            field("STUN/TURN URI:", url, HelpUi.button(
                "STUN/TURN URI",
                "The ICE server to gather candidates against. STUN reveals your public (server-reflexive) address; TURN allocates a relay. Blank gathers host candidates only. The server host and port must be in Burp Target scope — no HTTP request is made to it; the gather uses the ICE protocol directly from the browser.",
                "stun:stun.example.com:3478\nturn:turn.example.com:3478?transport=udp\nturns:turn.example.com:5349?transport=tcp"
            ))
            field("TURN username:", username, HelpUi.button(
                "TURN username",
                "Username for a TURN server that requires authentication (ignored for STUN). Testing whether a TURN server hands out relay allocations to unexpected or reused credentials is a common misconfiguration check.",
                "Often a time-limited value like 1699999999:alice"
            ))
            field("TURN credential:", credential, HelpUi.button(
                "TURN credential",
                "Password/secret paired with the TURN username. Stored in the Burp project file and preserved in telemetry, commands, exports and reports, so you can copy complete evidence — remove it from screenshots yourself if needed.",
                "The HMAC or shared secret issued by the app for its TURN server."
            ))
            advancedField("ICE transport policy:", policy, HelpUi.button(
                "ICE transport policy",
                "'all' gathers every candidate type (host, srflx, relay). 'relay' forces the browser to use only TURN relay candidates, which proves whether the TURN server actually issues a relay allocation for your credentials — an open-relay / credential-abuse test. 'relay' requires a TURN URI."
            ))
            advancedField("Timeout (seconds):", timeout, HelpUi.button(
                "Timeout (seconds)",
                "How long (3–30s) to wait for candidate gathering before closing the throwaway peer. Raise it on slow networks; lower it to fail fast when a server is unreachable."
            ))
            field("", JLabel("Blank URI gathers host candidates only. TURN relay policy checks allocation, not end-to-end relay traffic."))
            field("", JLabel("ICE traffic leaves the browser directly. The server host and port must be in Burp Target scope."))
            finishAdvanced("Gathering options")
        }
        val controls = JPanel(BorderLayout()).apply {
            preferredSize = java.awt.Dimension(800, 390)
            add(UiKit.scroll(form), BorderLayout.CENTER)
            add(JPanel(FlowLayout(FlowLayout.LEFT)).apply {
                add(runButton)
                add(JButton("Stop").apply { addActionListener {
                    status.text = if (controller.cancelJob(currentJob.orEmpty())) "Stop requested" else "No active test from this panel"
                } })
                add(saveSettings(this@IceProbePanel, status) { val cfg = settings(); cfg.validate(); store.save(store.config.copy(iceProbe = cfg)) })
                add(JButton("Show scope URL").apply { addActionListener {
                    runCatching { url.text.trim().takeIf { it.isNotEmpty() }?.let { IceEndpoint.parse(it).scopeUrl } ?: "No server: host candidates only" }
                        .onSuccess { JOptionPane.showMessageDialog(this@IceProbePanel, it, "ICE endpoint scope", JOptionPane.INFORMATION_MESSAGE) }
                        .onFailure { JOptionPane.showMessageDialog(this@IceProbePanel, it.message, "ICE URI", JOptionPane.ERROR_MESSAGE) }
                } })
            }, BorderLayout.SOUTH)
        }
        add(JSplitPane(JSplitPane.VERTICAL_SPLIT, controls, TestResultsPanel(telemetry, "ice-probe-.*", "ice-probe")).apply { resizeWeight = 0.35; dividerLocation = 390 })
        add(statusBar(status), BorderLayout.SOUTH)
        refresh()
        UiKit.refreshWhileShowing(this) { refresh() }
    }

    private fun refresh() {
        if (target.isPopupVisible) return
        val previous = (target.selectedItem as? ActiveTestController.Agent)?.id
        target.removeAllItems()
        controller.agents().forEach { target.addItem(it) }
        (0 until target.itemCount).firstOrNull { target.getItemAt(it).id == previous }?.let { target.selectedIndex = it }
        runButton.isEnabled = target.itemCount > 0
        runButton.toolTipText = if (target.itemCount == 0) "Enable the agent in Setup, then load an allowed page through Burp." else "Gather candidates on this page."
        if (currentJob == null) status.text = "${target.itemCount} live page(s) · updating automatically"
    }

    private fun settings() = IceProbeConfig(url.text.trim(), username.text, credential.text, policy.selectedItem as String, timeout.value as Int)

    private fun runTest() {
        try {
            val selected = target.selectedItem as? ActiveTestController.Agent ?: error("Refresh and select a live browser page")
            val cfg = settings()
            cfg.validate()
            store.save(store.config.copy(iceProbe = cfg))
            val id = controller.queueIce(selected.id, cfg)
            currentJob = id
            status.text = "Queued ${id.take(8)}; waiting for browser poll"
        } catch (e: Exception) { JOptionPane.showMessageDialog(this, e.message, "ICE probe", JOptionPane.ERROR_MESSAGE) }
    }
}

/**
 * T8 — opt-in, bounded local renegotiation / ICE-restart loop. It drives only the
 * page's own `createOffer`/`setLocalDescription`; nothing is sent to the signaling
 * server. Clicking Run or selecting it in Scan All explicitly starts this bounded test.
 */
class SignalingFloodPanel(
    private val store: ConfigStore, private val controller: ActiveTestController, telemetry: TelemetryTableModel
) : JPanel(BorderLayout()) {
    private val target = JComboBox<ActiveTestController.Agent>().apply { putClientProperty("webrtc.emptyText", "No live pages · enable the agent and browse the target") }
    private val count = JSpinner(SpinnerNumberModel(5, 1, 20, 1))
    private val interval = JSpinner(SpinnerNumberModel(1000, 500, 5000, 500))
    private val status = JLabel("Live pages update automatically.")
    private val runButton = UiKit.primary(JButton("Run negotiation loop").apply { addActionListener { runTest() } })
    private var currentJob: String? = null

    init {
        followJobStatus(telemetry, status) { currentJob }
        val saved = store.config.signalingFlood
        count.value = saved.count; interval.value = saved.intervalMs
        val form = TestForm().apply {
            field("Browser page:", target, HelpUi.button(
                "Browser page",
                "The live agent (browser page) that will run the loop. It creates a throwaway RTCPeerConnection and repeatedly calls createOffer/setLocalDescription with ICE restart, exercising the page's own negotiation path. The list updates automatically."
            ))
            field("Renegotiations:", count, HelpUi.button(
                "Renegotiations",
                "How many createOffer/setLocalDescription cycles to run (1-20). Keep it small; the loop is intentionally gentle and every attempt re-checks scope before continuing."
            ))
            field("Interval (ms):", interval, HelpUi.button(
                "Interval (ms)",
                "Delay between renegotiations (500-5000 ms). The whole run also stops on timeout or if the page leaves Burp Target scope."
            ))
            field("", JLabel("Local renegotiation only — nothing is sent to the signaling server. Reused ICE credentials across restarts are reported."))
        }
        val controls = JPanel(BorderLayout()).apply {
            preferredSize = java.awt.Dimension(800, 245)
            add(UiKit.scroll(form), BorderLayout.CENTER)
            add(JPanel(FlowLayout(FlowLayout.LEFT)).apply {
                add(runButton)
                add(JButton("Stop").apply { addActionListener {
                    status.text = if (controller.cancelJob(currentJob.orEmpty())) "Stop requested" else "No active test from this panel"
                } })
                add(saveSettings(this@SignalingFloodPanel, status) {
                    val cfg = store.config.signalingFlood.copy(count = count.value as Int, intervalMs = interval.value as Int)
                    cfg.copy(confirm = true).validate(); store.save(store.config.copy(signalingFlood = cfg))
                })
            }, BorderLayout.SOUTH)
        }
        add(JSplitPane(JSplitPane.VERTICAL_SPLIT, controls, TestResultsPanel(telemetry, "flood-.*|signaling-flood-.*", "signaling-flood")).apply { resizeWeight = 0.35; dividerLocation = 245 })
        add(statusBar(status), BorderLayout.SOUTH)
        refresh()
        UiKit.refreshWhileShowing(this) { refresh() }
    }

    private fun refresh() {
        if (target.isPopupVisible) return
        val previous = (target.selectedItem as? ActiveTestController.Agent)?.id
        target.removeAllItems()
        controller.agents().forEach { target.addItem(it) }
        (0 until target.itemCount).firstOrNull { target.getItemAt(it).id == previous }?.let { target.selectedIndex = it }
        runButton.isEnabled = target.itemCount > 0
        runButton.toolTipText = if (target.itemCount == 0) "Enable the agent in Setup, then load an allowed page through Burp." else "Run a bounded local negotiation loop."
        if (currentJob == null) status.text = "${target.itemCount} live page(s) · updating automatically"
    }

    private fun runTest() {
        try {
            val selected = target.selectedItem as? ActiveTestController.Agent ?: error("Refresh and select a live browser page")
            val cfg = SignalingFloodConfig(true, count.value as Int, interval.value as Int)
            cfg.validate()
            store.save(store.config.copy(signalingFlood = cfg))
            val id = controller.queueSignalingFlood(selected.id, cfg)
            currentJob = id
            status.text = "Queued ${id.take(8)}; waiting for browser poll"
        } catch (e: Exception) { JOptionPane.showMessageDialog(this, e.message, "Signaling flood", JOptionPane.ERROR_MESSAGE) }
    }
}
