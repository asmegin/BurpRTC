package webrtc.ui

import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.*
import webrtc.bridge.ActiveTestController
import webrtc.config.ConfigStore
import webrtc.config.Roles
import webrtc.datachannel.*
import webrtc.telemetry.TelemetryTableModel
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridLayout
import java.io.File
import javax.swing.*
import javax.swing.table.DefaultTableModel

/**
 * Tests → Data channel runner. Launches the controlled browser sessions, runs the suite with
 * recipient observation and shows every classified case with its evidence and the coverage map.
 */
class DataChannelRunnerPanel(
    private val store: ConfigStore,
    private val controller: ActiveTestController,
    private val runner: DcSuiteRunner,
    private val browser: BrowserRunner,
    private val results: DcResultStore,
    telemetry: TelemetryTableModel
) : JPanel(BorderLayout()) {
    private val pretty = Json { prettyPrint = true; encodeDefaults = true }
    private val status = JLabel("Launch sessions or open the call in two browsers routed through Burp, then run the suite.").apply { putClientProperty("webrtc.role", "muted") }
    private val log = JTextArea(10, 80).apply { isEditable = false; lineWrap = true; wrapStyleWord = true }

    // ---- participants ----
    private val participantModel = object : DefaultTableModel(arrayOf("Page", "Runner session", "Role", "Room", "Endpoint", "Transports"), 0) {
        override fun isCellEditable(row: Int, column: Int) = column == 2 || column == 3
    }
    private val participantTable = JTable(participantModel)
    private val participantIds = mutableListOf<String>()
    private val sender = JComboBox<String>()

    // ---- results ----
    private val resultModel = object : DefaultTableModel(arrayOf("Case", "Family", "Transport", "Verdict", "Title", "Reason"), 0) {
        override fun isCellEditable(row: Int, column: Int) = false
    }
    private val resultTable = JTable(resultModel)
    private val resultRows = mutableListOf<DcCaseResult>()
    private val detail = JTextArea(12, 80).apply { isEditable = false; lineWrap = true }
    private val coverage = JTextArea(20, 80).apply { isEditable = false; lineWrap = true; wrapStyleWord = true }

    // ---- sessions ----
    private val sessionModel = object : DefaultTableModel(arrayOf("Name", "Role", "Room", "Start URL", "Identity", "Running"), 0) {
        override fun isCellEditable(row: Int, column: Int) = column < 5
    }
    private val sessionTable = JTable(sessionModel)
    private val sessionScripts = mutableListOf<MutableMap<String, String>>()
    private val scriptFields = linkedMapOf("join" to JTextArea(5, 50), "leave" to JTextArea(3, 50), "hangup" to JTextArea(3, 50),
        "remove" to JTextArea(3, 50), "endpointExpr" to JTextArea(2, 50))
    private var editingSession = -1
    private val browserPath = JTextField(30)
    private val proxy = JTextField(16)
    private val headless = JCheckBox("Headless")
    private val keepProfiles = JCheckBox("Keep browser profiles (logins survive between runs)")
    private val mainRoom = JTextField(16)
    private val testRoom = JTextField(16)
    private val joinTimeout = JSpinner(SpinnerNumberModel(45, 5, 300, 5))

    // ---- suite settings ----
    private val families = DcScope.runnable.associateWith { JCheckBox(it.title) }
    private val maxCases = JSpinner(SpinnerNumberModel(200, 1, 1000, 10))
    private val maxMessageBytes = JSpinner(SpinnerNumberModel(65536, 1, 1048576, 1024))
    private val maxTotalMiB = JSpinner(SpinnerNumberModel(8, 1, 64, 1))
    private val maxDuration = JSpinner(SpinnerNumberModel(900, 30, 7200, 30))
    private val settle = JSpinner(SpinnerNumberModel(600, 50, 10000, 50))
    private val grace = JSpinner(SpinnerNumberModel(1500, 0, 15000, 100))
    private val probeEvery = JSpinner(SpinnerNumberModel(5, 1, 50, 1))
    private val maxBuffered = JSpinner(SpinnerNumberModel(1048576, 1024, 16 * 1048576, 65536))
    private val maxNesting = JSpinner(SpinnerNumberModel(64, 2, 512, 2))
    private val maxChannels = JSpinner(SpinnerNumberModel(8, 1, 64, 1))
    private val churnIterations = JSpinner(SpinnerNumberModel(5, 1, 64, 1))
    private val loadRates = JTextField(12)
    private val loadSeconds = JSpinner(SpinnerNumberModel(5, 1, 60, 1))
    private val burst = JSpinner(SpinnerNumberModel(25, 0, 1000, 5))
    private val minDelivery = JSpinner(SpinnerNumberModel(90, 0, 100, 5))
    private val maxLatency = JSpinner(SpinnerNumberModel(2000, 50, 60000, 100))
    private val maxLoss = JSpinner(SpinnerNumberModel(5.0, 0.0, 100.0, 0.5))
    private val seed = JTextField(12)
    private val jitsiVersion = JTextField(16)
    private val probeTemplate = JTextField(30)
    private val testRoomEndpoint = JTextField(16)
    private val expectDisconnect = JCheckBox("The customer session ends when the advisor hangs up")
    private val rejoinHangup = JComboBox(arrayOf("denied", "allowed", "unknown"))
    private val rejoinRemoval = JComboBox(arrayOf("denied", "allowed", "unknown"))
    private val bridgeLog = JTextField(30)
    private val protectedMessages = JTextArea(6, 60)
    private val payloadSources = listOf("automatic", "custom", "both")
    private val payloadSource = JComboBox(arrayOf("Automatic (recommended)", "My payloads only", "Automatic + my payloads"))
    private val customPayloads = JTextArea(8, 60)
    private val payloadFile = JTextField(30)

    private val runButton = UiKit.primary(JButton("Run suite"))
    @Volatile private var busy = false

    init {
        loadSettings()
        val tabs = JTabbedPane()
        tabs.addTab("Run", runTab())
        tabs.addTab("Results", resultsTab())
        tabs.addTab("Coverage", UiKit.scroll(coverage))
        tabs.addTab("Sessions & call controls", sessionsTab())
        tabs.addTab("Suite settings", settingsTab())
        add(tabs, BorderLayout.CENTER)
        add(JPanel(BorderLayout()).apply { status.preferredSize = Dimension(0, 30); add(status) }, BorderLayout.SOUTH)
        telemetry.onEvent { event ->
            if (event.type != "dc-case-result") return@onEvent
            val result = runCatching { Json.parseToJsonElement(event.raw).jsonObject["result"]?.let { Json { ignoreUnknownKeys = true }.decodeFromJsonElement(DcCaseResult.serializer(), it) } }.getOrNull()
                ?: return@onEvent
            SwingUtilities.invokeLater { addResult(result) }
        }
        results.onRun { run -> SwingUtilities.invokeLater { coverage.text = coverageText(run); status.text = summary(run) } }
        results.latest()?.let { run -> run.results.forEach(::addResult); coverage.text = coverageText(run) }
        UiKit.refreshWhileShowing(this) { refreshParticipants(); refreshRunning() }
    }

    // ---- tabs ----

    private fun runTab(): JComponent {
        runButton.addActionListener { runSuite() }
        val toolbar = UiKit.toolbar(
            UiKit.quiet(JButton("Check setup").apply { addActionListener { checkSetup() } }),
            JButton("Launch sessions").apply { addActionListener { background("Launching sessions") { launchAll() } } },
            JButton("Join calls").apply { addActionListener { background("Joining calls") { joinAll() } } },
            runButton,
            JButton("Stop").apply { addActionListener { runner.stop(); controller.cancelAll(); status.text = "Stop requested" } },
            UiKit.quiet(JButton("Close sessions").apply { addActionListener { background("Closing sessions") { browser.closeAll() } } }),
            UiKit.quiet(JButton("Export results JSON").apply { addActionListener { export() } }))
        val senderRow = JPanel(FlowLayout(FlowLayout.LEFT)).apply {
            add(JLabel("Sender:")); add(sender)
            add(HelpUi.button("Sender", "The page whose channel sends every test case. Automatic picks the lowest-privilege role in the main room (a customer), so authorization cases test what a customer can do to others. Every other page is an observer: it reports what it receives, renders or throws on.",
                "Customer browser sends; advisor browser and a separate test-room browser observe."))
            add(UiKit.quiet(JButton("Refresh pages").apply { addActionListener { refreshParticipants() } }))
        }
        val help = UiKit.note("Every case is sent once from the sender, then every instrumented page reports what it received, rendered or threw on. A case PASSES only with recipient-side evidence " +
            "(a delivered positive control and a delivery probe after it); a successful send() or silence is never a pass. Set Role and Room for pages you opened yourself; " +
            "runner sessions are labelled automatically. Reload pages after updating the extension so they run agent ${webrtc.BuildInfo.version}.")
        return JPanel(BorderLayout(0, 8)).apply {
            add(UiKit.stack(toolbar, help, senderRow), BorderLayout.NORTH)
            add(JSplitPane(JSplitPane.VERTICAL_SPLIT, UiKit.emptyTable(participantTable, "No instrumented pages", "Browse the app through Burp or launch runner sessions, then join a call."),
                JScrollPane(log)).apply { resizeWeight = 0.4 }, BorderLayout.CENTER)
        }
    }

    private fun resultsTab(): JComponent {
        resultTable.autoCreateRowSorter = true
        resultTable.selectionModel.addListSelectionListener {
            val row = resultTable.selectedRow.takeIf { it >= 0 }?.let(resultTable::convertRowIndexToModel) ?: return@addListSelectionListener
            detail.text = pretty.encodeToString(DcCaseResult.serializer(), resultRows[row])
            detail.caretPosition = 0
        }
        return JSplitPane(JSplitPane.VERTICAL_SPLIT, UiKit.emptyTable(resultTable, "No results yet", "Run the suite; each case appears here as soon as it is classified."),
            JScrollPane(detail)).apply { resizeWeight = 0.6 }
    }

    private fun sessionsTab(): JComponent {
        sessionTable.selectionModel.addListSelectionListener { if (!it.valueIsAdjusting) selectSession(sessionTable.selectedRow) }
        val roleEditor = JComboBox((Roles.ordered + "observer").toTypedArray()).apply { isEditable = true }
        sessionTable.columnModel.getColumn(1).cellEditor = DefaultCellEditor(roleEditor)
        sessionTable.columnModel.getColumn(2).cellEditor = DefaultCellEditor(JComboBox(arrayOf("main", "test")))
        val scripts = JPanel(GridLayout(0, 1, 0, 6))
        val help = mapOf(
            "join" to ("Join steps" to "How this session joins the call, one step per line: navigate, click, fill, wait, waitjs, eval, sleep, reload, offline, waitchannel. Selectors can cross iframes with >>>; prefix @<url text> to run inside a cross-origin frame."),
            "leave" to ("Leave steps" to "How this participant leaves the call without ending it for others."),
            "hangup" to ("Hang up steps" to "How the advisor ends the call for everyone (used to test that the customer is disconnected and cannot re-join)."),
            "remove" to ("Remove participant steps" to "How the advisor removes the customer (used to test that the removed customer loses and cannot regain access)."),
            "endpointExpr" to ("Endpoint expression" to "Optional JavaScript returning this participant's bridge endpoint ID when the agent cannot see it in a Colibri WebSocket URL."))
        val examples = mapOf(
            "join" to "navigate https://bank.example/meeting/{room}\nwait button#join-call\nclick button#join-call\nwaitchannel 30000",
            "leave" to "click iframe#video >>> button[aria-label='Leave']",
            "hangup" to "click button.end-meeting\nwait .meeting-ended",
            "remove" to "click .participant[data-role=customer] .menu\nclick .kick",
            "endpointExpr" to "APP.conference.getMyUserId()")
        scriptFields.forEach { (key, area) ->
            val (title, text) = help.getValue(key)
            scripts.add(JPanel(BorderLayout(6, 0)).apply {
                add(JLabel(title).apply { preferredSize = Dimension(160, 20) }, BorderLayout.WEST)
                add(JScrollPane(area), BorderLayout.CENTER)
                add(HelpUi.button(title, text, examples[key]), BorderLayout.EAST)
            })
        }
        val global = UiKit.form(
            "Browser path:" to withHelp(browserPath, "Browser path", "Chromium-based browser for runner sessions. Blank uses Burp's bundled Chromium, then Chrome, Edge or Chromium.", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
            "Burp proxy:" to withHelp(proxy, "Burp proxy", "Proxy listener the runner browsers use, so Burp injects the agent. Blank detects Burp's first proxy listener.", "127.0.0.1:8080"),
            "Main room:" to withHelp(mainRoom, "Main room", "Substituted for {room} / {mainRoom} in start URLs and steps for main-room sessions.", "advisor-meeting-1234"),
            "Test room:" to withHelp(testRoom, "Test room", "A separate meeting used only to observe isolation. Substituted for {room} / {testRoom} in test-room sessions.", "wrtc-isolation-room"),
            "Join timeout (s):" to joinTimeout,
            "" to JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply { add(headless); add(keepProfiles) })
        val buttons = UiKit.toolbar(
            JButton("Add session").apply { addActionListener { addSession(RunnerSession("session-${sessionModel.rowCount + 1}")) } },
            UiKit.quiet(JButton("Remove session").apply { addActionListener { removeSession() } }),
            UiKit.quiet(JButton("Insert advisor / customer / test-room example").apply { addActionListener { insertExample() } }),
            UiKit.primary(JButton("Save sessions").apply { addActionListener { saveSessions() } }),
            JButton("Launch selected").apply { addActionListener { selectedSessionName()?.let { name -> background("Launching $name") { saveSessionsQuiet(); browser.launch(store.config.browserRunner.sessions.first { it.name == name }) } } } },
            JButton("Run Join on selected").apply { addActionListener { selectedSessionName()?.let { name -> background("Joining $name") { browser.runSteps(name, "join") } } } })
        return UiKit.scroll(UiKit.stack(UiKit.section("Browser", global), buttons,
            JScrollPane(sessionTable).apply { preferredSize = Dimension(800, 150) },
            UiKit.section("Call controls for the selected session", scripts),
            UiKit.note("Runner sessions use isolated Chromium profiles routed through Burp, fake camera/microphone devices, and accept Burp's certificate. Start URLs and navigate steps must be allow-listed and in Burp Target scope.")))
    }

    private fun settingsTab(): JComponent {
        val familyPanel = JPanel(GridLayout(0, 2)).apply { families.values.forEach(::add) }
        val budgets = UiKit.form(
            "Maximum cases:" to withHelp(maxCases, "Maximum cases", "Total case budget across families; shares go to fuzzing (45%), authorization (20%), size boundaries (15%), transport (15%) and replay (5%). Cases not run are listed in Coverage."),
            "Bytes per message:" to withHelp(maxMessageBytes, "Bytes per message", "Hard cap per message (UTF-8 bytes for text). Larger size cases are BLOCKED, not sent.", "65536"),
            "Run byte budget (MiB):" to maxTotalMiB,
            "Run duration (s):" to maxDuration,
            "Settle window (ms):" to withHelp(settle, "Settle window", "Wait after each case before the next, so recipient receipts and errors are attributed to the right case."),
            "Receipt grace (ms):" to grace,
            "Probe every N cases:" to withHelp(probeEvery, "Probe every N cases", "A valid probe message follows every N cases. If a probe is not delivered, the runner waits for recovery and re-runs that group one case at a time to find the case that broke the session."),
            "Send buffer cap (bytes):" to maxBuffered,
            "Nesting bound:" to maxNesting,
            "Seed (0 = random):" to withHelp(seed, "Seed", "Seeds random payloads and mutation order. The seed used is recorded with every run so a run can be reproduced.", "1234"))
        val load = UiKit.form(
            "Rate steps (msg/s):" to withHelp(loadRates, "Rate steps", "Comma-separated message rates, each run for the step duration. The run stops at the first step that breaches a threshold.", "5, 10, 20"),
            "Step duration (s):" to loadSeconds,
            "Burst size:" to burst,
            "Churn channels (sequential):" to churnIterations,
            "Churn channels (concurrent):" to maxChannels,
            "Minimum delivery (%):" to minDelivery,
            "Maximum p95 latency (ms):" to maxLatency,
            "Maximum loss increase (%):" to maxLoss)
        val app = UiKit.form(
            "Jitsi version:" to withHelp(jitsiVersion, "Jitsi version", "Deployed Jitsi Videobridge version, used to choose message schemas. Blank detects it from ServerHello or observed message classes.", "2.3-105-ge155b81e"),
            "Probe template:" to withHelp(probeTemplate, "Probe template", "A valid application message containing {marker}. Blank uses a Colibri EndpointMessage broadcast for Jitsi, or the application's own observed JSON.", "{\"type\":\"chat\",\"text\":\"{marker}\"}"),
            "Test-room endpoint ID:" to withHelp(testRoomEndpoint, "Test-room endpoint ID", "Bridge endpoint ID of the test-room participant, if it cannot be detected automatically.", "a1b2c3d4"),
            "Re-join after hang-up:" to rejoinHangup,
            "Re-join after removal:" to rejoinRemoval,
            "" to expectDisconnect,
            "Bridge log file:" to withHelp(bridgeLog, "Bridge log file", "Optional local copy or mount of the bridge log (for example jvb.log). New error lines are attached to the run, and lines containing a case marker to that case.", "\\\\jvb-host\\logs\\jvb.log"),
            "Protected messages (JSON):" to withHelp(JScrollPane(protectedMessages), "Protected messages",
                "Application commands only some roles may send. The runner sends each from an allowed role (the state probe must change), restores state, then sends it from another role (the state must not change). Needs runner sessions.",
                "[{\"name\":\"mute participant\",\"template\":\"{\\\"colibriClass\\\":\\\"EndpointMessage\\\",\\\"to\\\":\\\"{to}\\\",\\\"msgPayload\\\":{\\\"type\\\":\\\"mute\\\",\\\"id\\\":\\\"{marker}\\\"}}\",\"allowedRoles\":[\"advisor\"],\"recipientRole\":\"customer\",\"stateProbe\":\"!!document.querySelector('.mic-muted')\",\"restore\":\"click .unmute\"}]"))
        val browse = UiKit.quiet(JButton("Browse…").apply { addActionListener {
            val chooser = JFileChooser()
            if (chooser.showOpenDialog(this@DataChannelRunnerPanel) == JFileChooser.APPROVE_OPTION) payloadFile.text = chooser.selectedFile.absolutePath
        } })
        fun syncPayloads() { val custom = payloadSource.selectedIndex > 0; customPayloads.isEnabled = custom; payloadFile.isEnabled = custom; browse.isEnabled = custom }
        payloadSource.addActionListener { syncPayloads() }
        syncPayloads()
        val payloads = UiKit.form(
            "Payloads:" to withHelp(payloadSource, "Message fuzzing payloads",
                "Automatic sends cases generated from the messages the app actually uses: one field changed at a time, malformed JSON, Unicode, overflow numbers and so on. My payloads sends only the list below. Automatic + my payloads sends your list first, then the generated cases. Size boundaries, authorization, replay and load are always generated.",
                "Start with Automatic. Add your own payloads when you have an application-specific idea to try."),
            "Your payloads (one per line):" to withHelp(JScrollPane(customPayloads), "Your payloads",
                "One payload per line, each sent once as its own case. Put {marker} anywhere in the text so recipients can report receiving, displaying or failing on it; without {marker} the line is sent byte-for-byte and matched by hash. Start a line with hex: or base64: to send binary. Lines starting with # are comments.",
                "{\"colibriClass\":\"EndpointMessage\",\"to\":\"\",\"msgPayload\":{\"type\":\"chat\",\"text\":\"<img src=x onerror=alert(1)> {marker}\"}}\n" +
                    "{\"type\":\"admin\",\"cmd\":\"promote\",\"id\":\"{marker}\"}\nhex:00 ff 7b 7d"),
            "Payload file:" to JPanel(BorderLayout(6, 0)).apply { add(payloadFile, BorderLayout.CENTER); add(browse, BorderLayout.EAST) })
        val buttons = UiKit.toolbar(UiKit.primary(JButton("Save settings").apply { addActionListener { saveSettings() } }),
            UiKit.quiet(JButton("Restore recommended defaults").apply { addActionListener { store.save(store.config.copy(dataChannelSuite = DcSuiteConfig())); loadSettings(); status.text = "Recommended suite defaults restored" } }))
        return UiKit.scroll(UiKit.stack(UiKit.section("Families", familyPanel), UiKit.section("Message fuzzing payloads", payloads), buttons, UiKit.section("Budgets", budgets),
            UiKit.disclosure("Load, churn and degradation thresholds", load), UiKit.disclosure("Application expectations", app),
            UiKit.note("Native SCTP / DCEP packet fuzzing is not part of this runner: browser JavaScript cannot craft SCTP chunks, fragmentation, stream resets or DCEP packets. " +
                "Coverage lists it as a separate DTLS/SCTP test-peer item (registry test DCH-04).")))
    }

    private fun withHelp(component: JComponent, title: String, plain: String, example: String? = null) = JPanel(BorderLayout(6, 0)).apply {
        add(component, BorderLayout.CENTER); add(HelpUi.button(title, plain, example), BorderLayout.EAST)
    }

    // ---- settings ----

    private fun loadSettings() {
        val s = store.config.dataChannelSuite
        families.forEach { (scope, box) -> box.isSelected = s.includes(scope) }
        maxCases.value = s.maxCases; maxMessageBytes.value = s.maxMessageBytes; maxTotalMiB.value = (s.maxTotalBytes / 1048576).coerceIn(1, 64)
        maxDuration.value = s.maxDurationSeconds; settle.value = s.settleMs; grace.value = s.receiptGraceMs; probeEvery.value = s.probeEvery
        maxBuffered.value = s.maxBufferedAmount; maxNesting.value = s.maxNesting; maxChannels.value = s.maxChannels; churnIterations.value = s.churnIterations
        loadRates.text = s.loadRates.joinToString(", "); loadSeconds.value = s.loadStepSeconds; burst.value = s.burstSize
        minDelivery.value = (s.minDeliveryRatio * 100).toInt(); maxLatency.value = s.maxP95LatencyMs; maxLoss.value = s.maxPacketLossIncreasePct
        seed.text = s.seed.toString(); jitsiVersion.text = s.jitsiVersion; probeTemplate.text = s.probeTemplate; testRoomEndpoint.text = s.testRoomEndpoint
        expectDisconnect.isSelected = s.expectDisconnectOnHangup; rejoinHangup.selectedItem = s.rejoinAfterHangup; rejoinRemoval.selectedItem = s.rejoinAfterRemoval
        bridgeLog.text = s.bridgeLogPath
        payloadSource.selectedIndex = payloadSources.indexOf(s.payloadSource).coerceAtLeast(0)
        customPayloads.text = s.customPayloads.joinToString("\n"); payloadFile.text = s.customPayloadFile
        protectedMessages.text = if (s.protectedMessages.isEmpty()) "[]" else pretty.encodeToString(ListSerializer(ProtectedMessage.serializer()), s.protectedMessages)
        val b = store.config.browserRunner
        browserPath.text = b.browserPath; proxy.text = b.proxy; headless.isSelected = b.headless; keepProfiles.isSelected = b.keepProfiles
        mainRoom.text = b.mainRoom; testRoom.text = b.testRoom; joinTimeout.value = b.joinTimeoutSeconds
        sessionModel.rowCount = 0; sessionScripts.clear(); editingSession = -1
        b.sessions.forEach(::addSession)
    }

    private fun suiteSettings(): DcSuiteConfig = DcSuiteConfig(
        families = families.filterValues { it.isSelected }.keys.map { it.id }.toSet(),
        maxCases = maxCases.value as Int, maxMessageBytes = maxMessageBytes.value as Int, maxTotalBytes = (maxTotalMiB.value as Int) * 1048576,
        maxDurationSeconds = maxDuration.value as Int, settleMs = settle.value as Int, receiptGraceMs = grace.value as Int, probeEvery = probeEvery.value as Int,
        maxBufferedAmount = maxBuffered.value as Int, maxNesting = maxNesting.value as Int, maxChannels = maxChannels.value as Int, churnIterations = churnIterations.value as Int,
        loadRates = loadRates.text.split(',', ' ').mapNotNull { it.trim().toIntOrNull() }, loadStepSeconds = loadSeconds.value as Int, burstSize = burst.value as Int,
        minDeliveryRatio = (minDelivery.value as Int) / 100.0, maxP95LatencyMs = maxLatency.value as Int, maxPacketLossIncreasePct = maxLoss.value as Double,
        seed = seed.text.trim().toLongOrNull() ?: 0, jitsiVersion = jitsiVersion.text.trim(), probeTemplate = probeTemplate.text.trim(),
        testRoomEndpoint = testRoomEndpoint.text.trim(), expectDisconnectOnHangup = expectDisconnect.isSelected,
        rejoinAfterHangup = rejoinHangup.selectedItem as String, rejoinAfterRemoval = rejoinRemoval.selectedItem as String, bridgeLogPath = bridgeLog.text.trim(),
        payloadSource = payloadSources[payloadSource.selectedIndex],
        customPayloads = customPayloads.text.lines().filter { it.isNotBlank() && !it.startsWith("#") },
        customPayloadFile = payloadFile.text.trim(),
        protectedMessages = protectedMessages.text.trim().ifBlank { "[]" }.let { Json.decodeFromString(ListSerializer(ProtectedMessage.serializer()), it) })

    private fun saveSettings() = runCatching {
        val settings = suiteSettings(); settings.validate()
        store.save(store.config.copy(dataChannelSuite = settings))
    }.onSuccess { status.text = "Suite settings saved for manual runs and Scan All" }
        .onFailure { JOptionPane.showMessageDialog(this, it.message, "Settings not saved", JOptionPane.ERROR_MESSAGE) }

    // ---- sessions ----

    private fun addSession(s: RunnerSession) {
        sessionModel.addRow(arrayOf(s.name, s.role, s.room, s.url, s.identity, if (browser.isRunning(s.name)) "yes" else ""))
        sessionScripts += mutableMapOf("join" to s.join, "leave" to s.leave, "hangup" to s.hangup, "remove" to s.remove, "endpointExpr" to s.endpointExpr)
    }

    private fun captureScripts() {
        if (editingSession in sessionScripts.indices) scriptFields.forEach { (key, area) -> sessionScripts[editingSession][key] = area.text }
    }

    private fun selectSession(row: Int) {
        captureScripts()
        editingSession = row
        scriptFields.forEach { (key, area) -> area.text = sessionScripts.getOrNull(row)?.get(key).orEmpty(); area.isEnabled = row >= 0 }
    }

    private fun removeSession() {
        val row = sessionTable.selectedRow.takeIf { it >= 0 } ?: return
        editingSession = -1
        sessionModel.removeRow(row); sessionScripts.removeAt(row)
    }

    private fun selectedSessionName(): String? = sessionTable.selectedRow.takeIf { it >= 0 }?.let { sessionModel.getValueAt(it, 0).toString() }

    private fun sessions(): List<RunnerSession> {
        captureScripts()
        if (sessionTable.isEditing) sessionTable.cellEditor.stopCellEditing()
        return (0 until sessionModel.rowCount).map { r ->
            val scripts = sessionScripts[r]
            RunnerSession(sessionModel.getValueAt(r, 0).toString().trim(), sessionModel.getValueAt(r, 1).toString().trim(), sessionModel.getValueAt(r, 2).toString(),
                sessionModel.getValueAt(r, 3).toString().trim(), sessionModel.getValueAt(r, 4).toString().trim(),
                scripts["join"].orEmpty(), scripts["leave"].orEmpty(), scripts["hangup"].orEmpty(), scripts["remove"].orEmpty(), scripts["endpointExpr"].orEmpty())
        }
    }

    private fun runnerSettings() = BrowserRunnerConfig(browserPath.text.trim(), proxy.text.trim(), headless.isSelected, keepProfiles.isSelected,
        mainRoom.text.trim(), testRoom.text.trim(), joinTimeout.value as Int, sessions())

    private fun saveSessionsQuiet() { val cfg = runnerSettings(); cfg.validate(); store.save(store.config.copy(browserRunner = cfg)) }

    private fun saveSessions() = runCatching { saveSessionsQuiet() }
        .onSuccess { status.text = "Sessions saved" }
        .onFailure { JOptionPane.showMessageDialog(this, it.message, "Sessions not saved", JOptionPane.ERROR_MESSAGE) }

    private fun insertExample() {
        listOf(
            RunnerSession("customer", "customer", "main", "https://bank.example/meeting/{room}", join = "wait button#join\nclick button#join\nwaitchannel 30000",
                leave = "click button#leave"),
            RunnerSession("advisor", "advisor", "main", "https://bank.example/advisor/meetings/{room}", join = "wait button#start\nclick button#start\nwaitchannel 30000",
                leave = "click button#leave", hangup = "click button#end-for-all", remove = "click .participant-customer .remove"),
            RunnerSession("isolation", "observer", "test", "https://bank.example/meeting/{room}", join = "wait button#join\nclick button#join\nwaitchannel 30000")
        ).filter { s -> (0 until sessionModel.rowCount).none { sessionModel.getValueAt(it, 0) == s.name } }.forEach(::addSession)
        status.text = "Example sessions added: replace the URLs, selectors and rooms with the application's, then Save sessions"
    }

    private fun refreshRunning() {
        for (r in 0 until sessionModel.rowCount) {
            val running = if (browser.isRunning(sessionModel.getValueAt(r, 0).toString())) "yes" else ""
            if (sessionModel.getValueAt(r, 5) != running) sessionModel.setValueAt(running, r, 5)
        }
    }

    // ---- participants ----

    private fun assignments(): Map<String, Pair<String, String>> {
        if (participantTable.isEditing) participantTable.cellEditor.stopCellEditing()
        return participantIds.indices.associate { r -> participantIds[r] to (participantModel.getValueAt(r, 2).toString() to participantModel.getValueAt(r, 3).toString()) }
    }

    private fun refreshParticipants() {
        if (busy || participantTable.isEditing) return
        val previous = assignments()
        val parts = runner.participants(DcSuiteRunner.Options(assignments = previous))
        participantModel.rowCount = 0; participantIds.clear()
        parts.forEach { p ->
            val targets = runner.targets(p.agentId).joinToString(", ") { "${it.transport} ${it.id} (${it.peerKind})" }
            participantIds += p.agentId
            participantModel.addRow(arrayOf<Any>("${p.agentId.takeLast(6)} ${p.frame.take(60)}", p.session, p.role, p.room, p.endpoint, targets.ifBlank { "none open" }))
        }
        val selected = sender.selectedIndex
        sender.removeAllItems(); sender.addItem("Automatic (lowest-privilege role)")
        parts.forEach { sender.addItem("${it.label} · ${it.agentId.takeLast(6)}") }
        if (selected in 0 until sender.itemCount) sender.selectedIndex = selected
        participantTable.columnModel.getColumn(2).cellEditor = DefaultCellEditor(JComboBox((listOf("") + Roles.ordered + "observer").toTypedArray()).apply { isEditable = true })
        participantTable.columnModel.getColumn(3).cellEditor = DefaultCellEditor(JComboBox(arrayOf("main", "test")))
    }

    // ---- actions ----

    private fun checkSetup() {
        val problems = mutableListOf<String>()
        runCatching { suiteSettings().validate() }.onFailure { problems += "Suite settings: ${it.message}" }
        problems += browser.check()
        val parts = runner.participants(DcSuiteRunner.Options(assignments = assignments()))
        if (parts.none { runner.targets(it.agentId).isNotEmpty() }) problems += "No instrumented page has an open DataChannel or Colibri WebSocket yet (join the call first)."
        if (parts.size < 2) problems += "Only ${parts.size} instrumented page(s): a second participant is needed to observe delivery."
        val text = if (problems.isEmpty()) "Setup looks ready. Browser: ${browser.browser()?.path}; proxy ${browser.proxy()}." else problems.joinToString("\n• ", "• ")
        JOptionPane.showMessageDialog(this, text, "Data channel runner setup", if (problems.isEmpty()) JOptionPane.INFORMATION_MESSAGE else JOptionPane.WARNING_MESSAGE)
    }

    private fun launchAll() {
        saveSessionsQuiet()
        store.config.browserRunner.sessions.forEach { s -> append("Launching ${s.name}…"); runCatching { browser.launch(s) }.onFailure { append("${s.name}: ${it.message}") } }
    }

    private fun joinAll() {
        // The advisor usually opens the meeting before the customer joins.
        store.config.browserRunner.sessions.sortedBy { if (it.role.equals("advisor", true)) 0 else 1 }.filter { browser.isRunning(it.name) && it.join.isNotBlank() }.forEach { s ->
            append("Joining ${s.name}…")
            runCatching { browser.runSteps(s.name, "join") }.onSuccess { append("${s.name} joined") }.onFailure { append("${s.name}: ${it.message}") }
        }
    }

    private fun runSuite() {
        val settings = runCatching { suiteSettings().also { it.validate() } }.getOrElse {
            JOptionPane.showMessageDialog(this, it.message, "Settings invalid", JOptionPane.ERROR_MESSAGE); return
        }
        store.save(store.config.copy(dataChannelSuite = settings))
        val chosen = sender.selectedIndex.takeIf { it > 0 }?.let { participantIds.getOrNull(it - 1) }
        val options = DcSuiteRunner.Options(sender = chosen, assignments = assignments())
        resultModel.rowCount = 0; resultRows.clear(); detail.text = ""; log.text = ""
        background("Running the DataChannel suite") {
            val run = runner.run(options) { append(it) }
            if (run != null) SwingUtilities.invokeLater { coverage.text = coverageText(run); status.text = summary(run) }
        }
    }

    private fun export() {
        val run = results.latest() ?: run { status.text = "No run to export yet"; return }
        val chooser = JFileChooser().apply { selectedFile = File("datachannel-run-${run.runId.take(8)}.json") }
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return
        runCatching { chooser.selectedFile.writeText(results.exportJson(run)) }
            .onSuccess { status.text = "Exported ${run.results.size} result(s) to ${chooser.selectedFile.name}" }
            .onFailure { JOptionPane.showMessageDialog(this, it.message, "Export failed", JOptionPane.ERROR_MESSAGE) }
    }

    private fun background(label: String, work: () -> Unit) {
        if (busy) { status.text = "Busy; wait or press Stop"; return }
        busy = true; runButton.isEnabled = false; status.text = "$label…"
        Thread({
            runCatching(work).onFailure { append("$label failed: ${it.message}") }
            SwingUtilities.invokeLater { busy = false; runButton.isEnabled = true; if (status.text == "$label…") status.text = "$label: done"; refreshParticipants() }
        }, "webrtc-dc-runner").apply { isDaemon = true }.start()
    }

    private fun append(line: String) = SwingUtilities.invokeLater { log.append(line + "\n"); log.caretPosition = log.document.length }

    private fun addResult(r: DcCaseResult) {
        resultRows += r
        resultModel.addRow(arrayOf(r.caseId, DcScope.byId(r.scope)?.title ?: r.scope, r.transport, r.verdict.label, r.title, r.reasons.firstOrNull().orEmpty()))
    }

    private fun summary(run: DcRun) = "Run ${run.runId.take(8)} (seed ${run.seed}): " + Verdict.entries.joinToString(" · ") { v -> "${v.label} ${run.results.count { it.verdict == v }}" } +
        if (run.stopReason.isNotBlank()) " — stopped: ${run.stopReason}" else ""

    private fun coverageText(run: DcRun) = "Run ${run.runId} · seed ${run.seed} · sender ${run.sender} via ${run.transport} · ${run.schema}\n" +
        "Participants: ${run.participants.joinToString("; ") { it.label }}\n\n" + DcCoverage.text(run.coverage) +
        (if (run.notes.isNotEmpty()) "\n\nNotes:\n" + run.notes.joinToString("\n") { "  $it" } else "")
}
