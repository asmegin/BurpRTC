package webrtc.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import webrtc.authz.AuthzMatrixRunner
import webrtc.bridge.ActiveTestController
import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryTableModel
import webrtc.workflow.RunAllController
import webrtc.workflow.SignalingMetadata
import webrtc.workflow.RequestCatalog
import webrtc.tls.TlsScanRunner
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.event.ActionEvent
import javax.swing.*

/** The single Burp suite tab. All modules M0–M7 are wired. */
class SuiteTab(
    api: MontoyaApi,
    private val configStore: ConfigStore,
    telemetry: TelemetryTableModel,
    private val runner: AuthzMatrixRunner,
    activeTests: ActiveTestController,
    tlsRunner: TlsScanRunner,
    assessments: webrtc.assessment.AssessmentController,
    requests: RequestCatalog,
    sessions: webrtc.authz.SessionCatalog = webrtc.authz.SessionCatalog(configStore, webrtc.scope.ScopeGate(api)),
    links: webrtc.authz.LinkCatalogs? = null,
    linkTester: webrtc.authz.LinkTester? = null,
    canaries: webrtc.canary.CanaryRegistry? = null,
    private val issues: webrtc.burp.IssueReporter? = null,
    collaboratorAvailable: () -> Boolean = { false },
    dcRunner: webrtc.datachannel.DcSuiteRunner? = null,
    browserRunner: webrtc.datachannel.BrowserRunner? = null,
    dcResults: webrtc.datachannel.DcResultStore? = null,
    onConfigSaved: () -> Unit
) : JPanel(BorderLayout()) {

    private val authzPanel = AuthzPanel(api, configStore, sessions, runner, links, linkTester) { issues?.reportAuthz(it) }
    private val cards = JPanel(CardLayout())
    private val factories = linkedMapOf<String, () -> JComponent>()
    private val screens = linkedMapOf<String, JComponent>()
    private val navigation = linkedMapOf<String, JButton>()
    var selectedScreenId: String = "scan"
        private set

    init {
        val orchestrator = RunAllController(configStore, activeTests, telemetry, tlsRunner, signalingEndpoints = {
            SignalingMetadata.collectFromProxy(api, configStore.config.hostAllowList)
        }, authzResults = { authzPanel.model.snapshot() }, assessments = assessments,
            automaticAuthz = { continueRun, emit ->
                var count = 0
                val selectedSessions = sessions.selection().filter { webrtc.authz.AuthTokens.hasCredentials(it.identity) }.take(8)
                val baselines = if (selectedSessions.isEmpty()) requests.recent().map { null to it }
                    else selectedSessions.flatMap { session -> session.requests.map { session to it } }.take(5)
                for ((owner, request) in baselines) {
                    if (!continueRun()) break
                    var replayed = false
                    val selected = authzPanel.selectedIdentities().filter { owner == null || it.name != owner.identity.name }
                    runCatching { runner.run(request, selected.ifEmpty { configStore.config.identities }, owner?.label ?: "Scan All captured request", continueRun, true,
                        ownerProfile = owner?.identity) { result ->
                        if (result.variant == "baseline") replayed = true
                        authzPanel.addResult(result); emit(result)
                    } }
                        .onFailure { emit(webrtc.authz.AuthzResult(request.url(), "ERROR", 0, 0, "", false, false, it.message.orEmpty(), null)) }
                    if (replayed) count++
                }
                count
            },
            automaticInvites = { continueRun, emit -> authzPanel.runInvites(continueRun, emit) },
            automaticArtifacts = { continueRun, emit -> authzPanel.runArtifacts(continueRun, emit) },
            dataChannelRunner = dcRunner)
        val navList = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS); putClientProperty("webrtc.role", "canvas") }
        fun group(title: String) {
            navList.add(Box.createVerticalStrut(16))
            navList.add(JLabel(title.uppercase()).apply {
                putClientProperty("webrtc.role", "muted")
                border = BorderFactory.createEmptyBorder(0, 12, 6, 0)
            })
        }
        fun screen(id: String, title: String, description: String, factory: () -> JComponent) {
            factories[id] = {
                JPanel(BorderLayout()).apply {
                    putClientProperty("webrtc.role", "canvas")
                    border = BorderFactory.createEmptyBorder(22, 24, 20, 24)
                    add(UiKit.header(title, description), BorderLayout.NORTH)
                    add(factory(), BorderLayout.CENTER)
                    api.userInterface().applyThemeToComponent(this)
                    UiKit.style(this)
                }
            }
            val button = JButton(title).apply {
                putClientProperty("webrtc.role", "nav")
                horizontalAlignment = SwingConstants.LEFT
                alignmentX = LEFT_ALIGNMENT
                maximumSize = Dimension(Int.MAX_VALUE, 38)
                toolTipText = description
                addActionListener { navigate(id) }
            }
            navigation[id] = button
            navList.add(button); navList.add(Box.createVerticalStrut(3))
        }
        group("Workspace")
        screen("scan", "Scan All", "Choose what to run. Your selection is saved, with every scan enabled by default.") { RunAllPanel(orchestrator, configStore) }
        screen("setup", "Setup", "Enable the browser agent, choose allowed hosts, and configure your test identities.") { ConfigPanel(api, configStore, onConfigSaved) }
        screen("evidence", "Evidence", "Browse captured events and inspect their full details. Filter by URL, type, or content.") { TelemetryPanel(telemetry, activeTests) }
        screen("report", "Report", "Build and export a report from captured evidence and completed tests.") { FindingsPanel(orchestrator, configStore, telemetry, authzPanel.model, assessments.store) }
        group("Tests")
        screen("security", "Security checks", "Review captured evidence and run STUN / TURN and scenario checks with the built-in runners.") { AssessmentPanel(configStore, assessments) }
        screen("tls", "TLS tests", "Check the certificates, protocols, and ciphers of a selected HTTPS, WSS, or TURN TLS listener.") { TlsScanPanel(configStore, telemetry, tlsRunner) }
        screen("access", "Access control", "Capture sessions, set customer / advisor roles, compare access, and test meeting links, documents and recordings.") { authzPanel }
        if (canaries != null) screen("canaries", "XSS canaries", "Place self-reporting canaries in chat, names and file names to prove stored XSS in the advisor or customer view.") {
            CanaryPanel(configStore, canaries, activeTests, telemetry, collaboratorAvailable)
        }
        screen("mutation", "SDP rules", "Apply saved rules to descriptions in the live page and compare the original and changed SDP.") { SdpMutationPanel(configStore, telemetry) }
        screen("sdp", "SDP fuzzing", "Try bounded malformed descriptions on throwaway peer connections in the selected page.") { SdpFuzzPanel(configStore, activeTests, telemetry) }
        screen("data", "Data channels", "Send bounded test payloads through a live data channel and inspect the results.") { DataChannelFuzzPanel(configStore, activeTests, telemetry) }
        if (dcRunner != null && browserRunner != null && dcResults != null)
            screen("dcrunner", "Data channel runner", "Run paired-session DataChannel tests: discovery, Colibri message fuzzing, size boundaries, authorization, replay, load and transport comparison, verified at the recipients.") {
                DataChannelRunnerPanel(configStore, activeTests, dcRunner, browserRunner, dcResults, telemetry)
            }
        screen("ice", "STUN & TURN", "Gather ICE candidates in the selected page using a specific server or host candidates only.") { IceProbePanel(configStore, activeTests, telemetry) }
        screen("loop", "Negotiation loop", "Run a bounded offer / answer loop on local throwaway peer connections.") { SignalingFloodPanel(configStore, activeTests, telemetry) }
        group("Tools")
        screen("external", "External commands", "Generate editable Linux / Bash commands to copy and run in your own terminal.") { ExternalTestsPanel(configStore, telemetry) }

        val injectionStatus = JLabel().apply { putClientProperty("webrtc.role", "muted") }
        fun updateStatus() { injectionStatus.text = if (configStore.config.injectionEnabled) "●  Browser agent enabled" else "○  Browser agent disabled" }
        updateStatus()
        configStore.onChange { SwingUtilities.invokeLater { updateStatus() } }
        val sidebar = JPanel(BorderLayout()).apply {
            putClientProperty("webrtc.role", "canvas")
            border = BorderFactory.createEmptyBorder(22, 12, 16, 12)
            preferredSize = Dimension(215, 0)
            add(JPanel(BorderLayout(0, 3)).apply {
                putClientProperty("webrtc.role", "canvas")
                border = BorderFactory.createEmptyBorder(0, 10, 2, 0)
                add(JLabel("WebRTC").apply { putClientProperty("webrtc.role", "heading") }, BorderLayout.NORTH)
                add(JLabel("Testing workspace").apply { putClientProperty("webrtc.role", "muted") }, BorderLayout.SOUTH)
            }, BorderLayout.NORTH)
            add(UiKit.scroll(navList), BorderLayout.CENTER)
            add(JPanel(BorderLayout(0, 5)).apply {
                putClientProperty("webrtc.role", "canvas")
                border = BorderFactory.createEmptyBorder(8, 8, 0, 0)
                add(injectionStatus, BorderLayout.NORTH)
                add(JLabel("v${webrtc.BuildInfo.version}").apply { putClientProperty("webrtc.role", "muted") }, BorderLayout.SOUTH)
            }, BorderLayout.SOUTH)
        }
        add(sidebar, BorderLayout.WEST); add(cards, BorderLayout.CENTER)
        api.userInterface().applyThemeToComponent(this)
        UiKit.style(this)
        (sidebar.getComponent(1) as? JScrollPane)?.border = BorderFactory.createEmptyBorder()
        listOf("scan", "setup", "evidence", "report").forEachIndexed { index, id ->
            val action = "navigate-$id"
            getInputMap(WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke("control ${index + 1}"), action)
            actionMap.put(action, object : AbstractAction() { override fun actionPerformed(e: ActionEvent) { navigate(id) } })
        }
        navigate("scan")
    }

    /** Screens are created once on first use, preserving edits and results when navigating. */
    fun navigate(id: String) {
        val factory = factories[id] ?: return
        if (!screens.containsKey(id)) { val screen = factory(); screens[id] = screen; cards.add(screen, id) }
        selectedScreenId = id
        (cards.layout as CardLayout).show(cards, id)
        navigation.forEach { (key, button) -> button.isSelected = key == id }
        revalidate(); repaint()
    }

    /** Called from the context menu; runs each baseline off the EDT. */
    fun runAuthz(selected: List<HttpRequestResponse>) {
        SwingUtilities.invokeLater { navigate("access") }
        Thread({
            for (rr in selected) {
                val identities = authzPanel.selectedIdentities()
                runCatching { runner.run(rr.request(), identities.ifEmpty { configStore.config.identities }, "Burp selected request", { true }, true) { res -> authzPanel.addResult(res) } }
                    .onFailure { authzPanel.addResult(webrtc.authz.AuthzResult(rr.request().url(), "ERROR", 0, 0, "", false, false, it.message.orEmpty(), null)) }
            }
        }, "webrtc-authz-runner").start()
    }

    fun stageAuthz(selected: List<HttpRequestResponse>) {
        SwingUtilities.invokeLater { authzPanel.stage(selected); navigate("access") }
    }
    fun stopAuthz() = authzPanel.stopComparison()
}
