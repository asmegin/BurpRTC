package webrtc

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import webrtc.authz.AuthzMatrixRunner
import webrtc.bridge.BridgeServer
import webrtc.bridge.ActiveTestController
import webrtc.config.ConfigStore
import webrtc.inject.InjectorHandler
import webrtc.scope.ScopeGate
import webrtc.telemetry.TelemetryTableModel
import webrtc.ui.AuthzContextMenu
import webrtc.ui.SuiteTab
import webrtc.tls.TlsScanRunner
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class WebRtcExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName(BuildInfo.NAME)

        val configStore = ConfigStore(api)
        val scope = ScopeGate(api)
        val telemetry = TelemetryTableModel()
        val activeTests = ActiveTestController(configStore, scope::inScope, telemetry)
        val bridge = BridgeServer(api, configStore, telemetry, activeTests)
        val runner = AuthzMatrixRunner(api, configStore, scope)
        val tlsRunner = TlsScanRunner(configStore, scope::inScope, telemetry)
        val outcomeStore = webrtc.assessment.OutcomeStore(api, telemetry) { configStore.config.assessment.engagementId }
        val protocolRunner = webrtc.protocol.ProtocolRunner(configStore, webrtc.assessment.NetworkAuthorization(configStore, scope::inScope),
            outcomeStore, webrtc.protocol.BurpScenarioTransport(api))
        val assessments = webrtc.assessment.AssessmentController(configStore, outcomeStore, protocolRunner, telemetry)

        // Burp-native integration: Collaborator-backed canaries and deduplicated issues.
        val data = api.persistence().extensionData()
        val collaborator = webrtc.burp.BurpCollaborator(api, { data.getString("webrtc.collaborator.v1") }, { data.setString("webrtc.collaborator.v1", it) })
        val canaries = webrtc.canary.CanaryRegistry({ data.getString("webrtc.canaries.v1") }, { data.setString("webrtc.canaries.v1", it) }, telemetry) {
            collaborator.takeIf { it.available() }
        }
        // DataChannel runner: integrated browser sessions, case execution and persisted results.
        val browserRunner = webrtc.datachannel.BrowserRunner(configStore, activeTests, telemetry, api)
        val dcResults = webrtc.datachannel.DcResultStore(telemetry, { data.getString("webrtc.dcsuite.runs.v1") }, { data.setString("webrtc.dcsuite.runs.v1", it) },
            { outcomeStore }, { configStore.config.assessment.engagementId })
        val dcRunner = webrtc.datachannel.DcSuiteRunner(configStore, activeTests, telemetry, dcResults, browserRunner)
        val issues = webrtc.burp.IssueReporter({ api.siteMap().add(webrtc.burp.IssueReporter.toAuditIssue(it)) }, configStore, telemetry).also { it.attach() }
        runCatching { api.intruder().registerPayloadGeneratorProvider(webrtc.burp.CanaryPayloadGeneratorProvider(canaries)) }
            .onFailure { api.logging().logToError("[canary] Intruder payload generator unavailable: ${it.message}") }

        val capture = webrtc.workflow.RtcCapture(configStore, scope, telemetry)
        val requests = webrtc.workflow.RequestCatalog()
        val sessions = webrtc.authz.SessionCatalog(configStore, scope)
        val links = webrtc.authz.LinkCatalogs(configStore, scope)
        val linkTester = webrtc.authz.LinkTester(api, configStore, scope)
        capture.sessions = sessions
        capture.canaries = canaries
        api.websockets().registerWebSocketCreatedHandler(capture)
        api.http().registerHttpHandler(InjectorHandler(api, configStore, scope, requests = requests, capture = capture, sessions = sessions,
            links = links, canaries = canaries))

        val suiteTab = SuiteTab(api, configStore, telemetry, runner, activeTests, tlsRunner, assessments, requests, sessions,
            links, linkTester, canaries, issues, { collaborator.available() }, dcRunner, browserRunner, dcResults) { tlsRunner.stop(); protocolRunner.stop(); bridge.restart() }
        api.userInterface().registerContextMenuItemsProvider(
            AuthzContextMenu(suiteTab::runAuthz, suiteTab::stageAuthz)
        )
        api.userInterface().registerSuiteTab("WebRTC", suiteTab)

        // Poll Collaborator only while out-of-band canaries exist.
        val poller = Executors.newSingleThreadScheduledExecutor { Thread(it, "webrtc-collaborator-poll").apply { isDaemon = true } }
        poller.scheduleWithFixedDelay({
            runCatching { if (canaries.all().any { it.collaborator.isNotBlank() }) canaries.pollOutOfBand() }
        }, 15, 15, TimeUnit.SECONDS)

        bridge.start()
        api.extension().registerUnloadingHandler {
            poller.shutdownNow(); suiteTab.stopAuthz(); dcRunner.stop(); browserRunner.closeAll(); tlsRunner.close(); protocolRunner.close(); bridge.stop()
        }

        api.logging().logToOutput(BuildInfo.loadedMessage())
    }
}
