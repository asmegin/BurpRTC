package webrtc.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import webrtc.authz.AuthzMatrixRunner
import webrtc.bridge.ActiveTestController
import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryTableModel
import webrtc.workflow.RunAllController
import webrtc.workflow.SignalingMetadata
import webrtc.tls.TlsScanRunner
import javax.swing.JTabbedPane
import javax.swing.SwingUtilities

/** The single Burp suite tab. All modules M0–M7 are wired. */
class SuiteTab(
    api: MontoyaApi,
    configStore: ConfigStore,
    telemetry: TelemetryTableModel,
    private val runner: AuthzMatrixRunner,
    activeTests: ActiveTestController,
    tlsRunner: TlsScanRunner,
    assessments: webrtc.assessment.AssessmentController,
    onConfigSaved: () -> Unit
) : JTabbedPane() {

    private val authzPanel = AuthzPanel(api)

    init {
        val orchestrator = RunAllController(configStore, activeTests, telemetry, tlsRunner, signalingEndpoints = {
            SignalingMetadata.collectFromProxy(api, configStore.config.hostAllowList)
        }, authzResults = { authzPanel.model.snapshot() }, assessments = assessments)
        addTab("Run All", RunAllPanel(orchestrator))
        addTab("Config (M0)", ConfigPanel(api, configStore, onConfigSaved))
        addTab("Telemetry (M2)", TelemetryPanel(telemetry, activeTests))
        addTab("Authz Matrix (M5)", authzPanel)
        addTab("SDP Mutation (M3)", SdpMutationPanel(configStore, telemetry))
        addTab("SDP Fuzz (M3+)", SdpFuzzPanel(configStore, activeTests, telemetry))
        addTab("DataChannel Fuzz (M4)", DataChannelFuzzPanel(configStore, activeTests, telemetry))
        addTab("TURN/STUN (M6)", IceProbePanel(configStore, activeTests, telemetry))
        addTab("Local negotiation loop (T8)", SignalingFloodPanel(configStore, activeTests, telemetry))
        addTab("Assessment tests", AssessmentPanel(configStore, assessments))
        addTab("External Tests", ExternalTestsPanel(configStore, telemetry))
        addTab("TLS Tests", TlsScanPanel(configStore, telemetry, tlsRunner))
        addTab("Findings (M7)", FindingsPanel(orchestrator, configStore, telemetry, authzPanel.model, assessments.store))
    }

    /** Called from the context menu; runs each baseline off the EDT. */
    fun runAuthz(selected: List<HttpRequestResponse>) {
        SwingUtilities.invokeLater { selectedComponent = authzPanel }
        Thread({
            for (rr in selected) {
                runCatching { runner.run(rr) { res -> authzPanel.addResult(res) } }
            }
        }, "webrtc-authz-runner").start()
    }
}
