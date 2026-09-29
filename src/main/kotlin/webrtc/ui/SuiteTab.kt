package webrtc.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import webrtc.authz.AuthzMatrixRunner
import webrtc.bridge.ActiveTestController
import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryTableModel
import webrtc.workflow.RunAllController
import webrtc.workflow.SignalingMetadata
import javax.swing.JTabbedPane
import javax.swing.SwingUtilities

/** The single Burp suite tab. All modules M0–M7 are wired. */
class SuiteTab(
    api: MontoyaApi,
    configStore: ConfigStore,
    telemetry: TelemetryTableModel,
    private val runner: AuthzMatrixRunner,
    activeTests: ActiveTestController,
    onConfigSaved: () -> Unit
) : JTabbedPane() {

    private val authzPanel = AuthzPanel(api)

    init {
        val orchestrator = RunAllController(configStore, activeTests, telemetry) {
            SignalingMetadata.collectFromProxy(api, configStore.config.hostAllowList)
        }
        addTab("Run All", RunAllPanel(orchestrator))
        addTab("Config (M0)", ConfigPanel(api, configStore, onConfigSaved))
        addTab("Telemetry (M2)", TelemetryPanel(telemetry, activeTests))
        addTab("Authz Matrix (M5)", authzPanel)
        addTab("SDP Mutation (M3)", SdpMutationPanel(configStore, telemetry))
        addTab("SDP Fuzz (M3+)", SdpFuzzPanel(configStore, activeTests, telemetry))
        addTab("DataChannel Fuzz (M4)", DataChannelFuzzPanel(configStore, activeTests, telemetry))
        addTab("TURN/STUN (M6)", IceProbePanel(configStore, activeTests, telemetry))
        addTab("Signaling Flood (T8)", SignalingFloodPanel(configStore, activeTests, telemetry))
        addTab("External Tests", ExternalTestsPanel(configStore, telemetry))
        addTab("Findings (M7)", FindingsPanel(orchestrator, configStore, telemetry, authzPanel.model))
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
