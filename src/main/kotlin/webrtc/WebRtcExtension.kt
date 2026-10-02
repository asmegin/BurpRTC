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

        api.http().registerHttpHandler(InjectorHandler(api, configStore, scope))

        val suiteTab = SuiteTab(api, configStore, telemetry, runner, activeTests, tlsRunner) { tlsRunner.stop(); bridge.restart() }
        api.userInterface().registerContextMenuItemsProvider(
            AuthzContextMenu { selected -> suiteTab.runAuthz(selected) }
        )
        api.userInterface().registerSuiteTab("WebRTC", suiteTab)

        bridge.start()
        api.extension().registerUnloadingHandler { tlsRunner.close(); bridge.stop() }

        api.logging().logToOutput(BuildInfo.loadedMessage())
    }
}
