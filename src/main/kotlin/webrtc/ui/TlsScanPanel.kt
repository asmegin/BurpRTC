package webrtc.ui

import webrtc.config.ConfigStore
import webrtc.external.ExternalInputs
import webrtc.telemetry.TelemetryTableModel
import webrtc.tls.TlsScanConfig
import webrtc.tls.TlsScanRunner
import webrtc.tls.TlsTarget
import java.awt.BorderLayout
import java.awt.GridLayout
import javax.swing.*

/** All target traffic comes from the selected TLS listener, not from observed relay candidates. */
class TlsScanPanel(
    private val store: ConfigStore,
    private val telemetry: TelemetryTableModel,
    private val runner: TlsScanRunner
) : JPanel(BorderLayout()) {
    private val python = JTextField(store.config.tlsScan.pythonExecutable)
    private val endpoint = JComboBox<String>().apply { isEditable = true; editor.item = store.config.tlsScan.endpoint }
    private val timeout = JSpinner(SpinnerNumberModel(store.config.tlsScan.timeoutSeconds.coerceIn(15, 300), 15, 300, 15))
    private val vulnerabilities = JCheckBox("Include Heartbleed, CCS, ROBOT and renegotiation probes", store.config.tlsScan.vulnerabilityChecks)
    private val runAll = JCheckBox("Include this selected TLS endpoint in Run All", store.config.tlsScan.includeInRunAll)
    private val scope = JLabel("Scope URL: enter a TLS endpoint")
    private val status = JLabel("Python 3.10+ required. Setup installs SSLyze into a managed environment.")
    private val output = SearchableTextPane(wrap = true)
    private val actions = mutableListOf<JButton>()

    init {
        val fields = JPanel(GridLayout(0, 2, 8, 4)).apply {
            add(JLabel("Python executable:")); add(python)
            add(JLabel("TLS endpoint:")); add(endpoint)
            add(JLabel("Scan timeout (seconds):")); add(timeout)
        }
        val settings = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(JLabel("TLS over TCP: HTTPS/WSS signaling or a turns: listener. Media DTLS/SRTP uses separate tests."))
            add(fields); add(scope); add(vulnerabilities); add(runAll)
            add(JLabel("One selected host/port; Burp Target scope + allow-list + injection must permit it. TURN allocation stays in M6."))
            add(JPanel().apply {
                fun button(label: String, action: () -> Unit) = JButton(label).also { it.addActionListener { action() }; add(it) }
                button("Refresh observed endpoints") { refresh() }
                button("Save settings") { runCatching { save() }.onSuccess { status.text = "TLS settings saved" }.onFailure { status.text = it.message } }
                actions += button("Setup TLS runner") { background { cfg -> runner.setup(cfg) { append(it) } } }
                actions += button("Check runtime") { background { runner.check(it) } }
                actions += button("Run TLS tests") { background { runner.scan(it) } }
                button("Stop") { runner.stop(); status.text = "Stopping TLS task…" }
            })
            add(status)
        }
        endpoint.addActionListener { updateScope() }
        add(settings, BorderLayout.NORTH)
        add(JSplitPane(JSplitPane.VERTICAL_SPLIT, output,
            TestResultsPanel(telemetry, "tls-runtime|tls-scan-start|tls-scan-result|tls-scan-error", "TLS")).apply { resizeWeight = 0.25 }, BorderLayout.CENTER)
        refresh()
    }

    private fun config(): TlsScanConfig = TlsScanConfig(python.text.trim(), endpoint.editor.item?.toString().orEmpty().trim(),
        (timeout.value as Number).toInt(), vulnerabilities.isSelected, runAll.isSelected)
    private fun save(): TlsScanConfig = config().also { it.validate(); store.save(store.config.copy(tlsScan = it)); updateScope() }
    private fun updateScope() {
        scope.text = runCatching { "Scope URL: ${TlsTarget.parse(endpoint.editor.item?.toString().orEmpty()).scopeUrl}" }
            .getOrElse { "Scope URL: ${it.message}" }
    }
    private fun refresh() {
        val selected = endpoint.editor.item?.toString().orEmpty()
        val inputs = ExternalInputs.detect(store.config, telemetry.snapshot())
        val targets = (inputs.pageOrigins.map { it.substringBefore('#') } + inputs.iceServers.flatMap { it.urls })
            .filter { runCatching { TlsTarget.parse(it) }.isSuccess }.distinct()
        endpoint.removeAllItems(); targets.forEach { endpoint.addItem(it) }; endpoint.editor.item = selected
        updateScope()
    }
    private fun append(text: String) = SwingUtilities.invokeLater { output.text = output.text + text + "\n" }
    private fun background(action: (TlsScanConfig) -> TlsScanRunner.Outcome) {
        val cfg = runCatching { save() }.getOrElse { status.text = it.message; return }
        if (runner.isBusy()) { status.text = "Another TLS task is active; stop it or wait"; return }
        actions.forEach { it.isEnabled = false }; status.text = "TLS task running…"; output.text = ""
        Thread({
            val result = runCatching { action(cfg) }.getOrElse { TlsScanRunner.Outcome("failed", it.message.orEmpty()) }
            append(result.detail)
            SwingUtilities.invokeLater { status.text = result.detail; actions.forEach { it.isEnabled = true } }
        }, "webrtc-tls-runner").apply { isDaemon = true; start() }
    }
}
