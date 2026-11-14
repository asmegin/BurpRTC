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
    private val vulnerabilities = JCheckBox("SSLyze only: include Heartbleed, CCS, ROBOT and renegotiation probes", store.config.tlsScan.vulnerabilityChecks)
    private val engine = JComboBox(arrayOf("Built-in (no install)", "SSLyze (optional Python)")).apply {
        selectedIndex = if (store.config.tlsScan.engine == "sslyze") 1 else 0
    }
    private val scope = JLabel("Scope URL: enter a TLS endpoint")
    private val status = JLabel("The built-in engine runs inside Burp. SSLyze is optional and needs Python 3.10+.")
    private val output = SearchableTextPane(wrap = true)
    private val actions = mutableListOf<JButton>()
    private var savedPython = store.config.tlsScan.pythonExecutable

    init {
        fun button(label: String, action: () -> Unit) = JButton(label).also { it.addActionListener { action() } }
        val setup = button("Setup SSLyze") { background { cfg -> runner.setup(cfg) { append(it) } } }
        val check = button("Check runtime") { background { runner.check(it) } }
        val run = UiKit.primary(button("Run TLS tests") { background { runner.scan(it) } })
        actions += listOf(setup, check, run)
        val buttons = UiKit.toolbar(run, button("Stop") { runner.stop(); status.text = "Stopping TLS task…" },
            button("Save settings") { runCatching { save() }.onSuccess { status.text = "TLS settings saved" }.onFailure { status.text = it.message } },
            UiKit.quiet(button("Refresh endpoints") { refresh() }))
        val settings = UiKit.stack(
            UiKit.section("TLS listener", UiKit.stack(UiKit.form("Endpoint:" to endpoint, "Engine:" to engine), scope,
                UiKit.note("Use https://host, wss://host, or turns:host:5349. The endpoint must pass injection, allow-list, and Burp Target scope checks. The built-in engine checks SSL 3.0 to TLS 1.3, TLS 1.2 cipher suites and the certificate with no install."))),
            UiKit.disclosure("Advanced scan options", UiKit.stack(UiKit.form("Timeout (seconds):" to timeout), vulnerabilities)),
            UiKit.disclosure("Optional SSLyze engine · Python setup", UiKit.stack(
                UiKit.note("Only needed for the SSLyze engine (SSL 2.0, compression, renegotiation and vulnerability probes). Python 3.10+ is required; Setup installs SSLyze into the extension's managed environment."),
                UiKit.form("Python executable:" to python), UiKit.toolbar(setup, check))))
        endpoint.addActionListener { updateScope() }
        output.text = "TLS output will appear here.\n\nChoose a listener above and click Run TLS tests. The built-in engine needs no setup."
        val tabs = JTabbedPane().apply {
            addTab("Runner output", output)
            addTab("Scan evidence", TestResultsPanel(telemetry, "tls-runtime|tls-scan-start|tls-scan-result|tls-scan-error", "TLS"))
        }
        val controls = JPanel(BorderLayout()).apply {
            preferredSize = java.awt.Dimension(800, 415)
            add(UiKit.scroll(JPanel(BorderLayout()).apply { add(settings, BorderLayout.NORTH) }), BorderLayout.CENTER)
            add(buttons, BorderLayout.SOUTH)
        }
        add(JSplitPane(JSplitPane.VERTICAL_SPLIT, controls, tabs).apply { resizeWeight = 0.35; dividerLocation = 415 }, BorderLayout.CENTER)
        status.preferredSize = java.awt.Dimension(0, 30); status.putClientProperty("webrtc.role", "muted")
        add(status, BorderLayout.SOUTH)
        refresh()
        store.onChange { cfg -> SwingUtilities.invokeLater {
            if (savedPython != cfg.tlsScan.pythonExecutable) { savedPython = cfg.tlsScan.pythonExecutable; python.text = savedPython }
        } }
    }

    private fun config(): TlsScanConfig = TlsScanConfig(python.text.trim(), endpoint.editor.item?.toString().orEmpty().trim(),
        (timeout.value as Number).toInt(), vulnerabilities.isSelected, store.config.tlsScan.includeInRunAll,
        if (engine.selectedIndex == 1) "sslyze" else "builtin")
    private fun save(): TlsScanConfig = config().also { it.validate(); store.save(store.config.copy(tlsScan = it)); updateScope() }
    private fun updateScope() {
        if (endpoint.editor.item?.toString().isNullOrBlank()) { scope.text = "Scope URL: enter a TLS endpoint"; return }
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
            try {
                val result = runCatching { action(cfg) }.getOrElse { UiKit.logError(it); TlsScanRunner.Outcome("failed", it.message.orEmpty()) }
                append(result.detail)
                SwingUtilities.invokeLater { status.text = result.detail }
            } finally {
                SwingUtilities.invokeLater { actions.forEach { it.isEnabled = true } }
            }
        }, "webrtc-tls-runner").apply { isDaemon = true; start() }
    }
}
