package webrtc.ui

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import webrtc.config.ConfigStore
import webrtc.config.IdentityProfile
import webrtc.config.WebRtcConfig
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.io.File
import javax.swing.*

/**
 * M0 view — all engagement-specific config. Nothing is seeded.
 *
 * The panel is split into a small **Basic** section (the few things a tester
 * must set) and a collapsed **Advanced** section that is auto-configured with
 * working defaults; advanced users can reveal and change it. Every setting has a
 * "?" help button explaining it in plain English with an example.
 */
class ConfigPanel(
    private val api: MontoyaApi,
    private val configStore: ConfigStore,
    private val onSaved: () -> Unit,
    private val scanControls: JComponent? = null
) : JPanel(BorderLayout()) {

    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true; encodeDefaults = true }

    private val injectionEnabled = JCheckBox("Enable agent injection")
    private val stripCsp = JCheckBox("Strip CSP on injected responses")
    private val burpIssues = JCheckBox("Add WebRTC findings to Burp's Issues list")
    private val hostAllowList = JTextArea(4, 40)
    private val bridgeHost = JTextField(16)
    private val bridgePort = JTextField(6)
    private val collectPath = JTextField(16)
    private val commandPath = JTextField(16)
    private val agentJsPath = JTextField(40)
    private val identitiesJson = JTextArea(10, 60)
    private val identifierKeys = JTextArea(3, 40)
    private val status = JLabel(" ")
    private var loading = false
    private val debounce = Timer(350) { save() }.apply { isRepeats = false }

    private val advancedPanel = JPanel(GridBagLayout())

    init {
        val sections = UiKit.stack(buildBasicSection())
        scanControls?.let { sections.add(it) }
        sections.add(Box.createVerticalStrut(12))
        sections.add(UiKit.disclosure("Access control identities & identifiers", buildAuthzSection(), configStore.config.identities.isNotEmpty()))
        sections.add(Box.createVerticalStrut(12))
        sections.add(buildAdvancedSection())
        sections.components.filterIsInstance<JComponent>().forEach { it.alignmentX = LEFT_ALIGNMENT }

        val buttons = JPanel().apply {
            add(UiKit.primary(JButton("Check configuration").apply { addActionListener { debounce.stop(); save(); checkConfig(showIfClean = true) } }))
            add(UiKit.quiet(JButton("Reload saved settings").apply { addActionListener { load() } }))
            add(status)
        }

        add(UiKit.scroll(JPanel(BorderLayout()).apply { add(sections, BorderLayout.NORTH) }), BorderLayout.CENTER)
        add(buttons, BorderLayout.SOUTH)

        load()
        listOf(hostAllowList, bridgeHost, bridgePort, collectPath, commandPath, agentJsPath, identitiesJson, identifierKeys).forEach {
            AutoSave.watch(it) { if (!loading) { status.text = "Saving…"; debounce.restart() } }
        }
        listOf(injectionEnabled, stripCsp, burpIssues).forEach { it.addActionListener { if (!loading) { debounce.stop(); save() } } }
        addFocusListener(object : java.awt.event.FocusAdapter() {
            override fun focusLost(e: java.awt.event.FocusEvent?) { if (debounce.isRunning) { debounce.stop(); save() } }
        })
    }

    // ---- sections -------------------------------------------------------

    private fun titled(title: String): JPanel = JPanel(GridBagLayout()).apply {
        border = BorderFactory.createTitledBorder(title)
    }

    private fun row(panel: JPanel, r: Int, label: String, comp: JComponent, help: JButton?) {
        val c = GridBagConstraints().apply {
            insets = Insets(8, 12, 8, 12); anchor = GridBagConstraints.WEST; fill = GridBagConstraints.HORIZONTAL
        }
        c.gridx = 0; c.gridy = r; c.weightx = 0.0
        panel.add(JLabel(label), c)
        c.gridx = 1; c.weightx = 1.0
        panel.add(comp, c)
        c.gridx = 2; c.weightx = 0.0; c.fill = GridBagConstraints.NONE
        panel.add(help ?: JLabel(" "), c)
    }

    private fun wideRow(panel: JPanel, r: Int, comp: JComponent) {
        val c = GridBagConstraints().apply {
            insets = Insets(4, 6, 4, 6); anchor = GridBagConstraints.WEST
            fill = GridBagConstraints.HORIZONTAL; gridx = 0; gridy = r; gridwidth = 3; weightx = 1.0
        }
        panel.add(comp, c)
    }

    private fun buildBasicSection(): JPanel {
        val p = titled("Browser agent")
        var r = 0
        wideRow(p, r++, injectionRow())
        wideRow(p, r++, stripCspRow())
        wideRow(p, r++, UiKit.toolbar(burpIssues, HelpUi.button(
            "Add WebRTC findings to Burp's Issues list",
            "When ON, confirmed and likely findings (executed XSS canaries, Collaborator callbacks, likely broken access control, capture left on after a call, failed TURN checks, weak TLS listeners) are added to Burp's Issues list with their evidence, so Burp's own report includes them. Generic header issues that Burp's scanner already reports are not duplicated.",
            "An executed canary appears in Target → Site map → Issues as \"Stored cross-site scripting (WebRTC canary executed)\" with Certain confidence.")))
        wideRow(p, r++, UiKit.note("1. Add the target to Burp Target scope.  2. Enter its hostname below.  3. Enable the agent and reload the page."))
        row(p, r++, "Allowed hosts:", JScrollPane(hostAllowList), HelpUi.button(
            "Host allow-list",
            "The hostnames the agent may be injected into — one per line. This is a second guardrail on top of Burp Target scope: a page is only touched if its host matches here AND the full URL is in Burp Target scope. Enter 'all' on its own line to allow every in-scope host.",
            "meet.example.com\napp.example.com\n\n…or a single line to allow every in-scope host:\nall"
        ))
        return p
    }

    private fun injectionRow(): JPanel = UiKit.toolbar().apply {
        add(injectionEnabled)
        add(HelpUi.button(
            "Enable agent injection",
            "Master on/off switch. When ON, Burp inserts the WebRTC test agent into pages you load — but only for hosts in the allow-list that are also inside Burp Target scope. Leave OFF to browse the app untouched.",
            "Typical flow: fill the host allow-list, add the site to Burp Target scope, then turn this on and reload the page."
        ))
    }

    private fun stripCspRow(): JPanel = UiKit.toolbar().apply {
        add(stripCsp)
        add(HelpUi.button(
            "Strip CSP on injected responses",
            "Removes CSP restrictions that can block the agent, report-only CSP headers, and CSP <meta> tags from injected pages. Preserves enforced frame-ancestors directives and X-Frame-Options so embedded video pages keep their original framing policy. Leave ON unless you need the app's full CSP intact.",
            "A page returning `Content-Security-Policy: script-src 'self'; frame-ancestors https://app.example` retains `frame-ancestors https://app.example`, letting the agent run while the app can still embed the page. This lowers the app's XSS protection during the test."
        ))
    }

    private fun buildAuthzSection(): JPanel {
        val p = JPanel(GridBagLayout())
        var r = 0
        row(p, r++, "Identifier keys (one per line):", JScrollPane(identifierKeys), HelpUi.button(
            "Identifier keys",
            "The names of ID fields that appear in the app's traffic and point at a user or resource — for example a user ID, room ID, or meeting ID. Access control swaps these values between identities to test for broken access control (IDOR).",
            "userId\nroomId\nmeetingId\n\nThe matrix can take a request containing roomId=500 captured as Alice and replay it as Bob, to check whether Bob can reach Alice's room."
        ))
        row(p, r++, "Identities (JSON array):", JScrollPane(identitiesJson).apply { preferredSize = Dimension(600, 200) }, HelpUi.button(
            "Identities (JSON array)",
            "Optional saved accounts for Access control. You can also select passively captured sessions directly in that tab. JSON entries contain a name, authentication headers, identifiers, optional queryTokens, bodyTokens and origins. Body tokens use JSON pointers (for example /auth/token) or form field names. Credentials are preserved in the Burp project file.",
            "[\n" +
                "  {\n" +
                "    \"name\": \"alice\",\n" +
                "    \"headers\": { \"Cookie\": \"session=ALICE_SESSION\" },\n" +
                "    \"identifiers\": { \"userId\": \"1001\", \"roomId\": \"500\" }\n" +
                "  },\n" +
                "  {\n" +
                "    \"name\": \"bob\",\n" +
                "    \"headers\": { \"Authorization\": \"Bearer BOB_TOKEN\" },\n" +
                "    \"identifiers\": { \"userId\": \"1002\", \"roomId\": \"600\" }\n" +
                "  }\n" +
                "]\n\n" +
                "The matrix replays each request across distinct credentials and with recognized credentials removed. A successful protected response is a review lead; confirm different principals, resource ownership and intended permissions."
        ))
        return p
    }

    private fun buildAdvancedSection(): JPanel {
        var r = 0
        row(advancedPanel, r++, "Bridge host:", bridgeHost, HelpUi.button(
            "Bridge host",
            "The local address the extension's telemetry bridge listens on. The injected agent sends SDP / ICE / DataChannel data here. 127.0.0.1 (localhost only) is correct almost always — keep it on localhost so the bridge is never exposed to the network."
        ))
        row(advancedPanel, r++, "Bridge port:", bridgePort, HelpUi.button(
            "Bridge port",
            "TCP port for the local telemetry bridge. Default 8777. Change only if another program already uses 8777 on your machine.",
            "If Burp logs a bind error on 8777, set 8788 here; the change saves automatically and the bridge restarts on the new port."
        ))
        row(advancedPanel, r++, "Collect path:", collectPath, HelpUi.button(
            "Collect path",
            "The URL path on the local bridge where the agent posts its telemetry beacons (SDP, ICE, ciphers, DataChannel events). The default /collect is fine — change it only in the rare case it would collide with a path the app under test uses."
        ))
        row(advancedPanel, r++, "Command path:", commandPath, HelpUi.button(
            "Command path",
            "The URL path on the local bridge where the agent fetches commands to run (SDP mutation rules, DataChannel fuzz, ICE probes). The default /command is fine — change it only to avoid a collision with the app's own paths."
        ))
        val agentRow = JPanel(BorderLayout())
        agentRow.add(agentJsPath, BorderLayout.CENTER)
        agentRow.add(JButton("Browse...").apply { addActionListener { browseAgent() } }, BorderLayout.EAST)
        row(advancedPanel, r++, "Agent JS override:", agentRow, HelpUi.button(
            "Agent JS override",
            "Blank = use the agent bundled inside the jar (recommended, and the normal setting). Set a file path only if you are editing the agent yourself and want Burp to load your working copy instead of the bundled one.",
            "C:\\Projects\\WebRTC\\agent\\webrtc-agent.js"
        ))
        wideRow(advancedPanel, r++, JButton("Restore recommended defaults").apply { addActionListener { restoreAdvancedDefaults() } })

        return UiKit.disclosure("Advanced · local bridge & agent override", advancedPanel)
    }

    // ---- actions --------------------------------------------------------

    private fun browseAgent() {
        val chooser = JFileChooser()
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            agentJsPath.text = chooser.selectedFile.absolutePath
        }
    }

    private fun restoreAdvancedDefaults() {
        val d = WebRtcConfig()
        bridgeHost.text = d.bridgeHost
        bridgePort.text = d.bridgePort.toString()
        collectPath.text = d.collectPath
        commandPath.text = d.commandPath
        agentJsPath.text = d.agentJsPath
        debounce.stop(); save()
    }

    private fun load() {
        debounce.stop(); loading = true
        val cfg = configStore.config
        injectionEnabled.isSelected = cfg.injectionEnabled
        stripCsp.isSelected = cfg.stripCsp
        burpIssues.isSelected = cfg.burpIssues
        hostAllowList.text = cfg.hostAllowList.joinToString("\n")
        bridgeHost.text = cfg.bridgeHost
        bridgePort.text = cfg.bridgePort.toString()
        collectPath.text = cfg.collectPath
        commandPath.text = cfg.commandPath
        agentJsPath.text = cfg.agentJsPath
        identifierKeys.text = cfg.identifierKeys.joinToString("\n")
        identitiesJson.text = json.encodeToString(ListSerializer(IdentityProfile.serializer()), cfg.identities)
        loading = false
        status.text = "Changes save automatically"
    }

    private fun save() {
        if (loading) return
        try {
            val previous = configStore.config
            val warnings = mutableListOf<String>()
            val identities = runCatching {
                if (identitiesJson.text.isBlank()) emptyList() else json.decodeFromString(ListSerializer(IdentityProfile.serializer()), identitiesJson.text)
            }.getOrElse { warnings += "Identities JSON unfinished; keeping last valid identities"; previous.identities }
            val port = bridgePort.text.trim().toIntOrNull()?.takeIf { it in 1..65535 }
                ?: previous.bridgePort.also { warnings += "Invalid bridge port; keeping $it" }
            val cfg = previous.copy(
                injectionEnabled = injectionEnabled.isSelected, stripCsp = stripCsp.isSelected, burpIssues = burpIssues.isSelected,
                hostAllowList = lines(hostAllowList.text),
                bridgeHost = bridgeHost.text.trim().ifBlank { "127.0.0.1" }, bridgePort = port,
                collectPath = collectPath.text.trim().ifBlank { "/collect" }, commandPath = commandPath.text.trim().ifBlank { "/command" },
                agentJsPath = agentJsPath.text.trim(), identities = identities, identifierKeys = lines(identifierKeys.text)
            )
            configStore.save(cfg)
            if (listOf(previous.bridgeHost, previous.bridgePort, previous.collectPath, previous.commandPath) !=
                listOf(cfg.bridgeHost, cfg.bridgePort, cfg.collectPath, cfg.commandPath)) onSaved()
            status.text = if (warnings.isEmpty()) "Saved automatically" else "Saved other settings. ${warnings.joinToString("; ")}"
        } catch (t: Exception) {
            api.logging().logToError("[config] autosave failed: ${t.message}")
            status.text = "Not saved: ${t.message}"
        }
    }

    /**
     * Automated sanity check over the current field values, reported in plain
     * English. Returns true when nothing needs the tester's attention.
     */
    private fun checkConfig(showIfClean: Boolean): Boolean {
        val problems = mutableListOf<String>()
        val notes = mutableListOf<String>()

        val hosts = lines(hostAllowList.text)
        val port = bridgePort.text.trim().toIntOrNull()

        if (injectionEnabled.isSelected && hosts.isEmpty())
            problems += "Injection is ON but the host allow-list is empty, so nothing will be injected. Add the app's hostname (or 'all')."
        if (port == null || port !in 1..65535)
            problems += "Bridge port must be a whole number between 1 and 65535."
        val idErr = runCatching {
            if (identitiesJson.text.isNotBlank())
                json.decodeFromString(ListSerializer(IdentityProfile.serializer()), identitiesJson.text)
        }.exceptionOrNull()
        if (idErr != null)
            problems += "Identities JSON does not parse: ${idErr.message}"
        if (agentJsPath.text.isNotBlank() && !File(agentJsPath.text.trim()).isFile)
            problems += "Agent JS override points at a file that doesn't exist. Leave it blank to use the bundled agent."

        if (hosts.any { it.equals("all", ignoreCase = true) })
            notes += "'all' allows injection into every in-scope host. Fine for a broad test; list specific hosts to be more precise."
        if (!injectionEnabled.isSelected)
            notes += "Injection is OFF — pages are browsed untouched until you enable it."
        if (!stripCsp.isSelected)
            notes += "Strip CSP is OFF — a strict Content-Security-Policy on the target may block the agent from loading."

        val clean = problems.isEmpty()
        if (clean && notes.isEmpty()) {
            status.text = "configuration OK"
            if (showIfClean)
                JOptionPane.showMessageDialog(this, "Configuration looks good.", "Check configuration", JOptionPane.INFORMATION_MESSAGE)
            return true
        }

        if (!clean || showIfClean || notes.isNotEmpty()) {
            val msg = buildString {
                if (problems.isNotEmpty()) {
                    append("Needs attention:\n")
                    problems.forEach { append("  • ").append(it).append('\n') }
                }
                if (notes.isNotEmpty()) {
                    if (isNotEmpty()) append('\n')
                    append("For your information:\n")
                    notes.forEach { append("  • ").append(it).append('\n') }
                }
            }
            val kind = if (clean) JOptionPane.INFORMATION_MESSAGE else JOptionPane.WARNING_MESSAGE
            JOptionPane.showMessageDialog(this, msg.trimEnd(), "Check configuration", kind)
            status.text = if (clean) "configuration OK (see notes)" else "configuration needs attention"
        }
        return clean
    }

    private fun lines(text: String): List<String> =
        text.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
}
