package webrtc.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import webrtc.authz.*
import webrtc.config.ConfigStore
import webrtc.config.IdentityProfile
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.*
import javax.swing.table.AbstractTableModel

/** Capture first, select credential bundles, then compare isolated requests or prepare fresh room logins. */
class AuthzPanel(private val api: MontoyaApi, private val config: ConfigStore,
                 private val sessions: SessionCatalog, private val runner: AuthzMatrixRunner,
                 private val links: LinkCatalogs? = null, private val linkTester: LinkTester? = null,
                 private val onResult: (AuthzResult) -> Unit = {}) : JPanel(BorderLayout(0, 8)) {
    val model = AuthzResultTableModel()
    private val table = JTable(model)
    private val sessionModel = SessionTableModel()
    private val sessionTable = JTable(sessionModel)
    private val details = textArea()
    private val evidence = textArea()
    private val swaps = textArea()
    private val status = JLabel()
    private val tabs = JTabbedPane()
    private val inviteModel by lazy { object : AbstractTableModel() {
        private val cols = arrayOf("Link", "Token", "Guessability", "Validation requests", "First seen")
        override fun getRowCount() = links?.invites()?.size ?: 0
        override fun getColumnCount() = cols.size
        override fun getColumnName(column: Int) = cols[column]
        override fun getValueAt(row: Int, column: Int): Any = links!!.invites()[row].let { l -> when (column) {
            0 -> l.pageUrl; 1 -> "${l.tokenName} (${l.location})"; 2 -> l.guessability; 3 -> l.validations.size; else -> l.firstSeen.toString().take(19).replace('T', ' ')
        } }
    } }
    private val inviteTable by lazy { JTable(inviteModel).apply { autoCreateRowSorter = true; TableCopyUi.install(this) } }
    private val artifactModel by lazy { object : AbstractTableModel() {
        private val cols = arrayOf("Download", "Kind", "Captured with", "Signed link")
        override fun getRowCount() = links?.artifacts()?.size ?: 0
        override fun getColumnCount() = cols.size
        override fun getColumnName(column: Int) = cols[column]
        override fun getValueAt(row: Int, column: Int): Any = links!!.artifacts()[row].let { a -> when (column) {
            0 -> a.url; 1 -> a.kind; 2 -> sessions.byId(a.ownerSession)?.let { "${it.label}${if (it.identity.role.isNotBlank()) " (${it.identity.role})" else ""}" } ?: "unknown"
            else -> if (LinkCatalogs.isSigned(a.url)) "yes" else ""
        } }
    } }
    private val artifactTable by lazy { JTable(artifactModel).apply { autoCreateRowSorter = true; TableCopyUi.install(this) } }

    private val run = UiKit.primary(JButton("Compare selected sessions"))
    private val stop = UiKit.quiet(JButton("Stop"))
    private val prepare = JButton("Prepare room swaps")
    private val staged = mutableListOf<HttpRequest>()
    private val useStaged = JCheckBox("Use requests sent from Burp")
    private val refreshPending = AtomicBoolean()
    @Volatile private var running = false
    @Volatile private var cancelled = false
    @Volatile private var selectedProfiles: List<IdentityProfile> = emptyList()

    init {
        sessionTable.autoCreateRowSorter = true
        TableCopyUi.install(sessionTable)
        sessionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        sessionTable.columnModel.getColumn(0).maxWidth = 50
        sessionTable.columnModel.getColumn(1).preferredWidth = 110
        sessionTable.columnModel.getColumn(3).preferredWidth = 240
        sessionTable.columnModel.getColumn(6).apply {
            cellEditor = DefaultCellEditor(JComboBox(arrayOf("", "guest", "customer", "advisor", "admin")))
            preferredWidth = 90
        }
        sessionTable.selectionModel.addListSelectionListener { if (!it.valueIsAdjusting) showSession() }
        val sessionBody = JSplitPane(JSplitPane.VERTICAL_SPLIT,
            UiKit.emptyTable(sessionTable, "Waiting for session tokens", "Browse two accounts or JWT room links through Burp on scoped, allowed hosts."),
            JScrollPane(details)).apply { resizeWeight = 0.65; preferredSize = Dimension(650, 300) }
        tabs.addTab("Sessions", sessionBody)

        table.autoCreateRowSorter = true
        TableCopyUi.install(table)
        table.selectionModel.addListSelectionListener { if (!it.valueIsAdjusting) showResult() }
        val filter = JTextField(20).apply { toolTipText = "Filter by URL, session, variant, or result." }
        AutoSave.watch(filter) {
            (table.rowSorter as javax.swing.table.TableRowSorter<*>).rowFilter = filter.text.takeIf { it.isNotBlank() }
                ?.let { RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(it)) }
        }
        val results = JPanel(BorderLayout(0, 5)).apply {
            add(UiKit.toolbar(JLabel("Filter results:"), filter), BorderLayout.NORTH)
            add(JSplitPane(JSplitPane.VERTICAL_SPLIT,
                UiKit.emptyTable(table, "No access control results yet", "Select sessions and compare, or send a request here from Burp."),
                JScrollPane(evidence)).apply { resizeWeight = 0.65 }, BorderLayout.CENTER)
        }
        tabs.addTab("Results", results)
        tabs.addTab("Room swaps", JPanel(BorderLayout(0, 5)).apply {
            add(UiKit.note("Open prepared links in separate browser profiles to test fresh room admission. Confirm expected guest and moderator permissions; decoded JWT claims are unverified."), BorderLayout.NORTH)
            add(JScrollPane(swaps), BorderLayout.CENTER)
            add(UiKit.toolbar(JButton("Copy room swaps").apply { addActionListener { copy(swaps.text) } }), BorderLayout.SOUTH)
        })
        if (links != null && linkTester != null) {
            tabs.addTab("Meeting links", JPanel(BorderLayout(0, 5)).apply {
                add(UiKit.note("Invite / meeting links opened through Burp are listed with the API requests that validated their token. Test replays each validation with the token altered, removed and without session cookies. After the meeting ends, Recheck links tests whether links can be reused."), BorderLayout.NORTH)
                add(UiKit.emptyTable(inviteTable, "No meeting links captured", "Open an invite link (for example from the SMS or e-mail) in a browser routed through Burp."), BorderLayout.CENTER)
                add(UiKit.toolbar(UiKit.primary(JButton("Test links").apply { addActionListener { testLinks(false) } }),
                    JButton("Recheck links (after the meeting)").apply { addActionListener { testLinks(true) } }), BorderLayout.SOUTH)
            })
            tabs.addTab("Documents & recordings", JPanel(BorderLayout(0, 5)).apply {
                add(UiKit.note("Documents, attachments, transcripts and recordings downloaded through Burp. Test replays each download with the other ticked sessions, without credentials, and with neighbouring numeric IDs. Set session roles so an advisor reading a customer's document is not flagged."), BorderLayout.NORTH)
                add(UiKit.emptyTable(artifactTable, "No downloads captured", "Exchange a document in the call and download it, or open a recording, through Burp."), BorderLayout.CENTER)
                add(UiKit.toolbar(UiKit.primary(JButton("Test downloads").apply { addActionListener { testArtifacts() } })), BorderLayout.SOUTH)
            })
            links.onChange { SwingUtilities.invokeLater { inviteModel.fireTableDataChanged(); artifactModel.fireTableDataChanged() } }
        }
        run.addActionListener { compare() }
        stop.addActionListener { cancelled = true; stop.isEnabled = false; status.text = "Stopping after the current request…" }
        prepare.addActionListener { swaps.text = SessionCatalog.roomSwaps(sessions.selection()); swaps.caretPosition = 0; tabs.selectedIndex = 2 }
        useStaged.addActionListener { updateStatus() }
        val rename = JButton("Name session").apply { addActionListener {
            val selected = highlightedSession() ?: return@addActionListener
            JOptionPane.showInputDialog(UiKit.parentWindow(this@AuthzPanel), "Session name (for example Alice / tenant A):", selected.label)
                ?.let { sessions.rename(selected.id, it) }
        } }
        val clear = UiKit.quiet(JButton("Clear sessions").apply { addActionListener { sessions.clear(); details.text = ""; swaps.text = "" } })
        add(UiKit.stack(
            UiKit.note("1. Browse separate accounts through Burp (for example a customer and an advisor).  2. Tick two or more captured sessions and set their Role.  3. Compare their captured API reads. With roles set, a lower role or another customer receiving the owner's data is reported as a likely violation."),
            UiKit.toolbar(run, stop, prepare, rename, clear),
            UiKit.toolbar(useStaged, status)), BorderLayout.NORTH)
        add(tabs, BorderLayout.CENTER)
        val send = UiKit.primary(JButton("Send to Repeater").apply { isEnabled = false; addActionListener { sendToRepeater() } })
        table.selectionModel.addListSelectionListener { send.isEnabled = selectedResult()?.requestResponse != null }
        add(UiKit.toolbar(send,
            JButton("Copy session credentials").apply { addActionListener { highlightedSession()?.let { copy(it.details()) } } },
            UiKit.quiet(JButton("Clear results").apply { addActionListener { this@AuthzPanel.model.clearAll(); evidence.text = "" } })), BorderLayout.SOUTH)
        sessions.onChange { scheduleRefresh() }
        config.onChange { scheduleRefresh() }
        refreshSessions()
    }

    fun addResult(result: AuthzResult) { model.add(result); runCatching { onResult(result) } }

    /** Run All entry points; return the number of links / downloads tested. */
    fun runInvites(continueRun: () -> Boolean, emit: (AuthzResult) -> Unit): Int {
        val tester = linkTester ?: return 0
        var count = 0
        for (link in links?.invites().orEmpty().take(5)) {
            if (!continueRun()) break
            runCatching { tester.testInvite(link, continueRun, { addResult(it); emit(it) }) }
                .onFailure { AuthzResult(link.pageUrl, "ERROR", 0, 0, "", false, false, it.message.orEmpty(), null).also { r -> addResult(r); emit(r) } }
            count++
        }
        return count
    }
    fun runArtifacts(continueRun: () -> Boolean, emit: (AuthzResult) -> Unit): Int {
        val tester = linkTester ?: return 0
        val pool = sessions.selection().ifEmpty { sessions.snapshot() }.filter { AuthTokens.hasCredentials(it.identity) }.take(6)
        var count = 0
        for (artifact in links?.artifacts().orEmpty().take(5)) {
            if (!continueRun()) break
            runCatching { tester.testArtifact(artifact, pool, sessions.byId(artifact.ownerSession), continueRun) { addResult(it); emit(it) } }
                .onFailure { AuthzResult(artifact.url, "ERROR", 0, 0, "", false, false, it.message.orEmpty(), null).also { r -> addResult(r); emit(r) } }
            count++
        }
        return count
    }
    private fun testLinks(recheck: Boolean) = background("link tests") {
        val tester = linkTester ?: return@background
        val selected = inviteTable.selectedRows.map { links!!.invites()[inviteTable.convertRowIndexToModel(it)] }.ifEmpty { links!!.invites().take(5) }
        selected.forEach { if (!cancelled) tester.testInvite(it, { !cancelled }, ::addResult, recheck) }
    }
    private fun testArtifacts() = background("download tests") {
        val selected = artifactTable.selectedRows.map { links!!.artifacts()[artifactTable.convertRowIndexToModel(it)] }
        if (selected.isEmpty()) runArtifacts({ !cancelled }) {} else {
            val pool = sessions.selection().ifEmpty { sessions.snapshot() }.filter { AuthTokens.hasCredentials(it.identity) }.take(6)
            selected.forEach { if (!cancelled) linkTester!!.testArtifact(it, pool, sessions.byId(it.ownerSession), { !cancelled }, ::addResult) }
        }
    }
    private fun background(label: String, action: () -> Unit) {
        if (running) return
        running = true; cancelled = false; updateStatus(); tabs.selectedIndex = 1
        Thread({
            try {
                runCatching(action).onFailure { UiKit.logError(it); addResult(AuthzResult("", "ERROR", 0, 0, "", false, false, "$label: ${it.message}", null)) }
            } finally {
                running = false
                SwingUtilities.invokeLater { updateStatus(); status.text = if (cancelled) "Stopped $label" else "Finished $label; inspect verdicts in Results" }
            }
        }, "webrtc-$label").apply { isDaemon = true }.start()
    }
    fun selectedIdentities(): List<IdentityProfile> = selectedProfiles
    fun stage(requests: List<HttpRequestResponse>) {
        requests.forEach { rr -> if (staged.none { it.toString() == rr.request().toString() }) staged += rr.request() }
        while (staged.size > 10) staged.removeAt(0)
        useStaged.isSelected = true
        tabs.selectedIndex = 0
        updateStatus()
    }
    private fun scheduleRefresh() {
        if (refreshPending.compareAndSet(false, true)) SwingUtilities.invokeLater { refreshPending.set(false); refreshSessions() }
    }
    private fun refreshSessions() {
        val highlighted = highlightedSession()?.id
        sessionModel.rows = sessions.snapshot()
        sessionModel.fireTableDataChanged()
        val row = sessionModel.rows.indexOfFirst { it.id == highlighted }
        if (row >= 0) { val view = sessionTable.convertRowIndexToView(row); sessionTable.setRowSelectionInterval(view, view) }
        selectedProfiles = sessions.selection().filter { AuthTokens.hasCredentials(it.identity) }.take(8).map { it.identity }
        showSession(); updateStatus()
    }
    private fun updateStatus() {
        val selection = sessions.selection()
        val reusable = selection.count { AuthTokens.hasCredentials(it.identity) }
        val ready = config.config.injectionEnabled && config.config.hostAllowList.isNotEmpty()
        run.isEnabled = !running && selection.size in 2..8 && reusable >= 2 && ready
        stop.isEnabled = running && !cancelled
        prepare.isEnabled = !running && selection.size in 2..8
        if (!running) status.text = when {
            selection.size > 8 -> "Select at most 8 sessions per comparison"
            selection.size >= 2 && reusable < 2 -> "XMPP-only credentials need a fresh protocol login; prepare room swaps for observed JWTs"
            !ready -> "${selection.size} selected · Enable the browser agent and allowed hosts in Setup to replay"
            useStaged.isSelected -> "${selection.size} selected · ${staged.size} explicit request(s), including writes"
            else -> "${selection.size} selected · Up to 10 captured JSON reads · Scope checked before every replay"
        }
    }
    private fun highlightedSession(): CapturedSession? = sessionTable.selectedRow.takeIf { it >= 0 }
        ?.let { sessionModel.rows.getOrNull(sessionTable.convertRowIndexToModel(it)) }
    private fun showSession() { details.text = highlightedSession()?.details().orEmpty(); details.caretPosition = 0 }
    private fun selectedResult(): AuthzResult? = table.selectedRow.takeIf { it >= 0 }
        ?.let { model.resultAt(table.convertRowIndexToModel(it)) }
    private fun showResult() {
        evidence.text = selectedResult()?.let { r -> buildString {
            appendLine(r.note)
            appendLine("\nBASELINE REQUEST\n${r.baselineRequestResponse?.request().orEmptyText()}")
            appendLine("\nBASELINE RESPONSE\n${r.baselineRequestResponse?.response().orEmptyText()}")
            appendLine("\nREPLAY REQUEST\n${r.requestResponse?.request().orEmptyText()}")
            appendLine("\nREPLAY RESPONSE\n${r.requestResponse?.response().orEmptyText()}")
        } }.orEmpty()
        evidence.caretPosition = 0
    }
    private fun compare() {
        val selected = sessions.selection().take(8)
        if (running || selected.size < 2) return
        val explicit = useStaged.isSelected
        val plans = if (explicit) staged.toList().map { Triple(-1L, "selected Burp request", it) }
            else selected.flatMap { session -> session.requests.map { Triple(session.id, session.label, it) } }.take(10)
        if (plans.isEmpty()) {
            status.text = "No JSON reads captured. Browse a protected API, send a request here from Burp, or prepare room swaps."
            return
        }
        running = true; cancelled = false; updateStatus(); tabs.selectedIndex = 1
        val profiles = selected.filter { AuthTokens.hasCredentials(it.identity) }.map { it.identity }
        Thread({
            var completed = 0
            try {
                for ((ownerId, owner, request) in plans) {
                    if (cancelled) break
                    val donors = selected.filter { it.id != ownerId && AuthTokens.hasCredentials(it.identity) }.map { it.identity }
                    var replayed = false
                    runCatching {
                        runner.run(request, if (explicit) profiles else donors, owner, { !cancelled },
                            ownerProfile = if (explicit) null else sessions.byId(ownerId)?.identity) { result ->
                            if (result.variant == "baseline") replayed = true
                            addResult(result)
                        }
                    }.onFailure { addResult(AuthzResult(request.url(), "ERROR", 0, 0, "", false, false, "$owner: ${it.message}", null)) }
                    if (replayed) completed++
                    val done = completed
                    SwingUtilities.invokeLater { if (!cancelled) status.text = "Compared $done / ${plans.size} requests" }
                }
            } catch (e: Throwable) {
                UiKit.logError(e)
                addResult(AuthzResult("", "ERROR", 0, 0, "", false, false, e.message.orEmpty(), null))
            } finally {
                running = false
                SwingUtilities.invokeLater { updateStatus(); status.text = if (cancelled) "Stopped; completed $completed requests" else "Compared $completed requests; inspect protected content and intended access" }
            }
        }, "webrtc-session-comparison").apply { isDaemon = true }.start()
    }
    private fun sendToRepeater() { selectedResult()?.requestResponse?.request()?.let { api.repeater().sendToRepeater(it) } }
    fun stopComparison() { cancelled = true }
    fun isCancelled(): Boolean = cancelled
    private fun copy(value: String) { if (value.isNotEmpty()) Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(value), null) }
    private fun Any?.orEmptyText() = this?.toString().orEmpty()
    private fun textArea() = JTextArea().apply { isEditable = false; lineWrap = true; wrapStyleWord = true; border = BorderFactory.createEmptyBorder(8, 10, 8, 10) }

    private inner class SessionTableModel : AbstractTableModel() {
        var rows: List<CapturedSession> = emptyList()
        private val cols = arrayOf("Use", "Session", "Origin", "Claims / identity hints", "State", "Reads", "Role")
        override fun getRowCount() = rows.size
        override fun getColumnCount() = cols.size
        override fun getColumnName(column: Int) = cols[column]
        override fun getColumnClass(column: Int): Class<*> = when (column) { 0 -> java.lang.Boolean::class.java; 5 -> java.lang.Integer::class.java; else -> String::class.java }
        override fun isCellEditable(row: Int, column: Int) = (column == 0 || column == 6) && !running
        override fun getValueAt(row: Int, column: Int): Any = rows[row].let { s -> when (column) {
            0 -> sessions.isSelected(s.id); 1 -> s.label; 2 -> s.origin; 3 -> s.summary(); 4 -> s.state(); 5 -> s.requests.size; else -> s.identity.role
        } }
        override fun setValueAt(value: Any?, row: Int, column: Int) {
            if (column == 0) sessions.select(rows[row].id, value == true)
            if (column == 6) sessions.setRole(rows[row].id, value?.toString().orEmpty())
        }
    }
}
