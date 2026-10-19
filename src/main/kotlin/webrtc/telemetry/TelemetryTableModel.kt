package webrtc.telemetry

import javax.swing.SwingUtilities
import javax.swing.table.AbstractTableModel
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.CopyOnWriteArrayList

data class TelemetryEvent(
    val seq: Long,
    val time: String,
    val type: String,
    val frame: String,
    val pcId: String,
    val private: Boolean,
    val summary: String,
    val raw: String
)

/** Known agent event types (informational; the table accepts any type string). */
object EventTypes {
    val KNOWN = listOf(
        "assessment-result", "signaling-observation", "ws-connection", "ws-binary", "ws-closed", "original-policy",
        "pc-config", "pc-operation", "ice-input", "getUserMedia-result", "browser-capabilities", "capture-result", "track-state",
        "installed", "pc-new", "pc-state", "ice", "crypto", "selected-pair",
        "sdp-local", "sdp-remote", "dc-created", "dc-send", "dc-recv",
        "getUserMedia", "fuzz-result", "fuzz-error", "sdp-mutation", "sdp-result", "sdp-error", "sdp-mutation-status",
        "dc-state", "test-job", "command-result", "ice-probe-candidate", "ice-probe-error", "ice-probe-result",
        "sdp-fuzz-result", "sdp-fuzz-error", "sdp-fuzz-summary",
        "stats-snapshot", "dtls-cert", "stats-capture-result", "stats-capture-error",
        "flood-result", "signaling-flood-summary", "signaling-flood-error",
        "internals-import", "internals-comparison",
        "tls-runtime", "tls-scan-start", "tls-scan-result", "tls-scan-error",
        "getDisplayMedia", "enumerateDevices-result", "browser-checks-error",
        "message-listener", "message-received", "message-sent",
        "xss-canary-fired", "xss-canary-reflected", "collaborator-interaction", "burp-issue",
        // DataChannel runner (1.3.0): agent case/receipt/health events and Burp-side results.
        "dc-case", "dc-markers", "dc-health", "dc-load-step", "dc-churn-result", "dc-churn-summary", "ws-admission-result",
        "transport-action-result", "page-error", "ws-colibri", "ws-colibri-send", "ws-colibri-recv",
        "dc-suite-error", "dc-load-error", "dc-churn-error", "dc-health-error", "ws-admission-error", "transport-action-error",
        "dc-case-result", "dc-runner", "runner-action", "bridge-log"
    )
}

class TelemetryTableModel : AbstractTableModel() {
    private val cols = arrayOf("#", "Time", "Type", "Frame", "PC", "Private", "Summary")
    private val rows = ArrayList<TelemetryEvent>()
    private val seq = AtomicLong(0)
    private val archive = CopyOnWriteArrayList<TelemetryEvent>()
    private val listeners = CopyOnWriteArrayList<(TelemetryEvent) -> Unit>()

    fun snapshot(): List<TelemetryEvent> = archive.toList()

    fun nextSeq(): Long = seq.incrementAndGet()

    /** Called on the adding thread for every new event; listener failures are isolated. */
    fun onEvent(listener: (TelemetryEvent) -> Unit) { listeners += listener }

    fun add(event: TelemetryEvent) {
        archive.add(event)
        listeners.forEach { runCatching { it(event) } }
        SwingUtilities.invokeLater {
            rows.add(event)
            fireTableRowsInserted(rows.size - 1, rows.size - 1)
        }
    }

    fun eventAt(index: Int): TelemetryEvent? = rows.getOrNull(index)

    fun clearAll() {
        archive.clear()
        SwingUtilities.invokeLater {
            val n = rows.size
            rows.clear()
            if (n > 0) fireTableRowsDeleted(0, n - 1)
        }
    }

    override fun getRowCount(): Int = rows.size
    override fun getColumnCount(): Int = cols.size
    override fun getColumnName(c: Int): String = cols[c]
    override fun isCellEditable(r: Int, c: Int): Boolean = false

    override fun getValueAt(r: Int, c: Int): Any {
        val e = rows[r]
        return when (c) {
            0 -> e.seq
            1 -> e.time
            2 -> e.type
            3 -> e.frame
            4 -> e.pcId
            5 -> if (e.private) "PRIVATE" else ""
            else -> e.summary
        }
    }
}
