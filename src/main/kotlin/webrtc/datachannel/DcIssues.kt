package webrtc.datachannel

/**
 * Maps a FAIL from the DataChannel runner to a specific Burp issue type. Only FAIL results
 * become issues; other verdicts stay in the runner's results and coverage report.
 */
object DcIssues {
    data class Issue(val category: String, val name: String, val severity: String, val confidence: String,
                     val remediation: String, val background: String)

    private const val RECIPIENT = "Every DataChannel case carried a unique marker. The instrumented recipient page reported receiving, rendering or failing on it, and the run's positive control passed."

    fun classify(r: DcCaseResult): Issue? {
        if (r.verdict != Verdict.FAIL) return null
        val m = r.mutation
        val id = r.caseId
        return when {
            id.startsWith("authz-ws-") || id == "lifecycle-old-url" || id == "lifecycle-ended-url" -> Issue("ws-admission",
                "Colibri WebSocket admits tampered or stale credentials (WebRTC)", "high", "firm",
                "Bind each bridge WebSocket to the authenticated endpoint, conference and a per-session secret. Reject wrong or missing secrets, other conferences or endpoints, and URLs from ended or left sessions. Never let a new connection displace another participant's channel.",
                "The extension opened a fresh Colibri WebSocket from an in-scope page with a modified or old URL. The bridge accepted it (opened and sent data), although the application's own socket to the same bridge proved the control path.")
            m in setOf("spoof-from", "spoof-from-foreign", "replay-received") -> Issue("spoof",
                "Spoofable sender identity in DataChannel messages (WebRTC)", "high", "firm",
                "Have the bridge or server overwrite the sender identity (for example the Colibri 'from' field) with the authenticated endpoint, and have receiving clients trust only that value.",
                "$RECIPIENT The recipient saw the message attributed to another participant.")
            m in setOf("direction", "foreign-source") -> Issue("direction",
                "Client can inject server-to-client bridge messages (WebRTC)", "high", "firm",
                "Accept only client-to-server message classes from clients, and only for sources the sender owns. Drop server-only classes (speaker, connectivity, source-map and constraint messages) received from endpoints.",
                "$RECIPIENT A server-to-client message class sent by a client reached another participant.")
            m == "protected-role" -> Issue("role",
                "Role-restricted application command accepted from an unauthorized role (WebRTC)", "high", "firm",
                "Authorize application commands (mute, remove, end meeting, document actions) on the server or verify the sender's role before acting on them in the receiving client.",
                "The same command changed the recipient's protected state when sent by an allowed role (positive control). It changed it again when sent by a role that should not be allowed.")
            r.scope == DcScope.AUTHZ.id -> Issue("isolation",
                "DataChannel message delivered to an unauthorized participant (WebRTC)", "high", "firm",
                "Route bridge messages only to endpoints inside the sender's conference that the message addresses. Reject unknown or malformed recipients and ignore client-supplied room or conference fields.",
                "$RECIPIENT A participant that must not receive the message (another room, an unaddressed endpoint) observed it.")
            id in setOf("lifecycle-leave", "lifecycle-hangup", "lifecycle-removal") -> Issue("termination",
                "Call access not revoked when a participant leaves, is removed or the call ends (WebRTC)", "high", "firm",
                "When a participant leaves, is removed or the host ends the call, close that participant's bridge channel and peer connections on the server side and invalidate its session credentials.",
                "The integrated runner performed the action through the application's own call controls, then checked the old channel against the action time.")
            id == "lifecycle-admission" -> Issue("readmission",
                "Participant can re-join after the call ended or after removal (WebRTC)", "high", "firm",
                "Invalidate meeting admission (tokens, invite links, bridge credentials) when the host ends the call or removes a participant, and require fresh authorization to join.",
                "The integrated runner re-ran the participant's join steps after the call ended. A connected channel reopened although re-joining was configured as denied.")
            id.startsWith("health-") || r.reasons.any { it.contains("Session health was lost") } && r.scope != DcScope.LOAD.id -> Issue("disruption",
                "Single DataChannel message disrupts the call (WebRTC)", "medium", "firm",
                "Validate and bound bridge and application messages before processing them. Isolate parse and handler failures so one malformed message cannot break delivery or the session.",
                "A delivery probe failed immediately after the case was re-run on its own. Before the case, the same path delivered.")
            r.receipts.any { it.kind == "error" } -> Issue("client-error",
                "Malformed DataChannel message causes errors in the receiving client (WebRTC)", "medium", "firm",
                "Validate message structure and types in the receiving client before use. Handle unknown or malformed messages without throwing.",
                "$RECIPIENT A page error in the receiving application contained the case marker.")
            r.scope in setOf(DcScope.FUZZ.id, DcScope.BINARY.id, DcScope.TRANSPORT.id) && r.expect == "reject" -> Issue("relay",
                "Bridge relays malformed or unexpected DataChannel messages (WebRTC)", "low", "firm",
                "Parse and validate bridge-channel messages strictly (known class, expected types, JSON only) and drop invalid ones instead of relaying them to other participants.",
                "$RECIPIENT A message the bridge should have rejected (malformed JSON, unknown or control class, binary on a JSON channel) reached another participant.")
            r.scope == DcScope.LOAD.id -> Issue("load",
                "DataChannel traffic degrades the call under bounded load (WebRTC)", "low", "tentative",
                "Apply per-endpoint rate limits and message quotas on the bridge, and protect media and signaling from data-channel bursts.",
                "A bounded, configured load step breached the degradation thresholds (delivery, latency, packet loss or session health). Thresholds are tester-defined.")
            r.caseId == "lifecycle-reconnect" || r.caseId == "transport-reconnect" -> Issue("recovery",
                "Call does not recover after a transport interruption (WebRTC)", "information", "tentative",
                "Reconnect the bridge channel automatically and resume delivery after short network or socket interruptions.",
                "The runner interrupted the transport and checked for a working replacement within the recovery window.")
            else -> Issue("other", "DataChannel security test failed (WebRTC)", "medium", "tentative",
                "Review the case evidence in Tests → Data channel runner and restrict the demonstrated behaviour.", RECIPIENT)
        }
    }
}
