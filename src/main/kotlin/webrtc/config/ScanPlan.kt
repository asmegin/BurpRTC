package webrtc.config

import kotlinx.serialization.Serializable

/** Every entry has an extension execution path. External recipes belong in External Tests. */
enum class ScanModule(val id: String, val title: String, val detail: String) {
    PASSIVE("passive", "Evidence review", "Review captured SDP, ICE privacy, DTLS/SRTP, codecs and signaling metadata."),
    STATS("stats", "Live statistics", "Capture transport and media statistics from live browser peers."),
    BROWSER("browser", "Browser & capture checks", "Record camera, microphone and screen-share permission states, permission policy and device-label exposure in each live page."),
    ICE("ice", "STUN & TURN gathering", "Gather candidates using saved or observed ICE servers; needs a live browser page."),
    SDP("sdp", "SDP / codec fuzzing", "Run bounded parser mutations on a throwaway browser peer."),
    MUTATION("mutation", "SDP rules", "Enable saved rewrite rules for the next negotiation; needs a rule and a fresh call."),
    DATA("data", "Data channel fuzzing", "Send bounded test payloads; needs an open data channel."),
    DC_RUNNER("dc-runner", "Data channel runner", "Run the DataChannel test runner on live pages: channel discovery, Colibri message fuzzing, size boundaries, authorization and isolation, replay, bounded load and transport comparison, with recipient-side verification."),
    AUTHZ("authz", "Access control", "Replay recent GET/HEAD requests across selected captured sessions or configured identities, including removal of recognized header, URL and body credentials. Customer / advisor roles turn matching responses into likely violations."),
    INVITES("invites", "Meeting links", "Replay captured meeting / invite link validation requests with the token altered, removed and without cookies, and estimate token guessability."),
    ARTIFACTS("artifacts", "Documents & recordings", "Replay captured document, file and recording downloads across sessions and without credentials; review signed-link expiry and neighbouring numeric IDs."),
    TLS("tls", "TLS listener tests", "Scan the endpoint saved in TLS tests with the built-in JVM scanner (no install), or SSLyze when selected."),
    SECURITY("security", "Security checks", "Run captured-evidence checks, built-in STUN/TURN tests and any saved HTTP/WebSocket scenarios."),
    LOCAL_FLOOD("local-flood", "Negotiation loop", "Run a bounded ICE-restart loop on a throwaway peer; sends no server signaling.")
}

@Serializable
data class ScanPlan(
    val enabled: Set<String> = ScanModule.entries.map { it.id }.toSet(),
    val selectionVersion: Int = CURRENT_VERSION
) {
    companion object {
        const val CURRENT_VERSION = 4
        /** Modules added after selection version 2; existing non-empty selections gain them once. */
        val ADDED_IN_V3 = setOf(ScanModule.BROWSER.id, ScanModule.INVITES.id, ScanModule.ARTIFACTS.id)
        /** Added after selection version 3. */
        val ADDED_IN_V4 = setOf(ScanModule.DC_RUNNER.id)

        /** Modules an earlier non-empty selection gains once when upgraded. */
        fun addedSince(version: Int): Set<String> = (if (version < 3) ADDED_IN_V3 else emptySet()) + (if (version < 4) ADDED_IN_V4 else emptySet())
    }
    fun includes(module: ScanModule) = module.id in enabled
    fun with(module: ScanModule, selected: Boolean) = copy(enabled =
        if (selected) enabled + module.id else enabled - module.id)
}
