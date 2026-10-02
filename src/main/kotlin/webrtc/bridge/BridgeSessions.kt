package webrtc.bridge

import java.net.URI
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64

/** Per-injection capabilities. A page cannot poll another page's commands by guessing an agent ID. */
class BridgeSessions {
    private data class Session(val frame: String, val created: Instant, var agent: String? = null)
    private val sessions = LinkedHashMap<String, Session>()
    @Synchronized fun issue(frame: String): String {
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).also(SecureRandom()::nextBytes))
        sessions[token] = Session(frame, Instant.now())
        while (sessions.size > 512) sessions.remove(sessions.keys.first())
        return token
    }
    @Synchronized fun permits(token: String, origin: String, frame: String, agent: String): Boolean {
        val session = sessions[token] ?: return false
        if (session.created.plusSeconds(43200).isBefore(Instant.now())) { sessions.remove(token); return false }
        if (frame != session.frame || origin != originOf(frame) || agent.isBlank() || agent.length > 160) return false
        if (session.agent == null) session.agent = agent
        return session.agent == agent
    }
    @Synchronized fun acceptsOrigin(token: String, origin: String): Boolean =
        sessions[token]?.let { origin == originOf(it.frame) && it.created.plusSeconds(43200).isAfter(Instant.now()) } == true
    @Synchronized fun clear() = sessions.clear()
    companion object {
        fun originOf(frame: String): String = runCatching { URI(frame).let { "${it.scheme}://${it.rawAuthority}" } }.getOrDefault("")
    }
}
