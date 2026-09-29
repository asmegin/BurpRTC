package webrtc.scope

import burp.api.montoya.MontoyaApi

/** Every active action (inject, replay, mutate, fuzz) must pass through here first. */
class ScopeGate(private val api: MontoyaApi) {
    fun inScope(url: String): Boolean =
        runCatching { api.scope().isInScope(url) }.getOrDefault(false)

    companion object {
        fun hostAllowed(host: String, allow: List<String>): Boolean = allow.any { entry ->
            val value = entry.trim()
            value.equals("all", true) || (value.isNotEmpty() &&
                (host.equals(value, true) || host.endsWith(".$value", true)))
        }
    }
}
