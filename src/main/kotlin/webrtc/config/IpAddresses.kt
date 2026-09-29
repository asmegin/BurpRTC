package webrtc.config

import java.net.InetAddress

/** Literal-only parsing: never resolve hostnames or scan arbitrary text for IP fragments. */
object IpAddresses {
    fun literal(value: String): InetAddress? {
        val text = value.removePrefix("[").removeSuffix("]")
        if (text.contains(':')) {
            if (!text.matches(Regex("[0-9a-fA-F:.]+"))) return null
        } else {
            val parts = text.split('.')
            if (parts.size != 4 || parts.any { !it.matches(Regex("[0-9]{1,3}")) || it.toInt() !in 0..255 }) return null
        }
        return runCatching { InetAddress.getByName(text) }.getOrNull()
    }

    fun normalize(value: String): String? {
        if (value.matches(Regex("(?i)[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.local"))) return value.lowercase()
        return literal(value)?.takeUnless { it.isAnyLocalAddress }?.hostAddress?.lowercase()
    }

    fun isPrivate(value: String): Boolean {
        val ip = literal(value) ?: return false
        val bytes = ip.address
        return ip.isSiteLocalAddress || ip.isLinkLocalAddress || ip.isLoopbackAddress ||
            (bytes.size == 16 && (bytes[0].toInt() and 0xfe) == 0xfc)
    }
}
