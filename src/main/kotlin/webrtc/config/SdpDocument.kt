package webrtc.config

/** Bounded SDP model. Attributes inherit from the session, never from a sibling m-line. */
data class SdpDocument(val session: List<String>, val media: List<Media>, val bundles: List<List<String>>) {
    data class Media(val index: Int, val kind: String, val port: Int?, val protocol: String,
                     val formats: List<String>, val lines: List<String>) {
        val mid: String get() = values("mid").firstOrNull() ?: "#$index"
        fun values(name: String): List<String> = attributes(lines, name)
        val rtp: Boolean get() = kind in setOf("audio", "video") && protocol.contains("RTP", true)
    }
    fun active(m: Media): Boolean = m.port != 0 ||
        (m.lines.contains("a=bundle-only") && bundles.any { m.mid in it && it.firstOrNull() != m.mid &&
            media.any { tag -> tag.mid == it.firstOrNull() && tag.port != 0 } })
    fun values(m: Media, name: String): List<String> = m.values(name).ifEmpty { attributes(session, name) }
    // A bundle-only offer uses the tagged section's transport; ordinary offers can
    // still propose independent transports, so do not infer negotiated BUNDLE.
    fun transportValues(m: Media, name: String): List<String> = values(m, name).ifEmpty {
        if (!m.lines.contains("a=bundle-only") || !active(m)) emptyList() else {
            val tag = bundles.firstOrNull { m.mid in it }?.firstOrNull()
            media.firstOrNull { it.mid == tag }?.let { values(it, name) }.orEmpty()
        }
    }
    fun credentials(): Map<String, Detectors.IceCredential> = media.filter(::active).mapNotNull { m ->
        val u = transportValues(m, "ice-ufrag").singleOrNull()
        val p = transportValues(m, "ice-pwd").singleOrNull()
        if (u == null || p == null) null else m.mid to Detectors.IceCredential(u, p)
    }.toMap().ifEmpty {
        if (media.isNotEmpty()) emptyMap() else {
            val u = attributes(session, "ice-ufrag").singleOrNull()
            val p = attributes(session, "ice-pwd").singleOrNull()
            if (u == null || p == null) emptyMap() else mapOf("session" to Detectors.IceCredential(u, p))
        }
    }
    companion object {
        fun attributes(lines: List<String>, name: String): List<String> = lines.mapNotNull {
            when { it == "a=$name" -> ""; it.startsWith("a=$name:") -> it.substring(name.length + 3); else -> null }
        }
        fun parse(text: String): SdpDocument {
            require(text.length <= 1_048_576) { "SDP exceeds 1 MiB" }
            val session = mutableListOf<String>()
            val sections = mutableListOf<MutableList<String>>()
            text.lineSequence().take(16384).map(String::trim).filter(String::isNotEmpty).forEach {
                if (it.startsWith("m=")) sections += mutableListOf(it)
                else if (sections.isEmpty()) session += it else sections.last() += it
            }
            val media = sections.mapIndexed { i, lines ->
                val fields = lines.first().substring(2).split(Regex("\\s+"))
                Media(i, fields.firstOrNull().orEmpty(), fields.getOrNull(1)?.substringBefore('/')?.toIntOrNull(),
                    fields.getOrNull(2).orEmpty(), fields.drop(3), lines)
            }
            val bundles = attributes(session, "group").filter { it.startsWith("BUNDLE ") }
                .map { it.split(Regex("\\s+")).drop(1) }
            return SdpDocument(session, media, bundles)
        }
    }
}
