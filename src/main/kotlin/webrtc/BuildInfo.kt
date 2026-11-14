package webrtc

import java.util.Properties

/**
 * The version of the actually-loaded artifact. Prefers the JAR manifest's
 * `Implementation-Version` (set from `project.version` at build time), then the
 * generated `webrtc-version.properties` resource, and only falls back to "dev"
 * when neither is available (e.g. running from an IDE classpath). This makes the
 * startup banner identify the build that is really loaded, not a hard-coded string.
 */
object BuildInfo {
    const val NAME = "BurpRTC"

    val version: String by lazy { detect() }

    private fun detect(): String {
        val fromManifest = BuildInfo::class.java.`package`?.implementationVersion
        if (!fromManifest.isNullOrBlank()) return fromManifest
        val fromResource = runCatching {
            BuildInfo::class.java.getResourceAsStream("/webrtc-version.properties")?.use { stream ->
                Properties().apply { load(stream) }.getProperty("version")
            }
        }.getOrNull()
        return fromResource?.takeIf { it.isNotBlank() } ?: "dev"
    }

    /** Banner written to Burp's extension Output console on load/reload. */
    fun loadedMessage(): String = "$NAME v$version loaded"
}
