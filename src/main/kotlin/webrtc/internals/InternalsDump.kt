package webrtc.internals

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import webrtc.config.Detectors
import webrtc.config.IpAddresses
import java.io.File
import java.util.zip.GZIPInputStream

/**
 * A parsed `chrome://webrtc-internals` export.
 *
 * Chrome's privileged page cannot be read by the extension, so the tester exports
 * the dump (the "Download the PeerConnection updates and stats data" button, or a
 * copy of the page) and imports it here for comparison with what the extension
 * captured through the W3C JS API.
 *
 * The parser is deliberately tolerant. Chrome's dump shape has changed across
 * versions and a user may paste plain text instead of a JSON file, so this walks
 * any JSON recursively and otherwise scans text, pulling out only what the
 * comparison needs: ICE candidates and their addresses, codecs, DTLS/SRTP/TLS
 * ciphers, and whether SDP was present. It is a best-effort extractor, not a
 * faithful re-serialization of the dump.
 */
data class InternalsDump(
    val userAgent: String? = null,
    val candidates: Set<String> = emptySet(),
    val addresses: Set<String> = emptySet(),
    val codecs: Set<String> = emptySet(),
    val dtlsCiphers: Set<String> = emptySet(),
    val srtpCiphers: Set<String> = emptySet(),
    val tlsVersions: Set<String> = emptySet(),
    val sdpBlocks: Int = 0,
    val mdnsNames: Set<String> = emptySet()
) {
    /** True when nothing the comparator understands was found in the input. */
    val isEmpty: Boolean
        get() = candidates.isEmpty() && addresses.isEmpty() && codecs.isEmpty() && dtlsCiphers.isEmpty() &&
            srtpCiphers.isEmpty() && tlsVersions.isEmpty() && sdpBlocks == 0

    companion object {
        private val json = Json { ignoreUnknownKeys = true; isLenient = true }

        private val addressKey = Regex("(?i)(?:.*[-_])?(?:address|ip|ipAddress|relatedAddress)")
        private val mdnsRegex = Regex("""[0-9a-fA-F-]{36}\.local""")
        private val dtlsCipherRegex = Regex("""(?i)\bTLS_[A-Z0-9_]+\b""")
        private val srtpCipherRegex = Regex("""(?i)\b(SRTP_[A-Z0-9_]+|AEAD_[A-Z0-9_]+|AES_CM_[A-Z0-9_]+)\b""")
        private val tlsVersionRegex = Regex("""(?i)^(?:D?TLS)\s?\d(?:\.\d)?$""")
        private val userAgentHint = Regex("""(Mozilla/|AppleWebKit/|Chrome/\d)""")

        /** Detect gzip by its bytes, including Chrome's extensionless exports. */
        fun read(file: File): InternalsDump = file.inputStream().buffered().use { input ->
            input.mark(2)
            val gzip = input.read() == 0x1f && input.read() == 0x8b
            input.reset()
            val decoded = if (gzip) GZIPInputStream(input) else input
            decoded.use { stream ->
                val limit = 64 * 1024 * 1024
                val bytes = stream.readNBytes(limit + 1)
                require(bytes.size <= limit) { "Dump exceeds the 64 MiB decompressed import limit." }
                require(gzip || !file.name.endsWith(".gz", true)) { "The .gz file is not a valid gzip dump." }
                parse(bytes.toString(Charsets.UTF_8).removePrefix("\uFEFF"))
            }
        }

        /** Parse a dump from JSON text or from a plain-text copy of the page. */
        fun parse(text: String): InternalsDump {
            val b = Builder()
            val trimmed = text.trim()
            val element: JsonElement? = if (trimmed.isEmpty()) null
                else runCatching { json.parseToJsonElement(trimmed) }.getOrNull()
            when (element) {
                is JsonObject -> walkObject(element, b)
                is JsonArray -> element.forEach { walk(it, null, b) }
                is JsonPrimitive -> handleString(element.contentOrNull, null, b)
                null -> handleString(trimmed, null, b)
            }
            return b.build()
        }

        private fun walk(element: JsonElement, key: String?, b: Builder) {
            when (element) {
                is JsonObject -> walkObject(element, b, key)
                is JsonArray -> element.forEach { walk(it, key, b) }
                is JsonPrimitive -> element.contentOrNull?.let { handleString(it, key, b) }
            }
        }

        private fun walkObject(obj: JsonObject, b: Builder, parentKey: String? = null) {
            for ((k, v) in obj) {
                val context = if (k == "values") parentKey else k
                // Chrome serializes stats time series as JSON strings in `values`.
                val series = if (k == "values" && v is JsonPrimitive)
                    runCatching { json.parseToJsonElement(v.content) }.getOrNull() else null
                walk(series ?: v, context, b)
            }
        }

        private fun handleString(value: String?, key: String?, b: Builder) {
            if (value.isNullOrBlank()) return
            val trimmed = value.trim()

            if (b.userAgent == null && (key.equals("userAgent", true) || userAgentHint.containsMatchIn(trimmed))) {
                // Only accept a short, UA-looking value so a large stats blob is not mistaken for one.
                if (trimmed.length <= 512) b.userAgent = trimmed
            }

            extractCandidates(trimmed, b)
            if (key != null && addressKey.matches(key)) {
                IpAddresses.normalize(trimmed)?.let { b.addresses += it }
            }

            mdnsRegex.findAll(trimmed).forEach { b.mdnsNames += it.value.lowercase() }

            // A whole SDP block (offer/answer).
            if (trimmed.contains("v=0") && trimmed.contains("m=")) b.sdpBlocks++
            // Plain-text internals exports may contain isolated rtpmap lines without m-sections.
            if (trimmed.contains("a=rtpmap:")) b.codecs += Regex("a=rtpmap:[0-9]+\\s+([A-Za-z0-9._-]+)/[0-9]+")
                .findAll(trimmed).map { it.groupValues[1] }.toList()

            // A stats "codec" / "mimeType" field, e.g. "VP8" or "audio/opus".
            if (key != null && (key.contains("codec", true) || key.equals("mimeType", true)) && trimmed.length <= 64) {
                val name = trimmed.substringAfterLast('/').trim()
                if (name.isNotEmpty() && name.none { it.isWhitespace() }) b.codecs += name
            }

            dtlsCipherRegex.findAll(trimmed).forEach { b.dtlsCiphers += it.value.uppercase() }
            srtpCipherRegex.findAll(trimmed).forEach { b.srtpCiphers += it.value.uppercase() }
            if (key != null && key.contains("tlsVersion", true) && tlsVersionRegex.matches(trimmed)) {
                b.tlsVersions += trimmed
            } else if (tlsVersionRegex.matches(trimmed)) {
                b.tlsVersions += trimmed
            }
        }

        /** Collect full `candidate:...` strings and the addresses/related addresses in them. */
        private fun extractCandidates(text: String, b: Builder) {
            for (line in text.split('\n', '\r')) {
                val idx = line.indexOf("candidate:")
                if (idx < 0) continue
                val candidate = line.substring(idx).trim()
                    .trimEnd('"', ',', '\\', ' ', '\t', '{', '}')
                if (addressOf(candidate) != null) {
                    b.candidates += candidate
                    addressOf(candidate)?.let { b.addresses += it }
                    relatedAddressOf(candidate)?.let { b.addresses += it }
                }
            }
            // Copied tables may contain explicit address/ip fields. Never interpret
            // timestamps, SDP fingerprints or arbitrary strings as addresses.
            for (line in text.lineSequence()) {
                val match = Regex("(?i)^\\s*(?:address|ip|relatedAddress)\\s*[:=\\t ]\\s*(\\S+)\\s*$").matchEntire(line)
                match?.groupValues?.get(1)?.let { IpAddresses.normalize(it) }?.let { b.addresses += it }
            }
        }

        /** The address field of an ICE candidate string, or null. */
        fun addressOf(candidate: String): String? {
            val tokens = candidate.trim().split(Regex("\\s+"))
            if (tokens.size < 8 || !tokens[0].startsWith("candidate:") || tokens[6] != "typ") return null
            return IpAddresses.normalize(tokens[4])
        }

        /** The `raddr` (related address) of a srflx/relay candidate, or null. */
        fun relatedAddressOf(candidate: String): String? {
            val tokens = candidate.trim().split(Regex("\\s+"))
            val i = tokens.indexOf("raddr")
            if (i < 0 || i + 1 >= tokens.size) return null
            return IpAddresses.normalize(tokens[i + 1])
        }
    }

    private class Builder {
        var userAgent: String? = null
        val candidates = linkedSetOf<String>()
        val addresses = linkedSetOf<String>()
        val codecs = linkedSetOf<String>()
        val dtlsCiphers = linkedSetOf<String>()
        val srtpCiphers = linkedSetOf<String>()
        val tlsVersions = linkedSetOf<String>()
        var sdpBlocks = 0
        val mdnsNames = linkedSetOf<String>()

        fun build() = InternalsDump(
            userAgent = userAgent,
            candidates = candidates,
            addresses = addresses,
            codecs = codecs,
            dtlsCiphers = dtlsCiphers,
            srtpCiphers = srtpCiphers,
            tlsVersions = tlsVersions,
            sdpBlocks = sdpBlocks,
            mdnsNames = mdnsNames
        )
    }
}
