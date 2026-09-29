package webrtc.internals

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import webrtc.config.Detectors
import webrtc.config.IpAddresses
import webrtc.telemetry.TelemetryEvent

/**
 * Compares an imported `chrome://webrtc-internals` dump with the telemetry the
 * extension captured through the W3C JS API.
 *
 * The two views are produced under different conditions (Chrome's page shows the
 * engine's view at export time; the extension records what it observed while
 * browsing), so a mismatch is a lead to investigate, never a confirmed
 * vulnerability. The comparator says so in its output and never invents a
 * finding.
 */
object InternalsComparator {

    enum class Level { FINDING, WARN, OK, INFO }
    data class Line(val level: Level, val text: String)

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    fun compare(dump: InternalsDump, events: List<TelemetryEvent>): List<Line> {
        val out = mutableListOf<Line>()

        if (dump.isEmpty) {
            out += Line(
                Level.WARN,
                "The imported file did not contain any ICE candidates, SDP, codecs, or ciphers. In Chrome, " +
                    "open chrome://webrtc-internals during the call and use 'Download the PeerConnection updates " +
                    "and stats data' (or copy the page text), then import that file."
            )
            return out
        }

        dump.userAgent?.let { out += Line(Level.INFO, "Imported Chrome dump reported by: $it") }

        val extCandidates = events.filter { it.type == "ice" }
            .mapNotNull { field(it, "candidate") }.filter { it.isNotBlank() }.distinct()
        val extAddresses = extCandidates.flatMap { listOfNotNull(InternalsDump.addressOf(it), InternalsDump.relatedAddressOf(it)) }.toSet()
        val extCodecs = events.filter { it.type == "sdp-local" || it.type == "sdp-remote" }
            .mapNotNull { field(it, "sdp") }
            .flatMap { Detectors.enumerateCodecs(it) }.toSet()
        val extCrypto = events.filter { it.type == "crypto" }.mapNotNull { field(it, "detail") }

        compareCandidates(dump, extCandidates, extAddresses, out)
        compareCrypto(dump, extCrypto, out)
        compareCodecs(dump, extCodecs, out)

        out += Line(Level.INFO, "Cross-check only: the dump and the extension may cover different sessions or peers.")
        return out
    }

    private fun compareCandidates(
        dump: InternalsDump,
        extCandidates: List<String>,
        extAddresses: Set<String>,
        out: MutableList<Line>
    ) {
        if (dump.candidates.isEmpty() && dump.addresses.isEmpty()) return
        out += Line(
            Level.INFO,
            "Chrome's engine reported ${dump.candidates.size} ICE candidate(s) across ${dump.addresses.size} " +
                "address(es); the extension captured ${extCandidates.size} candidate(s) across ${extAddresses.size} address(es)."
        )

        val onlyDump = (dump.addresses - extAddresses).sorted()
        val onlyExt = (extAddresses - dump.addresses).sorted()
        if (onlyDump.isNotEmpty())
            out += Line(
                Level.WARN,
                "Address(es) in the Chrome dump but not in extension telemetry: ${onlyDump.joinToString(", ")}. " +
                    "This can be a different page/session, a candidate the extension did not observe (e.g. trickle " +
                    "timing), or an mDNS/private address worth reviewing — confirm against the Telemetry (M2) rows."
            )
        if (onlyExt.isNotEmpty())
            out += Line(
                Level.INFO,
                "Address(es) captured by the extension but not in the Chrome dump: ${onlyExt.joinToString(", ")} " +
                    "(often a different session or candidate set)."
            )
        if (onlyDump.isEmpty() && onlyExt.isEmpty())
            out += Line(Level.OK, "ICE candidate addresses match the Chrome dump.")

        val mdns = dump.addresses.filter { it.endsWith(".local", true) }
        if (mdns.isNotEmpty()) out += Line(Level.INFO,
            "Chrome reported mDNS hostnames: ${mdns.sorted().joinToString(", ")}. These conceal the underlying IP; this is not proof of private-IP disclosure.")
        val privateDump = dump.addresses.filter { IpAddresses.isPrivate(it) }
        if (privateDump.isNotEmpty())
            out += Line(
                Level.INFO,
                "Chrome's local diagnostics contain private IP address(es): ${privateDump.sorted().joinToString(", ")}. " +
                    "A local dump alone does not prove these addresses were disclosed to the application or remote peer."
            )
    }

    private fun compareCrypto(dump: InternalsDump, extCrypto: List<String>, out: MutableList<Line>) {
        if (dump.dtlsCiphers.isEmpty() && dump.srtpCiphers.isEmpty() && dump.tlsVersions.isEmpty()) return

        val detail = "dtls=${dump.dtlsCiphers.joinToString(",")} srtp=${dump.srtpCiphers.joinToString(",")} " +
            "tls=${dump.tlsVersions.map { it.removePrefix("TLS ").removePrefix("DTLS ").trim() }.joinToString(",")}"
        val findings = Detectors.analyzeTransportSecurity(detail)
        findings.forEach { out += Line(Level.FINDING, "Chrome dump transport: $it") }

        val extText = extCrypto.joinToString(" ")
        val missing = (dump.dtlsCiphers + dump.srtpCiphers).filter { !extText.contains(it, ignoreCase = true) }
        if (missing.isNotEmpty())
            out += Line(
                Level.WARN,
                "Chrome's stats reported cipher(s) the extension did not capture: ${missing.sorted().joinToString(", ")}. " +
                    "Compare matching peers and collection times; absent telemetry is unknown, not evidence of absent encryption."
            )
        else if (findings.isEmpty() && dump.dtlsCiphers.isNotEmpty())
            out += Line(Level.OK, "The reported cipher values match extension telemetry; no weak cipher was identified. This does not assess missing fields or prove session equivalence.")
        if (dump.dtlsCiphers.isEmpty()) out += Line(Level.WARN, "DTLS cipher was not present in the dump; encryption status is unknown.")
    }

    private fun compareCodecs(dump: InternalsDump, extCodecs: Set<String>, out: MutableList<Line>) {
        if (dump.codecs.isEmpty()) return
        out += Line(Level.INFO, "Chrome's dump advertises codecs: ${dump.codecs.sorted().joinToString(", ")}.")
        val onlyDump = (dump.codecs - extCodecs).sorted()
        if (onlyDump.isNotEmpty())
            out += Line(
                Level.WARN,
                "Codec(s) in the Chrome dump not seen in captured SDP: ${onlyDump.joinToString(", ")}. " +
                    "This may be a codec the extension did not observe or a dump from another session."
            )
        else if (extCodecs.isNotEmpty())
            out += Line(Level.OK, "Codec list matches captured SDP.")
    }

    private fun field(ev: TelemetryEvent, key: String): String? =
        runCatching { (json.parseToJsonElement(ev.raw).jsonObject[key] as? JsonPrimitive)?.contentOrNull }.getOrNull()

    /** Serialize comparison lines into a telemetry event's `raw` JSON. */
    fun encodeLines(lines: List<Line>): String = buildJsonObject {
        put("kind", "internals-comparison")
        put("lines", buildJsonArray {
            lines.forEach { line ->
                add(buildJsonObject {
                    put("level", line.level.name)
                    put("text", line.text)
                })
            }
        })
    }.toString()

    /** Recover comparison lines from a stored telemetry event's `raw` JSON. */
    fun decodeLines(raw: String): List<Line> = runCatching {
        val array = json.parseToJsonElement(raw).jsonObject["lines"]?.jsonArray ?: return emptyList()
        array.mapNotNull { element ->
            val obj = element.jsonObject
            val text = (obj["text"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null
            val level = runCatching { Level.valueOf((obj["level"] as? JsonPrimitive)?.contentOrNull ?: "INFO") }
                .getOrDefault(Level.INFO)
            Line(level, text)
        }
    }.getOrDefault(emptyList())
}
