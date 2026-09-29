package webrtc.external

import java.net.URI

/**
 * One ready-to-copy external-tool recipe. [command] is a complete Bash block:
 * assignment lines for every detected value (correctly quoted) followed by the
 * tool command with `$VAR` references. Values that were not detected appear as
 * `<NAME>` placeholders and are listed in [missing], so the recipe is visibly
 * incomplete rather than silently dropped or populated with invented values.
 */
data class Recipe(
    val id: String,
    val tool: String,
    val title: String,
    val purpose: String,
    val coverage: String,
    val prerequisites: String,
    val setupUrl: String,
    val sourceUrl: String,
    val evidence: String,
    val effects: String,
    val limitations: String,
    val missing: List<String>,
    val command: String,
    val notApplicableReason: String? = null
) {
    val ready: Boolean get() = missing.isEmpty() && notApplicableReason == null
    val status: String get() = when { notApplicableReason != null -> "Not applicable"; ready -> "Ready"; else -> "Missing" }
}

/**
 * Builds Linux/Bash commands for the ten initial external RTC testing tools from
 * passively observed telemetry and Config. It only renders text; it never executes
 * a tool, and a ready command is not a completed scan.
 */
object ExternalTools {

    /** Short descriptions used when an input could not be detected. */
    private val labels = mapOf(
        "TURN_ENDPOINT" to "TURN host:port",
        "TURN_HOST" to "TURN hostname",
        "TURN_PORT" to "TURN port",
        "TURN_USER" to "TURN username",
        "TURN_PASSWORD" to "TURN password",
        "TURN_PROTOCOL" to "TURN transport (udp/tcp)",
        "STUN_HOST" to "STUN hostname",
        "STUN_PORT" to "STUN port",
        "TEST_PEER_IP" to "test peer IP",
        "TEST_PEER_PORTS" to "test peer ports",
        "TEST_PEER_ENDPOINT" to "test peer host:port",
        "ALLOCATION_COUNT" to "allocation count",
        "TURNT_ICE_URL" to "TURN URL for TURNt",
        "TURNT_CONFIG" to "valid TURNt configuration (turn:/turns: URL, username and password)",
        "TURNT_OFFER" to "runtime offer from the controller",
        "TEST_URL" to "URL to fetch over the tunnel",
        "SIP_HOST" to "SIP hostname",
        "SIP_PORT" to "SIP port",
        "SIP_PROTOCOL" to "SIP transport (udp/tcp/tls)",
        "SIP_TARGET" to "SIP target (host:port or WS/WSS URL)",
        "SIP_USER" to "SIP username",
        "SIP_PASSWORD" to "SIP password",
        "SIP_TEST_URI" to "SIP test URI",
        "EXTENSION_RANGE" to "SIP extension range",
        "PASSWORD_FILE" to "password list path",
        "SIPPTS_REPORT" to "SIPPTS output path",
        "MEDIA_IP" to "media endpoint IP",
        "RTP_START_PORT" to "RTP range start port",
        "RTP_END_PORT" to "RTP range end port",
        "RTP_PAYLOAD_TYPE" to "RTP payload type",
        "TARGET_HOST" to "target host",
        "NMAP_OUTPUT_PREFIX" to "Nmap output prefix",
        "TLS_ENDPOINT" to "TLS hostname:port",
        "TLS_REPORT" to "TLS report path",
        "CAPTURE_INTERFACE" to "capture interface",
        "CAPTURE_FILTER" to "capture filter",
        "PCAP_FILE" to "pcap output path"
    )

    fun describe(name: String): String = labels[name] ?: name.replace('_', ' ').lowercase()

    /** Build the ordered catalogue of recipes for the current inputs. */
    fun catalogue(inputs: ExternalInputs, manual: Map<String, String>): List<Recipe> {
        val vars = buildValues(inputs, manual)
        fun v(name: String) = vars[name]
        fun r(
            id: String, tool: String, title: String, purpose: String, coverage: String,
            prerequisites: String, setupUrl: String, sourceUrl: String, evidence: String,
            effects: String, limitations: String, command: String
        ) = make(id, tool, title, purpose, coverage, prerequisites, setupUrl, sourceUrl,
            evidence, effects, limitations, command, vars)

        return listOf(
            r(
                "stunner-range", "stunner", "Broad: restricted-address range scan",
                "Check which destinations the TURN server allows, using stunner's built-in private/restricted address cases.",
                "Runs stunner's range-scan subcommand; not a universal scan-all.",
                "stunner installed and built from source.", "https://github.com/firefart/stunner",
                "https://github.com/firefart/stunner",
                "Allocations/permissions granted for addresses that should be restricted.",
                "Sends TURN allocation requests from your host.", "Upstream is noncommercial-licensed; review before use.",
                "stunner range-scan -s \"{TURN_ENDPOINT}\" -u \"{TURN_USER}\" -p \"{TURN_PASSWORD}\" --protocol \"{TURN_PROTOCOL}\""
            ),
            r(
                "stunner-info", "stunner", "Focused: server information",
                "Query TURN server information without a destination scan.",
                "stunner info subcommand only.",
                "stunner installed.", "https://github.com/firefart/stunner", "https://github.com/firefart/stunner",
                "Server software/attributes returned.", "One information request.", "Does not test destinations.",
                "stunner info -s \"{TURN_ENDPOINT}\" --protocol \"{TURN_PROTOCOL}\""
            ),
            r(
                "stunner-tcp", "stunner", "Focused: HTTP reachability through TURN",
                "Test whether the TURN server relays TCP/HTTP to a specific destination.",
                "stunner tcp-scanner against one explicit destination.",
                "stunner installed; an explicit destination is required (omitting --ip broadens the scan).",
                "https://github.com/firefart/stunner", "https://github.com/firefart/stunner",
                "Successful permission/allocation to the destination.",
                "Sends relay requests toward the destination.", "A permission is not proof that data reached the destination.",
                "stunner tcp-scanner -s \"{TURN_ENDPOINT}\" -u \"{TURN_USER}\" -p \"{TURN_PASSWORD}\" --protocol \"{TURN_PROTOCOL}\" --ip \"{TEST_PEER_IP}\" --ports \"{TEST_PEER_PORTS}\""
            ),
            r(
                "turnado-info", "TURNado", "Broad: capabilities and permissions",
                "Actively probe TURN allocation/permission capabilities, including loopback permissions.",
                "TURNado info mode performs active checks, not a passive banner lookup.",
                "TURNado installed.", "https://github.com/SySS-Research/TURNado", "https://github.com/SySS-Research/TURNado",
                "Capabilities and loopback permission results.",
                "Creates allocations on the server.", "Specialist tool with smaller adoption.",
                "turnado info -t \"{TURN_ENDPOINT}\" -T \"{TURN_PROTOCOL}\" -u \"{TURN_USER}\" -p \"{TURN_PASSWORD}\""
            ),
            r(
                "turnado-forward", "TURNado", "Focused: UDP forwarding to a test peer",
                "Forward UDP through TURN to a specified test peer and local listener.",
                "TURNado forward mode.",
                "TURNado installed; a test peer endpoint and a local listener.",
                "https://github.com/SySS-Research/TURNado", "https://github.com/SySS-Research/TURNado",
                "UDP data forwarded through the relay.",
                "Opens a local listener and sends relay traffic.", "Successful forwarding alone does not prove an authorization bug.",
                "turnado forward -t \"{TURN_ENDPOINT}\" -T \"{TURN_PROTOCOL}\" -u \"{TURN_USER}\" -p \"{TURN_PASSWORD}\" -P \"{TEST_PEER_ENDPOINT}\" -l 127.0.0.1:9999"
            ),
            r(
                "turnado-dos", "TURNado", "Intensive: allocation stress (30s cap)",
                "Stress the TURN server's allocation handling; stopped after 30 seconds.",
                "TURNado dos mode, bounded by timeout.",
                "TURNado installed; an allocation count; confirmed authorization to stress the service.",
                "https://github.com/SySS-Research/TURNado", "https://github.com/SySS-Research/TURNado",
                "Allocation behavior under load / errors.",
                "Consumes server allocations and may degrade service.", "The timeout exit status does not by itself mean allocations failed; only run with permission.",
                "timeout --signal=INT 30s turnado dos -t \"{TURN_ENDPOINT}\" -T \"{TURN_PROTOCOL}\" -u \"{TURN_USER}\" -p \"{TURN_PASSWORD}\" -s \"{ALLOCATION_COUNT}\""
            ),
            r(
                "turnt-tunnel", "TURNt", "Two-host tunnel verification workflow",
                "Verify a complete TURN tunnel: controller on host A, relay on host B, then fetch a URL through the SOCKS proxy.",
                "TURNt has no scan-all command; this is its documented two-host workflow.",
                "TURNt built on both hosts; export turnt-config.yaml from this tab; a URL to fetch.",
                "https://github.com/praetorian-inc/turnt", "https://github.com/praetorian-inc/turnt",
                "Successful forwarding demonstrates tunnel capability.",
                "Opens a SOCKS listener (host A) and a relay (host B).",
                "Successful forwarding alone does not establish an authorization bug; exchange the runtime offer/answer manually.",
                "# Host A: start the controller with the exported configuration\n" +
                    "turnt-controller -config turnt-config.yaml -socks 127.0.0.1:1080\n\n" +
                    "# Host B: paste the offer produced by the controller\n" +
                    "turnt-relay -offer \"{TURNT_OFFER}\"\n\n" +
                    "# Host A: paste the relay's answer into the controller, then verify\n" +
                    "curl --socks5-hostname 127.0.0.1:1080 \"{TEST_URL}\""
            ),
            r(
                "coturn-uclient", "coturn utilities", "Main: allocate and exchange messages",
                "Independently verify TURN allocation and data transfer between test clients.",
                "turnutils_uclient allocates relays and exchanges messages.",
                "coturn utilities installed.", "https://github.com/coturn/coturn",
                "https://github.com/coturn/coturn/blob/master/man/man1/turnutils.1",
                "Relay allocation plus five exchanged messages.",
                "Consumes allocations.", "A protocol/transfer check, not a vulnerability scan.",
                "turnutils_uclient -v -y -n 5 -u \"{TURN_USER}\" -w \"{TURN_PASSWORD}\" -p \"{TURN_PORT}\" \"{TURN_HOST}\""
            ),
            r(
                "coturn-negative", "coturn utilities", "Focused: limited negative tests",
                "Run turnutils_uclient's limited negative/auth tests.",
                "Negative mode only.", "coturn utilities installed.",
                "https://github.com/coturn/coturn", "https://github.com/coturn/coturn/blob/master/man/man1/turnutils.1",
                "Authentication/negative-path behavior.", "Consumes allocations.", "Not comprehensive.",
                "turnutils_uclient -v -y -N -n 5 -u \"{TURN_USER}\" -w \"{TURN_PASSWORD}\" -p \"{TURN_PORT}\" \"{TURN_HOST}\""
            ),
            r(
                "coturn-stunclient", "coturn utilities", "Focused: STUN binding information",
                "Query UDP STUN binding information with turnutils_stunclient.",
                "UDP STUN only.", "coturn utilities installed.",
                "https://github.com/coturn/coturn", "https://github.com/coturn/coturn/blob/master/man/man1/turnutils.1",
                "Mapped public address.", "One STUN binding request.", "UDP STUN only.",
                "turnutils_stunclient -p \"{STUN_PORT}\" \"{STUN_HOST}\""
            ),
            r(
                "sippts-scan", "SIPPTS", "Broad: SIP discovery across ports/transports",
                "Scan all ports over UDP/TCP/TLS for SIP services and fingerprint CVEs.",
                "The broad command scans ports/transports; it does not run every SIPPTS module.",
                "SIPPTS installed; a SIP service or broad host.", "https://github.com/Pepelux/sippts",
                "https://github.com/Pepelux/sippts",
                "Discovered SIP services and fingerprint-based CVE leads.", "Sends SIP traffic across ports.",
                "CVE matches are fingerprint leads, not confirmed vulnerabilities.",
                "sippts scan -i \"{SIP_HOST}\" -r all -p all -fp -cve -o \"{SIPPTS_REPORT}\""
            ),
            r(
                "sippts-enumerate", "SIPPTS", "Focused: SIP method enumeration",
                "Enumerate supported SIP methods on the selected service.",
                "Method enumeration only.", "SIPPTS installed; SIP host/port/protocol.",
                "https://github.com/Pepelux/sippts", "https://github.com/Pepelux/sippts/wiki/Command-enumerate",
                "Supported SIP methods.", "Sends multiple SIP methods.",
                "Method enumeration sends several requests; only use on authorized services.",
                "sippts enumerate -i \"{SIP_HOST}\" -r \"{SIP_PORT}\" -p \"{SIP_PROTOCOL}\""
            ),
            r(
                "sippts-rtpbleed", "SIPPTS", "Focused: RTP Bleed against confirmed media",
                "Probe for RTP Bleed only against a confirmed media endpoint/range.",
                "rtpbleed subcommand.", "SIPPTS installed; confirmed media IP, port range and payload type.",
                "https://github.com/Pepelux/sippts", "https://github.com/Pepelux/sippts/wiki/Command-rtpbleed",
                "Responses to injected RTP that indicate media bleed.", "Injects raw RTP toward the media endpoint.",
                "Do not apply blindly to browser SRTP/ICE candidates; requires confirmed plaintext media.",
                "sippts rtpbleed -i \"{MEDIA_IP}\" -s \"{RTP_START_PORT}\" -e \"{RTP_END_PORT}\" -l 1 -p \"{RTP_PAYLOAD_TYPE}\""
            ),
            r(
                "sipvicious-svmap", "SIPVicious OSS", "Broad: SIP OPTIONS discovery",
                "Discover SIP services across all UDP ports of the selected host.",
                "svmap over UDP.", "SIPVicious installed.", "https://github.com/EnableSecurity/sipvicious",
                "https://github.com/EnableSecurity/sipvicious/wiki/SVMap-Usage",
                "Responding SIP services.", "Sends SIP OPTIONS to all UDP ports.",
                "Recipes target SIP over UDP; add documented IPv6 options if needed.",
                "sipvicious_svmap -p 1-65535 \"{SIP_HOST}\""
            ),
            r(
                "sipvicious-svwar", "SIPVicious OSS", "Focused: extension enumeration",
                "Enumerate a specified extension range.",
                "svwar only.", "SIPVicious installed; an explicit extension range.",
                "https://github.com/EnableSecurity/sipvicious", "https://github.com/EnableSecurity/sipvicious/wiki/SVWar-Usage",
                "Valid extensions.", "Sends registration/INVITE probes for the range.",
                "Do not infer extensions from unrelated meeting IDs.",
                "sipvicious_svwar -p \"{SIP_PORT}\" -e \"{EXTENSION_RANGE}\" \"{SIP_HOST}\""
            ),
            r(
                "sipvicious-svcrack", "SIPVicious OSS", "Intensive: dictionary password test",
                "Dictionary password test for one specified account.",
                "svcrack only.", "SIPVicious installed; test account and password-file path.",
                "https://github.com/EnableSecurity/sipvicious", "https://github.com/EnableSecurity/sipvicious/wiki/SVCrack-Usage",
                "Account credentials accepted from the list.", "Attempts many authentications; may lock accounts.",
                "Only run against accounts you are authorized to test.",
                "sipvicious_svcrack -p \"{SIP_PORT}\" -u \"{SIP_USER}\" -d \"{PASSWORD_FILE}\" \"{SIP_HOST}\""
            ),
            r(
                "sipexer-options", "sipexer", "Main: OPTIONS over the observed transport",
                "Send a SIP OPTIONS request using the observed transport, including WS/WSS.",
                "sipexer has no universal scan-all mode; this is the basic request.",
                "sipexer installed; SIP target preserving transport and full WS/WSS path.",
                "https://github.com/miconda/sipexer", "https://github.com/miconda/sipexer",
                "Server capabilities/response code.", "One SIP request.", "Not a scan-all.",
                "sipexer -sd \"{SIP_TARGET}\""
            ),
            r(
                "sipexer-register", "sipexer", "Focused: registration with a test account",
                "Register a specified test account and observe the result.",
                "Registration scenario.", "sipexer installed; test account credentials.",
                "https://github.com/miconda/sipexer", "https://github.com/miconda/sipexer",
                "Registration accepted/rejected.", "Creates a registration on the server.",
                "Label the effect; requires account and deployment-specific identity inputs.",
                "sipexer -register -cb -ex 60 -au \"{SIP_USER}\" -ap \"{SIP_PASSWORD}\" -sd \"{SIP_TARGET}\""
            ),
            r(
                "sipexer-invite", "sipexer", "Focused: short signaling call",
                "Initiate a short SIP call to a specified test URI.",
                "INVITE scenario.", "sipexer installed; test account and destination URI.",
                "https://github.com/miconda/sipexer", "https://github.com/miconda/sipexer",
                "Call setup signaling.", "Places a call to the destination.",
                "Only call numbers/URIs you are authorized to contact.",
                "sipexer -invite -au \"{SIP_USER}\" -ap \"{SIP_PASSWORD}\" -ruri \"{SIP_TEST_URI}\" -cb -sd -sw 5000 \"{SIP_TARGET}\""
            ),
            r(
                "nmap-broad", "Nmap", "Broad: full port/service assessment with RTC scripts",
                "Full TCP/UDP port scan with service detection and selected RTC/TLS NSE scripts.",
                "Every TCP/UDP port; can be lengthy. Individual NSE scripts run only when their rules match.",
                "nmap installed with sudo; authorization for a full-port scan.",
                "https://github.com/nmap/nmap", "https://nmap.org/book/man-port-specification.html",
                "Open ports/services and script output where rules matched.", "Full-port scan generates significant traffic.",
                "All ports and all vulnerability checks are different claims; scripts may not run.",
                "sudo nmap -Pn -sS -sU -sV -p- --script stun-info,sip-methods,ssl-cert,ssl-enum-ciphers -oA \"{NMAP_OUTPUT_PREFIX}\" \"{TARGET_HOST}\""
            ),
            r(
                "nmap-stun", "Nmap", "Focused: STUN information",
                "Run the stun-info NSE script against the observed UDP STUN listener.",
                "One UDP service/port.", "nmap installed with sudo.",
                "https://github.com/nmap/nmap", "https://nmap.org/nsedoc/scripts/stun-info.html",
                "STUN server attributes.", "Targeted UDP probe.", "UDP only; not TLS/WS endpoints.",
                "sudo nmap -Pn -sU -sV -p \"{STUN_PORT}\" --script stun-info \"{STUN_HOST}\""
            ),
            r(
                "nmap-sip", "Nmap", "Focused: SIP methods",
                "Run the sip-methods NSE script against the observed UDP SIP service.",
                "One UDP service/port.", "nmap installed with sudo.",
                "https://github.com/nmap/nmap", "https://nmap.org/nsedoc/scripts/sip-methods.html",
                "Supported SIP methods.", "Targeted UDP probe.", "UDP only; not TLS/WS endpoints.",
                "sudo nmap -Pn -sU -sV -p \"{SIP_PORT}\" --script sip-methods \"{SIP_HOST}\""
            ),
            r(
                "testssl-audit", "testssl.sh", "Broad: complete default TLS audit",
                "Run testssl.sh's full default audit against an HTTPS/WSS, SIP-over-TLS or TURN-over-TLS listener.",
                "The default audit does not include every optional check.",
                "testssl.sh checkout installed.", "https://github.com/testssl/testssl.sh",
                "https://github.com/testssl/testssl.sh/blob/3.2/doc/testssl.1.md",
                "Protocol/cipher/vulnerability summary.", "Connects repeatedly to the TLS listener.",
                "Does not assess WebRTC's UDP DTLS media transport.",
                "./testssl.sh --warnings batch --jsonfile \"{TLS_REPORT}\" \"{TLS_ENDPOINT}\""
            ),
            r(
                "testssl-ciphers", "testssl.sh", "Focused: cipher enumeration per protocol",
                "Enumerate ciphers separately for each protocol.",
                "Adds cipher-per-protocol coverage.", "testssl.sh checkout installed.",
                "https://github.com/testssl/testssl.sh", "https://github.com/testssl/testssl.sh/blob/3.2/doc/testssl.1.md",
                "Cipher suites per protocol.", "Connects repeatedly.", "TLS only.",
                "./testssl.sh -E \"{TLS_ENDPOINT}\""
            ),
            r(
                "testssl-vulns", "testssl.sh", "Focused: supported TLS vulnerability checks",
                "Run the supported TLS vulnerability checks.",
                "Vulnerability checks only.", "testssl.sh checkout installed.",
                "https://github.com/testssl/testssl.sh", "https://github.com/testssl/testssl.sh/blob/3.2/doc/testssl.1.md",
                "Known-vulnerability results.", "Connects repeatedly.", "TLS only; not DTLS media.",
                "./testssl.sh -U \"{TLS_ENDPOINT}\""
            ),
            r(
                "tshark-capture", "Wireshark/TShark", "Main: live capture matching the endpoint filter",
                "Capture traffic for the selected endpoints for 60 seconds.",
                "Live capture on a Linux interface.",
                "TShark installed; interface name and capture privileges.",
                "https://github.com/wireshark/wireshark", "https://www.wireshark.org/docs/man-pages/tshark.html",
                "A pcap file for offline analysis.", "Captures packets on the chosen interface.",
                "TShark observes traffic; it is not a vulnerability scanner.",
                "tshark -i \"{CAPTURE_INTERFACE}\" -f \"{CAPTURE_FILTER}\" -a duration:60 -w \"{PCAP_FILE}\""
            ),
            r(
                "tshark-inspect", "Wireshark/TShark", "Focused: inspect RTC and signaling packets",
                "Inspect recognizable RTC and signaling packets in the capture.",
                "Offline analysis of an existing pcap.", "TShark installed; a pcap file.",
                "https://github.com/wireshark/wireshark", "https://www.wireshark.org/docs/man-pages/tshark.html",
                "Decoded STUN/DTLS/RTP/RTCP/SIP/WebSocket packets.",
                "Reads a file; no network traffic.", "Encrypted payloads stay encrypted without keys.",
                "tshark -r \"{PCAP_FILE}\" -Y 'stun || dtls || rtp || rtcp || sip || websocket' -V"
            ),
            r(
                "tshark-streams", "Wireshark/TShark", "Focused: summarize RTP streams",
                "Summarize recognized RTP streams in the capture.",
                "Offline RTP stream summary.", "TShark installed; a pcap containing RTP.",
                "https://github.com/wireshark/wireshark", "https://www.wireshark.org/docs/man-pages/tshark.html",
                "RTP stream summary.", "Reads a file; no network traffic.", "Recognition depends on the capture.",
                "tshark -r \"{PCAP_FILE}\" -q -z rtp,streams"
            )
        )
    }

    /** Render a TURNt configuration file from the detected TURN values, or null if none. */
    fun turntConfig(values: Map<String, String>): String? {
        val url = values["TURNT_ICE_URL"] ?: return null
        if (ExternalInputs.parseIceUrl(url)?.turn != true) return null
        val username = values["TURN_USER"]?.takeIf { it.isNotEmpty() } ?: return null
        val credential = values["TURN_PASSWORD"]?.takeIf { it.isNotEmpty() } ?: return null
        // JSON double-quoted scalars are valid YAML and preserve control characters.
        fun yaml(value: String) = kotlinx.serialization.json.JsonPrimitive(value).toString()
        return buildString {
            appendLine("ice_servers:")
            appendLine("  - urls:")
            appendLine("      - ${yaml(url)}")
            appendLine("    username: ${yaml(username)}")
            appendLine("    credential: ${yaml(credential)}")
        }
    }

    /** Quote a value for Bash so spaces, quotes, `$`, backticks and newlines are literal. */
    fun bashQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    private val placeholderRegex = Regex("\\{([A-Z0-9_]+)\\}")

    private fun make(
        id: String, tool: String, title: String, purpose: String, coverage: String,
        prerequisites: String, setupUrl: String, sourceUrl: String, evidence: String,
        effects: String, limitations: String, template: String, values: Map<String, String>
    ): Recipe {
        val used = LinkedHashSet<String>()
        val missing = LinkedHashSet<String>()
        val body = placeholderRegex.replace(template) { match ->
            val name = match.groupValues[1]
            used += name
            val value = values[name]
            if (value == null) { missing += name; "<$name>" } else "\$$name"
        }
        if (id == "turnt-tunnel") {
            listOf("TURNT_ICE_URL", "TURN_USER", "TURN_PASSWORD").forEach { name ->
                if (values[name].isNullOrEmpty()) missing += name
            }
            if (missing.isEmpty() && turntConfig(values) == null) missing += "TURNT_CONFIG"
            if (values["TURNT_ICE_URL"] != null && ExternalInputs.parseIceUrl(values.getValue("TURNT_ICE_URL"))?.turn != true)
                missing += "TURNT_CONFIG"
        }
        val notApplicable = if (used.any { it.startsWith("SIP_") } &&
            values["SIP_HOST"].isNullOrBlank() && values["SIP_TARGET"].isNullOrBlank())
            "SIP endpoint not observed or entered; enter a SIP target if applicable." else null
        val assignments = used.filter { values.containsKey(it) }.joinToString("\n") { name ->
            "$name=${bashQuote(values.getValue(name))}"
        }
        val missingNote = if (missing.isEmpty()) ""
        else "# Missing inputs — fill before running: " + missing.joinToString(", ") { "$it (${describe(it)})" }
        val command = listOf(assignments, missingNote, body).filter { it.isNotBlank() }.joinToString("\n")
        return Recipe(
            id, tool, title, purpose, coverage, prerequisites, setupUrl, sourceUrl,
            evidence, effects, limitations, missing.toList(), command, notApplicable
        )
    }

    /** Build the variable map from observed inputs and tester-entered manual values. */
    fun buildValues(inputs: ExternalInputs, manual: Map<String, String>): Map<String, String> {
        val values = LinkedHashMap<String, String>()
        manual.forEach { (k, value) -> if (value.isNotBlank()) values[k.uppercase()] = value }

        inputs.pageOrigins.forEach { origin ->
            val uri = runCatching { URI(origin) }.getOrNull()
            val host = uri?.host
            if (host != null) {
                values.putIfAbsent("TARGET_HOST", host)
                if (origin.startsWith("https")) {
                    val port = if (uri.port > 0) uri.port else 443
                    values.putIfAbsent("TLS_ENDPOINT", "$host:$port")
                }
            }
        }

        for (server in inputs.iceServers) {
            for (raw in server.urls) {
                val ice = ExternalInputs.parseIceUrl(raw) ?: continue
                if (ice.turn) {
                    values.putIfAbsent("TURN_HOST", ice.host)
                    values.putIfAbsent("TURN_PORT", ice.port.toString())
                    values.putIfAbsent("TURN_ENDPOINT", "${ice.host}:${ice.port}")
                    values.putIfAbsent("TURN_PROTOCOL", ice.transport ?: "udp")
                    values.putIfAbsent("TURNT_ICE_URL", raw)
                    server.username?.let { values.putIfAbsent("TURN_USER", it) }
                    server.credential?.let { values.putIfAbsent("TURN_PASSWORD", it) }
                } else {
                    values.putIfAbsent("STUN_HOST", ice.host)
                    values.putIfAbsent("STUN_PORT", ice.port.toString())
                }
            }
        }
        return values
    }

    /** Export the whole guide as Markdown, preserving credentials. */
    fun toMarkdown(recipes: List<Recipe>): String = buildString {
        appendLine("# External tests — generated command guide")
        appendLine()
        appendLine("Generated by the WebRTC Test Suite. Commands run outside Burp's scope")
        appendLine("enforcement on a Linux host. A ready command is not a completed scan.")
        appendLine()
        recipes.groupBy { it.tool }.forEach { (tool, group) ->
            appendLine("## $tool")
            appendLine()
            group.forEach { recipe ->
                appendLine("### ${recipe.title} — ${recipe.status}")
                recipe.notApplicableReason?.let { appendLine(it) }
                if (recipe.missing.isNotEmpty()) appendLine("Missing inputs: " + recipe.missing.joinToString(", ") { describe(it) })
                appendLine()
                appendLine(recipe.purpose)
                appendLine()
                appendLine("- Coverage: ${recipe.coverage}")
                appendLine("- Prerequisites: ${recipe.prerequisites}")
                appendLine("- Evidence: ${recipe.evidence}")
                appendLine("- Effects: ${recipe.effects}")
                appendLine("- Limitations: ${recipe.limitations}")
                appendLine("- Setup: ${recipe.setupUrl}")
                appendLine("- Reference: ${recipe.sourceUrl}")
                appendLine()
                appendLine("```bash")
                appendLine(recipe.command)
                appendLine("```")
                appendLine()
            }
        }
    }
}
