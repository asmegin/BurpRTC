package webrtc.config

/**
 * Protocol-agnostic detectors. They flag WebRTC signaling wherever it appears —
 * any HTTP body or WS frame — without knowing the app's signaling format.
 */
object Detectors {
    private val sdpRegex = Regex("""(?s)v=0.*?\bm=.*?\ba=""")
    private val candidateRegex = Regex("""candidate:[0-9]+ """)
    private val iceServersRegex = Regex("iceServers", RegexOption.IGNORE_CASE)
    private val turnRegex = Regex("""\bturns?:""", RegexOption.IGNORE_CASE)

    private val privateIpRegex = Regex(
        """\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}""" +
            """|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}""" +
            """|192\.168\.\d{1,3}\.\d{1,3}""" +
            """|169\.254\.\d{1,3}\.\d{1,3})\b"""
    )
    private val privateV6Regex =
        Regex("""\b(fe80:[0-9a-f:]+|f[cd][0-9a-f]{2}:[0-9a-f:]+)""", RegexOption.IGNORE_CASE)

    fun containsSdp(text: String): Boolean = sdpRegex.containsMatchIn(text)

    fun containsIce(text: String): Boolean =
        candidateRegex.containsMatchIn(text) ||
            iceServersRegex.containsMatchIn(text) ||
            turnRegex.containsMatchIn(text)

    /** A raw private-IP hint; mDNS hostnames conceal an address, rather than expose it. */
    fun hasPrivateAddress(text: String): Boolean =
        privateIpRegex.containsMatchIn(text) ||
            privateV6Regex.containsMatchIn(text)

    // ---- transport / crypto analysis -----------------------------------

    private val rtpmapRegex = Regex("""(?im)^a=rtpmap:\d+\s+([A-Za-z0-9._-]+)/(\d+)""")
    private val sdesRegex = Regex("""(?im)^a=crypto:""")
    private val fingerprintRegex = Regex("""(?im)^a=fingerprint:""")
    private val mediaRegex = Regex("""(?im)^m=""")

    /**
     * Judges a captured DTLS/SRTP/TLS transport string of the form
     * "dtls=<cipher> srtp=<profile> tls=<version>" and returns plain-English
     * findings. An empty list means nothing stood out. Conservative on purpose —
     * it flags only explicitly weak crypto, not missing observations or standard
     * suites (e.g. HMAC-SHA1 SRTP auth is normal, not a finding).
     */
    fun analyzeTransportSecurity(detail: String): List<String> {
        // Anchor to start/whitespace so "tls=" does not match inside "dtls=".
        fun value(key: String): String =
            Regex("""(?:^|\s)$key=([^\s]+)""").find(detail)?.groupValues?.get(1)?.trim().orEmpty()

        val dtls = value("dtls")
        val srtp = value("srtp")
        val tls = value("tls")
        val findings = mutableListOf<String>()

        if (Regex("(?i)_NULL_|_RC4_|_DES_|_EXPORT|_MD5\\b").containsMatchIn(dtls))
            findings += "Weak DTLS cipher negotiated: $dtls."

        if (srtp.contains("NULL", ignoreCase = true))
            findings += "NULL SRTP profile negotiated ($srtp) — media is not encrypted."

        if (tls.equals("1.0", true) || tls.equals("1.1", true) || tls.equals("DTLS 1.0", true))
            findings += "Legacy (D)TLS version in use: $tls."

        return findings
    }

    fun transportValue(detail: String, key: String): String? =
        Regex("(?:^|\\s)${Regex.escape(key)}=([^\\s]+)").find(detail)?.groupValues?.get(1)
            ?.takeUnless { it in setOf("?", "unknown", "undefined", "null") }

    /** True if the SDP offers SDES (`a=crypto:`), i.e. media keys carried in cleartext SDP. */
    fun usesSdesKeys(sdp: String): Boolean = sdesRegex.containsMatchIn(sdp)

    /** True if the SDP carries a DTLS `a=fingerprint`, the WebRTC-mandated key-exchange binding. */
    fun hasDtlsFingerprint(sdp: String): Boolean = fingerprintRegex.containsMatchIn(sdp)

    /** True if the SDP declares at least one media section. */
    fun hasMedia(sdp: String): Boolean = mediaRegex.containsMatchIn(sdp)

    /** Distinct codec names advertised in the SDP, e.g. ["opus", "VP8", "H264"]. */
    fun enumerateCodecs(sdp: String): List<String> =
        rtpmapRegex.findAll(sdp).map { it.groupValues[1] }.distinct().toList()

    // ---- ICE candidate parsing + IP privacy (T3) ------------------------

    /** A parsed `a=candidate:` line (or an ICE candidate string from the agent). */
    data class Candidate(
        val foundation: String,
        val component: Int,
        val protocol: String,
        val priority: Long?,
        val address: String,
        val port: Int?,
        val type: String,
        val relatedAddress: String?,
        val relatedPort: Int?
    )

    private val candidateLineRegex = Regex(
        """^candidate:(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+typ\s+(\S+)""" +
            """(?:\s+raddr\s+(\S+))?(?:\s+rport\s+(\d+))?""",
        RegexOption.IGNORE_CASE
    )

    /** Parses a candidate string; returns null when it is not a candidate line. */
    fun parseCandidate(line: String): Candidate? {
        val match = candidateLineRegex.find(line.trim()) ?: return null
        return Candidate(
            foundation = match.groupValues[1],
            component = match.groupValues[2].toIntOrNull() ?: 0,
            protocol = match.groupValues[3].lowercase(),
            priority = match.groupValues[4].toLongOrNull(),
            address = match.groupValues[5],
            port = match.groupValues[6].toIntOrNull(),
            type = match.groupValues[7].lowercase(),
            relatedAddress = match.groupValues[8].ifBlank { null },
            relatedPort = match.groupValues[9].ifBlank { null }?.toIntOrNull()
        )
    }

    /**
     * True for a globally routable IP literal. Private, loopback, link-local,
     * unique-local IPv6 and mDNS `.local` names are not public. Literal-only:
     * hostnames are never resolved or scanned for embedded address fragments.
     */
    fun isPublicAddress(value: String): Boolean {
        if (isMdns(value)) return false
        val ip = IpAddresses.literal(value) ?: return false
        if (ip.isAnyLocalAddress || ip.isLoopbackAddress || ip.isLinkLocalAddress || ip.isSiteLocalAddress) return false
        val bytes = ip.address
        if (bytes.size == 16 && (bytes[0].toInt() and 0xfe) == 0xfc) return false
        return true
    }

    fun isIpv6(value: String): Boolean = IpAddresses.literal(value)?.address?.size == 16

    fun isMdns(value: String): Boolean = value.trim().endsWith(".local", ignoreCase = true)

    // ---- ICE credential hygiene (T4) ------------------------------------

    /** ICE user-fragment / password pairs declared in an SDP (`a=ice-ufrag`/`a=ice-pwd`). */
    data class IceCredential(val ufrag: String, val password: String)

    private val iceCredentialRegex = Regex("""a=ice-ufrag:(\S+)[\s\S]{0,16}?a=ice-pwd:(\S+)""")

    fun iceCredentials(sdp: String): List<IceCredential> =
        iceCredentialRegex.findAll(sdp)
            .map { IceCredential(it.groupValues[1], it.groupValues[2]) }
            .distinct()
            .toList()

    /**
     * RFC 8445 requires a ufrag of at least 4 and a password of at least 22
     * characters. Flags values below those minimums, or made of a single repeated
     * character, as low-entropy. Distinct from TURN account credentials.
     */
    fun auditIceCredential(credential: IceCredential): String? {
        val ufrag = credential.ufrag
        val password = credential.password
        if (ufrag.length < 4) return "ICE ufrag '$ufrag' is shorter than the 4-character minimum (RFC 8445)."
        if (password.length < 22) return "ICE password is ${password.length} characters; RFC 8445 requires at least 22."
        if (ufrag.toSet().size == 1) return "ICE ufrag '$ufrag' is a single repeated character — low entropy."
        if (password.toSet().size <= 3) return "ICE password has only ${password.toSet().size} distinct characters — low entropy."
        return null
    }

    /** Distinct credential pairs across successive offers; fewer pairs than offers means reuse. */
    fun iceCredentialReuse(credentialSets: List<List<IceCredential>>): String? {
        if (credentialSets.size < 2) return null
        val distinct = credentialSets.flatten().distinct().size
        if (distinct == 0) return null
        if (distinct < credentialSets.size)
            return "ICE credentials were reused across ${credentialSets.size} negotiated offers ($distinct distinct pair(s)); an ICE restart should rotate them."
        return null
    }

    // ---- SDP attribute + codec audit (T5) -------------------------------

    data class CodecDetail(
        val payloadType: String,
        val name: String,
        val clockRate: String,
        val channels: String?,
        val fmtp: String?
    )

    private val rtpmapFullRegex = Regex("""(?im)^a=rtpmap:(\d+)\s+([A-Za-z0-9._-]+)/(\d+)(?:/(\d+))?""")
    private val fmtpRegex = Regex("""(?im)^a=fmtp:(\d+)\s+(.+)$""")
    private val fingerprintHashRegex = Regex("""(?im)^a=fingerprint:(\S+)""")
    private val iceLiteRegex = Regex("""(?im)^a=ice-lite""")
    private val setupValueRegex = Regex("""(?im)^a=setup:(\S+)""")

    /** DTLS `a=setup:` role values advertised in the SDP (actpass/active/passive). */
    fun setupRoles(sdp: String): List<String> =
        setupValueRegex.findAll(sdp).map { it.groupValues[1].lowercase() }.distinct().toList()

    /** Codecs advertised in SDP with their clock rate, channels and `a=fmtp` line. */
    fun codecDetails(sdp: String): List<CodecDetail> {
        val fmtp = fmtpRegex.findAll(sdp).associate { it.groupValues[1] to it.groupValues[2].trim() }
        return rtpmapFullRegex.findAll(sdp).map { match ->
            val pt = match.groupValues[1]
            CodecDetail(
                payloadType = pt,
                name = match.groupValues[2],
                clockRate = match.groupValues[3],
                channels = match.groupValues[4].ifBlank { null },
                fmtp = fmtp[pt]
            )
        }.distinct().toList()
    }

    /** Distinct `a=` attribute names in SDP, e.g. ["fingerprint", "setup", "rtcp-mux"]. */
    fun attributeNames(sdp: String): List<String> =
        Regex("""(?im)^a=([A-Za-z0-9-]+)""").findAll(sdp).map { it.groupValues[1].lowercase() }.distinct().toList()

    /** Media sections (audio/video) that do not declare `a=rtcp-mux`. */
    fun mediaSectionsWithoutRtcpMux(sdp: String): Int =
        mediaSections(sdp).count { section ->
            (section.startsWith("m=audio") || section.startsWith("m=video")) &&
                !section.lineSequence().any { it.trim() == "a=rtcp-mux" }
        }

    private fun mediaSections(sdp: String): List<String> {
        val sections = mutableListOf<StringBuilder>()
        sdp.split(Regex("\\r?\\n")).forEach { line ->
            if (line.startsWith("m=")) sections.add(StringBuilder(line))
            else if (sections.isNotEmpty()) sections.last().append('\n').append(line)
        }
        return sections.map { it.toString() }
    }

    /** One SDP review item; [finding] marks the stronger (weak-fingerprint) signal. */
    data class SdpFinding(val text: String, val finding: Boolean)

    /**
     * Plain-English SDP attribute review items that complement codec enumeration.
     * Weak fingerprint hashes are a finding; the rest are review signals.
     */
    fun auditSdpAttributes(sdp: String): List<SdpFinding> {
        val out = mutableListOf<SdpFinding>()
        fingerprintHashRegex.findAll(sdp).map { it.groupValues[1].lowercase() }.distinct().forEach { algorithm ->
            if (algorithm in setOf("md5", "sha-1", "sha1"))
                out += SdpFinding(
                    "Weak DTLS fingerprint hash '$algorithm' in SDP; sha-256 binds the certificate more strongly (RFC 8827).",
                    true
                )
        }
        if (iceLiteRegex.containsMatchIn(sdp))
            out += SdpFinding("SDP advertises a=ice-lite: this peer will not gather its own candidates or initiate connectivity checks.", false)
        val missingMux = mediaSectionsWithoutRtcpMux(sdp)
        if (missingMux > 0)
            out += SdpFinding("$missingMux audio/video section(s) do not advertise a=rtcp-mux; RTCP may use a separate transport.", false)
        return out
    }

    /**
     * Heuristic guessability check over a set of identifier values (e.g. the
     * room/meeting IDs configured across identities). Returns a plain-English
     * warning when the values look sequential or low-entropy, else null.
     */
    fun guessableIdentifiers(values: List<String>): String? {
        val nums = values.mapNotNull { it.trim().toLongOrNull() }
        if (nums.size < 2 || nums.size != values.count { it.trim().isNotEmpty() }) return null
        val sorted = nums.sorted()
        val consecutive = sorted.zipWithNext().all { (a, b) -> b - a in 1..16 }
        val short = sorted.all { it in 0..999_999 }
        return when {
            consecutive -> "Identifier values are numeric and near-sequential (${sorted.first()}..${sorted.last()}) — likely guessable/enumerable."
            short -> "Identifier values are short numeric IDs — check whether they are enumerable."
            else -> null
        }
    }
}
