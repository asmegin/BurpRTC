package webrtc.datachannel

import kotlinx.serialization.json.*

/** What the runner learned about the session before generating cases. */
data class DcContext(
    val sender: Participant,
    val target: DcTarget,
    val others: List<Participant>,
    val jitsi: Boolean,
    val schema: ColibriSchemas.Selection?,
    /** colibriClass (or "" for non-Colibri traffic) → texts the sender's application sent. */
    val outbound: Map<String, List<String>> = emptyMap(),
    /** colibriClass → texts the sender received. */
    val inbound: Map<String, List<String>> = emptyMap(),
    /** endpoint → source names observed in bridge source maps. */
    val sourceNames: Map<String, List<String>> = emptyMap(),
    /** An endpoint ID in the separate test room, for cross-room targeting. */
    val foreignEndpoint: String = ""
) {
    val sameRoom: List<Participant> get() = others.filter { it.room == sender.room && it.session != sender.session.ifBlank { "\u0000" } }
    val otherRoom: List<Participant> get() = others.filter { it.room != sender.room }
    val recipient: Participant? get() = sameRoom.firstOrNull { it.endpoint.isNotBlank() && it.endpoint != sender.endpoint }
    val generation: Int get() = schema?.generation ?: 3
}

/**
 * Deterministic case generation. The same run seed reproduces the same mutations and
 * random payloads; markers are fresh per run so receipts cannot be confused across runs.
 */
class DcCaseGenerator(private val config: DcSuiteConfig, val seed: Long, private val marker: () -> String = Markers::next) {
    private var sequence = 0
    private fun id(prefix: String) = "$prefix-${(++sequence).toString().padStart(3, '0')}"
    private fun caseSeed(): Long = (seed * 31 + sequence * 2654435761L) and 0x7fffffffL
    private val markerKey = "wrtcMarker"

    // ---- message construction ----

    /** Put the marker where the bridge relays it: inside msgPayload for EndpointMessage, top level otherwise. */
    private fun carry(obj: JsonObject, m: String): JsonObject {
        val payload = obj["msgPayload"]
        return if (obj.str("colibriClass") == "EndpointMessage" && payload is JsonObject)
            JsonObject(obj + ("msgPayload" to JsonObject(payload + (markerKey to JsonPrimitive(m)))))
        else JsonObject(obj + (markerKey to JsonPrimitive(m)))
    }

    /** Serialize with raw fragments substituted for placeholder tokens (escapes, literals, duplicates). */
    private fun render(obj: JsonElement, raw: Map<String, String> = emptyMap()): String {
        var text = obj.toString()
        raw.forEach { (token, fragment) -> text = text.replace("\"$token\"", fragment) }
        return text
    }

    fun probeText(ctx: DcContext, m: String): String = when {
        config.probeTemplate.isNotBlank() -> config.probeTemplate.replace("{marker}", m)
        ctx.jitsi -> """{"colibriClass":"EndpointMessage","to":"","msgPayload":{"type":"wrtc-probe","$markerKey":"$m"}}"""
        else -> genericTemplates(ctx).firstOrNull()?.let { render(carry(it.second, m)) } ?: "wrtc-probe $m"
    }

    fun probe(ctx: DcContext, target: DcTarget? = null): DcCase {
        val m = marker()
        return DcCase(id("probe"), DcScope.DISCOVERY, "Delivery probe", PayloadSpec.text(probeText(ctx, m)), m, Expect.DELIVER,
            "EndpointMessage".takeIf { ctx.jitsi && config.probeTemplate.isBlank() }.orEmpty(), "probe",
            intended = ctx.sameRoom.map { it.agentId }.toSet(), probe = true, target = target)
    }

    /** The positive control: a valid application message that the intended recipients must receive. */
    fun control(ctx: DcContext, target: DcTarget? = null): DcCase = probe(ctx, target).copy(
        id = id("control"), title = "Positive control: valid message reaches the intended recipients", probe = false)

    // ---- templates ----

    private fun substitute(example: String, ctx: DcContext): String =
        example.replace("{self}", ctx.sender.endpoint.ifBlank { "self" }).replace("{victim}", ctx.recipient?.endpoint ?: ctx.sameRoom.firstOrNull()?.endpoint?.ifBlank { null } ?: "victim")

    /** (class, template, source) for every client-to-bridge class of the selected generation. Observed messages win. */
    fun colibriTemplates(ctx: DcContext): List<Triple<ColibriSchemas.MessageClass, JsonObject, String>> =
        ColibriSchemas.forGeneration(ctx.generation).filter { it.direction != ColibriSchemas.Direction.BRIDGE_TO_CLIENT }.mapNotNull { cls ->
            val observed = ctx.outbound[cls.name].orEmpty().firstNotNullOfOrNull { ColibriSchemas.parseObject(it) }
            val template = observed ?: ColibriSchemas.parseObject(substitute(cls.example, ctx)) ?: return@mapNotNull null
            Triple(cls, JsonObject(template - markerKey), if (observed != null) "observed" else "schema example")
        }

    /** JSON objects the application sent on a non-Colibri channel; a schema is inferred from them. */
    fun genericTemplates(ctx: DcContext): List<Pair<String, JsonObject>> =
        ctx.outbound.entries.flatMap { (key, texts) -> texts.mapNotNull { t -> ColibriSchemas.parseObject(t)?.let { key to it } }.take(2) }.take(4)

    // ---- application-message fuzzing ----

    private data class Mutation(val name: String, val path: String, val text: String, val expect: Expect, val note: String = "")

    private fun jsonPathSet(obj: JsonObject, path: List<String>, value: JsonElement?): JsonObject {
        val key = path.first()
        if (path.size == 1) return JsonObject(if (value == null) obj - key else obj + (key to value))
        val child = obj[key] as? JsonObject ?: return obj
        return JsonObject(obj + (key to jsonPathSet(child, path.drop(1), value)))
    }

    private fun fields(obj: JsonObject, cls: String): List<Pair<List<String>, JsonElement>> {
        val top = obj.filterKeys { it != "colibriClass" && it != markerKey }.entries.take(10).map { listOf(it.key) to it.value }
        val nested = (obj["msgPayload"] as? JsonObject)?.filterKeys { it != markerKey }?.entries?.take(8)?.map { listOf("msgPayload", it.key) to it.value }.orEmpty()
        return top + if (cls == "EndpointMessage") nested else emptyList()
    }

    private fun nest(depth: Int): JsonElement { var e: JsonElement = JsonPrimitive(0); repeat(depth) { e = buildJsonObject { put("n", e) } }; return e }

    private fun wrongType(value: JsonElement): JsonElement = when {
        value is JsonObject -> JsonArray(listOf(JsonPrimitive(1)))
        value is JsonArray -> buildJsonObject { put("0", 1) }
        value is JsonPrimitive && value.isString -> JsonPrimitive(12345)
        value is JsonPrimitive && value.booleanOrNull != null -> JsonPrimitive("true")
        else -> JsonPrimitive("12345")
    }

    private fun mutations(cls: ColibriSchemas.MessageClass?, name: String, template: JsonObject, m: String, jitsi: Boolean): List<Mutation> {
        val base = carry(template, m)
        val forwarded = cls?.forwarded ?: false
        fun expectFor(path: String, kind: String): Expect = when {
            !jitsi -> Expect.TOLERATE
            !forwarded -> Expect.REJECT
            path.startsWith("msgPayload") -> Expect.TOLERATE
            path == "to" && kind in setOf("wrong-type", "array-instead", "object-instead", "long", "unicode", "control") -> Expect.REJECT
            else -> Expect.TOLERATE
        }
        val out = mutableListOf<Mutation>()
        fun field(path: List<String>, kind: String, value: JsonElement?, raw: Map<String, String> = emptyMap()) {
            val p = path.joinToString(".")
            var mutated = jsonPathSet(base, path, value)
            // Replacing msgPayload removes its marker; carry one at the top level instead.
            if (!mutated.toString().contains(m)) mutated = JsonObject(mutated + (markerKey to JsonPrimitive(m)))
            out += Mutation(kind, p, render(mutated, raw), expectFor(p, kind))
        }
        val longLength = minOf(16384, config.maxMessageBytes / 2).coerceAtLeast(16)
        for ((path, value) in fields(template, name)) {
            field(path, "missing", null)
            field(path, "null", JsonNull)
            field(path, "wrong-type", wrongType(value))
            val primitive = value as? JsonPrimitive
            when {
                primitive != null && !primitive.isString && primitive.doubleOrNull != null && primitive.booleanOrNull == null -> {
                    field(path, "negative", JsonPrimitive(-1))
                    field(path, "oversized-number", JsonPrimitive("__WRTC_RAW_N__"), mapOf("__WRTC_RAW_N__" to "1e308"))
                    field(path, "int64-overflow", JsonPrimitive("__WRTC_RAW_N__"), mapOf("__WRTC_RAW_N__" to "9223372036854775808"))
                    field(path, "unsafe-integer", JsonPrimitive("__WRTC_RAW_N__"), mapOf("__WRTC_RAW_N__" to "9007199254740993"))
                    field(path, "fraction", JsonPrimitive(0.5))
                }
                primitive != null && primitive.isString -> {
                    field(path, "empty-string", JsonPrimitive(""))
                    field(path, "long", JsonPrimitive("A".repeat(longLength)))
                    // Escapes are written raw so lone surrogates and controls reach the bridge's parser intact.
                    field(path, "unicode", JsonPrimitive("__WRTC_RAW_S__"), mapOf("__WRTC_RAW_S__" to "\"\\u202eevil\\ud83d\\ud83d\\ude00\\ufeff\\u0301\""))
                    field(path, "control", JsonPrimitive("__WRTC_RAW_S__"), mapOf("__WRTC_RAW_S__" to "\"\\u0000\\u0007\\u001b[31m\\r\\n\""))
                    field(path, "format-string", JsonPrimitive("%s%n%x%p"))
                }
                value is JsonObject -> {
                    field(path, "array-instead", JsonArray(emptyList()))
                    field(path, "nested-${config.maxNesting / 2}", nest(config.maxNesting / 2))
                }
                value is JsonArray -> {
                    field(path, "object-instead", buildJsonObject { })
                    field(path, "large-array", JsonArray(List(minOf(1000, config.maxMessageBytes / 4)) { JsonPrimitive(0) }))
                }
            }
        }
        val body = render(base).removePrefix("{").removeSuffix("}")
        val rejectStructure = if (jitsi) Expect.REJECT else Expect.TOLERATE
        fun whole(kind: String, text: String, expect: Expect = rejectStructure, note: String = "") { out += Mutation(kind, "", text, expect, note) }
        whole("extra-field", render(JsonObject(base + ("wrtcExtra" to buildJsonObject { put("x", 1) }))), if (jitsi && !forwarded) Expect.REJECT else Expect.TOLERATE)
        if (jitsi) {
            whole("unknown-class", render(JsonObject(base + ("colibriClass" to JsonPrimitive("WrtcUnknownClass")))))
            whole("class-case", render(JsonObject(base + ("colibriClass" to JsonPrimitive(name.lowercase())))))
            whole("class-empty", render(JsonObject(base + ("colibriClass" to JsonPrimitive("")))))
            whole("class-number", render(JsonObject(base + ("colibriClass" to JsonPrimitive(1)))))
            whole("class-missing", render(JsonObject(base - "colibriClass")))
            whole("duplicate-class", "{\"colibriClass\":\"WrtcUnknownClass\",$body}", if (forwarded) Expect.TOLERATE else Expect.REJECT,
                "Duplicate keys: parsers disagree on first-wins / last-wins; the observed relayed class is recorded")
        }
        base.keys.firstOrNull { it != "colibriClass" }?.let { key ->
            whole("duplicate-field", "{$body,\"$key\":${base[key]}}", if (jitsi && !forwarded) Expect.REJECT else Expect.TOLERATE)
        }
        // Cut after the marker so a relayed fragment can still be attributed.
        whole("malformed-truncated", render(base).let { it.take(maxOf(it.indexOf(m) + m.length + 1, it.length * 2 / 3)) })
        whole("malformed-trailing-comma", "{$body,}")
        whole("malformed-single-quotes", "{" + body.replace('"', '\'') + "}")
        whole("malformed-unquoted-key", "{wrtcKey:1,$body}")
        whole("malformed-nan-literal", "{\"wrtcNumber\":NaN,$body}")
        whole("malformed-comment", "{/*wrtc*/$body}")
        // Valid or commonly tolerated input: a relay of the bridge's own re-serialization is not a validation failure.
        val lenient = if (jitsi && !forwarded) Expect.REJECT else Expect.TOLERATE
        whole("bom-prefix", "﻿" + render(base), lenient)
        whole("trailing-garbage", render(base) + "}{]", lenient, "Many JSON parsers ignore trailing tokens; the relayed form is recorded")
        whole("huge-number-literal", "{\"wrtcNumber\":1e999999,$body}", lenient)
        whole("top-level-array", "[" + render(base) + "]")
        whole("top-level-string", JsonPrimitive(render(base)).toString())
        whole("nesting-16", render(JsonObject(base + ("wrtcNest" to nest(16)))), if (jitsi && !forwarded) Expect.REJECT else Expect.TOLERATE)
        whole("nesting-${config.maxNesting}", render(JsonObject(base + ("wrtcNest" to nest(config.maxNesting)))), if (jitsi && !forwarded) Expect.REJECT else Expect.TOLERATE)
        return out.filter { it.text.toByteArray(Charsets.UTF_8).size <= config.maxMessageBytes }
    }

    /** One field (or one structural property) changed per case; families interleaved so small budgets keep variety. */
    fun fuzzCases(ctx: DcContext, target: DcTarget? = null): List<DcCase> {
        val sources: List<Triple<ColibriSchemas.MessageClass?, String, Pair<JsonObject, String>>> = if (ctx.jitsi)
            colibriTemplates(ctx).map { (cls, template, source) -> Triple(cls, cls.name, template to source) }
        else genericTemplates(ctx).map { (key, template) -> Triple(null, key.ifBlank { "application JSON" }, template to "observed") }.ifEmpty {
            listOf(Triple(null, "synthetic JSON", buildJsonObject { put("type", "wrtc-test"); put("value", 1); put("text", "x"); put("items", buildJsonArray { add(1) }) } to
                "synthetic: no application JSON observed"))
        }
        val perSource = sources.map { (cls, name, pair) ->
            val (template, source) = pair
            mutations(cls, name, template, PLACEHOLDER, ctx.jitsi).map { mutation ->
                Triple(name, source, mutation)
            }
        }
        val interleaved = mutableListOf<Triple<String, String, Mutation>>()
        var index = 0
        while (perSource.any { index < it.size }) { perSource.forEach { if (index < it.size) interleaved += it[index] }; index++ }
        val others = ctx.others.map { it.agentId }.toSet()
        return interleaved.map { (name, source, mutation) ->
            val m = marker()
            val title = "$name: ${mutation.name}${if (mutation.path.isNotEmpty()) " on ${mutation.path}" else ""}"
            DcCase(id("fuzz"), DcScope.FUZZ, title, PayloadSpec.text(mutation.text.replace(PLACEHOLDER, m)), m, mutation.expect, name,
                mutation.name + if (mutation.path.isNotEmpty()) "@${mutation.path}" else "", forbidden = if (mutation.expect == Expect.REJECT) others else emptySet(),
                target = target, notes = listOfNotNull("Template: $source", mutation.note.ifBlank { null }))
        }
    }

    /**
     * Tester payloads, one case each. Delivery is allowed (TOLERATE): a case fails on a
     * recipient error carrying its marker, a spoofed identity, or lost session health.
     */
    fun customCases(entries: List<CustomPayloads.Entry>, target: DcTarget? = null): List<DcCase> = entries.map { e ->
        DcCase(id("custom"), DcScope.FUZZ, "Custom payload ${e.index}: ${e.raw.take(60)}${if (e.raw.length > 60) "…" else ""}", e.spec, e.marker,
            Expect.TOLERATE, ColibriSchemas.colibriClass(e.raw).orEmpty(), "custom-${e.index}", target = target,
            notes = listOf("Your payload ${e.index}" + if (e.marker.isEmpty()) "; sent byte-for-byte without a marker, so recipients are matched by hash while observing" else ""))
    }

    // ---- binary and size boundaries ----

    fun binaryCases(ctx: DcContext, target: DcTarget = ctx.target): List<DcCase> {
        val out = mutableListOf<DcCase>()
        val expect = if (ctx.jitsi) Expect.REJECT else Expect.TOLERATE
        val others = ctx.others.map { it.agentId }.toSet()
        val cap = config.maxMessageBytes
        fun add(title: String, spec: PayloadSpec, m: String, mutation: String, expectation: Expect = expect, notes: List<String> = emptyList()) {
            val bytes = spec.byteLength()
            out += DcCase(id("size"), DcScope.BINARY, title, spec, m, expectation, if (spec.binary) "binary" else "text", mutation,
                forbidden = if (expectation == Expect.REJECT) others else emptySet(), seed = spec.parts.firstOrNull { it.fill == "random" }?.seed ?: 0,
                target = target, preVerdict = if (bytes > cap) Verdict.BLOCKED else null,
                preReason = if (bytes > cap) "$bytes bytes exceeds the configured per-message cap of $cap bytes" else "", notes = notes)
        }
        fun filled(kind: String, total: Int, fill: String, m: String): PayloadSpec {
            val markerBytes = m.length.coerceAtMost(total)
            val rest = total - markerBytes
            val parts = mutableListOf(PayloadPart(text = m.take(markerBytes)))
            if (rest > 0) parts += if (fill == "ascii") PayloadPart(repeat = "A", count = rest) else PayloadPart(fill = fill, count = rest, seed = caseSeed())
            return PayloadSpec(kind, parts)
        }
        add("Empty text message", PayloadSpec("text", listOf(PayloadPart(text = ""))), "", "text-0", Expect.TOLERATE,
            listOf("Carries no marker: recipient receipt is not observable; judged on errors and session health"))
        add("1-byte text message", PayloadSpec.text("a"), "", "text-1", Expect.TOLERATE, listOf("Carries no marker; judged on errors and session health"))
        listOf(16384, 65536).forEach { size ->
            val m = marker(); add("${size / 1024} KiB text (UTF-8 bytes)", filled("text", size, "ascii", m), m, "text-$size")
        }
        marker().let { m -> add("UTF-8 multi-byte character crossing 16 KiB", PayloadSpec("text", listOf(PayloadPart(text = m), PayloadPart(repeat = "A", count = 16384 - m.length - 1), PayloadPart(text = "é"))), m, "text-utf8-16385") }
        marker().let { m -> add("4-byte UTF-8 characters", PayloadSpec("text", listOf(PayloadPart(text = m), PayloadPart(repeat = "😀", count = 256))), m, "text-emoji") }
        add("Empty ArrayBuffer", PayloadSpec("arraybuffer", listOf(PayloadPart(fill = "zero", count = 0))), "", "arraybuffer-0", Expect.TOLERATE, listOf("Carries no marker"))
        add("1-byte zero ArrayBuffer", PayloadSpec("arraybuffer", listOf(PayloadPart(fill = "zero", count = 1))), "", "arraybuffer-1", Expect.TOLERATE, listOf("Carries no marker"))
        marker().let { m -> add("16 KiB zero-filled Uint8Array", filled("uint8array", 16384, "zero", m), m, "uint8array-16384-zero") }
        marker().let { m -> add("16 KiB seeded random ArrayBuffer", filled("arraybuffer", 16384, "random", m), m, "arraybuffer-16384-random") }
        marker().let { m -> add("64 KiB seeded random ArrayBuffer", filled("arraybuffer", 65536, "random", m), m, "arraybuffer-65536-random") }
        listOf("int16array", "float64array", "dataview", "blob").forEach { kind ->
            val m = marker(); add("1 KiB seeded random ${kind.replaceFirstChar { it.uppercase() }}", filled(kind, 1024, "random", m), m, "$kind-1024-random")
        }
        marker().let { m -> add("JSON sent as binary", PayloadSpec("arraybuffer", listOf(PayloadPart(text = probeText(ctx, m)))), m, "json-as-binary") }
        val max = target.maxMessageSize
        if (max == null || max <= 0 || max >= Int.MAX_VALUE) {
            out += DcCase(id("size"), DcScope.BINARY, "maxMessageSize − 1 / = / + 1", PayloadSpec.text(""), "", expect, "text", "max-message-size",
                target = target, preVerdict = Verdict.NOT_APPLICABLE,
                preReason = "The peer did not advertise a finite SCTP maxMessageSize${if (target.transport == "colibri-ws") " (Colibri WebSocket has no SCTP limit)" else ""}")
        } else listOf(-1L, 0L, 1L).forEach { delta ->
            val size = max + delta
            val m = marker()
            val label = when (delta) { -1L -> "− 1"; 0L -> "(equal)"; else -> "+ 1" }
            if (size > cap) out += DcCase(id("size"), DcScope.BINARY, "maxMessageSize $label ($size bytes)", PayloadSpec.text(""), m, expect, "text", "max-message-size$delta",
                target = target, preVerdict = Verdict.BLOCKED, preReason = "$size bytes exceeds the configured per-message cap of $cap bytes")
            else add("maxMessageSize $label ($size bytes)", filled("text", size.toInt(), "ascii", m), m, "max-message-size$delta",
                notes = if (delta > 0) listOf("Browsers must reject sends above maxMessageSize; a local rejection is not server validation") else emptyList())
        }
        return out
    }

    // ---- authorization and isolation ----

    private fun endpointMessage(to: JsonElement, m: String, extra: Map<String, JsonElement> = emptyMap()): String =
        render(JsonObject(mapOf("colibriClass" to JsonPrimitive("EndpointMessage"), "to" to to) + extra +
            ("msgPayload" to buildJsonObject { put("type", "wrtc-authz"); put(markerKey, m) })))

    fun authzCases(ctx: DcContext, target: DcTarget? = null): List<DcCase> {
        if (!ctx.jitsi) return emptyList()
        val out = mutableListOf<DcCase>()
        val all = ctx.others.map { it.agentId }.toSet()
        val same = ctx.sameRoom.map { it.agentId }.toSet()
        val foreign = ctx.otherRoom.map { it.agentId }.toSet()
        val recipient = ctx.recipient
        fun add(title: String, text: String, m: String, expect: Expect, mutation: String, intended: Set<String> = emptySet(), forbidden: Set<String> = emptySet(),
                spoofed: String = "", cls: String = "EndpointMessage", direction: String = "client-to-server", pre: Verdict? = null, preReason: String = "", notes: List<String> = emptyList()) {
            out += DcCase(id("authz"), DcScope.AUTHZ, title, PayloadSpec.text(text), m, expect, cls, mutation, direction, intended, forbidden, spoofed,
                target = target, preVerdict = pre, preReason = preReason, notes = notes)
        }
        if (recipient != null) {
            val group = ctx.sameRoom.filter { it.endpoint == recipient.endpoint || (recipient.session.isNotBlank() && it.session == recipient.session) }.map { it.agentId }.toSet()
            marker().let { m -> add("Unicast to ${recipient.label} reaches only that participant", endpointMessage(JsonPrimitive(recipient.endpoint), m), m,
                Expect.DELIVER, "unicast-control", group, all - group) }
        }
        marker().let { m -> add("Broadcast stays inside the call (not the test room)", endpointMessage(JsonPrimitive(""), m), m, Expect.DELIVER, "broadcast-isolation", same, foreign) }
        marker().let { m ->
            if (ctx.foreignEndpoint.isBlank()) add("Cross-room unicast to a test-room endpoint", endpointMessage(JsonPrimitive("unknown"), m), m, Expect.REJECT, "cross-room-unicast",
                forbidden = foreign, pre = Verdict.INCONCLUSIVE, preReason = "No test-room endpoint ID is known; start a test-room session or enter its endpoint ID")
            else add("Cross-room unicast to test-room endpoint ${ctx.foreignEndpoint}", endpointMessage(JsonPrimitive(ctx.foreignEndpoint), m), m, Expect.REJECT, "cross-room-unicast", forbidden = foreign)
        }
        marker().let { m -> add("Unicast to a non-existent endpoint", endpointMessage(JsonPrimitive("wrtcnobody"), m), m, Expect.REJECT, "unknown-endpoint", forbidden = all) }
        marker().let { m -> add("Recipient list as an array", endpointMessage(JsonArray(listOfNotNull(recipient?.endpoint?.let(::JsonPrimitive), ctx.foreignEndpoint.ifBlank { null }?.let(::JsonPrimitive))), m), m,
            Expect.REJECT, "to-array", forbidden = all) }
        val victim = recipient?.endpoint
        marker().let { m ->
            if (victim == null) add("Spoofed sender identity (from = another participant)", endpointMessage(JsonPrimitive(""), m), m, Expect.TOLERATE, "spoof-from",
                pre = Verdict.INCONCLUSIVE, preReason = "No other participant's endpoint ID is known in this call")
            else add("Spoofed sender identity (from = $victim)", endpointMessage(JsonPrimitive(""), m, mapOf("from" to JsonPrimitive(victim))), m, Expect.TOLERATE, "spoof-from",
                intended = same, spoofed = victim)
        }
        if (ctx.foreignEndpoint.isNotBlank()) marker().let { m ->
            add("Spoofed sender identity (from = test-room endpoint)", endpointMessage(JsonPrimitive(""), m, mapOf("from" to JsonPrimitive(ctx.foreignEndpoint))), m,
                Expect.TOLERATE, "spoof-from-foreign", intended = same, spoofed = ctx.foreignEndpoint)
        }
        val foreignConference = ctx.otherRoom.firstOrNull { it.conference.isNotBlank() }?.conference
        marker().let { m -> add("Conference / room identifier injected into the envelope", endpointMessage(JsonPrimitive(""), m,
            mapOf("conference" to JsonPrimitive(foreignConference ?: "wrtc-test-room"), "room" to JsonPrimitive(foreignConference ?: "wrtc-test-room"))), m,
            Expect.DELIVER, "room-identifier", same, foreign) }
        // Server-to-client classes sent by a client must not be relayed or acted on.
        ColibriSchemas.forGeneration(ctx.generation).filter { it.direction == ColibriSchemas.Direction.BRIDGE_TO_CLIENT }.forEach { cls ->
            val m = marker()
            val learned = ctx.inbound[cls.name].orEmpty().firstNotNullOfOrNull { ColibriSchemas.parseObject(it) }
            val template = learned ?: ColibriSchemas.parseObject(substitute(cls.example, ctx)) ?: return@forEach
            add("Server-to-client ${cls.name} sent by a client", render(carry(JsonObject(template - markerKey), m)), m, Expect.REJECT, "direction",
                forbidden = all, cls = cls.name, direction = "server-to-client-from-client",
                notes = listOf(if (learned != null) "Replays a ${cls.name} the bridge sent to this client" else "Built from the schema example"))
        }
        if (ctx.generation >= 2 && victim != null) {
            val source = ctx.sourceNames[victim]?.firstOrNull() ?: "$victim-v0"
            marker().let { m -> add("Video type change for another participant's source ($source)",
                render(buildJsonObject { put("colibriClass", "SourceVideoTypeMessage"); put("sourceName", source); put("videoType", "desktop"); put(markerKey, m) }), m,
                Expect.REJECT, "foreign-source", forbidden = all, cls = "SourceVideoTypeMessage") }
        }
        return out
    }

    // ---- replay ----

    /** Exact replays of captured traffic. They carry no marker; recipients are matched by payload hash. */
    fun replayCases(ctx: DcContext, target: DcTarget? = null): List<DcCase> {
        val out = mutableListOf<DcCase>()
        ctx.outbound.values.flatten().distinct().filter { it.toByteArray().size <= config.maxMessageBytes }.take(5).forEach { text ->
            val cls = ColibriSchemas.colibriClass(text).orEmpty()
            out += DcCase(id("replay"), DcScope.REPLAY, "Replay own ${cls.ifBlank { "message" }} within the session", PayloadSpec.text(text), "", Expect.TOLERATE,
                cls, "replay-own", target = target, notes = listOf("Exact captured bytes; recipients matched by payload hash while observing"))
        }
        ctx.inbound.filterKeys { it == "EndpointMessage" || it == "" }.values.flatten().distinct().filter { it.toByteArray().size <= config.maxMessageBytes }.take(2).forEach { text ->
            val from = ColibriSchemas.parseObject(text)?.str("from").orEmpty()
            out += DcCase(id("replay"), DcScope.REPLAY, "Replay a message received from ${from.ifBlank { "another participant" }}", PayloadSpec.text(text), "",
                Expect.TOLERATE, ColibriSchemas.colibriClass(text).orEmpty(), "replay-received", spoofedFrom = from, target = target,
                notes = listOf("Carries the original sender's 'from'; recipients must see the replaying sender instead"))
        }
        return out
    }

    /** Equivalent cases for the transport comparison: control, a fuzz sample and broadcast isolation. */
    fun transportCases(ctx: DcContext, target: DcTarget): List<DcCase> {
        val sample = fuzzCases(ctx, target).let { all -> all.filterIndexed { i, _ -> i % maxOf(1, all.size / 10) == 0 }.take(10) }
        val isolation = authzCases(ctx, target).filter { it.mutation in setOf("broadcast-isolation", "cross-room-unicast") }
        return (listOf(control(ctx, target)) + sample + isolation).map { it.copy(scope = DcScope.TRANSPORT, title = "[${target.transport}] ${it.title}") }
    }

    /** Load message frame around the marker: prefix + marker + suffix. */
    fun loadFrame(ctx: DcContext): Pair<String, String> {
        val text = probeText(ctx, "\u0001")
        return text.substringBefore("\u0001") to text.substringAfter("\u0001")
    }

    companion object {
        /** Survives JSON escaping and every structural mutation; never matches the marker pattern. */
        private const val PLACEHOLDER = "wrtc_MARKER_PLACEHOLDER"
        private fun JsonObject.str(key: String) = (this[key] as? JsonPrimitive)?.contentOrNull

        /** Shares of the case budget; unused shares flow to the families that still have cases. */
        val shares = mapOf(DcScope.FUZZ to 45, DcScope.BINARY to 15, DcScope.AUTHZ to 20, DcScope.REPLAY to 5, DcScope.TRANSPORT to 15)

        /** Truncate each family to its share of [max]; returns kept cases and how many were dropped per family. */
        fun allocate(families: Map<DcScope, List<DcCase>>, max: Int): Pair<Map<DcScope, List<DcCase>>, Map<DcScope, Int>> {
            val quota = families.mapValues { 0 }.toMutableMap()
            var remaining = max
            var open = families.filter { it.value.isNotEmpty() }.keys.toMutableSet()
            while (remaining > 0 && open.isNotEmpty()) {
                val weight = open.sumOf { shares[it] ?: 10 }
                var spent = 0
                for (scope in open.toList()) {
                    val give = minOf(maxOf(1, remaining * (shares[scope] ?: 10) / weight),
                        families.getValue(scope).size - quota.getValue(scope), remaining - spent)
                    quota[scope] = quota.getValue(scope) + give; spent += give
                }
                remaining -= spent
                open = open.filter { quota.getValue(it) < families.getValue(it).size }.toMutableSet()
                if (spent == 0) break
            }
            val kept = families.mapValues { (scope, cases) -> cases.take(quota.getValue(scope)) }
            return kept to families.mapValues { (scope, cases) -> cases.size - kept.getValue(scope).size }
        }
    }
}
