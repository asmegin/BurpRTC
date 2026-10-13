package webrtc.protocol

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.websocket.BinaryMessage
import burp.api.montoya.websocket.TextMessage
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler
import kotlinx.serialization.json.*
import webrtc.assessment.*
import webrtc.config.IdentityProfile
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.time.Instant
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** Network side of scenarios; the Burp implementation sends through Burp's HTTP and WebSocket stacks. */
interface ScenarioTransport {
    data class HttpResult(val status: Int, val headers: List<Pair<String, String>>, val body: String)
    interface Socket { fun send(text: String); fun receive(timeoutMs: Long): JsonObject; fun close() }
    data class Opened(val status: Int, val request: String, val response: String, val socket: Socket?)
    fun http(method: String, url: String, headers: Map<String, String>, body: String): HttpResult
    fun webSocket(url: String, headers: Map<String, String>): Opened
}

class BurpScenarioTransport(private val api: MontoyaApi) : ScenarioTransport {
    private fun request(method: String, url: String, headers: Map<String, String>, body: String): HttpRequest {
        val uri = URI(url)
        val secure = uri.scheme in setOf("https", "wss")
        val service = HttpService.httpService(uri.host, if (uri.port > 0) uri.port else if (secure) 443 else 80, secure)
        var req = HttpRequest.httpRequest().withService(service).withMethod(method)
            .withPath((uri.rawPath ?: "/").ifEmpty { "/" } + (uri.rawQuery?.let { "?$it" } ?: ""))
            .withHeader("Host", uri.rawAuthority)
        headers.forEach { (k, v) -> req = req.withHeader(k, v) }
        return if (body.isNotEmpty() || method in setOf("POST", "PUT", "PATCH")) req.withBody(body) else req
    }
    override fun http(method: String, url: String, headers: Map<String, String>, body: String): ScenarioTransport.HttpResult {
        val response = api.http().sendRequest(request(method, url, headers, body)).response()
            ?: return ScenarioTransport.HttpResult(0, emptyList(), "")
        return ScenarioTransport.HttpResult(response.statusCode().toInt(), response.headers().map { it.name() to it.value() }, response.bodyToString())
    }
    override fun webSocket(url: String, headers: Map<String, String>): ScenarioTransport.Opened {
        val upgrade = request("GET", url, headers + mapOf("Connection" to "Upgrade", "Upgrade" to "websocket", "Sec-WebSocket-Version" to "13",
            "Sec-WebSocket-Key" to java.util.Base64.getEncoder().encodeToString(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) })), "")
        val creation = api.websockets().createWebSocket(upgrade)
        val response = creation.upgradeResponse().orElse(null)
        val socket = creation.webSocket().orElse(null)?.let(::BurpSocket)
        return ScenarioTransport.Opened(response?.statusCode()?.toInt() ?: if (socket != null) 101 else 0, upgrade.toString(),
            response?.toString() ?: "status ${creation.status()}", socket)
    }
    private class BurpSocket(private val socket: ExtensionWebSocket) : ScenarioTransport.Socket {
        private val queue = LinkedBlockingQueue<JsonObject>(256)
        init {
            socket.registerMessageHandler(object : ExtensionWebSocketMessageHandler {
                override fun textMessageReceived(message: TextMessage) {
                    val text = message.payload()
                    queue.offer(buildJsonObject { put("body", text); runCatching { Json.parseToJsonElement(text) }.getOrNull()?.let { put("json", it) } })
                }
                override fun binaryMessageReceived(message: BinaryMessage) {
                    val bytes = message.payload().getBytes()
                    queue.offer(buildJsonObject { put("base64", java.util.Base64.getEncoder().encodeToString(bytes)); put("bytes", bytes.size) })
                }
                override fun onClose() { queue.offer(buildJsonObject { put("closed", true) }) }
            })
        }
        override fun send(text: String) = socket.sendTextMessage(text)
        override fun receive(timeoutMs: Long): JsonObject = queue.poll(timeoutMs, TimeUnit.MILLISECONDS)
            ?: throw java.util.concurrent.TimeoutException("No WebSocket message before the step timeout")
        override fun close() = runCatching { socket.close() }.let { }
    }
}

/**
 * Multi-identity HTTP / WebSocket scenarios (SIG-02..06, APP-*, SFU-* and others).
 * A positive control must demonstrate the protected effect before any case runs;
 * assertions inspect response content, never status codes alone. Every step is
 * scope-checked first and the run is bounded by the scenario's time and step budget.
 */
class ScenarioRunner(private val transport: ScenarioTransport, private val allows: (String) -> Boolean, private val cancelled: () -> Boolean) {
    class Blocked(message: String) : Exception(message)
    private fun now() = Instant.now().toString()

    private fun scopeUrl(url: String): String {
        val uri = URI(url)
        require(uri.scheme in setOf("http", "https", "ws", "wss") && uri.host != null && uri.userInfo == null && uri.fragment == null) { "Scenario URL must be http(s) or ws(s), without userinfo/fragment" }
        require(url.none { it == '\r' || it == '\n' || it == '\u0000' }) { "Invalid URL" }
        val secure = uri.scheme in setOf("https", "wss")
        return URI(if (secure) "https" else "http", uri.rawAuthority, uri.rawPath, uri.rawQuery, null).toString()
    }

    fun run(scenario: Scenario, runId: String, engagementId: String, identities: List<IdentityProfile>): TestOutcome {
        scenario.validate()
        val started = now()
        val deadline = System.nanoTime() + scenario.timeoutSeconds * 1_000_000_000L
        var steps = 0
        val byName = identities.associateBy { it.name }
        val evidence = mutableListOf<TestEvidence>()
        val limitations = mutableListOf("Assertions use tester-supplied application policy: ${scenario.policy}",
            "Raw-client Origin acceptance is a lead; this runner does not reproduce browser SameSite/user-consent behavior.")
        var execution = "completed"; var security = "inconclusive"; var control = "not-run"; var cleanup = "not-required"
        var confidence = "low"; var severity = "information"
        val variables = HashMap<String, JsonElement>(); val sockets = HashMap<String, ScenarioTransport.Socket>()

        fun expand(value: JsonElement): JsonElement = when (value) {
            is JsonPrimitive -> if (value.isString && value.content.startsWith("\${") && value.content.endsWith("}"))
                variables[value.content.drop(2).dropLast(1)] ?: throw IllegalArgumentException("Missing extracted variable ${value.content}") else value
            is JsonObject -> JsonObject(value.mapValues { expand(it.value) })
            is JsonArray -> JsonArray(value.map(::expand))
        }
        fun expandText(text: String) = (expand(JsonPrimitive(text)) as? JsonPrimitive)?.content ?: expand(JsonPrimitive(text)).toString()

        fun runSteps(items: List<ScenarioStep>, stage: String): List<String> {
            val observed = mutableListOf<String>()
            for (step in items) {
                if (cancelled()) throw InterruptedException("Stopped")
                if (System.nanoTime() >= deadline) throw java.util.concurrent.TimeoutException("Scenario duration budget exhausted")
                require(++steps <= 400) { "Scenario step budget exhausted" }
                var url = expandText(step.url)
                var headers = step.headers.mapValues { expandText(it.value) }
                var doc: JsonElement? = step.body.takeIf { it.isNotBlank() }?.let { runCatching { expand(Json.parseToJsonElement(it)) }.getOrNull() }
                var body = step.body
                if (step.identity.isNotEmpty()) {
                    if (step.identity != "absent" && step.identity !in byName) throw IllegalArgumentException("Missing identity ${step.identity}")
                    val identity = byName[step.identity]
                    val uri = URI(url)
                    val origin = "${if (uri.scheme in setOf("https", "wss")) "https" else "http"}://${uri.rawAuthority}"
                    if (identity != null && identity.origins.none { it.trimEnd('/') == origin || webrtc.authz.AuthTokens.origin(it) == webrtc.authz.AuthTokens.origin(origin) })
                        throw Blocked("Identity is not associated with this origin: $origin")
                    val headerNames = setOf("authorization", "cookie", "x-auth-token", "x-api-key") + identities.flatMap { it.headers.keys }.map { it.lowercase() }
                    headers = headers.filterKeys { it.lowercase() !in headerNames } + identity?.headers.orEmpty()
                    val queryNames = identities.flatMap { it.queryTokens.keys }.toSet()
                    val query = uri.rawQuery.orEmpty().split('&').filter { it.isNotEmpty() }
                        .filter { URLDecoder.decode(it.substringBefore('='), Charsets.UTF_8) !in queryNames } +
                        identity?.queryTokens.orEmpty().map { "${URLEncoder.encode(it.key, Charsets.UTF_8)}=${URLEncoder.encode(it.value, Charsets.UTF_8)}" }
                    url = "${uri.scheme}://${uri.rawAuthority}${uri.rawPath.orEmpty()}" + if (query.isEmpty()) "" else "?" + query.joinToString("&")
                    val bodyNames = identities.flatMap { it.bodyTokens.keys }.map { it.removePrefix("/") }.toSet()
                    if (bodyNames.isNotEmpty()) {
                        val obj = doc as? JsonObject ?: throw IllegalArgumentException("Body authentication requires a JSON object")
                        doc = JsonObject(obj.filterKeys { it !in bodyNames } + identity?.bodyTokens.orEmpty().mapKeys { it.key.removePrefix("/") }.mapValues { JsonPrimitive(it.value) })
                    }
                }
                if (doc != null) body = doc.toString()
                val scope = scopeUrl(url)
                if (!allows(scope)) throw Blocked("Step ${step.id} target is outside Burp scope / allow-list: $scope")
                val input = buildJsonObject { put("url", url); put("transport", step.transport); put("identity", step.identity); put("body", body)
                    put("headers", JsonObject(headers.mapValues { JsonPrimitive(it.value) })) }
                val output: JsonObject = when (step.transport) {
                    "http" -> {
                        require(step.method in setOf("GET", "HEAD", "POST", "PATCH", "PUT", "DELETE", "OPTIONS")) { "Unsupported HTTP method" }
                        val r = transport.http(step.method, url, headers, body)
                        require(r.body.length <= 262144) { "Response evidence exceeded capture limit" }
                        buildJsonObject { put("status", r.status); put("headers", buildJsonArray { r.headers.forEach { (k, v) -> add(buildJsonArray { add(k); add(v) }) } })
                            put("body", r.body); runCatching { Json.parseToJsonElement(r.body) }.getOrNull()?.let { put("json", it) } }
                    }
                    "ws-open" -> {
                        require(step.connection !in sockets) { "Close existing connection before reopening" }
                        val opened = transport.webSocket(url, headers)
                        opened.socket?.let { sockets[step.connection] = it }
                        buildJsonObject { put("status", opened.status); put("request", opened.request); put("response", opened.response) }
                    }
                    "ws-send" -> { (sockets[step.connection] ?: throw IllegalArgumentException("WebSocket handshake was not accepted")).send(body); buildJsonObject { put("sent", true) } }
                    "ws-receive" -> (sockets[step.connection] ?: throw IllegalArgumentException("WebSocket handshake was not accepted"))
                        .receive(((deadline - System.nanoTime()) / 1_000_000).coerceIn(100, 10_000))
                    "ws-close" -> { sockets.remove(step.connection)?.close(); buildJsonObject { put("closed", true) } }
                    else -> throw IllegalArgumentException("Unsupported scenario transport")
                }
                evidence += TestEvidence(stage, now(), input, output, step.id)
                if (step.expectStatus.isNotEmpty() && output["status"]?.jsonPrimitive?.intOrNull !in step.expectStatus)
                    throw IllegalArgumentException("Unexpected HTTP status at ${step.id}")
                step.extract.forEach { (name, pointer) -> variables[name] = JsonPointer.get(output, pointer) ?: throw IllegalArgumentException("Missing extraction $pointer") }
                step.assertion?.let { assertion ->
                    val matched = JsonPointer.get(output, assertion.pointer) == expand(assertion.equals)
                    evidence += TestEvidence(if (stage == "case") "effect" else "control", now(),
                        buildJsonObject { put("assertion", Json.encodeToJsonElement(Assertion.serializer(), assertion)); put("step", step.id) },
                        buildJsonObject { put("matched", matched); put("meaning", assertion.meaning) })
                    if (matched) observed += assertion.meaning
                    else if (stage == "control") throw IllegalArgumentException("Positive control assertion failed at ${step.id}")
                }
                val delay = scenario.intervalMs.toLong()
                if (System.nanoTime() + delay * 1_000_000 >= deadline) throw java.util.concurrent.TimeoutException("Scenario duration budget exhausted")
                Thread.sleep(delay)
            }
            return observed
        }

        val effects = mutableListOf<String>()
        try {
            for (case in scenario.cases) {
                variables.clear()
                try {
                    runSteps(scenario.setup, "setup")
                    val controlled = runSteps(scenario.control, "control")
                    require(controlled.any { it in setOf("protected-effect", "receiver-marker", "health-control") }) { "Control did not demonstrate the protected effect" }
                    control = "passed"
                    val observed = runSteps(case.steps, "case")
                    effects += if (case.expectation == "rejected") when {
                        observed.any { it in setOf("protected-effect", "receiver-marker") } -> "policy-violation"
                        "explicit-rejection" in observed -> "demonstrated-rejection"
                        else -> "inconclusive"
                    } else if (observed.any { it in setOf("protected-effect", "receiver-marker") }) "observed" else "inconclusive"
                } finally {
                    try { if (scenario.cleanup.isNotEmpty()) { runSteps(scenario.cleanup, "cleanup"); cleanup = "completed" } }
                    catch (e: Exception) { cleanup = "unconfirmed: ${e.message}"; throw e }
                    finally { sockets.values.forEach { runCatching { it.close() } }; sockets.clear() }
                }
            }
            security = when {
                "policy-violation" in effects -> "policy-violation"
                "inconclusive" in effects -> "inconclusive"
                effects.isNotEmpty() && effects.all { it == "demonstrated-rejection" } -> "demonstrated-rejection"
                else -> "observed"
            }
            if (security == "policy-violation") { confidence = "medium"; severity = "medium" }
        } catch (e: Blocked) { execution = "blocked"; security = "inconclusive"; limitations += e.message.orEmpty() }
        catch (e: java.util.concurrent.TimeoutException) { execution = "timeout"; security = "inconclusive"; limitations += e.message.orEmpty() }
        catch (e: InterruptedException) { execution = "cancelled"; security = "inconclusive"; limitations += "Stopped" }
        catch (e: Exception) { execution = "partial"; security = "inconclusive"; limitations += (e.message ?: e.javaClass.simpleName) }
        return TestOutcome(engagementId = engagementId, runId = runId, testId = scenario.testId, target = scenario.id, backend = "recorded-scenario",
            execution = execution, security = security, confidence = confidence, severity = severity, control = control, cleanup = cleanup,
            evidence = evidence.takeLast(200), limitations = limitations, startedAt = started, endedAt = now())
    }
}
