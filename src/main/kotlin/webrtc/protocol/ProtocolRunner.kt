package webrtc.protocol

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import webrtc.assessment.*
import webrtc.config.ConfigStore
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit

/** Bundled Python adapter; duplex scope grants occur before every connect and send. */
class ProtocolRunner(private val config: ConfigStore, private val authorization: NetworkAuthorization,
                     private val store: OutcomeStore) : AutoCloseable {
    @Volatile private var stopped = false
    @Volatile private var closed = false
    @Volatile private var current: Process? = null
    private val json = Json { encodeDefaults = true }
    fun stop() { stopped = true; current?.let(::terminate) }
    override fun close() { closed = true; stop() }
    private fun terminate(p: Process) {
        runCatching { p.toHandle().descendants().use { it.forEach { child -> child.destroyForcibly() } } }
        runCatching { p.destroyForcibly() }
    }
    @Synchronized fun runScenario(scenario: Scenario, cancelled: () -> Boolean = { false }): TestOutcome {
        stopped = false
        val cfg = config.config
        val id = UUID.randomUUID().toString(); val started = Instant.now().toString()
        val outcome = try {
            scenario.validate()
            require(scenario.profile == "standard" || scenario.profile == cfg.assessment.profile) { "Select the scenario's stress/lab profile" }
            if (closed || cancelled()) error("cancelled")
            val root = Path.of(System.getProperty("user.home"), ".webrtc-testsuite", "protocol")
            Files.createDirectories(root)
            val script = Files.createTempFile(root, "scenario-", ".py")
            try {
                Files.write(script, javaClass.getResourceAsStream("/runner/protocol_runner.py")!!.use { it.readBytes() })
                execute(listOf(cfg.tlsScan.pythonExecutable, "-I", "-u", script.toString()), buildJsonObject {
                    put("scenario", json.encodeToJsonElement(scenario)); put("runId", id); put("testId", scenario.testId)
                    put("engagementId", cfg.assessment.engagementId); put("identities", json.encodeToJsonElement(cfg.identities))
                }, scenario.timeoutSeconds, cancelled)
            } finally { Files.deleteIfExists(script) }
        } catch (e: Exception) {
            TestOutcome(engagementId = cfg.assessment.engagementId, runId = id, testId = scenario.testId, target = scenario.id,
                backend = "recorded-scenario", startedAt = started,
                execution = when { stopped || closed || cancelled() -> "cancelled"; e is SecurityException -> "blocked"; e is java.util.concurrent.TimeoutException -> "timeout"; else -> "error" },
                cleanup = "unconfirmed; runner terminated", limitations = listOf(e.message.orEmpty()))
        }
        store.add(outcome)
        return outcome
    }
    @Synchronized fun run(testId: String, target: ProtocolTarget, cancelled: () -> Boolean = { false }): TestOutcome {
        stopped = false
        val cfg = config.config
        val settings = cfg.protocolScan
        val runId = UUID.randomUUID().toString(); val started = Instant.now().toString()
        fun failed(execution: String, message: String) = TestOutcome(engagementId = cfg.assessment.engagementId, runId = runId,
            testId = testId, target = target.input, backend = "bundled-turn", startedAt = started, execution = execution,
            cleanup = "unconfirmed; process terminated, allocation may persist until its server lifetime expires", limitations = listOf(message))
        val result = try {
            settings.validate()
            require(testId in TestRegistry.protocolTests)
            if (closed || cancelled()) error("cancelled")
            if (!authorization.allows(target.scopeUrl)) throw SecurityException("Listener outside configured scope: ${target.scopeUrl}")
            val root = Path.of(System.getProperty("user.home"), ".webrtc-testsuite", "protocol")
            Files.createDirectories(root)
            val script = Files.createTempFile(root, "rtc-", ".py")
            try {
                Files.write(script, javaClass.getResourceAsStream("/runner/protocol_runner.py")!!.use { it.readBytes() })
                val request = buildJsonObject {
                    put("testId", testId); put("runId", runId); put("engagementId", cfg.assessment.engagementId)
                    put("target", target.json()); put("timeoutSeconds", settings.timeoutSeconds)
                    if (settings.relayPeer.isNotBlank()) put("peer", ProtocolTarget.parse(settings.relayPeer).json())
                    put("credentials", buildJsonArray {
                        if (settings.turnUsername.isNotEmpty()) add(buildJsonObject { put("condition", "valid"); put("username", settings.turnUsername); put("password", settings.turnCredential) })
                        if (testId == "TRN-02") {
                            add(buildJsonObject { put("condition", "absent"); put("username", ""); put("password", "") })
                            add(buildJsonObject { put("condition", "incorrect"); put("username", settings.turnUsername); put("password", UUID.randomUUID().toString()) })
                            settings.credentialConditions.forEach { add(json.encodeToJsonElement(it)) }
                        }
                    })
                }
                execute(listOf(cfg.tlsScan.pythonExecutable, "-I", "-u", script.toString()), request, settings.timeoutSeconds, cancelled)
            } finally { Files.deleteIfExists(script) }
        } catch (e: Exception) {
            failed(when { stopped || closed || cancelled() -> "cancelled"; e is SecurityException -> "blocked"; e is java.util.concurrent.TimeoutException -> "timeout"; else -> "error" }, e.message.orEmpty())
        }
        store.add(result)
        return result
    }
    private data class Line(val text: String? = null, val error: String? = null, val end: Boolean = false)
    private fun execute(args: List<String>, request: JsonObject, timeout: Int, cancelled: () -> Boolean): TestOutcome {
        val process = ProcessBuilder(args).start(); current = process
        val lines = ArrayBlockingQueue<Line>(16)
        val stderr = StringBuilder()
        val readers = listOf(process.inputStream to false, process.errorStream to true).map { (stream, errorStream) ->
            Thread({
                try {
                    stream.use { input ->
                        val bytes = java.io.ByteArrayOutputStream(); var total = 0
                        while (true) {
                            val b = input.read(); if (b < 0) break
                            require(++total <= 2_100_000) { "Runner output limit exceeded" }
                            if (b == 10) {
                                val text = bytes.toString(Charsets.UTF_8); bytes.reset()
                                if (errorStream) synchronized(stderr) { stderr.appendLine(text) } else lines.put(Line(text))
                            } else bytes.write(b)
                        }
                        if (bytes.size() > 0) {
                            if (errorStream) synchronized(stderr) { stderr.append(bytes.toString(Charsets.UTF_8)) }
                            else lines.put(Line(bytes.toString(Charsets.UTF_8)))
                        }
                    }
                    if (!errorStream) lines.put(Line(end = true))
                } catch (e: Exception) { lines.offer(Line(error = e.message ?: "Output failure")) }
            }, "webrtc-protocol-output").apply { isDaemon = true; start() }
        }
        val legs = mutableSetOf<Triple<String, String, Int>>()
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout.toLong() + 5)
        val writer = process.outputStream.bufferedWriter(Charsets.UTF_8)
        try {
            writer.write(request.toString()); writer.newLine(); writer.flush()
            var result: TestOutcome? = null
            while (true) {
                if (closed || stopped || cancelled()) error("Stopped")
                if (System.nanoTime() >= deadline) throw java.util.concurrent.TimeoutException("Protocol runner exceeded its budget")
                if (legs.any { !authorization.allowsLeg(it.first, it.second, it.third) }) throw SecurityException("Scope revoked; runner stopped")
                val line = lines.poll(200, TimeUnit.MILLISECONDS) ?: continue
                line.error?.let { error(it) }
                if (line.end) break
                val text = line.text ?: continue
                require(webrtc.bridge.boundedJson(text)) { "Malformed runner JSON" }
                val doc = Json.parseToJsonElement(text).jsonObject
                (doc["authorize"] as? JsonObject)?.let { leg ->
                    val tuple = Triple(leg.getValue("url").jsonPrimitive.content, leg.getValue("address").jsonPrimitive.content, leg.getValue("port").jsonPrimitive.int)
                    val allowed = authorization.allowsLeg(tuple.first, tuple.second, tuple.third)
                    writer.write("{\"allowed\":$allowed}\n"); writer.flush()
                    if (!allowed) throw SecurityException("Authorize both listener and resolved destination in Burp scope and allow-list: $tuple")
                    legs += tuple
                }
                doc["result"]?.let { require(result == null); result = json.decodeFromJsonElement<TestOutcome>(it) }
                doc["error"]?.let { error(it.jsonPrimitive.content) }
            }
            require(process.waitFor(1000, TimeUnit.MILLISECONDS) && process.exitValue() == 0) { "Runner failed: $stderr" }
            val outcome = result ?: error("No structured result returned")
            require(outcome.runId == request["runId"]?.jsonPrimitive?.content && outcome.testId == request["testId"]?.jsonPrimitive?.content &&
                outcome.engagementId == request["engagementId"]?.jsonPrimitive?.content && outcome.target ==
                (request["scenario"]?.jsonObject?.get("id") ?: request["target"]?.jsonObject?.get("input"))?.jsonPrimitive?.content)
            outcome.validate()
            return outcome
        } finally {
            terminate(process); runCatching { writer.close() }; readers.forEach { it.interrupt() }; current = null
        }
    }
    private fun ProtocolTarget.json() = buildJsonObject {
        put("input", input); put("scheme", scheme); put("host", host); put("port", port); put("transport", transport); put("scopeUrl", scopeUrl)
    }
}
