package webrtc.tls

import kotlinx.serialization.json.*
import webrtc.config.ConfigStore
import webrtc.scope.ScopeGate
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.LocalTime
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Runs only our bundled script, with arguments (never a shell) and continuous scope checks. */
class TlsScanRunner(
    private val configStore: ConfigStore,
    private val inScope: (String) -> Boolean,
    private val telemetry: TelemetryTableModel,
    private val root: Path = Path.of(System.getProperty("user.home"), ".webrtc-testsuite", "tls"),
    private val launch: (List<String>) -> Process = { ProcessBuilder(it).start() },
    private val nanoTime: () -> Long = System::nanoTime
) : AutoCloseable {
    data class Outcome(val status: String, val detail: String, val result: JsonObject? = null)
    private class Aborted(val status: String, message: String) : Exception(message)
    private val json = Json { ignoreUnknownKeys = true }
    private val gate = Any()
    @Volatile private var busy = false
    @Volatile private var stopped = false
    @Volatile private var closed = false
    @Volatile private var current: Process? = null
    fun isBusy(): Boolean = busy

    fun stop(): Unit = synchronized(gate) {
        stopped = true
        current?.let(::terminate)
        Unit
    }

    override fun close() { synchronized(gate) { closed = true; stop() } }

    fun runtimeDirectory(config: TlsScanConfig): Path {
        val key = MessageDigest.getInstance("SHA-256").digest(config.pythonExecutable.toByteArray())
            .take(8).joinToString("") { "%02x".format(it) }
        return root.resolve("sslyze-6.3.1-$key")
    }

    private fun python(config: TlsScanConfig): String = runtimeDirectory(config)
        .resolve(if (System.getProperty("os.name").startsWith("Windows")) "Scripts/python.exe" else "bin/python").toString()

    private fun script(): String {
        Files.createDirectories(root)
        val path = root.resolve("tls_runner-1.0.3.py")
        val bytes = javaClass.getResourceAsStream("/runner/tls_runner.py")?.use { it.readBytes() }
            ?: error("Bundled TLS runner is missing; reload the extension JAR")
        if (!Files.exists(path) || !Files.readAllBytes(path).contentEquals(bytes)) Files.write(path, bytes)
        return path.toString()
    }

    private fun authorized(target: TlsTarget): Boolean {
        val cfg = configStore.config
        return cfg.injectionEnabled && ScopeGate.hostAllowed(target.host, cfg.hostAllowList) &&
            runCatching { inScope(target.scopeUrl) }.getOrDefault(false)
    }

    private fun event(type: String, detail: String, target: TlsTarget? = null, result: JsonObject? = null) {
        val raw = buildJsonObject {
            put("type", type); put("module", "TLS"); put("detail", detail)
            target?.let { put("target", it.input); put("scopeUrl", it.scopeUrl); put("hostname", it.host); put("port", it.port) }
            result?.let { put("result", it) }
        }
        telemetry.add(TelemetryEvent(telemetry.nextSeq(), LocalTime.now().toString(), type,
            target?.scopeUrl.orEmpty(), "", false, detail, raw.toString()))
    }

    private fun task(target: TlsTarget? = null, action: () -> Outcome): Outcome {
        synchronized(gate) {
            if (closed) return Outcome("failed", "TLS runner is unloaded")
            if (busy) return Outcome("busy", "Another TLS runner task is active; stop it or wait")
            busy = true; stopped = false
        }
        return try {
            action()
        } catch (error: Exception) {
            val status = (error as? Aborted)?.status ?: "failed"
            val detail = error.message ?: error.javaClass.simpleName
            val result = buildJsonObject { put("status", status); put("error", detail) }
            event(if (target == null) "tls-runtime" else "tls-scan-error", detail, target, result)
            Outcome(status, detail, result)
        } finally {
            synchronized(gate) { current?.let(::terminate); current = null; busy = false }
        }
    }

    fun setup(config: TlsScanConfig, log: (String) -> Unit = {}): Outcome = task {
        config.validate()
        val deadline = nanoTime() + TimeUnit.SECONDS.toNanos(300)
        log("Checking Python 3.10+…")
        execute(listOf(config.pythonExecutable, "-I", "-c",
            "import sys; sys.exit(0 if sys.version_info >= (3,10) else 'Python 3.10+ required')"), "", deadline, null, log)
        log("Creating managed Python environment: ${runtimeDirectory(config)}")
        Files.createDirectories(root)
        execute(listOf(config.pythonExecutable, "-I", "-m", "venv", runtimeDirectory(config).toString()), "", deadline, null, log)
        log("Installing SSLyze 6.3.1 and dependencies from PyPI…")
        execute(listOf(python(config), "-I", "-m", "pip", "install", "--disable-pip-version-check", "sslyze==6.3.1"), "", deadline, null, log)
        val result = parse(execute(listOf(python(config), "-I", "-u", script(), "--check"), "", deadline, null, log))
        require(result["ready"]?.jsonPrimitive?.booleanOrNull == true) { "TLS runtime check failed: $result" }
        val detail = "TLS runner ready: ${result["engine"]?.jsonPrimitive?.content} (Python ${result["python"]?.jsonPrimitive?.content})"
        event("tls-runtime", detail, result = result)
        Outcome("ready", detail, result)
    }

    fun check(config: TlsScanConfig): Outcome = task {
        config.validate(); requireRuntime(config)
        val result = parse(execute(listOf(python(config), "-I", "-u", script(), "--check"), "",
            nanoTime() + TimeUnit.SECONDS.toNanos(30), null))
        require(result["ready"]?.jsonPrimitive?.booleanOrNull == true) { "TLS runtime check failed: $result" }
        val detail = "TLS runner ready: ${result["engine"]?.jsonPrimitive?.content} (Python ${result["python"]?.jsonPrimitive?.content})"
        event("tls-runtime", detail, result = result)
        Outcome("ready", detail, result)
    }

    fun scan(config: TlsScanConfig, isCancelled: () -> Boolean = { false }): Outcome {
        val target = try { config.validate(); TlsTarget.parse(config.endpoint) } catch (e: Exception) {
            val detail = e.message ?: "Invalid TLS target"
            event("tls-scan-error", detail, result = buildJsonObject { put("status", "failed"); put("error", detail) })
            return Outcome("failed", detail)
        }
        return task(target) {
            if (isCancelled()) throw Aborted("cancelled", "TLS task stopped")
            if (!authorized(target)) throw Aborted("blocked", "Enable injection, allow ${target.host}, and add ${target.scopeUrl} to Burp Target scope")
            if (config.engine == "builtin") {
                event("tls-scan-start", "TLS scan started (built-in): ${target.host}:${target.port}; scope ${target.scopeUrl}", target)
                val result = JvmTlsScanner({ authorized(target) }, { stopped || closed || isCancelled() },
                    nanoTime() + TimeUnit.SECONDS.toNanos(config.timeoutSeconds.toLong())).scan(target.host, target.port)
                val status = result["status"]?.jsonPrimitive?.content ?: "failed"
                val detail = "TLS scan $status (built-in): ${target.host}:${target.port}; ${(result["checks"] as JsonArray).size} checks, ${(result["findings"] as JsonArray).size} observations" +
                    (result["error"]?.jsonPrimitive?.content?.let { "; $it" } ?: "")
                event("tls-scan-result", detail, target, result)
                return@task Outcome(status, detail, result)
            }
            requireRuntime(config)
            val request = buildJsonObject {
                put("hostname", target.host); put("port", target.port); put("vulnerabilityChecks", config.vulnerabilityChecks)
            }
            event("tls-scan-start", "TLS scan started: ${target.host}:${target.port}; scope ${target.scopeUrl}", target)
            val result = parse(execute(listOf(python(config), "-I", "-u", script()), request.toString(),
                nanoTime() + TimeUnit.SECONDS.toNanos(config.timeoutSeconds.toLong()), target, isCancelled = isCancelled))
            require(result["schema"]?.jsonPrimitive?.intOrNull == 1 &&
                result["hostname"]?.jsonPrimitive?.content == target.host && result["port"]?.jsonPrimitive?.intOrNull == target.port &&
                result["checks"] is JsonArray && result["findings"] is JsonArray && result["raw"] is JsonObject) { "Unexpected TLS runner result schema" }
            val status = result["status"]?.jsonPrimitive?.content ?: "failed"
            require(status in setOf("completed", "partial", "failed")) { "Unknown TLS runner status" }
            val detail = "TLS scan $status: ${target.host}:${target.port}; ${(result["checks"] as JsonArray).size} checks, ${(result["findings"] as JsonArray).size} observations"
            event("tls-scan-result", detail, target, result)
            Outcome(status, detail, result)
        }
    }

    private fun requireRuntime(config: TlsScanConfig) {
        require(Files.isRegularFile(Path.of(python(config)))) { "SSLyze engine selected: click Setup SSLyze first (Python 3.10+ must be installed), or choose the built-in engine" }
    }
    private fun parse(value: String): JsonObject = json.parseToJsonElement(value.trim()).jsonObject

    private class Capture(stream: InputStream) {
        private val bytes = java.io.ByteArrayOutputStream()
        val overflow = AtomicBoolean(false)
        @Volatile var error: Exception? = null
        val thread = Thread({
            try {
                stream.use { input ->
                    val buffer = ByteArray(8192)
                    while (true) {
                        val n = input.read(buffer); if (n < 0) break
                        synchronized(bytes) {
                            if (bytes.size() + n > 8 * 1024 * 1024) overflow.set(true)
                            else bytes.write(buffer, 0, n)
                        }
                        if (overflow.get()) break
                    }
                }
            } catch (e: Exception) { error = e }
        }, "webrtc-tls-output").apply { isDaemon = true; start() }
        fun text(): String = synchronized(bytes) { bytes.toString(Charsets.UTF_8) }
    }

    private fun execute(args: List<String>, input: String, deadline: Long, target: TlsTarget?, log: (String) -> Unit = {}, isCancelled: () -> Boolean = { false }): String {
        fun checkAllowed() {
            if (stopped || closed || isCancelled()) throw Aborted("cancelled", "TLS task stopped")
            if (target != null && !authorized(target)) throw Aborted("blocked", "TLS task stopped: scope or injection/allow-list permission was removed")
            if (nanoTime() >= deadline) throw Aborted("timeout", "TLS task exceeded its time budget")
        }
        val process = synchronized(gate) { checkAllowed(); launch(args).also { current = it } }
        val out = Capture(process.inputStream)
        val err = Capture(process.errorStream)
        try {
            process.outputStream.use { it.write(input.toByteArray(Charsets.UTF_8)) }
            while (true) {
                checkAllowed()
                if (out.overflow.get() || err.overflow.get()) error("TLS output exceeded the 8 MiB limit; evidence is incomplete")
                if (process.waitFor(200, TimeUnit.MILLISECONDS)) break
            }
            checkAllowed()
            out.thread.join(1000); err.thread.join(1000)
            require(!out.thread.isAlive && !err.thread.isAlive && out.error == null && err.error == null && !out.overflow.get() && !err.overflow.get()) {
                "TLS process output could not be fully captured"
            }
            val stdout = out.text(); val stderr = err.text()
            if (stdout.isNotBlank()) log(stdout)
            if (stderr.isNotBlank()) log(stderr)
            require(process.exitValue() == 0) { "TLS process exited ${process.exitValue()}: ${stderr.ifBlank { stdout }}" }
            return stdout
        } finally {
            terminate(process)
            synchronized(gate) { if (current === process) current = null }
        }
    }

    private fun terminate(process: Process) {
        runCatching { process.toHandle().descendants().use { handles -> handles.forEach { runCatching { it.destroyForcibly() } } } }
        if (process.isAlive) runCatching { process.destroyForcibly() }
    }
}
