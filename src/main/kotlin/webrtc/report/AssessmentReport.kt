package webrtc.report

import webrtc.assessment.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

object EvidenceFormatting {
    fun markdown(value: String): String = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\\", "&#92;").replace("|", "&#124;").replace("[", "&#91;").replace("]", "&#93;")
        .replace("`", "&#96;").replace("*", "&#42;").replace("_", "&#95;").replace("#", "&#35;")
        .replace("\r", "&#13;").replace("\n", "&#10;")
    fun csv(value: String): String {
        val safe = if (value.trimStart().firstOrNull() in listOf('=', '+', '-', '@') || value.startsWith('\t') || value.startsWith('\r')) "'$value" else value
        return "\"${safe.replace("\"", "\"\"")}\""
    }
    fun code(value: String): String {
        val longest = Regex("`+").findAll(value).maxOfOrNull { it.value.length } ?: 0
        val fence = "`".repeat(maxOf(3, longest + 1))
        return "$fence\n$value\n$fence\n"
    }
}

object AssessmentReport {
    fun markdown(config: AssessmentConfig, outcomes: List<TestOutcome>, evidence: Boolean = false): String = buildString {
        appendLine("## Assessment registry and outcomes"); appendLine()
        appendLine("One row per requirement and target. Execution and security outcomes are separate. Missing adapters and prerequisites are not completed tests.")
        appendLine("Engagement: ${EvidenceFormatting.markdown(config.engagementId)}"); appendLine()
        appendLine("| Test | Execution path | Result / security | Target / limitation |")
        appendLine("| --- | --- | --- | --- |")
        for (definition in TestRegistry.definitions) {
            val history = outcomes.filter { it.testId == definition.id && it.engagementId == config.engagementId }
            if (history.isEmpty()) appendLine("| ${definition.id} ${EvidenceFormatting.markdown(definition.title)} | ${TestRegistry.capability(definition.id, config)} | Not tested | ${if (definition.id in config.selectedTests) "Selected" else "Not selected"} |")
            else for ((target, runs) in history.groupBy { it.target }) {
                val latest = runs.maxBy { it.endedAt }
                val previous = runs.sortedBy { it.endedAt }.dropLast(1).lastOrNull()
                appendLine("| ${definition.id} | ${EvidenceFormatting.markdown(latest.backend)} ${EvidenceFormatting.markdown(latest.backendVersion)} | ${latest.execution} / ${latest.security} (${latest.confidence}, ${latest.severity}) | ${EvidenceFormatting.markdown(target)}: ${EvidenceFormatting.markdown(latest.limitations.joinToString("; "))} |")
                if (previous != null && previous.security != latest.security)
                    appendLine("| | Comparison | ${previous.security} → ${latest.security} | ${EvidenceFormatting.markdown(previous.runId)} → ${EvidenceFormatting.markdown(latest.runId)}; inspect changed inputs before attributing remediation |")
            }
        }
        if (evidence) {
            appendLine(); appendLine("## Exact assessment evidence"); appendLine()
            outcomes.forEach { appendLine(EvidenceFormatting.code(Json { prettyPrint = true; encodeDefaults = true }.encodeToString(it))) }
        }
    }
}
