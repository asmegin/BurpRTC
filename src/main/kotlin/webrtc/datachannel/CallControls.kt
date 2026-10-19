package webrtc.datachannel

import kotlinx.serialization.json.JsonPrimitive

/**
 * Application-specific call controls, one step per line:
 *
 *   navigate <url>             open a URL ({mainRoom}, {testRoom}, {session}, {role} are substituted)
 *   click <selector>           click the first matching element
 *   fill <selector> | <text>   set an input's value and fire input/change events
 *   wait <selector> [ms]       wait until an element exists (default 15000 ms)
 *   waitjs <expression> [ms]   wait until a JavaScript expression is truthy
 *   eval <expression>          run JavaScript in the page
 *   sleep <ms>                 pause
 *   reload                     reload the page
 *   offline <ms>               emulate a network outage for HTTP/WebSocket traffic
 *   waitchannel [ms]           wait until the agent reports an open DataChannel or Colibri socket
 *
 * Selectors may cross same-origin iframes and shadow roots with ">>>", for example
 * "iframe#jitsi >>> button[aria-label='Leave']". Prefix a step with "@<text> " to run
 * it in the (cross-origin) frame whose URL contains <text>. Lines starting with # are comments.
 */
object CallControls {
    data class Step(val action: String, val argument: String, val text: String = "", val timeoutMs: Long = 15000, val frame: String = "", val line: String = "")

    private val actions = setOf("navigate", "click", "fill", "wait", "waitjs", "eval", "sleep", "reload", "offline", "waitchannel")

    fun parse(script: String): List<Step> = script.lines().mapIndexedNotNull { index, raw ->
        var line = raw.trim()
        if (line.isEmpty() || line.startsWith("#")) return@mapIndexedNotNull null
        var frame = ""
        if (line.startsWith("@")) { frame = line.substringBefore(' ').drop(1); line = line.substringAfter(' ', "").trim() }
        val action = line.substringBefore(' ').lowercase()
        val rest = line.substringAfter(' ', "").trim()
        require(action in actions) { "Line ${index + 1}: unknown step '$action'. Use ${actions.joinToString(", ")}" }
        require(line.length <= 8192) { "Line ${index + 1} is too long" }
        fun timeout(text: String, default: Long): Pair<String, Long> {
            val last = text.substringAfterLast(' ', "")
            return if (last.toLongOrNull() != null && text.contains(' ')) text.substringBeforeLast(' ').trim() to last.toLong().coerceIn(100, 300000) else text to default
        }
        when (action) {
            "fill" -> {
                require(rest.contains('|')) { "Line ${index + 1}: use fill <selector> | <text>" }
                Step(action, rest.substringBefore('|').trim(), rest.substringAfter('|').trim(), frame = frame, line = raw)
            }
            "sleep", "offline" -> {
                val ms = rest.toLongOrNull()
                require(ms != null && ms in 0..300000) { "Line ${index + 1}: $action needs milliseconds (0-300000)" }
                Step(action, rest, timeoutMs = ms, frame = frame, line = raw)
            }
            "wait", "waitjs" -> timeout(rest, 15000).let { (arg, ms) ->
                require(arg.isNotBlank()) { "Line ${index + 1}: $action needs a ${if (action == "wait") "selector" else "expression"}" }
                Step(action, arg, timeoutMs = ms, frame = frame, line = raw)
            }
            "waitchannel" -> Step(action, "", timeoutMs = rest.toLongOrNull()?.coerceIn(1000, 300000) ?: 30000, frame = frame, line = raw)
            "reload" -> Step(action, "", frame = frame, line = raw)
            else -> {
                require(rest.isNotBlank()) { "Line ${index + 1}: $action needs an argument" }
                Step(action, rest, frame = frame, line = raw)
            }
        }
    }

    fun substitute(text: String, vars: Map<String, String>): String = vars.entries.fold(text) { acc, (k, v) -> acc.replace("{$k}", v) }

    private fun js(value: String) = JsonPrimitive(value).toString()

    /** Resolve a ">>>" selector path through same-origin iframes and shadow roots. */
    private fun finder(selector: String) = """
        (function(path){var root=document,el=null;for(var i=0;i<path.length;i++){
          el=root.querySelector(path[i].trim());if(!el)return null;
          if(i<path.length-1){root=el.shadowRoot||(el.contentDocument)||null;if(!root)return null;}}
          return el;})(${js(selector)}.split('>>>'))""".trimIndent()

    /** JavaScript for a page-side step, or null for steps the runner performs itself. */
    fun script(step: Step): String? = when (step.action) {
        "click" -> "(function(){var el=${finder(step.argument)};if(!el)throw new Error('Element not found: '+${js(step.argument)});" +
            "if(el.scrollIntoView)el.scrollIntoView({block:'center'});el.click();return true;})()"
        "fill" -> "(function(){var el=${finder(step.argument)};if(!el)throw new Error('Element not found: '+${js(step.argument)});" +
            "var proto=Object.getPrototypeOf(el),d=Object.getOwnPropertyDescriptor(proto,'value');if(d&&d.set)d.set.call(el,${js(step.text)});else el.value=${js(step.text)};" +
            "el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));return true;})()"
        "wait" -> "(function(){return !!(${finder(step.argument)});})()"
        "waitjs" -> "(function(){return !!(${step.argument});})()"
        "eval" -> step.argument
        "navigate" -> "location.href=${js(step.argument)};true"
        else -> null
    }
}
