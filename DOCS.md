# WebRTC Test Suite — full reference

> This is the complete reference. For a short overview and download/build/load
> instructions, see [README.md](README.md).

A client-agnostic Burp extension that drives a WebRTC penetration test from one
Suite tab. Nothing target-specific is compiled in — every engagement detail is
configuration (Module 0), persisted in the Burp project file.

> Authorized testing only. Every active action (injection, mutation, fuzzing,
> ICE probing, replay) is gated on Burp **Target scope**. Credentials are preserved
> in full; captured session candidates are held in memory.

## Current status (2026-10-19)

**Version 1.3.0.** `build/libs/webrtc-testsuite-all.jar` bundles browser agent
**1.3.0** and the optional SSLyze adapter. STUN/TURN tests, HTTP/WebSocket
scenarios, the default TLS engine and the new DataChannel runner run on the JVM
inside Burp; Python is needed only if you choose the SSLyze engine.
Validated: **203 JVM tests passed**, with two opt-in tests skipped by default (the
SSLyze integration test and the live browser-runner test), and **55 agent tests**
passed. The DataChannel runner is tested end to end against simulated pages and a
simulated bridge.

Real-browser checks (Microsoft Edge / Chromium):

- `agent/browser-smoke.cjs` confirms that runner cases reach the real remote end of a
  DataChannel with marker receipts.
- The browser itself rejects a send one byte above maxMessageSize (`TypeError`).
- The opt-in live test (set `CHROME_PATH`) drives the integrated runner over
  DevTools: launch, session tagging before page scripts, fill / click / wait steps,
  evaluate and close.

The runner has not yet been exercised against a live Jitsi / LiveBank deployment.

### 1.3.0 — DataChannel test runner with paired-session observation

**Tests → Data channel runner** (also selectable as *Data channel runner* in Scan
All) runs DataChannel and Colibri bridge-channel tests from one sender page while
every other instrumented page observes. Each case carries a unique marker
(`wrtc` + 12 characters). Recipients report what they **received** (DataChannel or
Colibri WebSocket), **rendered** (DOM) or **threw on** (page errors). A successful
`send()` or silence is never a pass.

*Classification.* Every case is PASS, FAIL, INCONCLUSIVE, BLOCKED or NOT APPLICABLE:

- **PASS** needs recipient-side evidence: a delivered positive control, and a
  delivery probe after the case (one probe every *N* cases).
- **FAIL** means one of:
  - an unauthorized participant received or rendered the message;
  - a spoofed `from` reached a recipient;
  - an application error carried the case marker;
  - session health was lost.
- **INCONCLUSIVE** covers a browser-side rejection (never treated as server
  validation), a missing observer, an unknown identifier and a failed control.
- **BLOCKED** covers a closed channel, an exhausted budget and missing call
  controls.
- **NOT APPLICABLE** marks a transport or architecture the application does not use.

When a probe fails, the runner waits for recovery. It then re-runs that group
one case at a time, so the case that broke the session is found.

*Families* (each maps to a coverage row):

- **Channel discovery and baseline.** The agent records every channel: label,
  protocol, ordered, maxRetransmits, maxPacketLifeTime, negotiated, stream ID,
  bufferedAmount and lifecycle. It also records SCTP maxMessageSize, maxChannels
  and state, and the Colibri WebSocket URL hints.
  - Peers are classified as **JVB** (Colibri protocol/label), **SFU** (ICE-lite
    remote) or **participant**.
  - Before testing, the runner learns sample messages per class, takes a health
    snapshot and runs a positive control. Unavailable channels are BLOCKED.
  - The proxy injector now places the agent before the page's first head
    `<script>`, so hooks exist before application startup.
- **Application-message fuzzing.** Templates come from observed messages first,
  then from version-aware Colibri schemas. Generations are endpoint-based (≤2.1),
  source names (2.2) and source maps (2.3+). The generation is taken from the
  configured version, then ServerHello, then the observed classes.
  - Each case changes one field or one structural property: missing, null, wrong
    type, negative or oversized numbers, int64 overflow, long strings, raw Unicode
    and control escapes (including lone surrogates), and nesting up to the bound.
  - Whole-message cases: extra fields, duplicate keys, unknown / case-changed /
    missing `colibriClass`, and malformed JSON (truncated, trailing comma, single
    quotes, unquoted keys, NaN, comments, BOM, trailing garbage, top-level array
    or string).
  - Malformed EndpointStats are included. Non-forwarded control classes must reach
    nobody. `msgPayload` content is relayed by design and judged at the receivers.
- **Binary and size boundaries.** Payload types: text, ArrayBuffer, Uint8Array,
  Int16Array, Float64Array, DataView and Blob.
  - Payloads: empty, 1-byte, zero-filled, seeded random (reproducible) and JSON
    sent as binary.
  - Sizes: 16 KiB, 64 KiB, a multi-byte UTF-8 character across 16 KiB, and
    maxMessageSize − 1 / = / + 1 within the per-message cap. Sizes are measured in
    UTF-8 bytes.
- **Message authorization and isolation.**
  - Delivery: unicast to the intended recipient (other participants must not
    receive it), and broadcast that stays out of the test room.
  - Tampered addressing: cross-room unicast, an unknown endpoint, and an array
    recipient.
  - Identity spoofing: a spoofed `from` (call participant and test-room
    endpoint), and injected conference / room fields.
  - Direction: every server-to-client class sent by a client, and a video-type
    change for another participant's source.
  - Colibri WebSocket admission with a wrong pwd, no pwd, another conference, or
    another endpoint (the victim is checked for displacement).
  - Optional **protected messages**: advisor-only commands with a state probe. The
    allowed role is the positive control, state is restored, then the denied role
    is tested.
- **Replay and lifecycle.** Exact in-session replays are matched by payload hash.
  With runner sessions, the runner automates:
  - customer leave (closure correlated with the action; an old channel that still
    delivers is a FAIL);
  - re-join with stale replays and the old Colibri URL;
  - a network interruption with reconnect;
  - advisor hang-up, then a fresh admission attempt and the ended call's URL;
  - removal and re-admission.

  State is restored afterwards.
- **Bounded load and channel churn.** Configurable rate steps and a burst, with
  sequential markers for delivery ratio and estimated p95 latency.
  - Health and media packet loss are compared with the baseline. The run stops at
    the first degradation threshold and records recovery.
  - Churn runs sequentially (reliability variants, long label / protocol, an
    invalid combination) and concurrently up to the channel cap. It runs only on a
    connected SCTP association, so no renegotiation is triggered.
- **Colibri transport comparison.** When both an RTCDataChannel and a Colibri
  WebSocket carry bridge messages, equivalent cases run on the second transport
  and differences are listed. A Colibri WebSocket reconnect is also tested.
  Results are tagged with the transport actually used.

*Integrated browser runner.* It launches one isolated Chromium per session:

- The browser is Burp's bundled Chromium, Chrome or Edge, routed through the Burp
  proxy listener, with fake camera and microphone and a persistent or temporary
  profile.
- Every frame is tagged with the session name before page scripts run, and Setup
  identities are applied (cookies and headers).
- Call controls are per session: Join, Leave, Hang up, Remove and an endpoint
  expression.
- Each control is a script of steps: `navigate`, `click`, `fill`, `wait`,
  `waitjs`, `eval`, `sleep`, `reload`, `offline` and `waitchannel`.
- Selectors cross iframes and shadow roots with `>>>`; `@<url text>` targets a
  cross-origin frame.
- Start URLs and `navigate` targets must be allow-listed and in Burp scope.

*Configuration* (persisted): families, case / byte / duration budgets, settle
window, probe interval, buffer and nesting caps, load steps and degradation
thresholds, seed, Jitsi version, probe template, test-room endpoint, re-join
expectations, protected messages and an optional bridge-log file. New error
lines are attached to the run; lines with a case marker are attached to that case.

*Evidence and reporting.* Each result is a `dc-case-result` event in Evidence and
a row in the M7 DataChannel (or DoS, for load) section. A result records:

- case ID, payload or seed, direction, sender identity / role / room / endpoint
  and transport;
- timestamps, the local exception, bufferedAmount and states before and after;
- every recipient observation with latency, the probe outcome, recovery and
  bridge-log lines.

Runs persist in the project, export as JSON and roll up into registry tests
DCH-01/02/03. The **Coverage** tab maps every RTCDataChannel scope item to the
executed case IDs and the remaining limitations. Credentials, pwd parameters and
payloads are kept in full, following the project's no-masking policy.

*Not covered (separate harness).* Native SCTP / DCEP packet fuzzing is out of
scope: browser JavaScript cannot craft SCTP chunks, fragmentation, stream resets
or DCEP packets. It is listed as its own coverage item (registry DCH-04) for a
DTLS/SCTP-capable test peer with crash and log collection.

New agent events: `dc-case`, `dc-markers`, `dc-health`, `dc-load-step`,
`dc-churn-result`, `dc-churn-summary`, `ws-admission-result`,
`transport-action-result`, `page-error`, `ws-colibri`, `ws-colibri-send`,
`ws-colibri-recv` and the matching `*-error` types. Burp-side events:
`dc-case-result`, `dc-runner`, `runner-action` and `bridge-log`. Scan All selection
version 4 adds the runner once to existing non-empty selections. Reload browser
pages so they pick up agent 1.3.0.

### 1.2.0 — self-contained runners, video banking (advisor / customer) testing, Burp issues

**Self-contained.** No Python is needed for any default test:

- **Built-in STUN/TURN runner** (`protocol/TurnProbe.kt`) replaces the Python
  protocol runner for TRN-01/02/04/05/07 with the same scope grants per connect
  and send, budgets, MESSAGE-INTEGRITY checks and allocation release.
- **Forwarding without an echo host.** TRN-04/05 allocate a second relay on the
  same server and verify that a marker sent through the first allocation arrives
  at the second (Send/Data and ChannelData). Both run automatically from Scan All.
  A supplied UDP echo peer is still used when present, to test a specific
  destination.
- **Scenarios through Burp.** Saved HTTP/WebSocket scenarios are sent with Burp's
  own HTTP and WebSocket stacks, so the traffic appears in Burp's logs.
- **Built-in TLS engine** (`tls/JvmTlsScanner.kt`, default). Hand-built
  ClientHello probes measure SSL 3.0, TLS 1.0, 1.1 and 1.2 support and enumerate
  TLS 1.2 cipher suites. The JDK stack checks TLS 1.3, certificate trust,
  hostname, validity and key size. SSLyze stays available as the optional engine
  for SSL 2.0, compression, renegotiation and vulnerability probes.
- `runner/protocol_runner.py` is no longer bundled or used.

**Video banking (for example LiveBank-style advisor / customer apps):**

- **Roles.** Access control sessions have a Role column (guest, customer, advisor,
  admin). Replays then carry an expectation. A lower role that receives the
  baseline body, or another principal whose response contains the owner's
  identifying values (JWT subject, e-mail or name claims, configured identifiers),
  is reported as a **likely violation**. A credential-free control that returns
  the same body marks the resource **public** instead.
- **Meeting links.** Invite links opened through Burp (query tokens such as
  `token`, `code`, `invite`, or path tokens under `/join/`, `/meeting/` and similar)
  are catalogued with the API requests that validated them. Tests replay them
  without session cookies, with one character of the token altered, and with the
  token removed. They also estimate guessability. **Recheck links** after the
  meeting tests reuse and expiry.
- **Documents & recordings.** Downloads (PDF, attachments, office files,
  recordings, uploaded images under document paths) are replayed with the other
  sessions, without credentials, and with the neighbouring numeric ID. Signed-link
  lifetime is reported, and roles prevent advisor access from being flagged.
- **XSS canaries** (new screen). Generate a canary per injection point and paste
  its payload into chat, display names, file names or room titles. The payload
  calls a hook defined only by the agent, so when it executes in an instrumented
  page (for example the advisor console) that page reports the execution, origin
  and script-readable cookies. With Burp Collaborator (Professional) the payloads
  also load a Collaborator URL, and **callback canaries** provide URLs for webhook,
  export and import fields. Canaries returned in HTTP responses or WebSocket
  messages are classified as markup intact, encoded or plain. Canaries persist in
  the project, and an Intruder payload source named "WebRTC XSS canaries" is
  registered. Canary payloads can also be sent over a live DataChannel (M4 list
  mode).
- **Screen sharing and capture lifecycle.** The agent records `getDisplayMedia`
  outcomes and the shared surface (a whole monitor is a review item for advisors).
  It records track stop/end events, and flags camera, microphone or screen
  capture still live 3 s after the last peer connection closes.
- **Browser & capture checks** (new Scan All module) finishes the previously
  unhandled `browser-checks` command: permission states for camera, microphone and
  display capture, permission policy, secure context, framing and device-label
  exposure.
- **Cross-window messaging.** Message listeners without an `event.origin`
  reference, cross-origin messages received, and `postMessage(..., "*")` (flagged
  when the data looks like a token) are recorded.
- **Original header audit.** The headers captured before CSP stripping are now
  analyzed: framing, missing or inline-permitting CSP, Permissions-Policy for
  camera, microphone and display-capture, HSTS, session-cookie flags, CORS `null`
  with credentials, and meeting tokens leaking through `Referrer-Policy`.
- **Video banking preset** on Scan All selects every scan, uses the built-in TLS
  engine, enables Burp issues and shows a step-by-step customer / advisor checklist.

**Burp integration.** Confirmed and likely findings are added to Burp's Issues list
with evidence and deduplicated: executed canaries, Collaborator callbacks, likely
access violations, capture left on, wildcard postMessage with token data,
Permissions-Policy and Referrer issues, failed security checks and weak TLS
listeners. Generic header issues that Burp's scanner already raises are not
duplicated. Toggle in Setup ("Add WebRTC findings to Burp's Issues list").

**Report and coverage corrections.** TURN authentication and relay-abuse coverage
text now describes the existing TRN-02/04/05 backends. Security-check outcomes
appear in the report under their checks. WebSocket authentication, session/room
access, browser XSS/origin and recording storage have moved from external-only to
partial coverage. Likely violations are Findings.

Scan All selection version 3 adds the three new modules (Browser & capture checks,
Meeting links, Documents & recordings) once to existing non-empty selections.
Reload the extension JAR and browser pages for agent **1.2.0**.

### 1.1.4 — captured-session authorization workspace

Access control now captures credential bundles directly from scoped, allow-listed
HTTP and WebSocket traffic. Capture runs without injection; active replay still
requires injection, allow-list and Burp Target scope before every send. Extension
replays do not become new session candidates or overwrite the request catalog.
The catalog holds 100 candidates, five JSON read requests per candidate, and bounded
XMPP observations, in memory only. A candidate is not a confirmed distinct user.

Select 2–8 candidates with **Use**, name them, then **Compare selected sessions**.
The default plan uses at most ten captured JSON GET/HEAD requests, preserving each
resource and swapping donor authentication headers, URL fields and recognized
JSON-pointer/form token locations. Known credentials are removed for the absent
variant. Incompatible body locations and different origins are skipped. Unknown
application authentication still requires review. Explicit context-menu requests
can include writes; automatic capture never chooses writes or XMPP stream requests.
Results show full baseline and replay requests/responses, with Repeater handoff.
Scan All uses selected captured sessions or the existing configured identities.

**Prepare room swaps** builds fresh browser login links using observed JWT room
pages and Jitsi WebSocket room/token parameters, preserving tenant path prefixes.
It includes positive controls, missing URL-token controls and donor JWTs in both
directions. Room admission and guest/moderator policy must be checked in fresh
browser profiles routed through Burp. Live BOSH `sid/rid`, SASL state and existing
XMPP streams are not transplanted. SASL tokens with unknown transport binding are
displayed as observations, never fabricated into HTTP credentials. Duplicate JWT
comparisons are skipped. JWT claims/expiry are decoded without signature validation;
HTML shells and unsuccessful baselines do not establish an authorization finding.
M7 includes the actual HTTP requests/responses and comparison interpretation.

### 1.1.3 — workspace and UI refresh

The extension opens on **Scan All** and uses grouped sidebar navigation:

| Group | Screens |
|---|---|
| Workspace | Scan All, Setup, Evidence, Report |
| Tests | Security checks, TLS tests, Access control, SDP rules, SDP fuzzing, Data channels, STUN & TURN, Negotiation loop |
| Tools | External commands |

**Ctrl+1–4** selects the four workspace screens. Navigation preserves unsaved
drafts and results. Screens are created on first use and their refresh timers stop
when hidden. Page/channel lists pause refresh while their dropdown is open.

Settings and results use consistent spacing and light/dark colors. Scan descriptions
wrap, empty results explain the next step, and primary actions remain visible in
compact windows. Advanced settings and Python runtime controls are expandable.
The Evidence, Security checks, Report, and per-test detail panes support literal
search with **Ctrl+F**, **F3**, and **Shift+F3**, with case matching in search options.

Browser tests expose **Save settings** to persist inputs for Scan All without
starting a test. SDP fuzzing restores the saved case budget exactly. TURN credentials
are readable and saved verbatim. **Run negotiation loop** supplies the explicit
execution choice directly; it no longer needs a separate enable checkbox.
All existing scope checks and scan selection defaults still apply.

### 1.1.2 — scan selection and executable security checks

The first tab is **Scan All**. All ten scan switches default on and save
automatically in the Burp project. **Scan selected** runs only the checked modules;
**Clear selection** stays empty after reload and starts no scans. Existing projects
with the old unused ScanPlan receive these defaults once. Active execution still
requires injection, the host allow-list and Burp Target scope.

Selected TLS scans use the endpoint saved in **TLS tests** and its managed SSLyze
environment; the duplicate inclusion checkbox was removed. The bounded T8 local
loop uses Scan All's selection directly. In 1.1.3, clicking its manual Run button
also supplies the execution choice without another checkbox.
M3 enables saved mutation rules from Scan All; no rule is invented, and a fresh
browser negotiation is needed for actual mutation evidence. M5 now replays up to
five eligible captured GET/HEAD requests using saved identities and stripped auth
headers. Candidate requests have a successful HTML/JSON response; paths containing
logout/signout/delete/remove/revoke/unsubscribe are excluded. Replays remain scope
gated before every request. Status codes alone remain review leads.

**Security checks** replaces the old assessment checkbox registry. It displays
twelve checks with real backends: seven captured-evidence reviews and five
STUN/TURN protocol checks. Saved HTTP/WebSocket scenarios add their executable
checks. Manual-only backlog entries are omitted. Run/Resume/Stop, Inputs, runtime
setup/check and evidence are available in the tab. Scan All controls inclusion
of this group; the security tab has no test-selection checkboxes.

Python 3.10+ is required for protocol/scenario execution. The Python executable is
shared with TLS tests, while the dependency-free protocol runner has its own venv
under `~/.webrtc-testsuite/protocol/python-<key>/`. **Setup Python runner** creates
it without pip or third-party downloads; first Run also prepares it automatically.
**Check Python runtime** verifies its version. Runtime tasks are bounded and Stop
terminates the process. TLS setup remains separate because it installs SSLyze.

Blank listener overrides use observed ICE servers and their matching credentials;
recent observations take precedence. Enter STUN/TURN URIs, username and credential
in **Server inputs** to override specific listeners. TRN-04/05 require a controlled UDP
echo destination, such as `udp://192.0.2.10:9000`. The named listener, resolved IP
and echo destination need their own scope/allow-list permission; each network leg
requests a fresh grant from Burp. TRN-07 checks refresh/release, without claiming
cross-account ownership coverage. The optional scenarios editor preserves the
existing structured scenario contract and positive-control/content assertions.

Missing listeners, accounts, peers, runtime prerequisites and scope grants produce
explicit blocked/error/incomplete results. Captured-evidence review is observation,
not an active enforcement test. M7 includes actual execution/evidence; unsupported
coverage remains a gap. External commands remains the command builder for tools that
require an external harness. Reload the extension and browser pages after updating.

### 1.1.1 fixes — SPA interception, assessment selection & automatic Run All

- **Fixed constant HTTP 403s on the agent collect endpoint.** `BridgeSessions`
  bound each session to the exact injected URL, so single-page navigation (routing,
  fragments, query changes) made the agent's reported `location.href` diverge from
  Burp's `request.url()` and every telemetry beacon was rejected after the first
  load. Sessions now bind at **origin** granularity: the unguessable per-injection
  token, loopback-only `Host` check and same-origin check still isolate pages and
  block cross-origin / DNS-rebinding callers, while in-page navigation keeps
  collecting. Covered by a new `same-origin in-page navigation` bridge test.
- **Assessment Tests selection.** The Registry tab adds **Select all executable**
  (only tests with a ready automated backend — passive, TURN runner, configured
  scenarios), **Select all**, and **Clear selection**. The former "No execution
  adapter" execution-path label now reads "Manual / external — see contract", and
  the recorded reason explains the item is tested manually or with an external tool.
- **Run All runs assessments automatically.** Previously Run All executed only the
  tests explicitly ticked in the Assessment tab, which defaults to none — so the
  registry was silently skipped out of the box. When nothing is curated, Run All now
  auto-runs every test with a ready automated backend and reports how many.

This is an extension-side fix; reload the extension with the new jar. The bundled
agent is bumped to 1.1.1 for version alignment, but `webrtc-agent.js` behavior is
unchanged, so a browser page reload is optional.

### 1.1.0 additions — executable assessment suite, managed protocol runner & methodology corrections

**Assessment Tests tab**: backed by a shared 83-test executable registry (`catalog.json` /
`TestRegistry`), covering the comprehensive testing backlog.
- **Managed protocol runner (`runner/protocol_runner.py` / `ProtocolRunner.kt`)**: runs
  dependency-free protocol checks via JSON-lines IPC with hard budgets and cancellation.
  - TRN-01: STUN binding, software, realm, and alternate server inventory.
  - TRN-02: Automated TURN authentication matrix with challenge handling and `MESSAGE-INTEGRITY`.
  - TRN-04: Peer ACL/SSRF destination checking with synthetic echo markers.
  - TRN-05: Multi-path relay testing (Send/Data indications vs ChannelBind/ChannelData).
  - TRN-07: Allocation refresh and explicit zero-lifetime release.
  - Every network leg is gated by duplex scope authorization (`NetworkAuthorization`).
- **Stateful WebSocket & HTTP scenario harness (SIG-01–06, FND-04)**:
  - Multi-identity scenario execution with Origin/CSWSH checks, cross-tenant identifier substitution,
    and assertions on protected response data (`pointer`, `equals`, `meaning`).
  - Positive controls and explicit cleanup steps required.
- **Native WebSocket capture & RTC decoding (`RtcCapture`)**:
  - Registers Montoya WebSocketCreatedHandler to capture live signaling traffic.
  - Decodes Socket.IO envelopes, nested JSON, escaped SDP, and trickle ICE candidates with provenance.
- **Methodology analysis corrections (COR-01–06)**:
  - COR-01: Separates relay infrastructure from client IP addresses; evaluates per-peer privacy policy.
  - COR-02: Flags ICE credential reuse only during actual deliberate restarts (`iceRestart`).
  - COR-03: Binds DTLS certificates to exact peer, role, transport, generation, and MIDs.
  - COR-04: Enforces RFC 9143 BUNDLE and per-media SDP attribute inheritance.
  - COR-05: SDES is marked as a review item; self-signed DTLS certificates are recognized as standard WebRTC identities.
  - COR-06: Renamed T8 to "Negotiation loop" to accurately reflect local browser loop execution.
- **Extension & runner self-protection (LAB-05)**:
  - Per-frame session tokens issued by `BridgeSessions.kt` and required for bridge endpoints.
  - Host and Origin header validation to prevent cross-site and DNS rebinding attacks.
  - Request smuggling defenses and bounded JSON parser depth (`boundedJson`).
  - Formula-injection-safe CSV escaping (`EvidenceFormatting.csv`) and script-safe markdown rendering without redaction.
- **Configuration AutoSave**: edits save automatically with debounce.

### 1.0.5 additions — methodology checklist and coverage corrections

**Report** now starts with a concise point-form summary in five groups:
Authentication, Media and RTP security tests, Resilience testing, Signaling
protocol-specific tests, and Other security categories. It lists all 22 distinct
requested checks (codec and RTP fuzzing also appear under resilience), plus
transport/HSTS, ICE privacy/credentials, DataChannels, session lifecycle, browser
permissions/origin, SFU/MCU isolation, storage/compliance and end-to-end encryption.
The existing twelve detailed security areas and raw evidence follow.

Each bullet separates **Built in / Partial coverage / External / manual** from
recorded result states, and links to the limitation and concrete next step.
Where evidence exists, a short observation is included; full text and credentials
remain in the detailed tables and raw evidence. Mixed completed, error, cancelled
and review results stay visible together. A configured target, generated command,
baseline HTTP replay or unrelated observation never establishes test coverage.
Run All emits the same checklist after its active checks, including M5 results.

| Requested check | Implemented coverage | Remaining work / where to test |
| --- | --- | --- |
| Signaling authentication | M5 captured-session replay and recognized header/URL/body credential removal | Select distinct sessions and protected requests; verify ownership and actual room/application behavior |
| WebSocket authentication | External/manual | Burp handshake/message tests: credentials, Origin, logout/reconnect, per-message authorization |
| TURN authentication | M6 supplied-credential allocation observation | Compare valid, missing, invalid and expired credentials manually; gathering failure alone is inconclusive |
| SRTP authentication | External/manual | Packet harness with test keys, modified tags, replay and receiver rejection evidence |
| TLS version security | Integrated TCP TLS tests | Run for each selected HTTPS/WSS or TURN-over-TLS listener |
| Cipher-Suite analysis | Integrated TCP TLS cipher enumeration | Media DTLS/SRTP are separate observations |
| TURN relay abuse | M6 allocation precondition | External commands: stunner / TURNado / TURNt; confirm destination restrictions and actual transfer |
| DTLS certificates | Captured X.509 validity/key/fingerprint review | Remote handshake enforcement needs a peer harness |
| DTLS Crypto-Suite analysis | Negotiated browser cipher/version review | Supported-suite enumeration and downgrade tests need a DTLS harness |
| SRTP security | SDP keying and negotiated profile review | Packet authentication, SRTCP, rekey and replay tests remain external |
| RTP injection | External/manual | Controlled media peer/packet harness with receiver evidence |
| RTP bleed | External/manual | External commands: SIPPTS rtpbleed against a confirmed media endpoint |
| RTP flooding | External/manual | Bounded media load harness with loss/availability/recovery measurements |
| RTP packet fuzzing | External/manual | Raw packet/native parser harness; preserve seeds and crash reproduction |
| Codec fuzzing | M3+ codec SDP-parameter mutations | Encoded-frame/native decoder fuzzing is separate |
| Codec enumeration | Advertised SDP codecs and in-use RTP stats | Advertisement does not prove negotiation |
| Signalling black box fuzzing | M3 SDP mutation / M3+ local parser subset | Burp/application fuzzer for server messages and schema validation |
| Signaling denial of service | T8 bounded local browser loop | No signaling traffic is sent to the server; use a bounded signaling harness |
| API flooding | External/manual | Bounded application load test with throttling, quotas and recovery evidence |
| SIP over WebSocket | External/manual, conditional on confirmed SIP use | External commands: sipexer; exact WS/WSS path, accounts, registration/dialog checks |
| Injection security | M3 SDP modification / M3+ local parsing | Server-side SQL/command/template and application-message injection need dedicated tests |
| API security | M5 authorization / identifier replay | Business logic, CSRF, schemas and endpoint-specific requirements remain manual |

SIP applicability is unknown until established; SDP alone is not SIP evidence.
RTP/codec fuzzing shared between groups uses the same evidence, not two runs.
STUN/host-only gathers do not count as TURN tests. TLS scan completion without
protocol-check results does not count as version/cipher analysis. Agent installation
does not count as a media-permission outcome. No checklist item claims a security
pass from missing data or a successful API call.

M3+ now interleaves per-line, codec and structural mutation families after the
baseline, so long descriptions do not exhaust the case budget before codec tests.
The existing case count, payload bounds, authorization and cleanup remain in force.
M5 now checks **injectionEnabled + host allow-list + Burp Target scope** before
every request, including the baseline and after configuration/scope revocation.
Its unauthenticated variant removes known authentication headers and recognized
URL/body tokens, including explicitly configured token fields. Unrecognized
application authentication and intended permissions still need review.
M6 result/error/candidate evidence now preserves each run's exact listener URL
and credentials, so manually compared credential conditions remain attributable
after the configuration changes. Historical evidence without those fields stays
explicitly unknown; the current configuration is never substituted for run inputs.

Reload both the extension and browser page to install the new agent. Report
generation remains passive; external commands are generated only, and no new
raw-packet or automatic signaling-load backend was introduced.

### 1.0.4 additions — twelve-area test-results report

**Report** → **Generate report** creates these sections in the requested order:

1. Signaling Channel Security (WebSocket / HTTP-SSE)
2. Session Description Protocol (SDP) Manipulation
3. NAT Traversal Infrastructure (STUN / TURN)
4. Interactive Connectivity Establishment (ICE) & Candidate Harvesting
5. Media Transport & Encryption (SRTP / SRTCP)
6. Key Exchange & Handshake (DTLS)
7. DataChannel Security (SCTP)
8. Media Server Architecture (SFU / MCU / Gateway)
9. Authentication, Session Management & Access Control
10. Client-Side Security (Browser APIs, Permissions, XSS/Origin)
11. Recording, Storage & Regulatory Compliance (Media Archival)
12. Denial of Service (DoS / Resource Exhaustion)

Every section contains a table with the test/check, status, observed result and
limitations, and links to its raw evidence in the report. The opening coverage
table counts recorded results, incomplete/pending checks and coverage gaps.
SDP before/after and individual parser outcomes, DataChannel sends/errors/closure,
STUN/TURN gather results, latest transport/stats observations, Python TLS
per-check results and every authorization replay (URL, variant, HTTP status,
length, body hash, baseline comparison and flag) are included. Configured
identities, selected ICE servers, enabled checkboxes and generated commands do
not count as executed tests. Raw evidence and credentials are preserved in full.

**Observed** is passive evidence; **Completed** describes execution, not an overall
security pass. **Review required** is a triage lead. Errors, partial/unknown,
cancelled, queued/running and skipped/blocked states remain visible. SDP baseline
controls are separate from mutations; an incomplete summary is not a complete
run. A completed TLS scan does not leave its old start event marked pending.

**Not tested** means no result captured for an available check. **Not supported**
identifies checks the app does not implement, with the missing work stated. SFU/MCU
architecture and recording/compliance are explicit coverage gaps; the report
does not infer them from endpoint names or claim compliance. Raw media/SCTP/DTLS,
WebSocket/SSE application security, session lifecycle, XSS/origin enforcement and
server DoS coverage gaps also remain explicit. DataChannel-only captured SDP
marks SRTP profile checks **Not applicable** for that peer. TCP TLS listener
results go to signaling or STUN/TURN, never to media DTLS.

Generation reads existing telemetry, authorization results and captured HTTP
metadata only; it starts no scans/replays. Existing module analysis, configuration,
telemetry totals and CSV export remain available. Twelve report regression tests
cover empty/missing results, incomplete jobs, category mapping, conservative
interpretation, credentials, Markdown escaping and linked raw evidence.

### 1.0.3 additions — integrated Python TLS testing

**TLS tests** runs SSLyze 6.3.1 through a bundled Python adapter. Install Python
3.10+ on the Burp machine, enter its executable path (or `python` when on PATH),
and click **Setup TLS runner**. This creates a private environment under
`~/.webrtc-testsuite/tls/` and downloads dependencies from PyPI. Setup does not scan
any target. **Check runtime** verifies the pinned tool and native imports.

Use **Refresh endpoints** to populate suggestions from captured HTTPS
pages and configured secure TURN listeners, or type one endpoint. Supported
forms: `https://host:port/path`, `wss://host:port/path`, `tls://host:port`, and
`turns:host:5349?transport=tcp` (port defaults to 5349 for `turns:`). These are
listener addresses, never allocated relay/ICE candidate addresses. Plain TURN,
STUN and `turns:...?transport=udp` are rejected. No HTTP checks are sent to a TURN
TLS listener; credentials are not needed to inspect its TLS handshake.

The tab shows the exact URL checked against Burp Target scope. HTTPS keeps its
path/query; WSS maps to HTTPS with the same authority/path/query; `tls://` and
`turns:` map to `https://host:port/`. Put that URL in scope, allow the hostname in
Config, enable injection, and click **Run TLS tests**. A live browser agent is
not needed for this scan. The Python process connects directly; its handshakes
do not appear in Burp HTTP history and do not use Burp's upstream proxy settings.

Standard checks cover SSL 2/3, TLS 1.0–1.3 cipher support, certificate deployment
and validation, compression, fallback SCSV and elliptic curves. The optional
checkbox adds Heartbleed, OpenSSL CCS injection, ROBOT and renegotiation probes.
Vulnerability probes default off. **Save settings** persists the selected endpoint
for Scan All; its first-screen checkbox controls inclusion and defaults on.
The scanner runs against that selected listener, rather than every discovered host.

Execution uses argument lists and JSON stdin with the bundled adapter; editable
commands and arbitrary scripts are not executed. One task runs at a time, with
two concurrent TLS connections, five-second network timeouts and no retries.
The scan budget is 15–300 seconds (default 180); setup has a five-minute budget.
Stop, unload, scope removal, or disabled injection/allow-list permission cancels
the scan and terminates its process tree. Scope is rechecked every 200 ms while
running. Output is capped at 8 MiB per stream; overflow is an incomplete failure.

`tls-runtime`, `tls-scan-start`, `tls-scan-result` and `tls-scan-error` appear in
Telemetry and the TLS tab. Run All and M7 include per-check status and supported
protocol/weak-cipher/vulnerability evidence. Complete means execution completed;
errors, timeouts, cancellations and partial checks are never reported as passed.
Certificate validation uses SSLyze's packaged trust stores, which can differ from
the browser's trust policy. Select a TLS result to inspect the full SSLyze JSON.
TLS results cover the TCP listener only; M6 handles TURN allocation, and raw media
DTLS/SRTP tests require another backend.

Validation adds five Python unit tests and a real localhost TLS smoke test for
both profiles. Run `python -m unittest discover -s runner -p 'test_*.py'`. With
SSLyze installed, run `python runner/smoke_tls_runner.py` for the local fixture.
The optional JVM integration test creates a real managed environment, checks the
runtime and scans a closed localhost listener. Set `WEBRTC_TLS_SMOKE_PYTHON` to a
Python executable before running Gradle tests to include it; otherwise it skips.
SSLyze is installed separately under its [AGPLv3 license](https://github.com/nabla-c0d3/sslyze);
the JAR bundles our adapter, not SSLyze or a Python interpreter.

The earlier 1.0.0 release stabilized the 0.9.0 Tier 1 feature set: the
extension and bundled agent versions were aligned at 1.0.0 with no functional
change from 0.9.0 beyond the version bump. Tier 2 (T9–T14) remains planned
(see [PLAN.MD](PLAN.MD)).

### 1.0.2 additions — short-lived DataChannels

In **Data channels**, configure the payload and limits, then tick
**Run on next DataChannel open (once, this session)** before starting a fresh
call. The next channel that reaches `open` on an allow-listed, in-scope browser
page requests one M4 run directly from its open handler. This avoids waiting for
the normal three-second command poll. The bridge checks fresh page/channel
telemetry, scope, allow-list and injection; the browser rechecks authorization
and channel readiness before each send. Existing message/byte/rate limits apply.

The option snapshots the settings shown when armed and disarms after one run is
queued. A busy page leaves it armed for another open event. Uncheck it or use
**Stop** to disarm and cancel the automatic run. Arming is never persisted or
restored on extension/bridge restart. It applies to any eligible page; the manual
channel selection is not used. It does not launch Run All or unrelated tests.

`dc-created: local` means creation on the local peer, not successful opening.
New lifecycle detail records initial channel state, whether it ever opened,
elapsed lifetime, peer/ICE/signaling/SCTP states, error details and page calls to
channel/peer `close()` with caller stacks. The M4 results include `pc-state` and
SDP errors; Run All and the M7 passive report explain channels that close before
open and observed connectivity failures without classifying them as vulnerabilities.

A channel that never reaches `open` cannot send M4 payloads. To investigate early
closure, first disable SDP mutation and automatic fuzzing, reload and start a
fresh call, then inspect `sdp-error`, `pc-state` and `dc-state`. A `close-called`
record identifies a page API call; it does not by itself establish why the app
closed the connection. Compare with injection disabled if the failure persists.

Reload the extension **and the browser page** to install agent 1.0.2. The optional
real-browser smoke check verifies delivery before a channel closes after 700 ms:
set `CHROME_PATH` to a Chromium executable and run `node agent/browser-smoke.cjs`.

### 1.0.1 correction — embedded video frames

With **Strip CSP** enabled, the injector now retains the original enforced
`frame-ancestors` directive from each CSP policy, including multiple headers and
comma-separated policy lists. Other CSP directives, report-only headers and CSP
meta tags are removed as before. `X-Frame-Options` remains intact.

Previously, deleting an enforced `frame-ancestors` policy could reactivate
`X-Frame-Options: SAMEORIGIN`, blocking a previously permitted cross-origin video
frame even though Burp recorded HTTP 200. Preserving the directive maintains the
original allowed parents and denied frames. Injection remains gated on the host
allow-list, Burp Target scope and the injection switch.

Reload the extension and browser page after installing 1.0.1. The Config help
explains the retained framing policy. Six injector regression tests cover this
behavior, duplicate policies and scope/configuration gating.

### 0.9.0 additions — Tier 1 coverage (see [PLAN.MD](PLAN.MD))

- **T1 deeper `getStats` telemetry** — the agent now samples the browser's own
  statistics (transport/DTLS/ICE roles, every local/remote candidate, the chosen
  candidate pair, in-use RTP streams with payload type, packet/byte counts, loss
  and jitter, and certificate fingerprints) as a bounded `stats-snapshot`, plus one
  `dtls-cert` event per certificate. Run All reports the payload types actually in
  use, roles, chosen pair and packet loss/jitter as evidence only — never that
  media reached the peer. A **Capture live stats** button in **Evidence**
  forces a fresh snapshot for the live page.
- **T2 DTLS certificate + fingerprint binding** — `dtls-cert` DER bytes are parsed
  as X.509; the SHA-256 fingerprint is compared with the SDP `a=fingerprint`. A
  binding mismatch is a finding; expired, near-expiry and weak-key (RSA/EC)
  certificates are warnings.
- **T3 IP-privacy section** — a dedicated Run All / M7 review flags **public
  (srflx) IP disclosure** as a finding, lists host/IPv6/TCP candidates and mDNS
  names, and warns when no relay-only (`iceTransportPolicy=relay`) configuration
  is observed.
- **T4 ICE credential hygiene** — parses `a=ice-ufrag`/`a=ice-pwd`, flags values
  below the RFC 8445 minimums or with low entropy, and flags credentials reused
  across successive offers (an ICE restart should rotate them). Distinct from TURN
  account credentials.
- **T5 SDP attribute + codec audit** — flags a weak `a=fingerprint` hash
  (md5/sha-1) as a finding, reports `a=ice-lite`, missing `a=rtcp-mux`, the DTLS
  `a=setup` role(s), and per-codec `a=fmtp` (H.264 profile-level-id, Opus params).
- **T6 codec-focused fuzzing** — M3+ additionally mutates each `a=rtpmap`/`a=fmtp`
  line (payload-type/clock/channel overflows, malformed H.264/Opus parameters),
  still bounded by `maxCases`.
- **T7 signaling endpoint metadata** — reads only what Burp already captured and
  reports the HTTPS/WSS signaling origins and whether they sent
  `Strict-Transport-Security`, as review items. Burp proxy history does not expose
  the negotiated TLS version/cipher here. Test listener capabilities separately
  with TLS tests / SSLyze or the external `testssl.sh` recipe.
- **T8 opt-in signaling/ICE-restart flood** — a new tab drives a bounded, local
  `createOffer`/`setLocalDescription` loop (1–20 attempts, 500–5000 ms apart) on a
  throwaway peer. Nothing is sent to the signaling server. Off by default; Run All
  only includes it when explicitly enabled, and it reports ICE-credential reuse.

All additions remain passive-or-scope-gated as before: the new telemetry is
passive, and the flood is opt-in and bounded. A page reload is required to pick up
the new bundled agent.

### 0.8.1 corrections

- Chrome internals import accepts gzip (`.gz`, detected by content), JSON, and
  copied text. Import the downloaded compressed dump directly; decompression is
  automatic, with a 64 MiB decompressed size limit and errors for corrupt gzip.
- Address extraction uses candidate/address fields and validates complete IP
  literals. Timestamps and certificate fingerprint fragments are not addresses.
- mDNS `.local` candidates are informational, not private-IP disclosure findings.
  The report counts distinct application candidate addresses; probe candidates
  and import/comparison records are excluded. Local diagnostic addresses alone
  do not prove disclosure to a site or remote peer.
- Missing cipher statistics are **unknown**, not evidence of missing encryption.
  The agent samples after connection changes and retries for ten seconds, emitting
  changed transport values. Reports use the latest sample per peer/transport and
  do not require SRTP for DataChannel-only SDP.
- SDP line mutations preserve the final CRLF; deleting a line removes it rather
  than inserting a blank line. Offer/answer seeds are selected by description type,
  oversized seeds are not silently truncated, and a rejected baseline stops the
  run. The baseline is a separate control, excluded from mutation totals/findings.
- Reports identify incomplete fuzz runs separately from the latest completed
  run, and use one telemetry snapshot for findings and event totals.
- TURNt recipes require a valid TURN configuration as well as the runtime offer
  and test URL. SIP commands without a SIP endpoint are marked **Not applicable**.

Reload the extension and browser page after updating. Re-import old Chrome dumps
and rerun fuzzing: archived results retain their original payloads and outcomes.

M0–M7 are all implemented, plus an **SDP fuzzing** parser-robustness tab and an
**External commands** tab that generates Linux/Bash commands for ten external RTC
testing tools. A **Scan All** tab provides a selected-scan workflow that raises
plain-English
findings — weak/absent media crypto, SDES cleartext keys, missing DTLS
fingerprint, codec enumeration, guessable identifiers, SDP fuzz triage signals, and TURN
relay-allocation (the Ghost Calls precondition). **Evidence** can import a
user-exported `chrome://webrtc-internals` dump and cross-check it against captured
telemetry. Credentials are preserved in full everywhere. **Report** exports a
Markdown report (config, telemetry findings, M3/M5 guidance, telemetry summary) —
passive, so it can be generated any time without touching the target.

## Coverage & roadmap

### TODO / requested improvements

- [x] Print the extension name and version to Burp's extension **Output** console
  on every load/reload so the tester can confirm which version is running
  (`WebRTC Test Suite v1.1.4 loaded`). The version is read from the loaded JAR's
  build metadata (manifest `Implementation-Version`, then a generated
  `webrtc-version.properties`), so the message identifies the actual loaded
  artifact rather than a hard-coded string.
- [x] Added an **External commands** tab that automatically prepares complete Linux/Bash
  commands for ten external RTC testing tools from telemetry, Config, and captured
  signaling. It includes broad assessments, focused checks, intensive recipes, tool
  explanations, prerequisites, and upstream links, with preserved manual edits.
  See [External commands command builder](#external-commands-command-builder).
- [x] Passwords and other credentials are preserved throughout the extension:
  telemetry, UI fields, commands, configuration files, CSV exports, and reports.
  Automatic omission, masking, and redaction were removed; the tester controls what
  is removed from screenshots and report evidence. See [credential visibility](#credential-visibility).
- [x] Compare captured extension telemetry with a Chrome `chrome://webrtc-internals`
  dump. Chrome's privileged page cannot be read directly by this extension, so
  **Evidence** imports a user-exported dump (gzip, JSON or copied page text) and
  reports the comparison in plain English — matching/extra ICE candidate addresses,
  DTLS/SRTP/TLS ciphers, and codecs — as `internals-import` / `internals-comparison`
  telemetry, so Run All and the M7 report include it. It cross-checks only; a
  mismatch is a lead, not a confirmed finding.
- [x] Add broader SDP parser fuzzing seeded from observed application SDP. Mutate
  every line with known SDP payloads, malformed values, and bounded large/overflow
  strings; retain per-case results for triage.
- [x] Keep browser page and DataChannel lists current automatically, and save SDP
  mutation edits as they change without requiring Refresh or Apply.
- [x] Add a CSV export of telemetry and authorization-matrix results from across
  the extension's tabs.
- [x] Allow copying multiple selected rows from result tables for spreadsheet or
  issue-tracker triage.
- [x] Make SDP mutation edits persist automatically; support ordered substring
  match/replace rules and click-to-fill from observed SDP.
- [x] Report each SDP fuzz case in Run All: expected parser rejection is green;
  accepted or missing results are red review leads, not automatically findings.
- [x] Report whether browser camera/microphone requests were granted or rejected,
  without collecting track contents or device labels.

Coverage is benchmarked against public RTC-security references: Enable Security's
[penetration-testing service](https://www.enablesecurity.com/penetration-testing/)
and [awesome-rtc-hacking](https://github.com/EnableSecurity/awesome-rtc-hacking),
the [WebRTC Security whitepaper](https://webrtc-security.github.io/), Praetorian's
[Ghost Calls](https://www.praetorian.com/blog/ghost-calls-abusing-web-conferencing-for-covert-command-control-part-2-of-2/)
TURN-abuse research, and margin research's
[WebRTC RCE](https://margin.re/2024/07/you-cant-spell-webrtc-without-rce-part-1/) series.
The protocol boundary review also uses the IETF [WebRTC Security Architecture
(RFC 8827)](https://www.rfc-editor.org/rfc/rfc8827.html), [IP Address Handling
Requirements (RFC 8828)](https://www.rfc-editor.org/rfc/rfc8828.html), [Data
Channels (RFC 8831)](https://www.rfc-editor.org/rfc/rfc8831.html), and the
[WebRTC native fuzzing documentation](https://webrtc.googlesource.com/src/+/21677334ecde41b5feee28f9aca67b9bbb4cbdab/docs/native-code/development/fuzzers/README.md).

**Design boundary.** This tool is a Burp extension plus a browser agent that hooks
the **W3C WebRTC JavaScript API** (SDP, ICE, DataChannel) and observes/rewrites
HTTP(S). It therefore reaches the **signaling-visible and API-visible** surface.
The integrated TLS tests runner separately reaches selected TLS-over-TCP
listeners. It does not send raw media packets, so the **media plane** (RTP/RTCP/SRTP) and
**native-parser memory-safety** surfaces are out of scope by construction and are
delegated to the right tools rather than faked.

Within that boundary, the scan covers observed SDP and ICE (including private
address disclosure), DTLS-SRTP negotiation telemetry, cleartext SDES and missing
fingerprints, advertised codecs, ICE server configuration and relay allocation,
DataChannel lifecycle and bounded payload fuzzing, SDP parser behavior, browser
media permission outcomes, and configured cross-identity request authorization.
Burp can inspect and replay the app's HTTP/WebSocket signaling traffic separately.
These checks do not prove media reached the peer, validate application identity
trust, or confirm a vulnerability from parser acceptance alone. Browser versions
and exposed stats fields also limit what the JavaScript API can observe.

### Implemented (✅) / in progress (🔨) / planned (⬜) / out of scope (⛔)

- ✅ Agent injection + CSP strip (M1); telemetry of SDP/ICE/cipher/DataChannel (M2).
- ✅ Distinct private IPs in application ICE candidates for privacy review;
  mDNS (`.local`) names are informational, not private-IP disclosure findings.
- ✅ SDP mutation incl. DTLS `a=fingerprint` removal — encryption-downgrade test (M3).
- ✅ DataChannel payload fuzzing, bounded (M4).
- ✅ Authz matrix / IDOR across identities — the "guessable meeting IDs" class (M5).
- ✅ ICE gather, STUN srflx + TURN relay allocation with supplied creds (M6).
- ✅ Scan All workflow with saved scan checkboxes and plain-English findings.
- ✅ **Weak-crypto flagging** — Run All judges captured DTLS/SRTP/TLS ciphers
  (null/weak cipher, legacy TLS/DTLS) and flags **SDES `a=crypto` cleartext keys in
  SDP** and media SDP missing a DTLS `a=fingerprint`, instead of "review manually"
  (whitepaper §DTLS-SRTP vs SDES).
- ✅ **Codec enumeration** — Run All parses `m=`/`rtpmap` from captured SDP and
  lists the codecs advertised (Enable Security "codec enumeration").
- ✅ **Identifier guessability** — Run All flags sequential/low-entropy room/meeting
  ID values configured across identities, strengthening the M5 IDOR story.
- ✅ **TURN relay-allocation observation** — reports when supplied credentials
  obtain an allocation. Allocation capability alone is not an authorization
  vulnerability; destination restrictions require separate testing.
- ✅ **SDP parser fuzzing (M3+)** — the SDP Fuzz tab uses the latest observed
  application SDP when available, mutates each line with known attributes,
  malformed values, integer overflows, and bounded long strings, and adds
  whole-description cases (missing required lines, truncation, repeated sections,
  control chars, Unicode, and 8–256 KiB values). It submits cases to
  `setRemoteDescription` on throwaway peers and records acceptance/rejection.
  Accepted offers also run `createAnswer` to check the next negotiation step.
  Baseline acceptance is a separate successful control, not a mutation finding.
  Acceptance is a triage signal, not confirmation of a security vulnerability.
  Result tables support selecting multiple rows and copying them with **Ctrl+C**
  or the context menu.
  This is the JS API-reachable slice of the WebRTC-RCE parser surface; RTP/RTCP/
  SCTP native-parser fuzzing remains out of scope.
- ✅ **SDP mutation ergonomics** — each ordered rule replaces a literal substring
  (no full-line match required); add multiple rules with **+ Add text rule**. Click
  a line in the **Before** pane to populate a Match box, then edit it down to the
  substring you want. Edits save automatically and apply to subsequent operations.
- ✅ **Clear per-case fuzz report** — expected `setRemoteDescription` rejection
  with the browser error is green. Accepted mutations, missing outcomes, and
  errors are red review items. Acceptance is a parser behavior to investigate,
  not proof of an exploitable issue.
- ✅ **Media permission outcomes** — reports whether `getUserMedia` resolved or
  rejected and the browser error, without recording captured media or device names.
- ✅ **chrome://webrtc-internals comparison** — **Evidence** imports a
  user-exported dump (gzip, JSON or copied text) and cross-checks it against captured
  telemetry: ICE candidate addresses present in only one view, private-address and
  mDNS observations, DTLS/SRTP/TLS cipher agreement (reusing the weak-crypto judgement), and
  advertised codecs. Results are stored as `internals-comparison` telemetry and
  surfaced by Run All and the M7 report. It is a cross-check, not a verdict.
- ✅ **Startup version banner** — Burp's Output console shows `WebRTC Test Suite
  v<x.y.z> loaded`, read from the loaded JAR's build metadata.
- ✅ **External commands command builder** — a tab that renders complete Linux/Bash
  recipes for ten external RTC tools from observed page origins, ICE servers (with
  credentials) and Config, shows Ready/Missing states, preserves manual edits and
  manual inputs, and exports a Markdown guide plus a TURNt configuration file.
  Generating a command does not execute it.
- ✅ **Credential visibility** — TURN usernames/credentials observed on application
  peers are captured in telemetry, error details are no longer redacted, and the M7
  report and CSV export include identity headers and TURN credentials in full.
- ✅ **Public-IP / location disclosure** flag and a **relay-only IP-leak** check
  (whitepaper privacy mitigations) — a dedicated T3 privacy section flags public
  (srflx) disclosure, lists host/IPv6/TCP candidates and mDNS names, and warns when
  no `iceTransportPolicy=relay` configuration was observed.
- ✅ **Deeper `getStats` telemetry (T1)**, **DTLS certificate/fingerprint binding
  (T2)**, **ICE credential hygiene (T4)**, **SDP attribute + codec audit (T5)**,
  **codec-focused SDP fuzzing (T6)**, **signaling endpoint metadata (T7)**, and an
  bounded **local negotiation / ICE-restart loop (T8)**. Scan All now controls its inclusion.
- ✅ **Report export (M7)** — the Findings tab compiles a Markdown report (config
  with credentials preserved, telemetry findings, M3/M5 guidance, telemetry summary)
  and saves it to a file; passive, generatable at any time.
- ⛔ **RTP/RTCP injection, RTP Bleed, RTP packet fuzzing, SRTP auth** — media plane;
  needs raw packet tooling (e.g. the techniques in the RCE research use Frida +
  custom WebRTC builds). Not reachable from a JS-API hook.
- ⛔ **Native-parser memory-safety / RCE fuzzing** of RTP/RTCP/SCTP/DTLS — needs a
  native fuzzing harness against a WebRTC build, not a browser agent.
- ⛔ **Signaling / SIP fuzzing, WebSocket & signaling auth, registration hijack,
  signaling-flood DoS, API flooding** — signaling transport; covered by Burp
  Repeater/Intruder/native WS tooling and dedicated SIP fuzzers.
- ⛔ **Full TURN-as-C2 tunnelling** (arbitrary-destination relay, SOCKS over TURN)
  — needs a raw TURN client such as Praetorian's `TURNt`; we test the precondition
  (relay allocation) only.
- ⛔ **IdP/identity-provider trust model** — application-level testing.
- ✅ **TLS scanning** of selected HTTPS/WSS or TURN-over-TLS listeners — integrated
  Python SSLyze runner, scope gated and selected from Scan All (introduced in 1.0.3).

Other external tests remain command generation only. The
[External commands tab](#external-commands-command-builder) provides commands
for relevant external tools; generating a command does not execute the test or
mark that external surface as scanned by the extension.

There is no single browser-side scan that can cover every WebRTC vulnerability:
the native engine, OS device stack, application signaling rules, remote peer, and
network path expose different test surfaces. The standards define security
properties across these layers; this extension tests the subset available through
Burp traffic and browser APIs. For deeper engine memory-safety testing, use the
upstream WebRTC native fuzzing harness against a matching browser/library build.

## External commands command builder

**Status: implemented in 0.8.0** (the tab renders the commands below). It generates
text only and never executes a tool; a ready command is not a completed scan.
Research and command documentation were reviewed on **2026-09-29**. No external
scans were run during that review.

### Goal and agreed defaults

The **External commands** tab turns information collected by the extension
into complete, ready-to-copy **Linux/Bash commands**. Each suggestion explains the
test, why it applies, what evidence to look for, and where to find the external
tool's GitHub repository and official documentation.

Start with ten tools selected from
[awesome-rtc-hacking](https://github.com/EnableSecurity/awesome-rtc-hacking/blob/main/README.md)
and established supporting tools. Selection considers repository adoption, recent
maintenance, relevance to WebRTC deployments, and documented command interfaces.
This is a recommended integration shortlist, not a measured usage ranking.
TURNado is a deliberate specialist inclusion: it has smaller adoption but useful
TURN-specific forwarding and allocation-stress capabilities.

Provide the broadest useful assessment for each tool plus **one or two focused
recipes**. Include clearly labelled **stress, password-testing, and tunnel
recipes**. A tool without a scan-all operation gets its documented workflow and an
explicit explanation of its coverage; do not invent an `--all` flag or imply that
all modules were exercised. SIP tools apply when SIP is detected or entered.

### Tab behavior

- Populate suggestions automatically from telemetry, Config, and captured
  signaling. Update generated commands as information arrives, without Refresh
  or Apply. Preserve manual edits until **Reset to detected** is selected.
- Group suggestions by application and endpoint. Show the source event/request,
  peer connection where available, transport, timestamp, and target scope status.
  Do not combine credentials and endpoints from unrelated sessions or hosts.
- Show **Ready to copy**, **Missing TURN credentials**, **Needs capture file**,
  **Needs test account**, or other specific missing-input states. Keep incomplete
  recipes visible with editable fields rather than silently dropping them.
- Each recipe includes its purpose, detected and manual inputs, setup link,
  executable name, complete commands, expected evidence, limitations, and effects
  such as creating registrations, opening listeners, or consuming allocations.
- Offer **Copy command**, **Copy selected recipes**, and **Copy all ready recipes**;
  support selecting several rows. Export the command guide as Markdown and any
  required tool configuration files. All copied/exported credentials remain intact.
- Generate commands and files only. Installation and execution remain external
  in this first version; result import is a later feature. A ready command is not
  a completed scan or a finding.
- Show exactly which hosts, ports, destinations, and accounts a recipe uses.
  An application's Burp scope does not automatically include a third-party TURN
  provider or every port on a discovered host. Copied external commands execute
  outside Burp's scope enforcement.
- Use valid Bash argument quoting for spaces, quotes, dollar signs, backticks,
  and other shell characters. Do not trim or alter credential values. Use unique
  output filenames per target/recipe so repeated tests do not overwrite evidence.

**Implementation notes (0.8.0).** Suggestions update automatically and are grouped
by tool (not yet by application/endpoint). Each recipe shows purpose, coverage,
prerequisites, evidence, effects, limitations and upstream links, and reports
Ready versus a single Missing-inputs list (the finer "Needs capture file" / "Needs
test account" states are not yet separate). Each detected ICE server keeps its own
credentials. Bash quoting uses single-quote escaping; the only generated tool
configuration file is the TURNt `turnt-config.yaml`. Per-recipe source/peer/
transport/scope columns, grouping by application/endpoint, and unique per-target
output filenames beyond the values entered remain deferred.

### Credential visibility

**Passwords and other credentials are not automatically omitted, masked, or
redacted anywhere in the extension.** Full values are preserved in telemetry, UI
fields, generated commands, clipboard contents, configuration files, error details,
CSV exports, and Markdown reports. This includes credentials entered in Config and
credentials observed through the instrumented application's ICE configuration or
supported signaling data.

Use the ordinary **Copy command** action with all available values filled in.
There is no separate "Copy with credentials" action or reveal requirement. The
tester decides what to remove from screenshots or evidence in the pentest report.

This policy is implemented in 0.8.0: the browser agent captures observed ICE
servers (with TURN usernames/credentials) in `pc-new`/`agent-state`, error text is
no longer redacted, and the M7 report and CSV export include identity headers and
TURN credentials in full. Values omitted by older builds cannot be recovered from
old telemetry; obtain them from Config, new observations, or manual entry.

### Information sources and command generation

| Required information | Source and handling |
|---|---|
| STUN/TURN listener hostname, port, transport | ICE server URLs from `pc-new`, subsequent configuration observations, and TURN/STUN Config. Parse each URL independently. An allocated relay candidate's address is not the TURN listener. |
| TURN username/password | Credentials associated with the same observed ICE server configuration (`pc-new`), matching Config values, or manual entry. Never substitute SDP `ice-ufrag`/`ice-pwd` for TURN account credentials. |
| HTTPS/WSS and TLS endpoints | Observed page/request origins, signaling URLs, and secure TURN URLs. Preserve the hostname needed for TLS/SNI and the path needed for WebSocket signaling. |
| SIP endpoint and transport | Manual entry (the tab exposes SIP host/port/transport and account fields). SDP alone is not evidence of SIP; automatic SIP/WebSocket-subprotocol discovery is not implemented. |
| Media address, RTP ports, payload type | Confirmed gateway/media information or manual entry. Do not treat SDP port `9`, an mDNS name, or an encrypted ICE endpoint as a usable plaintext RTP target. |
| Capture interface/file, wordlist, test accounts, forwarding destination | Manual fields where these cannot be inferred. A browser cannot identify the interface or filesystem paths on a separate Linux test machine. |
| TURNt offer and answer | Runtime outputs from its controller and relay. Show the manual exchange steps; these cannot be pre-populated from the application's existing SDP. |

Normalize the detected scheme, host, port, address family, and transport before
rendering tool-specific arguments. Handle IPv6 bracket rules and each tool's
address-family options. Display unsupported combinations explicitly; never silently
downgrade a secure endpoint. Use only a tool's documented transports.

Record the source and age of credential observations, and any explicitly known
expiry. Do not invent an expiry from an arbitrary username. Require replacement
values when known to be expired. Preserve complete credentials in all displays.

The variables below describe template inputs; they are not a requirement for the
tester to hand-edit command strings. The tab must generate Bash assignments and
commands with detected/entered values already filled in, or render equivalently
quoted literal arguments. Unknown values remain explicitly incomplete. Tool
executables must be installed according to the linked upstream setup instructions;
the `testssl.sh` examples run from its checkout. Configuration files and outputs
use paths on the external Linux machine.

### Initial ten-tool catalogue

#### 1. stunner — TURN restrictions and relay reachability

The broad assessment checks built-in private/restricted address cases. Focused
recipes identify capabilities and test a specified destination through TURN.
These are separate subcommands, not a universal scan-all operation. Include the
upstream noncommercial licence information in the tool's setup details.
[GitHub and command documentation](https://github.com/firefart/stunner).

```bash
# Broad assessment: built-in restricted-address checks
stunner range-scan -s "$TURN_ENDPOINT" -u "$TURN_USER" -p "$TURN_PASSWORD" --protocol "$TURN_PROTOCOL"

# Focused: server information
stunner info -s "$TURN_ENDPOINT" --protocol "$TURN_PROTOCOL"

# Focused: HTTP reachability through TURN to a specified destination
stunner tcp-scanner -s "$TURN_ENDPOINT" -u "$TURN_USER" -p "$TURN_PASSWORD" --protocol "$TURN_PROTOCOL" --ip "$TEST_PEER_IP" --ports "$TEST_PEER_PORTS"
```

`TURN_PROTOCOL` is `udp` or `tcp`; add `--tls` for the corresponding secure
transport. The current `info --protocol` option is also confirmed in the
[CLI source](https://github.com/firefart/stunner/blob/main/main.go).
Require an explicit destination for `tcp-scanner`: omitting `--ip` broadens its
scan. Distinguish successful permissions from evidence of actual data reaching
the destination.

#### 2. TURNado — capabilities, UDP forwarding, and allocation stress

This specialist complements stunner with UDP forwarding and allocation testing.
Its `info` mode performs active checks, including loopback permissions; it is not
just a passive banner lookup.
[GitHub and documentation](https://github.com/SySS-Research/TURNado).

```bash
# Broad assessment: information and allocation/permission capabilities
turnado info -t "$TURN_ENDPOINT" -T "$TURNADO_TRANSPORT" -u "$TURN_USER" -p "$TURN_PASSWORD"

# Focused: forward UDP to a specified test peer
turnado forward -t "$TURN_ENDPOINT" -T "$TURNADO_TRANSPORT" -u "$TURN_USER" -p "$TURN_PASSWORD" -P "$TEST_PEER_ENDPOINT" -l 127.0.0.1:9999

# Intensive: allocation stress, stopped after 30 seconds
timeout --signal=INT 30s turnado dos -t "$TURN_ENDPOINT" -T "$TURNADO_TRANSPORT" -u "$TURN_USER" -p "$TURN_PASSWORD" -s "$ALLOCATION_COUNT"
```

Map transport to `udp`, `tcp`, or `tls`. Require the allocation count before the
stress command is ready; explain potential service impact and that the `timeout`
wrapper's timeout exit status does not by itself mean allocations failed.
The local listener and allocation-count flags are confirmed in the
[forwarding source](https://github.com/SySS-Research/TURNado/blob/main/internal/app/forward.go)
and [stress-test source](https://github.com/SySS-Research/TURNado/blob/main/internal/app/dos.go).

#### 3. TURNt — complete TURN tunnel verification workflow

Present a two-host workflow with numbered steps and separate command blocks.
TURNt is a tunneling tool and has no scan-all command.
[GitHub and workflow documentation](https://github.com/praetorian-inc/turnt).

Generate `turnt-config.yaml` using the selected TURN URL and full credentials.
Its structure is confirmed by the upstream
[configuration loader](https://github.com/praetorian-inc/turnt/blob/main/internal/config/config.go)
and [configuration writer](https://github.com/praetorian-inc/turnt/blob/main/internal/msteams/msteams.go).
Use a YAML serializer when rendering actual values. This illustrative configuration
is replaced with the selected endpoint's values during export:

```yaml
ice_servers:
  - urls:
      - "turn:turn.example.test:3478?transport=udp"
    username: "detected-or-entered-username"
    credential: "detected-or-entered-password"
```

```bash
# Host A: start the controller using the exported configuration
turnt-controller -config turnt-config.yaml -socks 127.0.0.1:1080

# Host B: paste the offer produced by the controller
turnt-relay -offer "$TURNT_OFFER"

# Host A: paste the relay's answer into the controller, then verify
curl --socks5-hostname 127.0.0.1:1080 "$TEST_URL"
```

The tab must explain how to transfer the configuration and exchange the runtime
offer/answer. Use the selected deployment's credentials rather than automatically
requesting credentials from an unrelated provider. Successful forwarding
demonstrates tunnel capability; it does not alone establish an authorization bug.

#### 4. coturn utilities — independent STUN/TURN verification

Use coturn's clients to verify allocation and data transfer independently of the
browser. The older wiki identifies itself as outdated; use the current repository
manual. [GitHub](https://github.com/coturn/coturn) and
[utility manual](https://github.com/coturn/coturn/blob/master/man/man1/turnutils.1).

```bash
# Main workflow: allocate relays and exchange five messages between test clients
turnutils_uclient -v -y -n 5 -u "$TURN_USER" -w "$TURN_PASSWORD" -p "$TURN_PORT" "$TURN_HOST"

# Focused: the utility's limited negative tests
turnutils_uclient -v -y -N -n 5 -u "$TURN_USER" -w "$TURN_PASSWORD" -p "$TURN_PORT" "$TURN_HOST"

# Focused: UDP STUN binding information
turnutils_stunclient -p "$STUN_PORT" "$STUN_HOST"
```

The first two examples use UDP. Generate `-t` for TCP, `-t -S` for TLS, or `-S`
for DTLS as applicable. These are protocol/transfer checks, not comprehensive
vulnerability scans. The basic `turnutils_stunclient` recipe applies to UDP STUN.

#### 5. SIPPTS — SIP discovery, method testing, and RTP Bleed

Generate SIP recipes for identified or entered SIP services. The broad command
scans all ports and supported SIP transports; it does not run every SIPPTS module.
[GitHub and scan documentation](https://github.com/Pepelux/sippts).

```bash
# Broad discovery: all ports over UDP, TCP, and TLS
sippts scan -i "$SIP_HOST" -r all -p all -fp -cve -o "$SIPPTS_REPORT"

# Focused: test SIP methods on the selected service
sippts enumerate -i "$SIP_HOST" -r "$SIP_PORT" -p "$SIP_PROTOCOL"

# Focused: RTP Bleed check against a confirmed media endpoint/range
sippts rtpbleed -i "$MEDIA_IP" -s "$RTP_START_PORT" -e "$RTP_END_PORT" -l 1 -p "$RTP_PAYLOAD_TYPE"
```

Explain that CVE matches are fingerprint-based leads and method enumeration sends
multiple SIP methods. Complete the RTP Bleed recipe only with confirmed media
information; do not apply it blindly to browser SRTP/ICE candidates.
[Method documentation](https://github.com/Pepelux/sippts/wiki/Command-enumerate)
and [RTP Bleed documentation](https://github.com/Pepelux/sippts/wiki/Command-rtpbleed).

#### 6. SIPVicious OSS — discovery, extension enumeration, and password testing

Use the current upstream installation's executable names: `sipvicious_svmap`,
`sipvicious_svwar`, and `sipvicious_svcrack`. These recipes target SIP over UDP.
[GitHub](https://github.com/EnableSecurity/sipvicious).

```bash
# Broad discovery: SIP OPTIONS across all UDP ports of the selected host
sipvicious_svmap -p 1-65535 "$SIP_HOST"

# Focused: enumerate an entered extension range
sipvicious_svwar -p "$SIP_PORT" -e "$EXTENSION_RANGE" "$SIP_HOST"

# Intensive: dictionary password test for one specified account
sipvicious_svcrack -p "$SIP_PORT" -u "$SIP_USER" -d "$PASSWORD_FILE" "$SIP_HOST"
```

Require explicit extension ranges and password-file paths. Do not infer SIP
extensions from unrelated meeting IDs. Include documented IPv6 options when
the selected endpoint requires them.
[Discovery documentation](https://github.com/EnableSecurity/sipvicious/wiki/SVMap-Usage),
[enumeration documentation](https://github.com/EnableSecurity/sipvicious/wiki/SVWar-Usage),
and [password-test documentation](https://github.com/EnableSecurity/sipvicious/wiki/SVCrack-Usage).

#### 7. sipexer — SIP over UDP, TCP, TLS, WS, and WSS

Include for browser applications using SIP over WebSockets. This is a request
and scenario tool, with no universal scan-all mode.
[GitHub and documented examples](https://github.com/miconda/sipexer).

```bash
# Main check: send OPTIONS using the observed transport
sipexer -sd "$SIP_TARGET"

# Focused: registration with a specified test account
sipexer -register -cb -ex 60 -au "$SIP_USER" -ap "$SIP_PASSWORD" -sd "$SIP_TARGET"

# Focused: initiate a short signaling call to a specified test URI
sipexer -invite -au "$SIP_USER" -ap "$SIP_PASSWORD" -ruri "$SIP_TEST_URI" -cb -sd -sw 5000 "$SIP_TARGET"
```

`SIP_TARGET` preserves the transport and full WS/WSS signaling path. Label the
registration and call effects. Require account and destination information when
absent; expose any deployment-specific SIP identity or handshake inputs needed
to reproduce the observed request rather than assuming an endpoint URL suffices.

#### 8. Nmap — infrastructure discovery and protocol-specific checks

Provide a broad port/service assessment plus named RTC scripts. All ports and
all vulnerability checks are different claims; describe the actual coverage.
[GitHub](https://github.com/nmap/nmap) and
[port-selection documentation](https://nmap.org/book/man-port-specification.html).

```bash
# Broad assessment: every TCP/UDP port, service detection, selected RTC/TLS scripts
sudo nmap -Pn -sS -sU -sV -p- --script stun-info,sip-methods,ssl-cert,ssl-enum-ciphers -oA "$NMAP_OUTPUT_PREFIX" "$TARGET_HOST"

# Focused: STUN information on the observed UDP listener
sudo nmap -Pn -sU -sV -p "$STUN_PORT" --script stun-info "$STUN_HOST"

# Focused: SIP methods on the observed UDP service
sudo nmap -Pn -sU -sV -p "$SIP_PORT" --script sip-methods "$SIP_HOST"
```

Label the broad recipe as a potentially lengthy full-port scan. Show its port
coverage separately from the application's observed endpoints. Individual NSE
scripts run when their service/port rules match; their inclusion does not prove
they executed. The focused examples are for UDP services, not TLS/WS endpoints.
[STUN script](https://nmap.org/nsedoc/scripts/stun-info.html),
[SIP script](https://nmap.org/nsedoc/scripts/sip-methods.html), and
[TLS cipher script](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html).

#### 9. testssl.sh — TLS configuration and vulnerability assessment

Offer this for HTTPS/WSS signaling, SIP-over-TLS, and TURN-over-TLS listeners.
It does not assess WebRTC's UDP DTLS media transport.
[GitHub](https://github.com/testssl/testssl.sh) and
[official manual](https://github.com/testssl/testssl.sh/blob/3.2/doc/testssl.1.md).

```bash
# Broad assessment: the tool's complete default audit
./testssl.sh --warnings batch --jsonfile "$TLS_REPORT" "$TLS_ENDPOINT"

# Focused: enumerate ciphers separately for each protocol
./testssl.sh -E "$TLS_ENDPOINT"

# Focused: supported TLS vulnerability checks
./testssl.sh -U "$TLS_ENDPOINT"
```

Use the actual `hostname:port` so hostname/SNI behavior is preserved. The default
audit does not include every optional check; `-E` adds cipher-per-protocol coverage.
For IPv6 use the documented bracketed endpoint form and address-family option.

#### 10. Wireshark/TShark — packet capture and protocol evidence

Provide capture and analysis workflows. TShark observes traffic; it is not an
active vulnerability scanner. [GitHub](https://github.com/wireshark/wireshark) and
[official TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html).

```bash
# Main workflow: capture traffic matching the generated endpoint filter
tshark -i "$CAPTURE_INTERFACE" -f "$CAPTURE_FILTER" -a duration:60 -w "$PCAP_FILE"

# Focused: inspect recognizable RTC and signaling packets
tshark -r "$PCAP_FILE" -Y 'stun || dtls || rtp || rtcp || sip || websocket' -V

# Focused: summarize recognized RTP streams
tshark -r "$PCAP_FILE" -q -z rtp,streams
```

Build the capture filter from selected endpoints. Require an interface for
capture or a file for offline analysis, and explain the capture privileges needed
on Linux. Encrypted payloads remain encrypted without appropriate keys, and
protocol recognition determines which packets and streams appear in summaries.

### Implementation acceptance criteria

- Exactly ten initial integrations, with official repository/setup/documentation
  links, reviewed date and source revision, clear coverage, and complete commands.
  Recheck the CLI against the selected release/revision when implementing; the
  review above verified documentation/source syntax, not live execution.
- Automatic updates with multiple applications and endpoints; preserve manual
  edits and keep each credential associated with the correct endpoint/session.
- Full credential visibility and lossless copying/export throughout the extension.
  Check values containing whitespace, quotes, dollar signs, backticks, and newlines;
  prove that Bash/YAML formatting does not execute or corrupt embedded values.
- Correct normal, nonstandard-port, IPv6, UDP, TCP, TLS, and supported DTLS cases.
  Unsupported transports and missing/expired inputs stay visibly unresolved.
- No confusion between TURN listeners, allocated relay addresses, ICE passwords,
  SIP accounts, SDP placeholder ports, or remote media targets.
- SIP suggestions require SIP evidence or manual input; TURNt shows its two-host
  exchange; capture recipes distinguish live capture from offline analysis.
- Stress/password recipes show their parameters and effects separately from the
  broad assessment. Ready-to-copy status never implies a test has run or passed.
- Documentation distinguishes shipped behavior from deferred items (see the
  implementation notes above). Further changes do not require a live scan.

### Candidates deferred beyond the first ten

[SIPp](https://github.com/SIPp/sipp) and
[Metasploit SIP modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/scanner/sip)
are useful later additions but overlap the selected signaling tools; SIPp also
benefits from application-specific scenarios.
[H26Forge](https://github.com/h26forge/h26forge) needs a decoder delivery and
reproduction workflow beyond endpoint-based commands.
The [Twilio security scanner](https://github.com/relayhawk/twilio-security-scanner)
requires provider-specific account access. These remain catalogue expansion
candidates rather than features promised for the initial tab.

## Configuration is mostly automatic

The **Setup** screen keeps the usual settings visible:

- **Browser agent** — enable injection, host allow-list, strip CSP. This is all most
  engagements need.
- **Access control identities & identifiers** — expandable account and identifier settings.
- **Advanced (auto-configured)** — bridge address, bridge port, collect/command
  paths and the agent override are in the **Advanced · local bridge & agent override**
  expandable section and have working defaults. **Restore recommended defaults**
  resets them in one click.

Every setting has a **"?" help button** that explains it in plain English with an
example (including example pentest payloads). **Check configuration** validates
the current settings and reports any problems in plain English (empty allow-list
while injection is on, bad port, unparseable identities JSON, a missing agent
override file, …). Changes save automatically; unfinished identities keep the last valid value.

The browser agent ships **inside the jar** as a classpath resource, so there is
no agent path to configure — leave **Advanced → Agent JS override** blank and the
extension injects the bundled agent automatically. You only fill that field to
point at an on-disk agent while developing the agent itself.

## Scan All — choose and run scans

The **Scan All** tab (first tab) contains the saved scan selection. All switches
start checked. Use **Select all** or **Clear selection**, or change individual
checkboxes, then click **Scan selected**. Missing inputs are reported in place.
The selected modules run in order:

1. Checks the M0 configuration is ready (injection on, allow-list set, valid port).
2. Reviews the passive telemetry already collected (M1/M2) and calls out findings
   in plain English — e.g. private/host IP disclosure from ICE candidates.
3. Runs the live active checks it safely can, one per page at a time: **M6** ICE
   gather, **M4** DataChannel fuzz, and **M3+** SDP parser fuzz against every
   browser page the agent is live on (using your saved settings, scope-gated as
   always).
4. Runs the selected local negotiation loop and saved TLS endpoint, enables saved
   M3 rules for the next browser negotiation, replays eligible captured M5 requests,
   and runs the Security checks backends. Missing inputs and skipped modules remain visible.

It never invents a finding — it reports what the modules actually observed, and
clearly marks anything it skipped and why. Export the results from **Report**.

## Implemented modules

| Module | Sub-tab | What it does |
|--------|---------|--------------|
| Scan All | Scan All | Persisted all-on scan selection and presets (generic / video banking); runs checked reviews (including the original-header and browser-security review), browser and capture checks, TLS, M5, meeting links, documents & recordings and Security checks; enables saved M3 rules for the next negotiation. |
| M0 Config + detectors | Setup | Host allow-list, bridge settings, identity profiles, identifier map; protocol-agnostic SDP/ICE/private-IP/candidate detectors (T3–T5). |
| M1 Injector + CSP | (Config) | Injects the bundled browser agent before `</head>` on allow-listed, in-scope HTML and strips CSP except enforced `frame-ancestors`, preserving the original framing policy. Controlled from Config. |
| M2 Telemetry bridge | Evidence | Embedded loopback HTTP server; agent beacons SDP / ICE (private-IP flagged) / DTLS-SRTP cipher / DataChannel / `stats-snapshot` / `dtls-cert` events. Imports a `chrome://webrtc-internals` dump and cross-checks candidates, ciphers and codecs; **Capture live stats** forces a fresh snapshot. |
| M3 SDP mutation | SDP rules | Scope-gated incoming/outgoing SDP edits, persisted rules, before/after evidence, and browser acceptance/rejection telemetry. |
| M3+ SDP fuzz | SDP fuzzing | Mutates every line of the latest observed SDP with malformed/known payloads and bounded size/overflow variants, then records accepted vs rejected on a throwaway peer. Local parse only, no packets sent. |
| M4 DataChannel fuzz | Data channels | Scope-gated payload sends (text / hex / json / boundary, and list mode for XSS canaries) over a live DataChannel, with bounded size and rate. Optional one-shot run on the next open event; channel/peer lifecycle diagnostics. |
| M5 Authz matrix | Access control | Capture/select sessions and set roles (guest / customer / advisor / admin) → compare JSON reads or explicit Burp requests with expectations and verdicts (likely violation, review lead, access denied, public); Meeting links and Documents & recordings tabs; prepare fresh JWT room swaps. |
| XSS canaries | XSS canaries | Per-injection-point canaries whose payloads report execution from any instrumented page; optional Burp Collaborator payloads and callback URLs; reflection tracking in HTTP and WebSocket traffic; Intruder payload source; DataChannel delivery. |
| M6 TURN/STUN | STUN & TURN | Isolated ICE gather against a configured STUN/TURN server; reports srflx/relay observations; credentials preserved in errors. |
| T8 loop | Negotiation loop | Bounded local `createOffer`/`setLocalDescription`/ICE-restart loop on a throwaway peer; starts from Scan All or Run negotiation loop. Nothing is sent to the signaling server. |
| Security checks | Security checks | Captured-evidence reviews (including WEB-01/02/03), built-in STUN/TURN inventory/auth/forwarding (second allocation or echo peer)/refresh/release, and saved HTTP/WebSocket scenarios sent through Burp. Only real execution backends are listed; nothing is installed. |
| External commands | External commands | Generates Linux/Bash commands for ten external RTC tools from telemetry and Config; Ready/Missing states, editable commands, Markdown and TURNt-config export. Generates text only. |
| TLS tests | TLS tests | Scope-gated TLS-over-TCP scan of one saved signaling or TURN listener with the built-in JVM engine (default) or the optional SSLyze engine; Scan All inclusion, M7 evidence and Burp issues. |
| M7 Findings | Report | Point-form methodology checklist followed by twelve evidence areas, per-test states, authorization, meeting-link and document replay rows, security-check outcomes and explicit external/manual next steps; configuration/module analysis and CSV retained. Passive, credentials intact. |
| Burp issues | (Target → Issues) | Deduplicated WebRTC findings added to Burp's Issues list with evidence; toggle in Setup. |

## Build

Requires JDK 21 (the bundled Gradle wrapper handles the rest). **Always** run
Gradle with `--no-daemon` so the detached daemon cannot hold the terminal's
output pipes open:

```
# JAVA_HOME must point at a JDK 21
cmd.exe /c "gradlew.bat shadowJar --offline --console=plain --no-daemon"
```

Output: `build/libs/webrtc-testsuite-all.jar` (the agent is copied into the jar
by `processResources`, so a rebuild always ships the current agent).

The telemetry bridge uses `java.net.ServerSocket`, so it also runs in Burp's
bundled runtime without the optional `jdk.httpserver` module. Run
`cmd.exe /c "gradlew.bat test --offline --console=plain --no-daemon"` for bridge
regression checks with that module excluded. After rebuilding, reload the
extension in Burp and look for `[bridge] listening on http://127.0.0.1:8777`.

Agent regression tests use Node.js 18+:

```
node --test agent/webrtc-agent.test.cjs agent/active-tests.test.cjs
```

## Load in Burp

1. Extensions → Installed → Add → Extension type **Java** → select the jar.
2. Output shows `WebRTC Test Suite v1.2.0 loaded`; a **WebRTC** suite tab appears.

## Use

1. **Setup:** check **Enable agent injection**, add the app host(s) to the
   allow-list. Changes save automatically. The advanced settings (bridge, paths, agent override) are
   auto-configured — leave them collapsed. Define identity profiles and
   identifier keys as needed for the authz matrix. Use the **"?"** buttons for a
   plain-English explanation of any field, and **Check configuration** to confirm
   you are ready.
2. Add the target to Burp **Target scope**.
3. Browse the app through Burp → the bundled agent is injected, CSP restrictions stripped except enforced `frame-ancestors`.
4. Join a call → **Evidence** fills with SDP, ICE (PRIVATE flag), cipher.
5. Right-click any request → **WebRTC: Run authz matrix** → results in **Access control**.
6. Open **External commands** to copy ready Linux/Bash commands for the external RTC
   tools, or export the Markdown guide and a TURNt configuration file. Commands are
   generated, not executed.
7. Open **TLS tests**, select an endpoint and Run. The built-in engine needs no
   setup; choose SSLyze (Python 3.10+) only for its extra vulnerability probes.
8. For advisor / customer applications, open **XSS canaries**, generate a canary per
   injection point (chat, display name, file name) and place it as the customer;
   view it as the advisor. In **Access control**, set each session's Role.
9. In **Scan All**, pick a preset or select scans (all checked by default), then click
   **Scan selected**. **Security checks** has optional listener/account/echo-peer
   inputs and saved scenario execution; nothing needs installing.

## SDP mutation (M3)

After updating the jar, reload the extension **and the browser page** so the
current bundled agent installs.

1. Open **SDP rules**. Select incoming (`setRemoteDescription`), outgoing
   (`createOffer` / `createAnswer`), or both. An optional peer ID (e.g. `pc1`)
   narrows the rule within each page; IDs restart in each frame/page.
2. Select removal of DTLS fingerprints or embedded ICE candidates, choose an
   audio/video direction, or add one or more literal substring match/replace
   rules. Rules run in order and replace every occurrence; multiline text works.
   Click an SDP line in the **Before** pane to fill an empty Match box, then edit
   the line to the substring you want to target.
3. Check **Enable SDP mutation**. Changes save automatically and affect subsequent
   SDP operations without restarting the bridge. Start a new call or renegotiate
   to exercise them. Uncheck it to stop subsequent edits.
4. Select an `sdp-mutation` row to compare before/after SDP. `sdp-result` records
   acceptance by the description setter; `sdp-error` records a rejection and its
   browser error. Match events using `mutationId` in the event detail. Acceptance
   by a setter does not prove the connection succeeded or identify a vulnerability.

For a simple test on the DataChannel sample, use **Incoming**, find `s=-`, and
replace with `s=m3-test`; then start a new connection and send text. For a rejection
test, clear find/replace, enable fingerprint removal, and start a fresh connection.
The latter may intentionally prevent negotiation. Disable M3 and reload to reset.

The agent fetches fresh rules before each mutation. The bridge requires injection
to be enabled, the current page host to be allow-listed, and the full page URL to
be in Burp Target scope. Missing authorization or a bridge timeout (1.5 seconds)
leaves SDP unchanged. Command responses are never cached.

M3 handles modern promise-based WebRTC methods. Legacy callback overloads,
implicit `setLocalDescription()` generation, signaling transport messages, and
trickled `addIceCandidate` values are not mutated. Removing embedded candidates
does not stop trickle ICE. Outgoing edits may be rejected by the browser before
signaling; incoming edits are the default. SDP text is limited to 262,144 characters
for mutation, and before/after evidence is truncated at 65,536 characters per side
(marked in the event). These are browser API hooks, not a signaling proxy.

## DataChannel fuzz (M4) and STUN & TURN

Both are active tests driven from their sub-tabs and gated on Burp Target scope.

- **Data channels:** with a call open, the live DataChannel list updates
  automatically; pick one, choose a payload mode (text / hex / json
  / boundary) and count/interval, then **Run**. Payloads are bounded (≤ 65,536
  bytes each, ≤ 1 MiB per run, 1–50 messages at 100–1000 ms). For short-lived channels,
  set the payload and tick **Run on next DataChannel open (once, this session)**
  before starting a call. **Stop** cancels the current test and disarms automatic
  testing. See the [1.0.2 additions](#102-additions--short-lived-datachannels).
- **STUN & TURN:** enter a `stun:` / `turn:` / `turns:` URI (the host:port must
  be in Burp Target scope — **Show scope URL** shows the URL that gate checks).
  **Gather candidates** runs an isolated ICE gather on a throwaway peer and reports
  srflx (STUN) and relay (TURN) observations separately. TURN credentials are
  preserved in full in telemetry and error text. No HTTP request is made to the ICE
  server.

## Layout

```
build.gradle.kts / settings.gradle.kts   Gradle Kotlin + Shadow fat jar
agent/webrtc-agent.js                     generic W3C hook, bundled into the jar
runner/tls_runner.py                      optional SSLyze adapter (Python runtime installed separately)
runner/protocol_runner.py                 retired Python STUN/TURN runner (not bundled; superseded by protocol/TurnProbe.kt)
src/main/kotlin/webrtc/
  WebRtcExtension.kt                       entry point
  config/                                  M0 model, store, detectors, active-test config
  inject/InjectorHandler.kt                M1 (loads bundled agent when path is blank)
  bridge/                                  M2 loopback bridge + active-test controller
  internals/InternalsDump.kt               chrome://webrtc-internals dump parser
  internals/InternalsComparator.kt         dump-vs-telemetry comparison
  external/ExternalInputs.kt               passive TURN/STUN/page observations for commands
  external/ExternalTools.kt                ten-tool command catalogue + Bash/YAML rendering
  tls/                                    TLS target parsing, built-in JVM scanner, optional SSLyze runtime
  protocol/                                built-in STUN/TURN client (TurnProbe) and Burp-routed scenario runner
  canary/CanaryRegistry.kt                 XSS / callback canaries, reflection tracking, Collaborator mapping
  burp/BurpIntegration.kt                  Collaborator client, Burp issue reporter, Intruder canary source
  report/SecurityTestReport.kt             twelve-area evidence/result tables and Markdown rendering
  report/CoverageCheck.kt                  methodology checklist, coverage limits and next steps
  telemetry/                               M2 event model
  telemetry/StatsSnapshot.kt               T1 getStats snapshot parser
  telemetry/CertificateAnalyzer.kt         T2 X.509 parse + fingerprint binding
  telemetry/PolicyAudit.kt                 original (pre-injection) header audit
  telemetry/BrowserReview.kt               canary, capture lifecycle and postMessage review
  authz/AuthzMatrixRunner.kt               M5 with role expectations and verdicts
  authz/LinkCatalogs.kt                    meeting-link and document/recording catalogs + replay tester
  workflow/                                request catalog + Run All orchestrator + T7 signaling metadata
  scope/ScopeGate.kt                       scope safety
  BuildInfo.kt                             reads version from JAR build metadata
  ui/                                       suite tab + panels (Scan All, Security checks, M0/M2/M3/M3+/M4/M5/M6/T8/External/M7)
                                           + HelpUi.kt (per-setting "?" help)
```

Contributor working notes (the Gradle `--no-daemon` requirement, the test
commands above, versioning, and telemetry conventions) are kept in a local
`AGENTS.md` that is not published to the repository.

Beginner-friendly UX runs through the whole tool: Setup auto-fills the
advanced settings and hides them behind a toggle, every setting has a plain-English
"?" help button with an example, and the Scan All tab ties the modules together.
