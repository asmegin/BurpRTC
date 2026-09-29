# WebRTC Test Suite — full reference

> This is the complete reference. For a short overview and download/build/load
> instructions, see [README.md](README.md).

A client-agnostic Burp extension that drives a WebRTC penetration test from one
Suite tab. Nothing target-specific is compiled in — every engagement detail is
configuration (Module 0), persisted in the Burp project file.

> Authorized testing only. Every active action (injection, mutation, fuzzing,
> ICE probing, replay) is gated on Burp **Target scope**. Credentials live only
> in the Burp project file.

## Current status (2026-09-29)

**Version 1.0.0.** `build/libs/webrtc-testsuite-all.jar` bundles browser agent
**1.0.0**. `./gradlew shadowJar` builds successfully, the agent passes
`node --check agent/webrtc-agent.js`, and the full suites pass: **70 JVM tests**
(`gradlew test`) and **30 agent tests** (`node --test agent/webrtc-agent.test.cjs
agent/active-tests.test.cjs`).

The 1.0.0 release is a stabilization of the 0.9.0 Tier 1 feature set: the
extension and bundled agent versions are aligned at 1.0.0 with no functional
change from 0.9.0 beyond the version bump. Tier 2 (T9–T14) remains planned
(see [PLAN.MD](PLAN.MD)).

### 0.9.0 additions — Tier 1 coverage (see [PLAN.MD](PLAN.MD))

- **T1 deeper `getStats` telemetry** — the agent now samples the browser's own
  statistics (transport/DTLS/ICE roles, every local/remote candidate, the chosen
  candidate pair, in-use RTP streams with payload type, packet/byte counts, loss
  and jitter, and certificate fingerprints) as a bounded `stats-snapshot`, plus one
  `dtls-cert` event per certificate. Run All reports the payload types actually in
  use, roles, chosen pair and packet loss/jitter as evidence only — never that
  media reached the peer. A **Capture stats (T1)** button in **Telemetry (M2)**
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
  the negotiated TLS version/cipher here, so confirming those stays with the
  external `testssl.sh` recipe.
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

M0–M7 are all implemented, plus an **SDP Fuzz (M3+)** parser-robustness tab and an
**External Tests** tab that generates Linux/Bash commands for ten external RTC
testing tools. A **Run All** tab provides a guided one-click workflow that raises
plain-English
findings — weak/absent media crypto, SDES cleartext keys, missing DTLS
fingerprint, codec enumeration, guessable identifiers, SDP fuzz triage signals, and TURN
relay-allocation (the Ghost Calls precondition). **Telemetry (M2)** can import a
user-exported `chrome://webrtc-internals` dump and cross-check it against captured
telemetry. Credentials are preserved in full everywhere. **Findings (M7)** exports a
Markdown report (config, telemetry findings, M3/M5 guidance, telemetry summary) —
passive, so it can be generated any time without touching the target.

## Coverage & roadmap

### TODO / requested improvements

- [x] Print the extension name and version to Burp's extension **Output** console
  on every load/reload so the tester can confirm which version is running
  (`WebRTC Test Suite v1.0.0 loaded`). The version is read from the loaded JAR's
  build metadata (manifest `Implementation-Version`, then a generated
  `webrtc-version.properties`), so the message identifies the actual loaded
  artifact rather than a hard-coded string.
- [x] Added an **External Tests** tab that automatically prepares complete Linux/Bash
  commands for ten external RTC testing tools from telemetry, Config, and captured
  signaling. It includes broad assessments, focused checks, intensive recipes, tool
  explanations, prerequisites, and upstream links, with preserved manual edits.
  See [External Tests command builder](#external-tests-command-builder).
- [x] Passwords and other credentials are preserved throughout the extension:
  telemetry, UI fields, commands, configuration files, CSV exports, and reports.
  Automatic omission, masking, and redaction were removed; the tester controls what
  is removed from screenshots and report evidence. See [credential visibility](#credential-visibility).
- [x] Compare captured extension telemetry with a Chrome `chrome://webrtc-internals`
  dump. Chrome's privileged page cannot be read directly by this extension, so
  **Telemetry (M2)** imports a user-exported dump (gzip, JSON or copied page text) and
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
It does not send raw packets, so the **media plane** (RTP/RTCP/SRTP) and
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
- ✅ Guided Run All workflow with plain-English findings.
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
- ✅ **chrome://webrtc-internals comparison** — **Telemetry (M2)** imports a
  user-exported dump (gzip, JSON or copied text) and cross-checks it against captured
  telemetry: ICE candidate addresses present in only one view, private-address and
  mDNS observations, DTLS/SRTP/TLS cipher agreement (reusing the weak-crypto judgement), and
  advertised codecs. Results are stored as `internals-comparison` telemetry and
  surfaced by Run All and the M7 report. It is a cross-check, not a verdict.
- ✅ **Startup version banner** — Burp's Output console shows `WebRTC Test Suite
  v<x.y.z> loaded`, read from the loaded JAR's build metadata.
- ✅ **External Tests command builder** — a tab that renders complete Linux/Bash
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
  opt-in **signaling/ICE-restart flood (T8)**. See the 0.9.0 additions above.
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
- ⛔ **IdP/identity-provider trust model** and **TLS scanning** of signaling
  endpoints — application-level / dedicated TLS scanners.

The external execution boundary above remains in place. The
[External Tests tab](#external-tests-command-builder) provides commands
for relevant external tools; generating a command does not execute the test or
mark that external surface as scanned by the extension.

There is no single browser-side scan that can cover every WebRTC vulnerability:
the native engine, OS device stack, application signaling rules, remote peer, and
network path expose different test surfaces. The standards define security
properties across these layers; this extension tests the subset available through
Burp traffic and browser APIs. For deeper engine memory-safety testing, use the
upstream WebRTC native fuzzing harness against a matching browser/library build.

## External Tests command builder

**Status: implemented in 0.8.0** (the tab renders the commands below). It generates
text only and never executes a tool; a ready command is not a completed scan.
Research and command documentation were reviewed on **2026-09-29**. No external
scans were run during that review.

### Goal and agreed defaults

The **External Tests** tab turns information collected by the extension
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

The **Config (M0)** tab is split so a first-time user only touches a few fields:

- **Basic** — enable injection, host allow-list, strip CSP. This is all most
  engagements need.
- **Identities & identifiers** — only for the Authz Matrix (M5).
- **Advanced (auto-configured)** — bridge address, bridge port, collect/command
  paths and the agent override are hidden behind a **Show advanced settings**
  toggle and pre-filled with working defaults. **Restore recommended defaults**
  resets them in one click.

Every setting has a **"?" help button** that explains it in plain English with an
example (including example pentest payloads). **Check configuration** validates
the current settings and reports any problems in plain English (empty allow-list
while injection is on, bad port, unparseable identities JSON, a missing agent
override file, …); the same check runs automatically on Save.

The browser agent ships **inside the jar** as a classpath resource, so there is
no agent path to configure — leave **Advanced → Agent JS override** blank and the
extension injects the bundled agent automatically. You only fill that field to
point at an on-disk agent while developing the agent itself.

## Run All — the guided workflow

The **Run All** tab (first tab) is the beginner path. One click **Run all checks**
and it, in order:

1. Checks the M0 configuration is ready (injection on, allow-list set, valid port).
2. Reviews the passive telemetry already collected (M1/M2) and calls out findings
   in plain English — e.g. private/host IP disclosure from ICE candidates.
3. Runs the live active checks it safely can, one per page at a time: **M6** ICE
   gather, **M4** DataChannel fuzz, and **M3+** SDP parser fuzz against every
   browser page the agent is live on (using your saved settings, scope-gated as
   always).
4. Reports what still needs a manual step: **M3** needs a fresh negotiation started
   in the browser, and **M5** needs you to pick a request to replay.

It never invents a finding — it reports what the modules actually observed, and
clearly marks anything it skipped and why. Export the results from the Findings
(M7) tab.

## Implemented modules

| Module | Sub-tab | What it does |
|--------|---------|--------------|
| Run All | Run All | Guided one-click workflow: config check → telemetry review (incl. T1 stats, T2 cert binding, T3 privacy, T4/T5 SDP audit, T7 signaling metadata) → live M6/T1/M4/M3+ checks → optional opt-in T8 flood → guidance for M3/M5. |
| M0 Config + detectors | Config (M0) | Host allow-list, bridge settings, identity profiles, identifier map; protocol-agnostic SDP/ICE/private-IP/candidate detectors (T3–T5). |
| M1 Injector + CSP | (Config) | Injects the bundled browser agent before `</head>` on allow-listed, in-scope HTML and strips CSP. Controlled from Config. |
| M2 Telemetry bridge | Telemetry (M2) | Embedded loopback HTTP server; agent beacons SDP / ICE (private-IP flagged) / DTLS-SRTP cipher / DataChannel / `stats-snapshot` / `dtls-cert` events. Imports a `chrome://webrtc-internals` dump and cross-checks candidates, ciphers and codecs; **Capture stats (T1)** forces a fresh snapshot. |
| M3 SDP mutation | SDP Mutation (M3) | Scope-gated incoming/outgoing SDP edits, persisted rules, before/after evidence, and browser acceptance/rejection telemetry. |
| M3+ SDP fuzz | SDP Fuzz (M3+) | Mutates every line of the latest observed SDP with malformed/known payloads and bounded size/overflow variants, then records accepted vs rejected on a throwaway peer. Local parse only, no packets sent. |
| M4 DataChannel fuzz | DataChannel Fuzz (M4) | Scope-gated payload sends (text / hex / json / boundary) over a live DataChannel, with bounded size and rate. |
| M5 Authz matrix | Authz Matrix (M5) | Right-click any request → replay across identities, substitute identifiers, unauth; flags cross-principal 2xx. |
| M6 TURN/STUN | TURN/STUN (M6) | Isolated ICE gather against a configured STUN/TURN server; reports srflx/relay observations; credentials preserved in errors. |
| T8 Flood | Signaling Flood (T8) | Opt-in, bounded local `createOffer`/`setLocalDescription`/ICE-restart loop on a throwaway peer; reports ICE-credential reuse. Nothing is sent to the signaling server. |
| External Tests | External Tests | Generates Linux/Bash commands for ten external RTC tools from telemetry and Config; Ready/Missing states, editable commands, Markdown and TURNt-config export. Generates text only. |
| M7 Findings | Findings (M7) | Compiles and saves a Markdown report (including credentials) and exports telemetry plus authorization-matrix results as CSV. Passive. |

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
2. Output shows `WebRTC Test Suite v1.0.0 loaded`; a **WebRTC** suite tab appears.

## Use

1. **Config (M0):** check **Enable agent injection**, add the app host(s) to the
   allow-list, Save. The advanced settings (bridge, paths, agent override) are
   auto-configured — leave them collapsed. Define identity profiles and
   identifier keys as needed for the authz matrix. Use the **"?"** buttons for a
   plain-English explanation of any field, and **Check configuration** to confirm
   you are ready.
2. Add the target to Burp **Target scope**.
3. Browse the app through Burp → the bundled agent is injected, CSP stripped.
4. Join a call → **Telemetry (M2)** fills with SDP, ICE (PRIVATE flag), cipher.
5. Right-click any request → **WebRTC: Run authz matrix** → results in **Authz Matrix (M5)**.
6. Open **External Tests** to copy ready Linux/Bash commands for the external RTC
   tools, or export the Markdown guide and a TURNt configuration file. Commands are
   generated, not executed.

## SDP mutation (M3)

After updating the jar, reload the extension **and the browser page** so the
current bundled agent installs.

1. Open **SDP Mutation (M3)**. Select incoming (`setRemoteDescription`), outgoing
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

## DataChannel fuzz (M4) and TURN/STUN (M6)

Both are active tests driven from their sub-tabs and gated on Burp Target scope.

- **DataChannel Fuzz (M4):** with a call open, the live DataChannel list updates
  automatically; pick one, choose a payload mode (text / hex / json
  / boundary) and count/interval, then **Run**. Payloads are bounded (≤ 65,536
  bytes each, ≤ 1 MiB per run, 1–50 messages at 100–1000 ms). **Stop** cancels.
- **TURN/STUN (M6):** enter a `stun:` / `turn:` / `turns:` URI (the host:port must
  be in Burp Target scope — **Show scope URL** shows the URL that gate checks).
  **Gather candidates** runs an isolated ICE gather on a throwaway peer and reports
  srflx (STUN) and relay (TURN) observations separately. TURN credentials are
  preserved in full in telemetry and error text. No HTTP request is made to the ICE
  server.

## Layout

```
build.gradle.kts / settings.gradle.kts   Gradle Kotlin + Shadow fat jar
agent/webrtc-agent.js                     generic W3C hook, bundled into the jar
src/main/kotlin/webrtc/
  WebRtcExtension.kt                       entry point
  config/                                  M0 model, store, detectors, active-test config
  inject/InjectorHandler.kt                M1 (loads bundled agent when path is blank)
  bridge/                                  M2 loopback bridge + active-test controller
  internals/InternalsDump.kt               chrome://webrtc-internals dump parser
  internals/InternalsComparator.kt         dump-vs-telemetry comparison
  external/ExternalInputs.kt               passive TURN/STUN/page observations for commands
  external/ExternalTools.kt                ten-tool command catalogue + Bash/YAML rendering
  telemetry/                               M2 event model
  telemetry/StatsSnapshot.kt               T1 getStats snapshot parser
  telemetry/CertificateAnalyzer.kt         T2 X.509 parse + fingerprint binding
  authz/AuthzMatrixRunner.kt               M5
  workflow/                                request catalog + Run All orchestrator + T7 signaling metadata
  scope/ScopeGate.kt                       scope safety
  BuildInfo.kt                             reads version from JAR build metadata
  ui/                                       suite tab + panels (Run All, M0/M2/M3/M3+/M4/M5/M6/T8/External/M7)
                                           + HelpUi.kt (per-setting "?" help)
```

Contributor working notes (the Gradle `--no-daemon` requirement, the test
commands above, versioning, and telemetry conventions) are kept in a local
`AGENTS.md` that is not published to the repository.

Beginner-friendly UX runs through the whole tool: Config (M0) auto-fills the
advanced settings and hides them behind a toggle, every setting has a plain-English
"?" help button with an example, and the Run All tab ties the modules together.
