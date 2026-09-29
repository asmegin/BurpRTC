# PLAN.MD — WebRTC Test Suite coverage expansion

Status: **Tier 1 (T1–T8) shipped; released as 1.0.0** (extension and agent aligned at
1.0.0, no functional change from 0.9.0). Tier 2 (T9–T14) and the Tier 3 external
catalogue additions remain planned. Target: increase self-contained coverage of the
extension against Enable Security's WebRTC pentest methodology, the HackTricks WebRTC DoS
note, the WebRTC Security whitepaper, and `awesome-rtc-hacking`, while keeping the stated
design boundary (browser W3C JS-API hook + Burp traffic; no raw packets, no native fuzzing).

Baseline: extension 0.8.0, agent 0.7.0. Implemented on extension 0.9.0 / agent 0.8.0. All
changes are additive; the full JVM (70) and agent (30) suites pass.

Tier 1 implementation notes:
- T1 events: `stats-snapshot` + `dtls-cert`, with a manual **Capture stats (T1)** button in
  Telemetry (M2) and an automatic bounded burst+steady sampling in the agent.
- T2/T4/T5 live in `CertificateAnalyzer` + `Detectors`; T3 is a dedicated Run All privacy
  section; T6 extends `sdpFuzzCases`; T7 is `workflow/SignalingMetadata` (passive Burp proxy
  history read; negotiated TLS version/cipher are not exposed by the Montoya API, so that
  remains a `testssl.sh` review item); T8 is `SignalingFloodConfig` + `SignalingFloodPanel`
  (opt-in, default off, Run All includes it only when confirmed).
- T9 (WebSocket handlers) is feasible — the pinned Montoya 2026.7 API exposes
  `Proxy.webSocketHistory()` and `ProxyWebSocketCreationHandler` — but is deferred to Tier 2.

## Current coverage (do not duplicate)

- M1 inject + CSP strip; M2 SDP/ICE/cipher/DataChannel/userMedia telemetry; M3 SDP
  mutation; M3+ SDP parser fuzz; M4 DataChannel fuzz; M5 HTTP authz matrix/IDOR; M6
  STUN/TURN gather + relay allocation; M7 report/CSV; chrome://webrtc-internals compare;
  External Tests command builder; full credential visibility.
- Known code gaps confirmed: agent `reportStats` reads only `transport` + one
  `candidate-pair`; no certificates, no RTP stats, no ICE-ufrag/pwd analysis; `Detectors.kt`
  lacks attribute/cert/privacy logic; only HTTP handler registered (`WebRtcExtension.kt:26`)
  — no WebSocket handling; M5 replays HTTP only; README public-IP/relay-only privacy check
  is unimplemented.

## Boundary and safety rules (apply to every task)

- Every active action (fuzzing, probing, flooding, replay) stays gated on Burp Target scope
  via `ScopeGate` + allow-list + `injectionEnabled`, exactly as M3/M4/M6 do today.
- Bounded by construction: hard caps on message counts, sizes, durations, concurrency;
  `Stop` must cancel; timeouts must release peers/timers.
- The extension must not execute external tools; External Tests only generates commands.
- New telemetry event types go through `BridgeServer.store`/`summarize`, `EventTypes.KNOWN`,
  and the Run All / M7 passive review. Credentials remain preserved (no masking).
- Adding a new agent capability requires a **page reload** to pick up the bundled agent;
  note this in the affected module's UI help/README.

## Tier 1 — SHOULD add (closes concrete gaps within the boundary)

### T1. Deeper `getStats` telemetry
- Where: `agent/webrtc-agent.js` (`reportStats`), new Kotlin stats parsing/detectors
  (e.g. `src/main/kotlin/webrtc/telemetry/`), `RunAllController.reviewTelemetry`,
  `FindingsPanel`.
- What: periodic stats sampling (on connect + N-second interval while connected, capped
  samples/run) capturing: outbound/inbound RTP (SSRC, payloadType, packets, bytes, loss,
  jitter), remote-inbound, full candidate-pair set + ICE candidate stats (type/protocol/
  address/port/priority), transport/DtlsTransport (dtlsCipher/srtpCipher/tlsVersion, dtlsRole,
  iceRole), certificates, data-channel metrics.
- New events: `rtp-stats`, `candidate-stats`, `transport-stats` (or one `stats-snapshot`
  with sections). Keep payloads bounded and mark truncation.
- Run All: report payload types actually in use, ICE/DTLS roles, packet loss/jitter, chosen
  pair; evidence only, never a verdict.
- Validation: agent unit test with a fake `getStats` report; Kotlin parser tests; Run All test.

### T2. DTLS certificate + fingerprint binding
- Where: agent (capture `getRemoteCertificates()`/`getLocalCertificates()` from the DTLS
  transport, base64/DER strings in a new `dtls-cert` event), new Kotlin analyzer, Run All, M7.
- What: parse X.509 with `java.security.cert`; compute SHA-256; compare to SDP
  `a=fingerprint`. Flag: fingerprint mismatch (binding failure, RFC 8827), expired/near-expiry,
  weak key size, unexpected issuer/self-signed where unexpected, missing `a=fingerprint`.
- Validation: parse fixtures for matching/mismatching/expired certs; Run All finding test.

### T3. IP-privacy completion (README roadmap item + whitepaper §4.5)
- Where: `Detectors.kt` (public-IP, IPv6, TCP candidate, mDNS classification), agent ICE
  events already carry candidate text, Run All, M7.
- What: flag **public (srflx) IP disclosure**; list host/IPv6/TCP candidates and mDNS names;
  detect `iceTransportPolicy: relay` and warn when host/srflx addresses are exposed (no
  relay-only protection). Add a dedicated "IP location privacy" section to Run All/M7.
- Validation: detector tests (public vs private vs mDNS vs IPv6), Run All finding test.

### T4. ICE credential hygiene from SDP
- Where: `Detectors.kt` + Run All; SDP text already stored in `sdp-local`/`sdp-remote`.
- What: parse `a=ice-ufrag`/`a=ice-pwd` per media/session; flag short/low-entropy values and
  reuse across ICE restarts (correlate successive SDP for the same pc). Distinct from TURN
  credentials; never substitute SDP ICE creds for TURN account creds.
- Validation: detector tests for entropy/reuse; Run All test.

### T5. SDP attribute + codec audit
- Where: `Detectors.kt`, Run All, M7; complements existing codec enumeration.
- What: enumerate/classify `a=` attributes; flag `a=crypto` (have), `a=ice-lite`, missing
  `a=rtcp-mux`, weak `a=fingerprint` hash (md5/sha-1), `a=setup` roles, and per-codec
  `a=fmtp` (H.264 profile-level-id, opus params); list codecs with their fmtp.
- Validation: detector tests over representative SDP; Run All INFO/FINDING test.

### T6. Codec-focused fuzzing in M3+
- Where: `agent/webrtc-agent.js` `sdpFuzzCases`, M3+ panel/help text.
- What: systematic `a=rtpmap`/`a=fmtp` mutation per codec (profile-level-id overflows,
  malformed params, known codec payloads), in addition to the existing generic line
  mutations; still submitted via `setRemoteDescription` on throwaway peers.
- Validation: extend `agent/active-tests.test.cjs` case-count/outcome assertions; keep
  `maxCases` cap semantics.

### T7. Signaling endpoint TLS metadata
- Where: new passive source reading in-scope HTTPS/WSS endpoints from Burp proxy history
  (Montoya API), new `RunAllController`/M7 section.
- What: report observed signaling origins and flag legacy TLS/ciphers and missing HSTS as
  **review items** (metadata from Burp, no network scan). Reuse External Tests endpoint
  detection. Do not duplicate external `testssl.sh`.
- Validation: pure function tests for origin/TLS classification; confirm no live request.

### T8. Bounded renegotiation / ICE-restart flood (opt-in)
- Where: new active-test type in `ActiveTestController` + command in agent; new panel in
  `ActiveTestPanels.kt` or Run All entry; Config flag (default off).
- What: scope-gated, hard-capped loop of `createOffer`/`setLocalDescription`/ICE restart to
  probe signaling-server rate limiting ("API flooding"/"signaling flood DoS"), plus ICE-restart
  credential-reuse observation (feeds T4). Explicit UI warning, max count/duration, `Stop`,
  auto-cancel on scope loss.
- Validation: controller bounds test; agent test that it honours cancellation and never
  exceeds caps; ensure Run All does not enable it without opt-in.

## Tier 2 — CAN add (valuable, optional)

### T9. WebSocket signaling support
- First verify whether the pinned Montoya API (`2026.7`) exposes WebSocket handlers; if not,
  emit Repeater/Intruder instructions instead.
- What: capture WS upgrade (`Origin`, `Sec-WebSocket-Protocol`, auth headers) and messages;
  detect **SIP-over-WS** subprotocol to auto-populate External Tests; origin/auth checks.
- Validation: handler unit tests with fixtures if API available.

### T10. Signaling mutation/replay helper
- What: from a captured signaling request (HTTP, and WS if T9 lands), generate RTC-aware
  mutations (SDP/ICE injection, type confusion, oversized fields, JSON structure)
  for Repeater/Intruder; extend M5 replay to WS where reachable.
- Validation: pure generator tests (quoting/serialization); no execution in the extension.

### T11. DataChannel negotiation fuzz
- Where: `agent/webrtc-agent.js` `runFuzz`, M4 panel.
- What: `ordered`/`maxRetransmits`/`maxPacketLifeTime`, negotiated-id collisions, label/
  protocol strings, `binaryType`, send-after-close/backpressure. Keep existing caps.
- Validation: extend `active-tests.test.cjs` fuzz-mode assertions.

### T12. Permissions/device surface
- What: `enumerateDevices`, `getDisplayMedia` outcome, `getSupportedConstraints`,
  permission-policy checks; do not record media contents. Extends M2 getUserMedia outcome.
- Validation: agent test that outcomes are recorded without media.

### T13. Client/dependency fingerprint
- What: report UA + WebRTC stack and outdated JS-library versions from observed bundles
  ("outdated dependencies"); informational CVE mapping, not a scan.
- Validation: parser tests; Run All INFO note.

### T14. Codec downgrade checks
- What: use `setCodecPreferences`/`getCapabilities` to attempt forcing weak/removed codecs;
  verify negotiated set from T1 stats; flag forbidden downgrades.
- Validation: agent test with fake capabilities; report as review lead only.

## Tier 3 — External Tests catalogue additions (not runnable in Burp)

Extend `src/main/kotlin/webrtc/external/ExternalTools.kt` catalogue and the README
catalogue section:
- **E1 Scapy/rtcsec DTLS ClientHello race** (HackTricks/Enable Security DoS) — high relevance.
- **E2 Turner** (HTTP over TURN) and **turnproxy** (open-relay abuse); deeper TURNado
  SOCKS/L3 modes.
- **E3 rtpnatscan** (RTP Bleed); retain existing SIPPTS `rtpbleed`.
- **E4 SIPp** digest-leak + registration-race scenarios; **sipsak** (flood/random); **Mr.SIP**.
- **E5 VoIPShark/sngrep** SIP capture.
- **E6 H26Forge** (H.264 decoder/codec fuzz); **DVRTC** / **RTC_Attacks** practice labs.
- Each recipe needs purpose, coverage, prerequisites, evidence, effects, limitations,
  upstream links, missing-input states, and preserved credentials; stress/password recipes
  labelled and separated. Update `ExternalToolsTest` counts/metadata assertions.

## Explicitly out of scope

RTP/RTCP injection, RTP bleed, RTP flooding, raw RTP packet fuzz, SRTP auth, native-parser/
RCE fuzzing, full TURN-as-C2 tunnelling, live TLS scanning, IdP trust. Keep these in the
External Tests command builder / labs and state so in docs.

## Cross-cutting work (required by the above)

- Add new event types to `EventTypes.KNOWN` and `BridgeServer.summarize`.
- Wire every new finding into `RunAllController.reviewTelemetry`/`passiveReport` and the M7
  Markdown report; keep plain-English, non-overclaiming wording.
- Keep credential visibility (no masking) in new events, reports, CSV, and External Tests.
- Update module table, roadmap list, Layout, and Use sections in `README.md` after
  implementation; bump extension version and agent `AGENT_VERSION` together.

## Validation plan

- `gradlew test --offline --console=plain --no-daemon` — all existing + new Kotlin tests.
- `node --test agent/webrtc-agent.test.cjs agent/active-tests.test.cjs` — agent tests.
- `gradlew shadowJar` — fat jar builds; confirm manifest `Implementation-Version`.
- Manual: reload extension + browser page, join a call, confirm new events appear and Run All
  reports them; verify scope gating by un-scoping a target and confirming active tests skip.
- Confirm no task executes an external tool and no live scan is triggered by TLS metadata (T7).

## Open questions / decisions to resolve during implementation

1. T9 WebSocket: does the pinned Montoya API expose WebSocket handlers? If not, deliver the
   instruction-only fallback.
2. T8 flood: ship as opt-in Config flag (recommended) vs. Run All default off; confirm exact
   caps (count, duration, interval).
3. T1 sampling: choose interval/cap and whether to also expose a manual "Capture stats"
   button in Telemetry (M2) — recommended: automatic interval + manual button.
4. T2/T14: whether to attempt X.509 key-strength parsing limits given browser-provided
   cert formats (recommended: best-effort, skip gracefully).
5. Tier 2 ordering: T9/T10 depend on WebSocket API availability; T11–T14 are independent.
