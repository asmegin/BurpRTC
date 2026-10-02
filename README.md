# WebRTC Test Suite — Burp Suite extension

A client-agnostic Burp Suite Professional extension that drives a WebRTC
penetration test from a single Suite tab. Nothing target-specific is compiled
in — every engagement detail is configuration, persisted in the Burp project file.

> **Authorized testing only.** Every active action (injection, mutation, fuzzing,
> ICE probing, replay, flood) is gated on Burp **Target scope**. Credentials live
> only in the Burp project file and are never masked.

**Version 1.0.5** · JDK 21 · Burp Montoya API 2026.7

## What it does

It injects a browser agent that hooks the W3C WebRTC JavaScript API (SDP, ICE,
DataChannel) and observes/rewrites HTTP(S), giving you the signaling- and
API-visible attack surface from inside Burp:

- **Passive telemetry (M1/M2)** — SDP, ICE candidates (private-IP flagged),
  DTLS/SRTP ciphers, DataChannels, deep `getStats`, and DTLS certificate /
  fingerprint binding.
- **Guided Run All** — one click: config check → telemetry review → live checks,
  with plain-English findings (weak/absent media crypto, cleartext SDES keys,
  public-IP disclosure, codec enumeration, guessable IDs, TURN relay allocation).
- **Active modules** — SDP mutation (M3), SDP parser fuzz (M3+), DataChannel fuzz
  (M4), authz/IDOR matrix (M5), STUN/TURN gather (M6), opt-in signaling flood (T8).
- **External Tests** — generates ready-to-copy Linux/Bash commands for ten
  external RTC tools (text only; it never executes them).
- **TLS Tests** — runs a bundled Python scanner from Burp for HTTPS/WSS and
  TURN-over-TLS listeners, with setup, cancellation, scope checks and M7 results.
- **Findings (M7)** — begins with a point-form security checklist covering
  authentication, media/RTP, resilience, protocol-specific signaling and other
  security categories, then 12 detailed evidence sections. Built-in, partial and
  external/manual coverage stay separate from actual execution results.
  CSV and credentials remain intact.

Version **1.0.5** explicitly tracks every requested methodology item, including
WebSocket/TURN/SRTP authentication, TLS and cipher checks, DTLS certificates,
TURN abuse, RTP injection/bleed/flood/fuzzing, codec fuzzing/enumeration,
signaling/API resilience, SIP-over-WebSocket, injection and API security.
Each checklist item includes its coverage limit and links to details and a next
step. Run All uses the same checklist. This does **not** add raw-packet testing:
SRTP authentication, RTP attacks, native decoder fuzzing, automated WebSocket/SIP
authentication and server load tests still need external/manual execution.
See the [coverage matrix](DOCS.md#105-additions--methodology-checklist-and-coverage-corrections).

M3+ now samples mutation families so long SDP does not crowd out codec cases;
M5 rechecks injection, host allow-list and Burp scope before every replay.
Reload the extension **and browser page** after upgrading.

Version 1.0.2 adds **Run on next DataChannel open** in M4: arm one test using the
current payload settings, then start a call. The browser requests the run from
the actual open event without waiting for the three-second poll. Arming is for
this session only, and Stop disarms it. Lifecycle telemetry distinguishes local
creation from open, records early closure and ICE/peer states, and identifies
page calls to `close()`. Reload the extension and browser page after updating.

Version 1.0.3 adds integrated **TLS Tests**. Install Python 3.10+, select its
executable in the tab, and click **Setup TLS runner** once. Burp creates a managed
environment and installs SSLyze 6.3.1. Select an observed endpoint or enter
`turns:host:5349?transport=tcp`, add the displayed scope URL to Burp Target scope,
allow the host in Config and enable injection, then click **Run TLS tests**.
Protocol/cipher/certificate checks run inside the extension workflow; optional
vulnerability probes and inclusion in **Run All** default off. Results appear in
TLS Tests, Telemetry and the M7 report. No separate terminal is required.
These are direct TCP connections from Python, outside Burp's HTTP proxy/history.
Media DTLS over UDP and SRTP packet testing still require separate tooling.

Version 1.0.4 organizes the report into signaling, SDP, STUN/TURN, ICE,
SRTP/SRTCP, DTLS, DataChannels, SFU/MCU/gateways, authentication/session/access
control, browser security, recording/storage/compliance, and DoS. Observed and
completed checks stay separate from security findings and incomplete runs.
Unsupported checks and missing results appear explicitly; report generation
does not start tests. Open **Findings (M7)** → **Generate report** → **Save report**.

The 1.0.1 iframe correction is included: CSP stripping preserves enforced
`frame-ancestors` directives so `X-Frame-Options: SAMEORIGIN` does not unexpectedly
block previously permitted embeds.

## Download

Prebuilt extension (bundles the browser agent):
**[`dist/webrtc-testsuite-all.jar`](dist/webrtc-testsuite-all.jar)**.

## Build from source

Requires JDK 21 (the Gradle wrapper handles the rest):

```
cmd.exe /c "gradlew.bat shadowJar --offline --console=plain --no-daemon"
```

Output: `build/libs/webrtc-testsuite-all.jar`.

## Load in Burp

1. Extensions → Installed → Add → extension type **Java** → select the jar.
2. Output shows `WebRTC Test Suite v1.0.5 loaded`; a **WebRTC** tab appears.
3. In **Config (M0)**: enable agent injection, add the app host(s) to the
   allow-list, Save. Advanced settings are auto-configured — leave them collapsed.
4. Add the target to Burp **Target scope**, browse the app through Burp, join a
   call — telemetry fills in, and **Run All** ties the modules together.

## Design boundary

This reaches the **signaling- and API-visible** surface and selected **TLS-over-TCP
listeners** through the integrated Python runner. The media plane
(RTP/RTCP/SRTP) and native-parser memory-safety fuzzing are out of scope by
construction and delegated to external tooling (see the External Tests tab). API
acceptance or a generated command is a lead to investigate, never a confirmed
vulnerability.

## Documentation

Full reference — every module, the coverage roadmap, the external-tool catalogue
and detailed usage — is in **[DOCS.md](DOCS.md)**.

## License

[Apache 2.0](LICENSE).

The optional Python environment installs [SSLyze](https://github.com/nabla-c0d3/sslyze),
licensed under AGPLv3, and its dependencies under their own licenses. Their code
is installed separately by Setup and is not included in the extension JAR.
