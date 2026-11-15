
**One-line summary:** WebRTC security testing for Burp Suite — instruments browser calls, audits SDP/ICE/DTLS and STUN/TURN, tests signaling and DataChannel access control, and reports findings as Burp issues.

**Version 1.3.3** · JDK 21 · Burp Montoya API 2026.7 · [Apache 2.0](LICENSE)

> **Authorized testing only.** Every active action is gated on Burp **Target scope**,
> the host allow-list and the agent switch.

## What it does

- **Passive evidence** — SDP, ICE, DTLS/SRTP, certificates, DataChannels, getStats and signaling from an injected browser agent.
- **Access control** — replays captured requests, meeting links and documents across customer / advisor sessions.
- **Active tests** — SDP mutation and fuzzing, DataChannel fuzzing and a paired-session DataChannel runner, XSS canaries.
- **Infrastructure** — built-in STUN/TURN and TLS checks; no extra install needed.
- **Reporting** — a test checklist, evidence report and deduplicated Burp issues.

## Install

1. Download `burprtc-all.jar` from [Releases](../../releases), or build it:
   `gradlew shadowJar` → `build/libs/burprtc-all.jar`.
2. Burp → Extensions → Add → type **Java** → select the jar. A **BurpRTC** tab appears.
3. In **Setup**, enable the agent and add the app's host to the allow-list.
4. Add the target to Burp **Target scope**, browse the app through Burp and join a call.
5. In **Scan All**, pick a preset and click **Scan selected**.

## Good to know

- While the agent is enabled, the Content-Security-Policy of allow-listed pages is
  relaxed in the proxied browser so the agent can run. Other Burp tools see the
  original response.
- STUN/TURN and TLS checks connect directly from your machine, not through Burp's
  upstream proxy.
- Credentials are shown and exported in full; treat reports and exports as sensitive.
- Raw media (RTP/SRTP) testing is left to external tools; the **External commands**
  tab generates the commands.

Full reference and release history: **[DOCS.md](DOCS.md)**.
