const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(`${__dirname}/webrtc-agent.js`, 'utf8');

function harness(initialChannelState = 'open') {
  const events = [], sends = [], timers = new Map(), peers = [];
  let queued = [], permit = true, sequence = 0, timerId = 0, gather = true, iceFailure = false;
  let onSend = () => {};
  let autoRequest = () => null;
  const autoRequests = [];
  class Emitter {
    constructor() { this.listeners = {}; }
    addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
    emit(type, event) { for (const fn of this.listeners[type] || []) fn(event); }
  }
  class Channel extends Emitter {
    constructor(label) { super(); this.label = label; this.readyState = initialChannelState; this.bufferedAmount = 0; }
    send(value) { sends.push(value); onSend(value); }
    close() { this.readyState = 'closed'; this.emit('close'); }
  }
  class Peer extends Emitter {
    constructor(config) { super(); this.config = config; this.connectionState = 'new'; this.iceConnectionState = 'new'; this.signalingState = 'stable'; this.sctp = { maxMessageSize: 65536, state: 'connecting' }; peers.push(this); }
    createDataChannel(label) { return new Channel(label); }
    createOffer() { return Promise.resolve({ type: 'offer', sdp: 'v=0\r\na=fingerprint:sha-256 AA\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10\r\n' }); }
    getStats() {
      const stats = [
        { id: 'T01', type: 'transport', dtlsCipher: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', srtpCipher: 'AEAD_AES_128_GCM', tlsVersion: '1.3', dtlsState: 'connected', dtlsRole: 'client', iceRole: 'controlling', localCertificateId: 'C1', remoteCertificateId: 'C2' },
        { id: 'C1', type: 'certificate', fingerprint: 'AA:BB', fingerprintAlgorithm: 'sha-256', base64Certificate: 'Zm9v' },
        { id: 'C2', type: 'certificate', fingerprint: 'CC:DD', fingerprintAlgorithm: 'sha-256', base64Certificate: 'YmFy' },
        { id: 'O1', type: 'outbound-rtp', kind: 'audio', ssrc: 42, payloadType: 111, packetsSent: 10, bytesSent: 1000, codecId: 'CD1' },
        { id: 'CD1', type: 'codec', mimeType: 'audio/opus', payloadType: 111 },
        { id: 'L1', type: 'local-candidate', candidateType: 'host', protocol: 'udp', address: '192.168.1.2', port: 5000 },
        { id: 'R1', type: 'remote-candidate', candidateType: 'srflx', protocol: 'udp', address: '203.0.113.9', port: 6000 },
        { id: 'P1', type: 'candidate-pair', state: 'succeeded', selected: true, localCandidateId: 'L1', remoteCandidateId: 'R1' }
      ];
      return Promise.resolve({ forEach: fn => stats.forEach(fn) });
    }
    setLocalDescription() {
      if (iceFailure) return Promise.reject(new Error('secret-user secret-password failed'));
      if (gather) queueMicrotask(() => {
        this.emit('icecandidate', { candidate: { type: 'srflx', candidate: 'candidate:1 1 udp 1 203.0.113.1 1234 typ srflx' } });
        this.emit('icecandidate', { candidate: null });
      });
      return Promise.resolve();
    }
    // Simulate a parser that rejects SDP without a v=0 line (empty, whitespace, missing-v).
    setRemoteDescription(desc) {
      const sdp = desc && desc.sdp;
      if (typeof sdp !== 'string' || !/(^|\r\n)v=0/.test(sdp)) return Promise.reject(new Error('Failed to parse SessionDescription'));
      return Promise.resolve();
    }
    close() { this.closed = true; this.connectionState = 'closed'; this.signalingState = 'closed'; this.emit('connectionstatechange'); }
  }
  const context = {
    location: { href: 'https://example.test/call' }, navigator: {}, AbortController, TextEncoder,
    setTimeout: (fn, delay) => { timers.set(++timerId, { fn, delay }); return timerId; },
    clearTimeout: id => timers.delete(id),
    RTCPeerConnection: Peer,
    __WRTC_CFG__: { collect: '/collect', command: '/command' },
    fetch: (url, options) => {
      if (options.method === 'POST') { events.push(JSON.parse(options.body)); return Promise.resolve({ ok: true }); }
      const query = new URL(url, 'http://localhost').searchParams;
      let automatic = null;
      if (query.has('autoFuzz')) { autoRequests.push(query.get('autoFuzz')); automatic = autoRequest(query.get('autoFuzz')); }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({
        commands: automatic ? [automatic] : query.get('poll') === '1' ? queued : [], authorized: permit && query.has('authorize')
      }) });
    }
  };
  context.window = context;
  vm.runInNewContext(source, context);
  const flush = async () => { for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve)); };
  const tick = async delay => {
    const pair = [...timers].find(([, t]) => t.delay === delay);
    assert.ok(pair, `No ${delay}ms timer`);
    timers.delete(pair[0]); pair[1].fn(); await flush();
  };
  const queue = command => {
    const value = { id: `command-${++sequence}`, agent: events[0].agent, frame: context.location.href, ...command };
    queued = [value]; return value;
  };
  return { events, sends, timers, peers, context, flush, tick, queue,
    auto: callback => { autoRequest = callback; }, autoRequests, nativeChannel: label => new Channel(label),
    channel: () => new context.RTCPeerConnection().createDataChannel('same-label'),
    start: async command => { await flush(); const value = queue(command); await tick(3000); return value; },
    permit: value => { permit = value; }, onSend: value => { onSend = value; },
    gather: value => { gather = value; }, iceFailure: () => { iceFailure = true; }
  };
}
const fuzz = (config = {}) => ({ type: 'dc-fuzz', channelId: 'dc1', config: {
  mode: 'text', payload: 'hello', count: 1, intervalMs: 100, maxBytes: 4096, stopOnError: true, ...config
} });
const ice = (config = {}) => ({ type: 'ice-probe', config: {
  url: 'stun:example.test', policy: 'all', timeoutSeconds: 3, ...config
} });

test('M4 sends one command once despite repeated polls and targets the selected channel', async () => {
  const h = harness(); h.channel(); h.channel();
  await h.start({ ...fuzz(), channelId: 'dc2' });
  assert.deepEqual(h.sends, ['hello']);
  assert.equal(h.events.find(e => e.type === 'fuzz-result').channelId, 'dc2');
  await h.tick(3000);
  assert.equal(h.sends.length, 1);
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'completed');
  assert.ok(h.events.filter(e => e.type === 'agent-state').at(-1).completed.length);
});

test('M4 sends UTF8 text and hex binary with byte-accurate telemetry', async () => {
  const h = harness(); h.channel();
  await h.start(fuzz({ payload: 'é', maxBytes: 2 }));
  assert.equal(h.events.find(e => e.type === 'fuzz-result').bytes, 2);
  await h.start(fuzz({ mode: 'hex', payload: '00 FF 7a' }));
  assert.deepEqual(Array.from(h.sends[1]), [0, 255, 122]);
});

test('M4 JSON and boundary presets produce distinct payloads', async () => {
  const h = harness(); h.channel();
  await h.start(fuzz({ mode: 'json', count: 2 })); await h.tick(100);
  assert.deepEqual(h.sends, ['null', 'true']);
  await h.start(fuzz({ mode: 'boundary', count: 3, maxBytes: 255 }));
  await h.tick(100); await h.tick(100);
  assert.deepEqual(h.sends.slice(2).map(v => v.length), [0, 1, 255]);
});

test('M4 stops before the next send after authorization is revoked', async () => {
  const h = harness(); h.channel(); h.onSend(() => h.permit(false));
  await h.start(fuzz({ count: 3 })); await h.tick(100);
  assert.equal(h.sends.length, 1);
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'cancelled');
});

test('M4 refuses wrong page instances, wrong frames and denied authorization', async () => {
  for (const extra of [{ agent: 'other' }, { frame: 'https://elsewhere.test/' }]) {
    const h = harness(); h.channel(); await h.start({ ...fuzz(), ...extra }); assert.equal(h.sends.length, 0);
  }
  const h = harness(); h.channel(); h.permit(false); await h.start(fuzz());
  assert.equal(h.sends.length, 0);
});

test('M4 handles closed channels, backpressure and negotiated message limits', async () => {
  for (const setup of [h => { h.channel().readyState = 'closed'; }, h => { h.channel().bufferedAmount = 300000; },
    h => { h.channel(); h.peers[0].sctp.maxMessageSize = 1; }]) {
    const h = harness(); setup(h); await h.start(fuzz());
    assert.equal(h.sends.length, 0);
    assert.equal(h.events.find(e => e.type === 'command-result').status, 'failed');
  }
});

test('M4 rejects oversized runs and malformed binary payloads', async () => {
  for (const config of [{ count: 50, maxBytes: 65536 }, { mode: 'hex', payload: 'z1' }, { payload: 'é', maxBytes: 1 }]) {
    const h = harness(); h.channel(); await h.start(fuzz(config)); assert.equal(h.sends.length, 0);
    assert.equal(h.events.find(e => e.type === 'command-result').status, 'failed');
  }
});

test('M4 open-triggered command sends without waiting for the poll and runs once per channel', async () => {
  const h = harness('connecting');
  h.auto(channelId => h.queue({ ...fuzz(), channelId }));
  const channel = h.channel(); await h.flush();
  assert.equal(h.autoRequests.length, 0); assert.equal(h.sends.length, 0);
  channel.readyState = 'open'; channel.emit('open'); await h.flush();
  assert.deepEqual(h.sends, ['hello']);
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'completed');
  assert.equal(h.events.filter(e => e.type === 'agent-state').at(-1).channels[0].state, 'open');
  channel.emit('open'); await h.flush(); await h.tick(3000);
  assert.deepEqual(h.autoRequests, ['dc1']); assert.equal(h.sends.length, 1);
});

test('M4 connecting channels that close are diagnosed and never request automatic payloads', async () => {
  const h = harness('connecting'); h.auto(channelId => h.queue({ ...fuzz(), channelId }));
  const channel = h.channel(); h.peers[0].iceConnectionState = 'failed';
  channel.close(); await h.flush();
  assert.equal(h.autoRequests.length, 0); assert.equal(h.sends.length, 0);
  const state = h.events.find(e => e.type === 'dc-state' && e.detail.includes('before reaching open'));
  assert.equal(state.everOpened, false); assert.equal(state.iceConnectionState, 'failed');
  assert.equal(typeof state.elapsedMs, 'number');
  assert.ok(h.events.some(e => e.type === 'dc-state' && e.action === 'close-called' && e.stack));
});

test('M4 automatic command honors revocation and closure during bridge authorization', async () => {
  for (const action of ['revoke', 'close']) {
    const h = harness('connecting'); const channel = h.channel();
    h.auto(channelId => {
      const command = h.queue({ ...fuzz(), channelId });
      if (action === 'revoke') h.permit(false); else channel.close();
      return command;
    });
    channel.readyState = 'open'; channel.emit('open'); await h.flush();
    assert.equal(h.sends.length, 0);
    assert.equal(h.events.find(e => e.type === 'command-result').status, action === 'revoke' ? 'cancelled' : 'failed');
  }
});

test('M4 remote already-open channels trigger once and disarmed bridge sends nothing', async () => {
  const h = harness(); await h.flush();
  const pc = new h.context.RTCPeerConnection();
  // A channel created by the native peer is then delivered by the remote event.
  const channel = h.nativeChannel('remote');
  pc.emit('datachannel', { channel }); await h.flush();
  assert.equal(h.autoRequests.length, 1); assert.equal(h.sends.length, 0);
  assert.ok(h.events.some(e => e.type === 'dc-created' && e.detail === 'remote'));
  channel.emit('open'); await h.flush();
  assert.equal(h.autoRequests.length, 1);
});

test('peer failure and page close calls carry lifecycle evidence', async () => {
  const h = harness('connecting'); const channel = h.channel(); const pc = h.peers[0];
  pc.connectionState = 'failed'; pc.iceConnectionState = 'failed'; pc.emit('connectionstatechange');
  channel.emit('error', { error: { name: 'RTCError', message: 'SCTP failed', errorDetail: 'sctp-failure', sctpCauseCode: 12 } });
  pc.close(); await h.flush();
  assert.ok(h.events.some(e => e.type === 'pc-state' && e.connectionState === 'failed' && e.iceConnectionState === 'failed'));
  assert.ok(h.events.some(e => e.type === 'pc-state' && e.action === 'close-called' && e.stack));
  assert.ok(h.events.some(e => e.type === 'dc-state' && e.errorDetail === 'sctp-failure' && e.sctpCauseCode === 12));
});

test('M6 uses an isolated native peer, gathers srflx and closes it', async () => {
  const h = harness(); await h.start(ice());
  assert.equal(h.peers.length, 1);
  assert.equal(h.peers[0].config.iceServers[0].urls, 'stun:example.test');
  assert.equal(h.peers[0].closed, true);
  const result = h.events.find(e => e.type === 'ice-probe-result');
  assert.equal(result.observed, true); assert.equal(result.counts.srflx, 1);
  assert.ok(!h.events.some(e => e.type === 'pc-new' || e.type === 'sdp-mutation'));
});

test('M6 reports TURN relay observations separately from STUN success', async () => {
  const h = harness(); await h.start(ice({ url: 'turn:example.test', username: 'secret-user', credential: 'secret-password', policy: 'relay' }));
  assert.equal(h.peers[0].config.iceServers[0].credential, 'secret-password');
  assert.equal(h.events.find(e => e.type === 'ice-probe-result').expected, 'relay');
  for (const result of h.events.filter(e => e.type.startsWith('ice-probe-'))) {
    assert.equal(result.url, 'turn:example.test');
    assert.equal(result.username, 'secret-user');
    assert.equal(result.credential, 'secret-password');
  }
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'failed');
});

test('M6 timeout and cancellation close the peer', async () => {
  const h = harness(); h.gather(false); await h.start(ice({ timeoutSeconds: 4 }));
  await h.tick(4000);
  assert.equal(h.peers[0].closed, true);
  assert.equal(h.events.find(e => e.type === 'ice-probe-result').reason, 'timeout');
  const c = harness(); c.gather(false); await c.start(ice()); c.permit(false); await c.tick(1000);
  assert.equal(c.peers[0].closed, true);
  assert.equal(c.events.find(e => e.type === 'command-result').status, 'cancelled');
});

test('M6 setup failure closes the peer and preserves full credentials in errors', async () => {
  const h = harness(); h.iceFailure();
  await h.start(ice({ url: 'turn:example.test', username: 'secret-user', credential: 'secret-password' }));
  assert.equal(h.peers[0].closed, true);
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'failed');
  // Credential visibility policy: nothing is masked or redacted in telemetry.
  const failure = h.events.find(e => e.type === 'ice-probe-error');
  assert.equal(failure.url, 'turn:example.test');
  assert.equal(failure.credential, 'secret-password');
  assert.ok(JSON.stringify(h.events).includes('secret-password'));
  assert.ok(JSON.stringify(h.events).includes('secret-user'));
});

test('pc-new and agent-state preserve observed ICE servers and TURN credentials', async () => {
  const h = harness();
  new h.context.RTCPeerConnection({ iceServers: [{ urls: 'turn:turn.example.test:3478', username: 'turn-user', credential: 'turn-pass' }] });
  await h.flush(); await h.tick(3000);
  const pcNew = h.events.find(e => e.type === 'pc-new');
  assert.ok(pcNew.detail.includes('turn-user') && pcNew.detail.includes('turn-pass'));
  const state = h.events.filter(e => e.type === 'agent-state').at(-1);
  assert.deepEqual(state.iceServers, ['turn:turn.example.test:3478']);
  assert.equal(state.iceServerDetails[0].username, 'turn-user');
  assert.equal(state.iceServerDetails[0].credential, 'turn-pass');
});

const sdpFuzz = (config = {}) => ({ type: 'sdp-fuzz', config: { descriptionType: 'offer', maxCases: 16, ...config } });

test('M3+ SDP fuzz feeds malformed descriptions to isolated native peers and reports outcomes', async () => {
  const h = harness();
  await h.start(sdpFuzz({ maxCases: 5 }));
  const results = h.events.filter(e => e.type === 'sdp-fuzz-result');
  assert.equal(results.length, 5);
  assert.ok(results.some(e => e.outcome === 'accepted'));
  assert.ok(results.some(e => e.outcome === 'rejected'));
  const summary = h.events.find(e => e.type === 'sdp-fuzz-summary');
  assert.equal(summary.cases, 5);
  // The baseline control is excluded from the mutation totals (0.8.1).
  assert.equal(summary.accepted + summary.rejected, summary.mutations);
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'completed');
  // Base peer + one throwaway peer per case, all closed; no M3 mutation telemetry leaks in.
  assert.ok(h.peers.length >= 6 && h.peers.every(p => p.closed));
  assert.ok(!h.events.some(e => e.type === 'sdp-remote' || e.type === 'sdp-mutation'));
});

test('M3+ SDP fuzz rejects invalid settings', async () => {
  for (const config of [{ descriptionType: 'bogus' }, { maxCases: 0 }, { maxCases: 501 }]) {
    const h = harness(); await h.start(sdpFuzz(config));
    assert.equal(h.events.find(e => e.type === 'command-result').status, 'failed');
    assert.ok(h.events.some(e => e.type === 'sdp-fuzz-error'));
  }
});

test('M3+ SDP fuzz adds codec-focused rtpmap/fmtp mutations', async () => {
  const h = harness();
  await h.start(sdpFuzz({ maxCases: 40 }));
  const labels = h.events.filter(e => e.type === 'sdp-fuzz-result').map(e => e.label);
  assert.ok(labels.some(l => l.includes('codec-')), `labels: ${labels}`);
});

test('M3+ long SDP still exercises codec and structural cases within a small budget', async () => {
  const h = harness();
  const peer = new h.context.RTCPeerConnection();
  const sdp = 'v=0\r\n' + 'a=x:padding\r\n'.repeat(150) +
    'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10\r\n';
  await peer.setRemoteDescription({ type: 'offer', sdp });
  await h.start(sdpFuzz({ maxCases: 10 }));
  const results = h.events.filter(e => e.type === 'sdp-fuzz-result');
  assert.equal(results.length, 10);
  assert.equal(results[0].label, 'baseline-observed');
  assert.ok(results.some(e => e.label.includes('codec-')));
  assert.ok(results.some(e => e.label === 'empty'));
  assert.ok(results.some(e => e.label.includes('deleted')));
  assert.equal(h.events.find(e => e.type === 'sdp-fuzz-summary').mutations, 9);
});

test('T1 capture-stats emits a bounded snapshot for live peers', async () => {
  const h = harness(); h.channel();
  await h.start({ type: 'capture-stats' });
  const snapshot = h.events.find(e => e.type === 'stats-snapshot');
  assert.ok(snapshot);
  assert.equal(snapshot.rtp.length, 1);
  assert.equal(snapshot.transport.dtlsRole, 'client');
  assert.ok(h.events.some(e => e.type === 'dtls-cert' && e.role === 'remote' && e.base64 === 'YmFy'));
  assert.equal(h.events.find(e => e.type === 'stats-capture-result').peers, 1);
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'completed');
});

test('T8 signaling flood is opt-in and bounds its settings', async () => {
  const denied = harness();
  await denied.start({ type: 'signaling-flood', config: { confirm: false, count: 2, intervalMs: 500 } });
  assert.equal(denied.events.find(e => e.type === 'command-result').status, 'failed');
  assert.ok(denied.events.some(e => e.type === 'signaling-flood-error'));

  const bad = harness();
  await bad.start({ type: 'signaling-flood', config: { confirm: true, count: 99, intervalMs: 500 } });
  assert.equal(bad.events.find(e => e.type === 'command-result').status, 'failed');
});

test('T8 signaling flood runs bounded renegotiations and reports credential reuse', async () => {
  const h = harness();
  await h.start({ type: 'signaling-flood', config: { confirm: true, count: 2, intervalMs: 500 } });
  await h.tick(500);
  await h.flush();
  const results = h.events.filter(e => e.type === 'flood-result');
  assert.equal(results.length, 2);
  assert.equal(results[1].reused, true);
  assert.equal(h.events.find(e => e.type === 'signaling-flood-summary').reusedCredentials, 1);
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'completed');
});

test('application peer telemetry preserves TURN credentials in full', () => {
  const h = harness();
  new h.context.RTCPeerConnection({ iceServers: [{ urls: 'turn:example.test', username: 'secret-user', credential: 'secret-password' }] });
  assert.ok(JSON.stringify(h.events).includes('secret-password'));
  assert.ok(JSON.stringify(h.events).includes('secret-user'));
});
