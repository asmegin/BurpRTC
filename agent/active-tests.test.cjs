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
    createDataChannel(label, options = {}) { const c = new Channel(label); Object.assign(c, options); return c; }
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
  let observe = false;
  const sockets = [];
  class Socket extends Emitter {
    constructor(url) { super(); this.url = url; this.readyState = 0; this.bufferedAmount = 0; this.sent = []; sockets.push(this); }
    send(value) { this.sent.push(value); }
    close() { this.readyState = 3; this.emit('close', { code: 1000, reason: '' }); }
  }
  const context = {
    location: { href: 'https://example.test/call' }, navigator: {}, AbortController, TextEncoder, Blob,
    setTimeout: (fn, delay) => { timers.set(++timerId, { fn, delay }); return timerId; },
    clearTimeout: id => timers.delete(id),
    RTCPeerConnection: Peer, WebSocket: Socket,
    __WRTC_CFG__: { collect: '/collect', command: '/command' },
    fetch: (url, options) => {
      if (options.method === 'POST') { events.push(JSON.parse(options.body)); return Promise.resolve({ ok: true }); }
      const query = new URL(url, 'http://localhost').searchParams;
      let automatic = null;
      if (query.has('autoFuzz')) { autoRequests.push(query.get('autoFuzz')); automatic = autoRequest(query.get('autoFuzz')); }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({
        commands: automatic ? [automatic] : query.get('poll') === '1' ? queued : [], authorized: permit && query.has('authorize'), observe
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
  return { events, sends, timers, peers, context, flush, tick, queue, sockets, observe: value => { observe = value; },
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

function mediaHarness() {
  const events = [], timers = new Map(), messageListeners = [], posted = [];
  let timerId = 0;
  class Track {
    constructor(kind, settings) { this.kind = kind; this.readyState = 'live'; this.settings = settings; this.listeners = {}; }
    getSettings() { return this.settings; }
    addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
    stop() { this.readyState = 'ended'; }
  }
  const camera = new Track('video', {}), screen = new Track('video', { displaySurface: 'monitor' });
  class Peer {
    constructor() { this.connectionState = 'new'; this.signalingState = 'stable'; this.listeners = {}; }
    addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
    close() { this.connectionState = 'closed'; this.signalingState = 'closed'; }
  }
  const context = {
    location: { href: 'https://bank.test/advisor', origin: 'https://bank.test' }, AbortController, TextEncoder,
    document: { cookie: 'advisor_session=readable' },
    navigator: { mediaDevices: {
      getUserMedia: () => Promise.resolve({ getTracks: () => [camera], getVideoTracks: () => [camera] }),
      getDisplayMedia: () => Promise.resolve({ getTracks: () => [screen], getVideoTracks: () => [screen] }),
      enumerateDevices: () => Promise.resolve([{ kind: 'videoinput', label: 'Secret Cam' }, { kind: 'audioinput', label: '' }])
    } },
    setTimeout: (fn, delay) => { timers.set(++timerId, { fn, delay }); return timerId; },
    clearTimeout: id => timers.delete(id),
    RTCPeerConnection: Peer,
    addEventListener: (type, fn) => { if (type === 'message') messageListeners.push(fn); },
    postMessage: (message, target) => { posted.push([message, target]); },
    __WRTC_CFG__: { collect: '/collect', command: '/command' },
    fetch: (url, options) => {
      if (options.method === 'POST') { events.push(JSON.parse(options.body)); return Promise.resolve({ ok: true }); }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ commands: [] }) });
    }
  };
  context.window = context;
  vm.runInNewContext(source, context);
  const flush = async () => { for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve)); };
  const fire = delay => { for (const [id, t] of [...timers]) if (t.delay === delay) { timers.delete(id); t.fn(); } };
  return { events, context, camera, screen, messageListeners, posted, flush, fire };
}

test('screen share and camera capture lifecycle is recorded without media or device labels', async () => {
  const h = mediaHarness();
  await h.context.navigator.mediaDevices.getDisplayMedia({ video: true });
  await h.context.navigator.mediaDevices.getUserMedia({ video: true });
  await h.flush();
  const granted = h.events.find(e => e.type === 'capture-result');
  assert.equal(granted.outcome, 'resolved');
  assert.deepEqual(granted.displaySurfaces, ['monitor']);
  assert.ok(h.events.some(e => e.type === 'track-state' && e.source === 'screen' && e.displaySurface === 'monitor'));
  h.screen.stop();
  await h.flush();
  assert.ok(h.events.some(e => e.type === 'track-state' && e.action === 'stop-called' && e.source === 'screen'));
  const pc = new h.context.RTCPeerConnection();
  pc.close();
  h.fire(3000);
  await h.flush();
  const live = h.events.filter(e => e.action === 'live-after-close');
  assert.equal(live.length, 1);
  assert.equal(live[0].source, 'camera/microphone');
  assert.ok(!JSON.stringify(h.events).includes('Secret Cam'));
});

test('device enumeration reports counts and label exposure only', async () => {
  const h = mediaHarness();
  await h.context.navigator.mediaDevices.enumerateDevices();
  await h.flush();
  const result = h.events.find(e => e.type === 'enumerateDevices-result');
  assert.deepEqual(result.counts, { videoinput: 1, audioinput: 1 });
  assert.equal(result.labelsExposed, true);
  assert.ok(!JSON.stringify(result).includes('Secret Cam'));
});

test('XSS canary beacons once with origin and readable cookies', async () => {
  const h = mediaHarness();
  h.context.__wrtcCanary('abc123XYZ', 'chat');
  h.context.__wrtcCanary('abc123XYZ', 'chat');
  await h.flush();
  const fired = h.events.filter(e => e.type === 'xss-canary-fired');
  assert.equal(fired.length, 1);
  assert.equal(fired[0].canaryId, 'abc123XYZ');
  assert.equal(fired[0].origin, 'https://bank.test');
  assert.equal(fired[0].readableCookies, 'advisor_session=readable');
});

test('message listeners without origin checks and wildcard posts are reported', async () => {
  const h = mediaHarness();
  h.context.addEventListener('message', function (event) { document.body.innerHTML = event.data; });
  h.context.addEventListener('message', function (event) { if (event.origin !== 'https://bank.test') return; });
  h.context.postMessage({ token: 'secret' }, '*');
  h.context.postMessage('safe', 'https://bank.test');
  h.messageListeners[0]({ origin: 'https://evil.test', data: 'hello' });
  await h.flush();
  const listeners = h.events.filter(e => e.type === 'message-listener');
  assert.deepEqual(listeners.map(e => e.checksOrigin), [false, true]);
  const sent = h.events.filter(e => e.type === 'message-sent');
  assert.equal(sent.length, 1);
  assert.ok(sent[0].data.includes('secret'));
  assert.equal(h.posted.length, 2);
  assert.equal(h.events.find(e => e.type === 'message-received').origin, 'https://evil.test');
});

test('M4 list mode sends each payload once in order', async () => {
  const h = harness(); h.channel();
  await h.start(fuzz({ mode: 'list', payloads: ['<img src=x>', 'second'], count: 2 }));
  await h.tick(100);
  assert.deepEqual(h.sends, ['<img src=x>', 'second']);
});

test('browser-checks command reports permission states and policy without media', async () => {
  const h = harness();
  h.context.navigator.permissions = { query: ({ name }) => Promise.resolve({ state: name === 'camera' ? 'granted' : 'prompt' }) };
  h.context.isSecureContext = true;
  await h.start({ type: 'browser-checks', config: {} });
  await h.flush();
  const result = h.events.find(e => e.type === 'browser-capabilities');
  assert.equal(result.permissions.camera, 'granted');
  assert.equal(result.permissions.microphone, 'prompt');
  assert.equal(result.secureContext, true);
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'completed');
});

// ---- DataChannel runner (1.3.0) ----
const suite = (cases, config = {}) => ({ type: 'dc-suite', config: {
  channelId: 'dc1', settleMs: 100, maxMessageBytes: 70000, maxTotalBytes: 1048576, maxBufferedAmount: 262144, cases, ...config
} });
const text = (value, marker = '') => ({ id: `case-${value.length}`, marker, payload: { kind: 'text', parts: [{ text: value }] } });
const settle = async (h, n, ms = 100) => { for (let i = 0; i < n; i++) await h.tick(ms); };

test('runner suite sends each case once with native send, UTF-8 byte counts and settle-window states', async () => {
  const h = harness(); h.channel();
  await h.start(suite([text('é wrtcaaaaaaaaaaaa', 'wrtcaaaaaaaaaaaa'), { id: 'bin', payload: { kind: 'arraybuffer', parts: [{ fill: 'zero', count: 16 }] } }]));
  await settle(h, 2);
  const cases = h.events.filter(e => e.type === 'dc-case');
  assert.equal(cases.length, 2);
  assert.equal(cases[0].bytes, 19); assert.equal(cases[0].stage, 'queued'); assert.equal(cases[0].marker, 'wrtcaaaaaaaaaaaa');
  assert.equal(cases[0].stateAfter.channel, 'open'); assert.ok(cases[0].textHash && cases[0].sentAt);
  assert.equal(cases[1].bytes, 16); assert.equal(Object.prototype.toString.call(h.sends[1]), '[object ArrayBuffer]');
  // Runner sends are not double-reported as application traffic.
  assert.ok(!h.events.some(e => e.type === 'dc-send'));
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'completed');
});

test('runner payload kinds and seeded random bytes are reproducible', async () => {
  const kinds = ['uint8array', 'int16array', 'float64array', 'dataview', 'blob'];
  const runs = [];
  for (let run = 0; run < 2; run++) {
    const h = harness(); h.channel();
    await h.start(suite(kinds.map(kind => ({ id: kind, payload: { kind, parts: [{ fill: 'random', count: 16, seed: 42 }] } }))));
    await settle(h, kinds.length);
    runs.push(h.sends);
    assert.deepEqual(h.events.filter(e => e.type === 'dc-case').map(e => e.bytes), [16, 16, 16, 16, 16]);
  }
  assert.ok(runs[0][4] instanceof Blob);
  assert.deepEqual(Array.from(runs[0][0]), Array.from(runs[1][0]));
  assert.ok(new Set(Array.from(runs[0][0])).size > 4);
});

test('runner distinguishes browser rejection from queued sends and blocks over-cap payloads', async () => {
  const h = harness(); h.channel();
  h.onSend(value => { if (typeof value === 'string' && value.length > 10) throw new TypeError('message too large'); });
  await h.start(suite([text('short'), text('this is longer than ten'),
    { id: 'huge', payload: { kind: 'text', parts: [{ repeat: 'A', count: 80000 }] } }]));
  await settle(h, 2);
  await h.flush();
  const cases = h.events.filter(e => e.type === 'dc-case');
  assert.deepEqual(cases.map(e => e.stage), ['queued', 'browser-rejected', 'blocked']);
  assert.match(cases[1].error, /TypeError: message too large/);
  assert.match(cases[2].error, /per-message byte cap/);
});

test('runner suite stops when the channel closes and honours revoked authorization', async () => {
  const h = harness(); const channel = h.channel();
  h.onSend(() => { channel.readyState = 'closed'; });
  await h.start(suite([text('one'), text('two')]));
  await settle(h, 1);
  assert.equal(h.sends.length, 1);
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'failed');
  const r = harness(); r.channel(); r.onSend(() => r.permit(false));
  await r.start(suite([text('one'), text('two')])); await settle(r, 1);
  assert.equal(r.sends.length, 1);
  assert.equal(r.events.find(e => e.type === 'command-result').status, 'cancelled');
});

test('marker receipts are batched with Colibri envelopes; ordinary messages are sampled', async () => {
  const h = harness(); const channel = h.channel();
  channel.emit('message', { data: '{"colibriClass":"EndpointMessage","from":"abcd1234","to":"","msgPayload":{"wrtcMarker":"wrtcbbbbbbbbbbbb"}}' });
  channel.emit('message', { data: '{"colibriClass":"EndpointStats","from":"abcd1234","bitrate":1}' });
  await h.tick(250);
  const batch = h.events.find(e => e.type === 'dc-markers');
  assert.equal(batch.receipts.length, 1);
  assert.equal(batch.receipts[0].marker, 'wrtcbbbbbbbbbbbb');
  assert.equal(batch.receipts[0].from, 'abcd1234'); assert.equal(batch.receipts[0].colibriClass, 'EndpointMessage');
  const recv = h.events.filter(e => e.type === 'dc-recv');
  assert.equal(recv.length, 1); assert.equal(recv[0].colibriClass, 'EndpointStats'); assert.ok(recv[0].text);
  await h.tick(3000);
  assert.deepEqual(h.events.filter(e => e.type === 'agent-state').at(-1).endpointHints, ['abcd1234']);
});

test('observe mode polls faster and reports hash receipts for replay matching', async () => {
  const h = harness(); h.observe(true); const channel = h.channel();
  await h.flush();
  assert.ok([...h.timers.values()].some(t => t.delay === 500));
  channel.emit('message', { data: '{"colibriClass":"EndpointMessage","from":"x","msgPayload":{"a":1}}' });
  await h.tick(250);
  const receipt = h.events.find(e => e.type === 'dc-markers').receipts[0];
  assert.equal(receipt.marker, ''); assert.ok(receipt.payloadHash);
});

test('Colibri channels and ICE-lite remotes are classified; heartbeat carries channel details', async () => {
  const h = harness(); await h.flush();
  const pc = new h.context.RTCPeerConnection();
  pc.createDataChannel('JVB data channel', { protocol: 'http://jitsi.org/protocols/colibri', ordered: true });
  const created = h.events.find(e => e.type === 'dc-created');
  assert.equal(created.peerKind, 'jvb'); assert.equal(created.protocol, 'http://jitsi.org/protocols/colibri');
  assert.equal(created.maxMessageSize, 65536);
  const sfu = new h.context.RTCPeerConnection();
  await sfu.setRemoteDescription({ type: 'offer', sdp: 'v=0\r\na=ice-lite\r\n' });
  await h.tick(3000);
  const state = h.events.filter(e => e.type === 'agent-state').at(-1);
  assert.deepEqual(state.pcs.map(p => p.kind), ['jvb', 'sfu']);
  assert.equal(state.channels[0].protocol, 'http://jitsi.org/protocols/colibri');
});

test('Colibri WebSocket is registered with URL hints and usable as a runner transport', async () => {
  const h = harness();
  const ws = new h.context.WebSocket('wss://meet.example.test/colibri-ws/jvb1/conf42/ep777?pwd=secret-pwd');
  ws.readyState = 1; ws.emit('open');
  ws.send('{"colibriClass":"ClientHello"}');
  await h.flush(); await h.tick(3000);
  const state = h.events.filter(e => e.type === 'agent-state').at(-1);
  assert.equal(state.endpoint, 'ep777');
  assert.equal(state.sockets[0].conference, 'conf42');
  assert.ok(state.sockets[0].url.includes('secret-pwd'));
  assert.equal(h.events.find(e => e.type === 'ws-colibri-send').colibriClass, 'ClientHello');
  await h.start(suite([text('{"colibriClass":"EndpointMessage","to":"","msgPayload":{}}')], { transport: 'colibri-ws', socketId: 'ws1', channelId: undefined }));
  await settle(h, 1);
  assert.equal(ws.sent.length, 2);
  assert.equal(h.events.find(e => e.type === 'dc-case').transport, 'colibri-ws');
  ws.emit('message', { data: '{"colibriClass":"EndpointMessage","from":"ep1","wrtcMarker":"wrtccccccccccccc"}' });
  await h.tick(250);
  assert.equal(h.events.find(e => e.type === 'dc-markers').receipts[0].kind, 'colibri-ws');
});

test('WebSocket admission uses an unwrapped socket and reports the first bridge message', async () => {
  const h = harness();
  await h.start({ type: 'ws-admission', config: { url: 'wss://meet.example.test/colibri-ws/jvb1/other/ep9?pwd=bad', timeoutMs: 3000, send: '{"colibriClass":"ClientHello"}' } });
  const ws = h.sockets[0]; ws.readyState = 1; ws.emit('open');
  ws.emit('message', { data: '{"colibriClass":"ServerHello","version":"2.3"}' });
  await h.flush();
  const result = h.events.find(e => e.type === 'ws-admission-result');
  assert.equal(result.opened, true); assert.equal(result.firstClass, 'ServerHello');
  assert.deepEqual(ws.sent, ['{"colibriClass":"ClientHello"}']);
  assert.ok(!h.events.some(e => e.type === 'ws-colibri'));
});

test('load burst sends sequential markers and stops on backpressure', async () => {
  const h = harness(); const channel = h.channel();
  h.onSend(() => { channel.bufferedAmount += 100; });
  await h.start({ type: 'dc-load', config: { mode: 'burst', count: 20, channelId: 'dc1', markerStem: 'wrtcload0001', prefix: '{"m":"', suffix: '"}',
    maxMessages: 100, maxBytes: 100000, maxBufferedAmount: 450 } });
  const step = h.events.find(e => e.type === 'dc-load-step');
  assert.equal(step.sent, 5); assert.equal(step.stopReason, 'backpressure');
  assert.equal(h.sends[0], '{"m":"wrtcload00010000"}'); assert.equal(h.sends[4], '{"m":"wrtcload00010004"}');
});

test('channel churn needs a connected SCTP association and closes every channel', async () => {
  const refused = harness(); refused.channel();
  await refused.start({ type: 'dc-churn', config: { pcId: 'pc1', mode: 'sequential', iterations: 2, openTimeoutMs: 1000, variants: [{ name: 'default' }] } });
  assert.match(refused.events.find(e => e.type === 'dc-churn-error').detail, /renegotiation/);
  const h = harness(); h.channel(); h.peers[0].sctp.state = 'connected';
  await h.start({ type: 'dc-churn', config: { pcId: 'pc1', mode: 'concurrent', iterations: 3, openTimeoutMs: 1000,
    variants: [{ name: 'unordered', ordered: false }, { name: 'lifetime', maxPacketLifeTime: 100 }] } });
  const results = h.events.filter(e => e.type === 'dc-churn-result');
  assert.equal(results.length, 3);
  assert.ok(results.every(r => r.outcome === 'open' && r.finalState === 'closed'));
  assert.equal(results[0].ordered, false); assert.equal(results[1].maxPacketLifeTime, 100);
  assert.equal(h.events.find(e => e.type === 'dc-churn-summary').outcomes.open, 3);
});

test('health snapshot reports peers, channels and DataChannel statistics', async () => {
  const h = harness(); h.channel();
  await h.start({ type: 'dc-health', config: {} });
  const health = h.events.find(e => e.type === 'dc-health');
  assert.equal(health.channels[0].state, 'open');
  assert.equal(health.peers[0].media.packetsReceived, 0);
  assert.equal(h.events.find(e => e.type === 'command-result').status, 'completed');
});

test('page errors carrying a marker become error receipts', async () => {
  const listeners = {};
  const h = harness();
  h.context.addEventListener = (type, fn) => { (listeners[type] ||= []).push(fn); };
  vm.runInNewContext(source.replace('if (window.__WRTC_AGENT_ACTIVE__) return;', ''), h.context);
  listeners.error.forEach(fn => fn({ target: h.context, message: 'TypeError: bad payload wrtcdddddddddddd', error: { stack: 'at handler' } }));
  await h.tick(250);
  const error = h.events.find(e => e.type === 'page-error');
  assert.deepEqual(error.markers, ['wrtcdddddddddddd']);
  assert.ok(h.events.some(e => e.type === 'dc-markers' && e.receipts.some(r => r.kind === 'error' && r.marker === 'wrtcdddddddddddd')));
});
