// Optional real Chromium check. Run with CHROME_PATH pointing at chrome.exe.
// Uses an isolated temporary profile and a local fixture, never the user's browser session.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const dgram = require('node:dgram');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

async function main() {
  assert.ok(process.env.CHROME_PATH, 'Set CHROME_PATH to a Chromium executable');
  const build = path.resolve(__dirname, '../build');
  fs.mkdirSync(build, { recursive: true });
  const profile = fs.mkdtempSync(path.join(build, 'webrtc-chromium-'));
  let rules = null;
  let job = null, permit = true, cancelAfterSend = false;
  let autoFuzz = null;
  const events = [];
  // Minimal local STUN Binding fixture; the documentation address produces a srflx candidate.
  const stun = dgram.createSocket('udp4');
  stun.on('message', (message, remote) => {
    if (message.length < 20 || message.readUInt16BE(0) !== 1 || message.readUInt32BE(4) !== 0x2112a442) return;
    const response = Buffer.alloc(32);
    response.writeUInt16BE(0x0101, 0); response.writeUInt16BE(12, 2); response.writeUInt32BE(0x2112a442, 4);
    message.copy(response, 8, 8, 20);
    response.writeUInt16BE(0x0020, 20); response.writeUInt16BE(8, 22); response[25] = 1;
    response.writeUInt16BE(remote.port ^ 0x2112, 26);
    response.writeUInt32BE((0xcb007101 ^ 0x2112a442) >>> 0, 28); // 203.0.113.1
    stun.send(response, remote.port, remote.address);
  });
  stun.bind(0, '127.0.0.1'); await once(stun, 'listening');
  const source = fs.readFileSync(path.join(__dirname, 'webrtc-agent.js'), 'utf8');
  const server = http.createServer(async (req, res) => {
    if (req.url.startsWith('/command')) {
      const query = new URL(req.url, 'http://localhost').searchParams;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      const commands = rules ? [{ type: 'sdp-mutation', config: rules }] : [];
      if (job && query.get('poll') === '1') commands.push(job);
      if (autoFuzz && query.has('autoFuzz')) {
        const state = events.findLast(e => e.type === 'agent-state' && e.agent === query.get('agent') && e.frame === query.get('frame'));
        if (state?.channels.some(c => c.channelId === query.get('autoFuzz') && c.state === 'open')) {
          job = { id: 'auto-open-smoke', type: 'dc-fuzz', agent: state.agent, frame: state.frame,
            channelId: query.get('autoFuzz'), config: autoFuzz };
          autoFuzz = null; commands.push(job);
        }
      }
      res.end(JSON.stringify({ commands, authorized: !!job && permit && query.get('authorize') === job.id }));
    } else if (req.url === '/collect') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const event = JSON.parse(body);
      events.push(event);
      if (cancelAfterSend && event.type === 'fuzz-result') permit = false;
      res.writeHead(204).end();
    } else if (req.url === '/agent.js') {
      res.setHeader('Content-Type', 'application/javascript'); res.end(source);
    } else {
      res.setHeader('Content-Type', 'text/html');
      res.end('<!doctype html><script>window.__WRTC_CFG__={collect:"/collect",command:"/command"}</script><script src="/agent.js"></script><p>M3 local smoke test</p>');
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  let browser, socket;
  const watchdog = setTimeout(() => { console.error('Browser smoke test timed out'); browser?.kill(); process.exitCode = 1; server.closeAllConnections(); server.close(); socket?.close(); stun.close(); }, 55_000);
  try {
    browser = spawn(process.env.CHROME_PATH, ['--headless=new', '--no-first-run', '--no-default-browser-check',
      '--disable-background-networking', '--disable-extensions', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
    { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
    const debugUrl = await new Promise((resolve, reject) => {
      let stderr = '';
      browser.on('error', reject);
      browser.on('exit', code => reject(new Error(`Chromium exited: ${code}`)));
      browser.stderr.on('data', chunk => {
        stderr += chunk;
        const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
        if (match) resolve(match[1]);
      });
    });
    const origin = debugUrl.replace(/^ws:/, 'http:').split('/devtools/')[0];
    const pages = await (await fetch(`${origin}/json/list`)).json();
    socket = new WebSocket(pages.find(p => p.type === 'page').webSocketDebuggerUrl);
    await once(socket, 'open');
    let sequence = 0;
    const pending = new Map();
    socket.addEventListener('message', ({ data }) => {
      const reply = JSON.parse(data);
      const task = pending.get(reply.id);
      if (task) { pending.delete(reply.id); reply.error ? task.reject(new Error(reply.error.message)) : task.resolve(reply.result); }
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const id = ++sequence; pending.set(id, { resolve, reject }); socket.send(JSON.stringify({ id, method, params }));
    });
    await send('Page.enable');
    const loaded = new Promise(resolve => {
      const listener = ({ data }) => {
        if (JSON.parse(data).method === 'Page.loadEventFired') { socket.removeEventListener('message', listener); resolve(); }
      };
      socket.addEventListener('message', listener);
    });
    await send('Page.navigate', { url: `http://127.0.0.1:${server.address().port}/` });
    await loaded;
    async function evaluate(expression) {
      const result = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
      if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
      return result.result.value;
    }
    const roundTrip = `(async () => {
      const a = new RTCPeerConnection(), b = new RTCPeerConnection();
      try {
        a.onicecandidate = e => { if (e.candidate) b.addIceCandidate(e.candidate).catch(() => {}); };
        b.onicecandidate = e => { if (e.candidate) a.addIceCandidate(e.candidate).catch(() => {}); };
        const received = new Promise(resolve => { b.ondatachannel = e => { e.channel.onmessage = msg => resolve(msg.data); }; });
        const channel = a.createDataChannel('m3-smoke');
        const opened = new Promise(resolve => { channel.onopen = resolve; });
        const offer = await a.createOffer(); await a.setLocalDescription(offer); await b.setRemoteDescription(offer);
        const answer = await b.createAnswer(); await b.setLocalDescription(answer); await a.setRemoteDescription(answer);
        await opened; channel.send('M3 works'); const message = await received;
        return { message, remoteSdp: b.remoteDescription.sdp };
      } finally { a.close(); b.close(); }
    })()`;
    assert.equal((await evaluate(roundTrip)).message, 'M3 works');
    console.log('PASS: disabled M3 preserves a real DataChannel round trip');

    rules = { enabled: true, target: 'remote', find: 's=-', replacement: 's=m3-test' };
    const edited = await evaluate(roundTrip);
    assert.equal(edited.message, 'M3 works');
    assert.ok(events.some(e => e.type === 'sdp-mutation' && e.after.includes('s=m3-test')),
      JSON.stringify({ remoteSdp: edited.remoteSdp.slice(0,160), events: events.map(e => [e.type, e.detail]) }));
    console.log('PASS: incoming literal mutation is accepted and DataChannel still works');

    rules = { enabled: true, target: 'remote', removeFingerprint: true };
    const error = await evaluate(`(async () => {
      const a = new RTCPeerConnection(), b = new RTCPeerConnection();
      try { a.createDataChannel('reject'); await b.setRemoteDescription(await a.createOffer()); return ''; }
      catch (e) { return e.name + ': ' + e.message; }
      finally { a.close(); b.close(); }
    })()`);
    assert.match(error, /fingerprint/i);
    console.log(`PASS: fingerprint removal is rejected by Chromium (${error})`);
    rules = null;
    assert.equal((await evaluate(roundTrip)).message, 'M3 works');
    console.log('PASS: disabling M3 restores successful negotiation');
    // All fixture requests run on the same local server; wait for in-flight beacons.
    await evaluate('new Promise(resolve => setTimeout(resolve, 200))');
    assert.ok(events.some(e => e.type === 'sdp-mutation' && e.before && e.after));
    assert.ok(events.some(e => e.type === 'sdp-result' && e.accepted));
    assert.ok(events.some(e => e.type === 'sdp-error' && e.accepted === false && e.mutationId));
    console.log('PASS: before/after, acceptance, and rejection telemetry received');

    await evaluate(`(async () => {
      const a = new RTCPeerConnection(), b = new RTCPeerConnection();
      window.smokeChannel = { a, b, received: [] };
      a.onicecandidate = e => { if(e.candidate) b.addIceCandidate(e.candidate).catch(() => {}); };
      b.onicecandidate = e => { if(e.candidate) a.addIceCandidate(e.candidate).catch(() => {}); };
      b.ondatachannel = e => { e.channel.binaryType = 'arraybuffer'; e.channel.onmessage = msg => smokeChannel.received.push(
        typeof msg.data === 'string' ? msg.data : Array.from(new Uint8Array(msg.data))); };
      const dc = a.createDataChannel('m4-smoke'); const ready = new Promise(resolve => dc.onopen = resolve);
      const offer = await a.createOffer(); await a.setLocalDescription(offer); await b.setRemoteDescription(offer);
      const answer = await b.createAnswer(); await b.setLocalDescription(answer); await a.setRemoteDescription(answer);
      await ready; return true;
    })()`);
    const local = events.find(e => e.type === 'dc-created' && e.label === 'm4-smoke' && e.detail === 'local');
    assert.ok(local);
    async function runJob(type, config, extra = {}) {
      const id = `smoke-${events.length}`;
      job = { id, type, agent: local.agent, frame: local.frame, config, ...extra };
      const deadline = Date.now() + 12000;
      while (Date.now() < deadline) {
        const result = events.find(e => e.type === 'command-result' && e.commandId === id);
        if (result) { job = null; return { id, result }; }
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      throw new Error(`Timed out waiting for ${type}`);
    }
    const fuzzConfig = { mode: 'text', payload: 'M4 real message', count: 2, intervalMs: 100, maxBytes: 1024, stopOnError: true };
    let run = await runJob('dc-fuzz', fuzzConfig, { channelId: local.channelId });
    assert.equal(run.result.status, 'completed');
    await evaluate('new Promise(resolve => setTimeout(resolve, 100))');
    assert.deepEqual(await evaluate('smokeChannel.received'), ['M4 real message', 'M4 real message']);
    console.log('PASS: M4 sends reach the other end of a real DataChannel');
    run = await runJob('dc-fuzz', { ...fuzzConfig, mode: 'hex', payload: '00 ff 7a', count: 1 }, { channelId: local.channelId });
    assert.equal(run.result.status, 'completed');
    await evaluate('new Promise(resolve => setTimeout(resolve, 100))');
    assert.deepEqual(await evaluate('smokeChannel.received.at(-1)'), [0, 255, 122]);
    console.log('PASS: M4 binary bytes arrive intact');
    cancelAfterSend = true;
    run = await runJob('dc-fuzz', { ...fuzzConfig, count: 10, intervalMs: 500 }, { channelId: local.channelId });
    assert.equal(run.result.status, 'cancelled');
    assert.equal(events.filter(e => e.type === 'fuzz-result' && e.commandId === run.id).length, 1);
    console.log('PASS: M4 cancellation stops subsequent sends');
    cancelAfterSend = false; permit = true;
    await evaluate('smokeChannel.a.close(); smokeChannel.b.close()');
    autoFuzz = { ...fuzzConfig, payload: 'automatic before close', count: 1 };
    await evaluate(`(async () => {
      const a = new RTCPeerConnection(), b = new RTCPeerConnection();
      window.autoSmoke = { a, b, received: [], openedAt: 0 };
      a.onicecandidate = e => { if (e.candidate) b.addIceCandidate(e.candidate).catch(() => {}); };
      b.onicecandidate = e => { if (e.candidate) a.addIceCandidate(e.candidate).catch(() => {}); };
      b.ondatachannel = e => { e.channel.onmessage = message => autoSmoke.received.push({ data: message.data, elapsedMs: performance.now() - autoSmoke.openedAt }); };
      const dc = a.createDataChannel('short-lived-auto');
      const ready = new Promise(resolve => dc.onopen = () => {
        autoSmoke.openedAt = performance.now();
        setTimeout(() => { a.close(); b.close(); }, 700); resolve();
      });
      await a.setLocalDescription(await a.createOffer());
      await b.setRemoteDescription(a.localDescription);
      await b.setLocalDescription(await b.createAnswer());
      await a.setRemoteDescription(b.localDescription); await ready;
    })()`);
    await evaluate('new Promise(resolve => setTimeout(resolve, 850))');
    const automatic = await evaluate('autoSmoke.received');
    assert.equal(automatic.length, 1); assert.equal(automatic[0].data, 'automatic before close');
    assert.ok(automatic[0].elapsedMs < 700);
    assert.ok(events.some(e => e.type === 'command-result' && e.commandId === 'auto-open-smoke' && e.status === 'completed'));
    assert.ok(events.some(e => e.type === 'dc-state' && e.label === 'short-lived-auto' && e.state === 'closed' && e.everOpened));
    job = null;
    console.log('PASS: automatic M4 reaches the remote peer before a 700ms channel closes, without the three-second poll');
    await evaluate('const unopened = new RTCPeerConnection(); unopened.createDataChannel("never-opened"); unopened.close()');
    await evaluate('new Promise(resolve => setTimeout(resolve, 100))');
    assert.ok(events.some(e => e.type === 'dc-state' && e.label === 'never-opened' && e.state === 'closed' && e.everOpened === false));
    assert.ok(events.some(e => e.type === 'pc-state' && e.action === 'close-called' && e.stack));
    console.log('PASS: never-opened channels and page close() calls are diagnosed');
    run = await runJob('ice-probe', { url: `stun:127.0.0.1:${stun.address().port}`, policy: 'all', timeoutSeconds: 5 });
    assert.equal(run.result.status, 'completed');
    assert.ok(events.some(e => e.type === 'ice-probe-candidate' && e.commandId === run.id && e.candidateType === 'srflx'));
    console.log('PASS: M6 gathers a server-reflexive candidate through the local UDP STUN fixture');
  } finally {
    clearTimeout(watchdog);
    socket?.close();
    if (browser && browser.exitCode === null) { const exited = once(browser, 'exit'); browser.kill(); await exited; }
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    stun.close();
    // Profile is intentionally retained under build for inspection after failures.
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
