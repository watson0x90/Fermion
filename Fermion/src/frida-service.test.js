// Unit tests for the pure helpers of the Frida service (node:test). The frida
// require is lazy inside the class, so this file loads headless.
const { test } = require('node:test');
const assert = require('node:assert');
const { routeMessage, parseDeviceSpec } = require('./frida-service.js');

test('routeMessage sends SEND to trace only in trace mode', () => {
  assert.equal(routeMessage('SEND', true), 'trace');
  assert.equal(routeMessage('SEND', false), 'terminal');
  assert.equal(routeMessage('LOG', true), 'terminal');
  assert.equal(routeMessage('STATUS', false), 'terminal');
});

test('parseDeviceSpec splits socket@ specs from plain ids', () => {
  assert.deepEqual(parseDeviceSpec('socket@127.0.0.1:27042'), { kind: 'socket', value: '127.0.0.1:27042' });
  assert.deepEqual(parseDeviceSpec('local'), { kind: 'id', value: 'local' });
});

// Frida 17 reports ppid as a BigInt, which JSON.stringify cannot serialize.
// The old conversion threw and silently returned {} — dropping ppid, user and
// path for every process, so the process tree had no parents.
test('enumerateProcesses keeps ppid/user/path when frida reports ppid as a BigInt', async () => {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  let askedScope;
  svc._frida = {
    getDevice: async () => ({
      enumerateProcesses: async (opts) => {
        askedScope = opts && opts.scope;
        return [
          { pid: 2000, name: 'chrome.exe', parameters: { ppid: 1000n, user: 'me', path: 'C:/chrome.exe', started: '2026-01-01T00:00:00Z', icons: [{ huge: true }] } },
          { pid: 7, name: 'bare', parameters: {} },
        ];
      },
    }),
  };
  const out = await svc.enumerateProcesses();
  assert.equal(out[0].parameters.ppid, 1000);
  assert.equal(typeof out[0].parameters.ppid, 'number');
  assert.equal(out[0].parameters.user, 'me');
  assert.equal(out[0].parameters.path, 'C:/chrome.exe');
  assert.equal('icons' in out[0].parameters, false);
  assert.deepEqual(out[1], { pid: 7, name: 'bare', parameters: {} });
  // The result must survive IPC (structured clone) and JSON.
  assert.doesNotThrow(() => JSON.stringify(out));
  assert.doesNotThrow(() => structuredClone(out));
  // Icons are never used, so they are not requested from the device at all.
  assert.equal(askedScope, 'metadata');
});

test('toPlain: BigInt beyond the safe integer range becomes a string rather than a wrong number', () => {
  const { toPlain } = require('./frida-service.js');
  assert.deepEqual(toPlain({ a: 5n, b: 2n ** 60n, c: 'x' }), { a: 5, b: String(2n ** 60n), c: 'x' });
});

// ---- REPL: evaluate() ----
// A fake session whose scripts record what happens to them.
function fakeSession() {
  const scripts = [];
  return {
    scripts,
    pid: 4821,
    detached: { connect: () => {} },
    detach: () => {},
    createScript: async (src) => {
      const s = {
        src, loaded: false, unloaded: false, logHandler: null, onMessage: null,
        message: { connect: (cb) => { s.onMessage = cb; } },
        load: async () => { s.loaded = true; },
        unload: async () => { s.unloaded = true; },
        exports: { evaluate: async (code) => ({ ok: true, type: 'string', text: 'ran:' + code }) },
      };
      scripts.push(s);
      return s;
    },
  };
}
function attachedService() {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  const session = fakeSession();
  svc._frida = { getDevice: async () => ({ attach: async () => session }) };
  return { svc, session };
}

test('evaluate: refuses when no process is attached', async () => {
  const { FridaService } = require('./frida-service.js');
  await assert.rejects(() => new FridaService().evaluate('1'), /not attached/i);
});

test('evaluate: loads the REPL agent once per session and returns its result', async () => {
  const { svc, session } = attachedService();
  await svc.attach(4821);
  const r1 = await svc.evaluate('Process.id');
  const r2 = await svc.evaluate('2');
  assert.deepEqual(r1, { ok: true, type: 'string', text: 'ran:Process.id' });
  assert.equal(r2.text, 'ran:2');
  assert.equal(session.scripts.length, 1);
  assert.equal(session.scripts[0].loaded, true);
  assert.match(session.scripts[0].src, /rpc\.exports/);
});

test('evaluate: console output and send() from REPL code reach the same events as hook output', async () => {
  const { svc, session } = attachedService();
  await svc.attach(4821);
  await svc.evaluate('1');
  const got = [];
  svc.on('log', (level, text) => got.push(['log', level, text]));
  svc.on('message', (m) => got.push(['message', m]));
  session.scripts[0].logHandler('info', 'from repl');
  session.scripts[0].onMessage({ type: 'send', payload: 1 });
  assert.deepEqual(got, [['log', 'info', 'from repl'], ['message', { type: 'send', payload: 1 }]]);
});

test('evaluate: the user script is separate — loading or reloading it does not replace the REPL agent', async () => {
  const { svc, session } = attachedService();
  await svc.attach(4821);
  await svc.evaluate('1');
  await svc.loadScript('send(1)');
  await svc.reloadScript('send(2)');
  await svc.evaluate('2');
  assert.equal(session.scripts.filter((s) => /rpc\.exports/.test(s.src)).length, 1);
  assert.equal(session.scripts[0].unloaded, false);
  assert.equal(svc.hasScript, true);
});

test('evaluate: hasScript reflects only the user script, not the REPL agent', async () => {
  const { svc } = attachedService();
  await svc.attach(4821);
  await svc.evaluate('1');
  assert.equal(svc.hasScript, false);
});

test('evaluate: a new session gets a fresh agent (after detach + attach)', async () => {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  const sessions = [fakeSession(), fakeSession()];
  let i = 0;
  svc._frida = { getDevice: async () => ({ attach: async () => sessions[i++] }) };
  await svc.attach(1);
  await svc.evaluate('1');
  await svc.detach();
  await assert.rejects(() => svc.evaluate('1'), /not attached/i);
  await svc.attach(2);
  await svc.evaluate('1');
  assert.equal(sessions[0].scripts.length, 1);
  assert.equal(sessions[1].scripts.length, 1);
});

test('evaluate: only accepts a non-empty string of sane size', async () => {
  const { svc } = attachedService();
  await svc.attach(4821);
  await assert.rejects(() => svc.evaluate(42), /string/);
  await assert.rejects(() => svc.evaluate(''), /empty/);
  await assert.rejects(() => svc.evaluate('x'.repeat(300000)), /too long/);
});

test('evaluate: an agent failure (target died mid-call) becomes a not-ok result, not a crash', async () => {
  const { svc, session } = attachedService();
  await svc.attach(4821);
  await svc.evaluate('1');
  session.scripts[0].exports.evaluate = async () => { throw new Error('script is destroyed'); };
  const r = await svc.evaluate('2');
  assert.equal(r.ok, false);
  assert.match(r.error, /script is destroyed/);
});

test('evaluate: two entries racing on a fresh session still load one agent', async () => {
  const { svc, session } = attachedService();
  await svc.attach(4821);
  await Promise.all([svc.evaluate('a'), svc.evaluate('b')]);
  assert.equal(session.scripts.length, 1);
});
