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

// ---- Inspector: read-only target inspection ----
function inspectorService() {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  const calls = [];
  const session = fakeSession();
  const create = session.createScript;
  session.createScript = async (src) => {
    const s = await create(src);
    if (/Inspector agent/.test(src)) {
      const rec = (name) => async (...args) => { calls.push([name, ...args]); return { items: [], total: 0, truncated: false }; };
      s.exports = { modules: rec('modules'), exports: rec('exports'), imports: rec('imports'), threads: rec('threads'),
        backtrace: rec('backtrace'), ranges: rec('ranges'), read: rec('read'), scan: rec('scan'), follow: rec('follow'), unfollow: rec('unfollow'), disassemble: rec('disassemble') };
    }
    return s;
  };
  svc._frida = { getDevice: async () => ({ attach: async () => session }) };
  return { svc, session, calls };
}

test('inspect*: every operation refuses when not attached', async () => {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  for (const call of [() => svc.inspectModules(), () => svc.inspectThreads(), () => svc.inspectRanges('r--'), () => svc.inspectRead('0x1000', 16)]) {
    await assert.rejects(call, /not attached/i);
  }
});

test('inspect*: forwards validated arguments to one inspector agent per session', async () => {
  const { svc, session, calls } = inspectorService();
  await svc.attach(1);
  await svc.inspectModules();
  await svc.inspectExports('kernel32.dll');
  await svc.inspectImports('kernel32.dll');
  await svc.inspectThreads();
  await svc.inspectBacktrace(4242);
  await svc.inspectRanges('r-x');
  await svc.inspectRead('0x7FF000', 256);
  await svc.inspectScan('4d 5a ?? 00', 'rw-');
  assert.deepEqual(calls, [
    ['modules'], ['exports', 'kernel32.dll'], ['imports', 'kernel32.dll'], ['threads'], ['backtrace', 4242],
    ['ranges', 'r-x'], ['read', '0x7ff000', 256], ['scan', '4d 5a ?? 00', 'rw-'],
  ]);
  assert.equal(session.scripts.filter((s) => /Inspector agent/.test(s.src)).length, 1);
});

test('inspect*: the inspector agent is separate from the REPL agent and the user script', async () => {
  const { svc, session } = inspectorService();
  await svc.attach(1);
  await svc.inspectModules();
  await svc.evaluate('1');
  await svc.loadScript('send(1)');
  assert.equal(session.scripts.length, 3);
  assert.equal(svc.hasScript, true);
  assert.equal(session.scripts.some((s) => s.unloaded), false);
});

test('inspect*: malformed arguments are rejected before reaching the target', async () => {
  const { svc, calls } = inspectorService();
  await svc.attach(1);
  const bad = [
    () => svc.inspectExports(''), () => svc.inspectExports(42), () => svc.inspectExports('x'.repeat(2000)),
    () => svc.inspectBacktrace(-1), () => svc.inspectBacktrace(1.5), () => svc.inspectBacktrace('12'),
    () => svc.inspectRanges('rwxx'), () => svc.inspectRanges('abc'), () => svc.inspectRanges(undefined),
    () => svc.inspectRead('1000', 16), () => svc.inspectRead('0xZZ', 16), () => svc.inspectRead('0x' + 'f'.repeat(17), 16),
    () => svc.inspectRead('0x1000', 0), () => svc.inspectRead('0x1000', 4097), () => svc.inspectRead('0x1000', '16'),
    () => svc.inspectScan('', 'r--'), () => svc.inspectScan('zz', 'r--'), () => svc.inspectScan('4d5a', 'r--'),
    () => svc.inspectScan('4d 5a', 'nope'), () => svc.inspectScan('4d '.repeat(3000).trim(), 'r--'),
    () => svc.inspectScan('?? ??', 'r--'),
  ];
  for (const call of bad) await assert.rejects(call, /invalid|empty|too long|must/i);
  assert.deepEqual(calls, []);
});

test('inspect*: an error thrown inside the target is passed on as a rejection with its message', async () => {
  const { svc, session } = inspectorService();
  await svc.attach(1);
  await svc.inspectModules();
  session.scripts[0].exports.exports = async () => { throw new Error('Module not found: nope.dll'); };
  await assert.rejects(() => svc.inspectExports('nope.dll'), /Module not found: nope\.dll/);
});

// ---- review fixes: timeouts, unload, session cleanup, scan pattern ----
test('evaluate: an entry that never finishes times out, and the next entry gets a fresh agent', async () => {
  const { svc, session } = attachedService();
  svc._evalTimeoutMs = 30;
  await svc.attach(4821);
  await svc.evaluate('1');
  session.scripts[0].exports.evaluate = () => new Promise(() => {}); // e.g. new Promise(() => {})
  const r = await svc.evaluate('hang()');
  assert.equal(r.ok, false);
  assert.match(r.error, /timed out/i);
  assert.equal(session.scripts[0].unloaded, true); // the stuck agent is dropped
  const next = await svc.evaluate('2');
  assert.equal(next.ok, true);
  assert.equal(session.scripts.length, 2);
});

test('unload: unloads the user script only, and is reachable through the dispatch', async () => {
  const { createDispatch } = require('./frida-ipc.js');
  const { svc, session } = attachedService();
  await svc.attach(4821);
  await svc.evaluate('1');
  await svc.loadScript('send(1)');
  await createDispatch(svc)('unload');
  const user = session.scripts.find((s) => s.src === 'send(1)');
  assert.equal(user.unloaded, true);
  assert.equal(svc.hasScript, false);
  assert.equal(session.scripts[0].unloaded, false); // the REPL agent stays
  await createDispatch(svc)('unload'); // nothing loaded: a no-op, not an error
});

test('detach: the service forgets the script and pid, so getState is truthful afterwards', async () => {
  const { svc } = attachedService();
  await svc.attach(4821);
  await svc.loadScript('send(1)');
  await svc.detach();
  assert.deepEqual(svc.getState(), { deviceId: 'local', isAttached: false, hasScript: false, currentPid: null });
});

test('an old session reporting "detached" late does not detach the new session', async () => {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  const handlers = [];
  const mk = () => { const s = fakeSession(); s.detached = { connect: (cb) => handlers.push(cb) }; return s; };
  const sessions = [mk(), mk()];
  let i = 0;
  svc._frida = { getDevice: async () => ({ attach: async () => sessions[i++] }) };
  const events = [];
  svc.on('detached', (reason) => events.push(reason));

  await svc.attach(1);
  await svc.detach();          // user detaches; frida will report it later
  await svc.attach(2);
  await svc.loadScript('send(1)');
  handlers[0]('application-requested'); // the OLD session's signal arrives now
  assert.equal(svc.isAttached, true);
  assert.equal(svc.hasScript, true);
  assert.deepEqual(events, []);

  handlers[1]('process-terminated');    // the current session really ends
  assert.equal(svc.isAttached, false);
  assert.equal(svc.hasScript, false);
  assert.equal(svc.currentPid, null);
  assert.deepEqual(events, ['process-terminated']);
});

test('inspectScan: a pattern needs at least two concrete bytes (a 1-byte scan matches nearly everything)', async () => {
  const { svc, calls } = inspectorService();
  await svc.attach(1);
  for (const p of ['00', '4d', '4d ??', '?? 4d ??', '4? 5?']) await assert.rejects(() => svc.inspectScan(p, 'r--'), /two concrete bytes/i);
  await svc.inspectScan('4d ?? 5a', 'r--');
  assert.deepEqual(calls, [['scan', '4d ?? 5a', 'r--']]);
});

test('loadScript / reloadScript without a session say "not attached" instead of a null error', async () => {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  await assert.rejects(() => svc.loadScript('send(1)'), /not attached/i);
  await assert.rejects(() => svc.reloadScript('send(1)'), /not attached/i);
});

// ---- roadmap: cancel a running REPL entry, follow a thread ----
test('cancelEvaluate: a running entry ends at once as "cancelled", and the REPL is restarted', async () => {
  const { svc, session } = attachedService();
  await svc.attach(4821);
  await svc.evaluate('1');
  session.scripts[0].exports.evaluate = () => new Promise(() => {}); // never finishes
  const running = svc.evaluate('while (true) {}');
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(await svc.cancelEvaluate(), true);
  const r = await running;
  assert.equal(r.ok, false);
  assert.equal(r.cancelled, true);
  assert.match(r.error, /cancelled/i);
  assert.equal(session.scripts[0].unloaded, true);
  assert.equal((await svc.evaluate('2')).ok, true);     // a fresh agent
  assert.equal(session.scripts.length, 2);
});

test('cancelEvaluate with nothing running does nothing', async () => {
  const { svc } = attachedService();
  assert.equal(await svc.cancelEvaluate(), false);
  await svc.attach(4821);
  await svc.evaluate('1');
  assert.equal(await svc.cancelEvaluate(), false);
  assert.equal((await svc.evaluate('2')).ok, true);
});

test('inspectFollow / inspectUnfollow: the thread id is validated; unfollow takes no arguments', async () => {
  const { svc, calls } = inspectorService();
  await svc.attach(1);
  await svc.inspectFollow(4242);
  await svc.inspectUnfollow('ignored', { also: 'ignored' });
  assert.deepEqual(calls, [['follow', 4242, { mode: 'all', module: '' }], ['unfollow']]);
  for (const bad of [-1, 1.5, '12', null, undefined, {}]) await assert.rejects(() => svc.inspectFollow(bad), /invalid thread id/i);
  assert.equal(calls.length, 2);
});

// ---- follow scope ----
test('inspectFollow: the scope is validated and passed on as a clean object', async () => {
  const { svc, calls } = inspectorService();
  await svc.attach(1);
  await svc.inspectFollow(7, { mode: 'app' });
  await svc.inspectFollow(7, { mode: 'module', module: 'target.exe', extra: 'dropped', __proto__: { polluted: true } });
  await svc.inspectFollow(7, { mode: 'all', module: 'ignored.dll' });
  assert.deepEqual(calls, [
    ['follow', 7, { mode: 'app', module: '' }],
    ['follow', 7, { mode: 'module', module: 'target.exe' }],
    ['follow', 7, { mode: 'all', module: '' }],
  ]);
  for (const c of calls) assert.deepEqual(Object.keys(c[2]), ['mode', 'module']);
  const bad = ['app', 5, [], { mode: 'everything' }, { mode: 'module' }, { mode: 'module', module: '' }, { mode: 'module', module: 7 }, { mode: 'module', module: 'x'.repeat(2000) }, { module: 'a.dll' }];
  for (const scope of bad) await assert.rejects(() => svc.inspectFollow(7, scope), /scope|module name/i, JSON.stringify(scope));
  assert.equal(calls.length, 3);
});

// Stalker exclusions cannot be undone inside a loaded agent, so a follow with
// a different scope gets a fresh copy of the agent.
function rescopeService() {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  const session = fakeSession();
  const create = session.createScript;
  const agents = [];
  session.createScript = async (src) => {
    const s = await create(src);
    if (/Inspector agent/.test(src)) {
      const n = agents.length;
      s.calls = [];
      s.exports = {
        follow: async (id, scope) => { s.calls.push(scope.mode); if (s.rescope) throw new Error('FERMION_RESCOPE'); return { following: true, threadId: id, agent: n }; },
        threads: async () => { if (s.unloaded) throw new Error('Script is destroyed'); if (s.gate) await s.gate; if (s.unloaded) throw new Error('Script is destroyed'); return { items: [], total: 0, truncated: false, agent: n }; },
      };
      agents.push(s);
    }
    return s;
  };
  svc._frida = { getDevice: async () => ({ attach: async () => session }) };
  return { svc, agents };
}

test('inspectFollow: an agent that asks to be replaced is unloaded and the follow retried on a fresh one', async () => {
  const { svc, agents } = rescopeService();
  await svc.attach(1);
  assert.equal((await svc.inspectFollow(7, { mode: 'app' })).agent, 0);
  agents[0].rescope = true;
  const r = await svc.inspectFollow(7, { mode: 'all' });
  assert.equal(r.agent, 1);
  assert.equal(agents.length, 2);
  assert.equal(agents[0].unloaded, true);
  assert.equal(agents[1].loaded, true);
  assert.deepEqual(agents[1].calls, ['all']);
  // Later inspector calls use the fresh agent.
  assert.equal((await svc.inspectThreads()).agent, 1);
});

test('inspectFollow: a fresh agent that still refuses is an error, not a loop', async () => {
  const { svc, agents } = rescopeService();
  await svc.attach(1);
  await svc.inspectFollow(7, { mode: 'app' });
  agents[0].rescope = true;
  const create = svc._session.createScript;
  svc._session.createScript = async (src) => { const s = await create(src); s.rescope = true; return s; };
  await assert.rejects(() => svc.inspectFollow(7, { mode: 'all' }), /FERMION_RESCOPE/);
  assert.equal(agents.length, 2);
});

test('an inspector call in flight while the agent is replaced is answered by the new agent', async () => {
  const { svc, agents } = rescopeService();
  await svc.attach(1);
  await svc.inspectFollow(7, { mode: 'app' });
  let release;
  agents[0].gate = new Promise((r) => { release = r; });
  const pending = svc.inspectThreads();           // waits inside the old agent
  agents[0].rescope = true;
  await svc.inspectFollow(7, { mode: 'all' });      // replaces the agent
  release();
  assert.equal((await pending).agent, 1);
});

test('an inspector error is not retried when the agent was not replaced', async () => {
  const { svc, agents } = rescopeService();
  await svc.attach(1);
  await svc.inspectFollow(7, { mode: 'app' });
  agents[0].exports.threads = async () => { throw new Error('boom'); };
  await assert.rejects(() => svc.inspectThreads(), /boom/);
  assert.equal(agents.length, 1);
});

// ---- Hooks tab ----
function hooksService() {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  const calls = [];
  const session = fakeSession();
  const create = session.createScript;
  session.createScript = async (src) => {
    const s = await create(src);
    if (/Fermion Hooks agent/.test(src)) {
      const rec = (name) => async (...args) => { calls.push([name, ...args]); return { ok: name }; };
      s.exports = { search: rec('search'), add: rec('add'), update: rec('update'), enable: rec('enable'), remove: rec('remove'), symbolicate: rec('symbolicate') };
    }
    return s;
  };
  svc._frida = { getDevice: async () => ({ attach: async () => session }) };
  return { svc, session, calls };
}
const HOOK = { id: 'hk-1', module: 'kernel32.dll', offset: 4096, address: '0x7FF010', code: '({ onEnter(log) { log(1); } })', enabled: true, backtrace: false };

test('hook*: every operation refuses when not attached', async () => {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  for (const call of [() => svc.hookSearch('exports', 'open'), () => svc.hookAdd(HOOK), () => svc.hookUpdate('hk-1', { code: 'x' }), () => svc.hookEnable('hk-1', true), () => svc.hookRemove('hk-1'), () => svc.hookSymbolicate(['0x10'])]) {
    await assert.rejects(call, /not attached/i);
  }
});

test('hook operations reach the hooks agent with checked, rebuilt arguments', async () => {
  const { svc, calls, session } = hooksService();
  await svc.attach(1);
  await svc.hookSearch('symbols', '  kernel32!Create*  ');
  await svc.hookAdd({ ...HOOK, extra: 'dropped' });
  await svc.hookAdd({ id: 'hk-2', module: '', offset: null, address: '0x9000', code: 'function () {}' });
  await svc.hookUpdate('hk-1', { code: '({})', backtrace: true, other: 1 });
  await svc.hookUpdate('hk-1', { backtrace: false });
  await svc.hookEnable('hk-1', false);
  await svc.hookRemove('hk-1');
  await svc.hookSymbolicate(['0x7FF010', '0x1']);
  assert.deepEqual(calls, [
    ['search', 'symbols', 'kernel32!Create*'],
    ['add', { id: 'hk-1', module: 'kernel32.dll', offset: 4096, address: '0x7ff010', code: HOOK.code, enabled: true, backtrace: false }],
    ['add', { id: 'hk-2', module: '', offset: null, address: '0x9000', code: 'function () {}', enabled: true, backtrace: true }],
    ['update', 'hk-1', { code: '({})', backtrace: true }],
    ['update', 'hk-1', { backtrace: false }],
    ['enable', 'hk-1', false],
    ['remove', 'hk-1'],
    ['symbolicate', ['0x7ff010', '0x1']],
  ]);
  // One hooks agent for the session, separate from the user's script.
  assert.equal(session.scripts.filter((s) => /Fermion Hooks agent/.test(s.src)).length, 1);
});

test('hook arguments are validated before anything reaches the target', async () => {
  const { svc, calls } = hooksService();
  await svc.attach(1);
  const bad = [
    [() => svc.hookSearch('everything', 'x'), /kind/],
    [() => svc.hookSearch('exports', ''), /query/],
    [() => svc.hookSearch('exports', '   '), /query/],
    [() => svc.hookSearch('exports', 'x'.repeat(300)), /query/],
    [() => svc.hookSearch('exports', 7), /query/],
    [() => svc.hookAdd(null), /hook/],
    [() => svc.hookAdd('x'), /hook/],
    [() => svc.hookAdd({ ...HOOK, id: '' }), /hook id/],
    [() => svc.hookAdd({ ...HOOK, id: '../x' }), /hook id/],
    [() => svc.hookAdd({ ...HOOK, id: 'a'.repeat(80) }), /hook id/],
    [() => svc.hookAdd({ ...HOOK, code: '' }), /handler/],
    [() => svc.hookAdd({ ...HOOK, code: 5 }), /handler/],
    [() => svc.hookAdd({ ...HOOK, code: 'x'.repeat(70000) }), /handler/],
    [() => svc.hookAdd({ ...HOOK, offset: -1 }), /offset/],
    [() => svc.hookAdd({ ...HOOK, offset: 1.5 }), /offset/],
    [() => svc.hookAdd({ ...HOOK, offset: null }), /offset/],
    [() => svc.hookAdd({ ...HOOK, module: 9 }), /module/],
    [() => svc.hookAdd({ ...HOOK, module: '', offset: null, address: 'nope' }), /address/],
    [() => svc.hookUpdate('hk-1', null), /nothing to change/],
    [() => svc.hookUpdate('hk-1', {}), /nothing to change/],
    [() => svc.hookUpdate('hk-1', { code: '' }), /handler/],
    [() => svc.hookUpdate('bad id', { code: 'x' }), /hook id/],
    [() => svc.hookEnable('hk-1', 'yes'), /true or false/],
    [() => svc.hookRemove(5), /hook id/],
    [() => svc.hookSymbolicate('0x10'), /addresses/],
    [() => svc.hookSymbolicate([]), /addresses/],
    [() => svc.hookSymbolicate(Array(65).fill('0x10')), /addresses/],
    [() => svc.hookSymbolicate(['0x10', 'zz']), /address/],
  ];
  for (const [call, re] of bad) await assert.rejects(call, re, String(call));
  assert.equal(calls.length, 0);
});

test('inspectDisassemble: address and count are validated; the count defaults to 60', async () => {
  const { svc, calls } = inspectorService();
  await svc.attach(1);
  await svc.inspectDisassemble('0x7FF010', 40);
  await svc.inspectDisassemble('0x10');
  assert.deepEqual(calls, [['disassemble', '0x7ff010', 40], ['disassemble', '0x10', 60]]);
  for (const bad of [['nope', 5], ['0x10', 0], ['0x10', 201], ['0x10', 1.5], ['0x10', '5'], [16, 5]]) {
    await assert.rejects(() => svc.inspectDisassemble(...bad), /invalid (address|instruction count)/i, JSON.stringify(bad));
  }
  assert.equal(calls.length, 2);
});

// ---- spawn options ----
function spawnService() {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  const spawned = [];
  const session = fakeSession();
  svc._frida = { getDevice: async () => ({
    spawn: async (program, options) => { spawned.push(options === undefined ? [program] : [program, options]); return 4242; },
    attach: async () => session,
    resume: async () => {},
  }) };
  return { svc, spawned };
}

test('splitArgs: spaces separate arguments; quotes keep an argument with spaces together; backslashes are left alone', () => {
  const { splitArgs } = require('./frida-service.js');
  assert.deepEqual(splitArgs('-a -b'), ['-a', '-b']);
  assert.deepEqual(splitArgs('  --file   "C:\\Program Files\\x y.txt"  -v '), ['--file', 'C:\\Program Files\\x y.txt', '-v']);
  assert.deepEqual(splitArgs("--name='two words' x"), ['--name=two words', 'x']);
  assert.deepEqual(splitArgs('""'), ['']);
  assert.deepEqual(splitArgs('a "unterminated b'), ['a', 'unterminated b']);
  assert.deepEqual(splitArgs(''), []);
  assert.deepEqual(splitArgs(undefined), []);
});

test('spawn: with no arguments or options the program is spawned as before', async () => {
  const { svc, spawned } = spawnService();
  assert.deepEqual(await svc.spawn('C:/app.exe', ''), { pid: 4242 });
  await svc.spawn('C:/app.exe');
  assert.deepEqual(spawned, [['C:/app.exe'], ['C:/app.exe']]);
});

test('spawn: arguments become argv after the program; environment and working directory are passed on', async () => {
  const { svc, spawned } = spawnService();
  await svc.spawn('C:/app.exe', '--in "a b.txt" -v');
  await svc.spawn('C:/app.exe', '', { env: { DEBUG: '1', PATH_EXTRA: 'C:\\x y' }, cwd: 'C:\\work dir', extra: 'dropped' });
  await svc.spawn('C:/app.exe', '-q', { env: {}, cwd: '' });
  assert.deepEqual(spawned, [
    ['C:/app.exe', { argv: ['C:/app.exe', '--in', 'a b.txt', '-v'] }],
    ['C:/app.exe', { env: { DEBUG: '1', PATH_EXTRA: 'C:\\x y' }, cwd: 'C:\\work dir' }],
    ['C:/app.exe', { argv: ['C:/app.exe', '-q'] }],
  ]);
});

test('spawn: the program, arguments and options are validated before anything is started', async () => {
  const { svc, spawned } = spawnService();
  const bad = [
    [['', ''], /program/],
    [[5, ''], /program/],
    [['x'.repeat(5000), ''], /program/],
    [['a.exe', 7], /arguments/],
    [['a.exe', 'x'.repeat(40000)], /arguments/],
    [['a.exe', '', 'env'], /spawn options/],
    [['a.exe', '', []], /spawn options/],
    [['a.exe', '', { env: 'A=1' }], /environment/],
    [['a.exe', '', { env: ['A=1'] }], /environment/],
    [['a.exe', '', { env: { '': '1' } }], /environment variable name/],
    [['a.exe', '', { env: { 'A=B': '1' } }], /environment variable name/],
    [['a.exe', '', { env: { A: 1 } }], /environment variable A/],
    [['a.exe', '', { env: { A: 'x\u0000y' } }], /environment variable A/],
    [['a.exe', '', { env: Object.fromEntries(Array.from({ length: 300 }, (_, i) => ['V' + i, '1'])) }], /too many environment/],
    [['a.exe', '', { cwd: 9 }], /working directory/],
    [['a.exe', '', { cwd: 'x'.repeat(5000) }], /working directory/],
  ];
  for (const [args, re] of bad) await assert.rejects(() => svc.spawn(...args), re, JSON.stringify(args).slice(0, 80));
  assert.equal(spawned.length, 0);
});
