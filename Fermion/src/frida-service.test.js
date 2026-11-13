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
  const session = {
    scripts,
    pid: 4821,
    detached: { connect: (cb) => { session.ended = cb; } },
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
  return session;
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

// ---- catching child processes ----
function childService() {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  const log = [];
  const handlers = new Set();
  const sessions = [];
  const makeSession = (pid) => {
    const s = fakeSession();
    s.pid = pid;
    s.gating = false;
    s.enableChildGating = async () => { s.gating = true; log.push(['enableChildGating', pid]); };
    s.disableChildGating = async () => { s.gating = false; log.push(['disableChildGating', pid]); };
    s.detach = () => { log.push(['detach', pid]); };
    sessions.push(s);
    return s;
  };
  const device = {
    childAdded: { connect: (cb) => handlers.add(cb), disconnect: (cb) => handlers.delete(cb) },
    attach: async (pid) => { if (device.attachFails) throw new Error('unable to attach'); log.push(['attach', pid]); return makeSession(pid); },
    resume: async (pid) => { log.push(['resume', pid]); },
  };
  svc._frida = { getDevice: async () => device };
  const events = [];
  svc.on('child', (c) => events.push(c));
  const report = (child) => { for (const cb of [...handlers]) cb(child); };
  const child = (pid, extra = {}) => ({ pid, parentPid: 100, origin: 'spawn', path: 'C:\\app\\helper.exe', argv: ['C:\\app\\helper.exe', '--type=renderer'], identifier: null, envp: ['SECRET=1'], ...extra });
  return { svc, device, log, handlers, sessions, events, report, child };
}

test('setChildGating: needs a session and a true/false; switching on gates the session and listens for children', async () => {
  const t = childService();
  await assert.rejects(() => t.svc.setChildGating(true), /not attached/i);
  await t.svc.attach(100);
  await assert.rejects(() => t.svc.setChildGating('yes'), /true or false/);
  assert.equal(await t.svc.setChildGating(true), true);
  assert.equal(t.handlers.size, 1);
  assert.deepEqual(t.log.slice(-1), [['enableChildGating', 100]]);
  // Asking again changes nothing.
  assert.equal(await t.svc.setChildGating(true), true);
  assert.equal(t.handlers.size, 1);
  assert.equal(t.log.filter((l) => l[0] === 'enableChildGating').length, 1);
});

test('a child of the attached process is announced with its pid, path and arguments, and nothing else', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.report(t.child(200));
  assert.deepEqual(t.events, [{ pid: 200, parentPid: 100, path: 'C:\\app\\helper.exe', argv: ['C:\\app\\helper.exe', '--type=renderer'] }]);
});

test('a child of some other process is not ours: it is not announced and not touched', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.report(t.child(300, { parentPid: 999 }));
  assert.deepEqual(t.events, []);
  await assert.rejects(() => t.svc.resolveChild(300, 'resume'), /no caught child/i);
  assert.equal(t.log.filter((l) => l[0] === 'resume').length, 0);
});

test('resolveChild resume lets a caught child run; only a caught pid and a known action are accepted', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.report(t.child(200));
  await assert.rejects(() => t.svc.resolveChild(201, 'resume'), /no caught child/i);
  await assert.rejects(() => t.svc.resolveChild('200', 'resume'), /invalid child pid/i);
  await assert.rejects(() => t.svc.resolveChild(200, 'kill'), /attach or resume/);
  assert.deepEqual(await t.svc.resolveChild(200, 'resume'), { pid: 200, action: 'resume' });
  assert.deepEqual(t.log.slice(-1), [['resume', 200]]);
  await assert.rejects(() => t.svc.resolveChild(200, 'resume'), /no caught child/i); // only once
});

test('resolveChild attach moves the session to the child, still suspended; the parent is kept until the child is resumed', async () => {
  const t = childService();
  const detached = [];
  t.svc.on('detached', (r) => detached.push(r));
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.report(t.child(200));
  t.report(t.child(201));
  assert.deepEqual(await t.svc.resolveChild(200, 'attach'), { pid: 200, action: 'attach' });
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(t.svc.getState().currentPid, '200');
  assert.equal(t.svc.getState().isAttached, true);
  const after = () => t.log.slice(t.log.findIndex((l) => l[0] === 'attach' && l[1] === 200));
  // The other caught child runs; the one we moved to does not.
  assert.deepEqual(after().filter((l) => l[0] === 'resume'), [['resume', 201]]);
  // Leaving the parent now would set the child running (Frida releases a
  // caught child when its parent is detached or stops catching): not yet.
  assert.equal(after().some((l) => l[0] === 'detach' || l[0] === 'disableChildGating'), false);
  assert.equal(t.handlers.size, 1);
  // The caller resumes the child once its script and hooks are in; then the parent is let go.
  await t.svc.resume(200);
  await new Promise((r) => setTimeout(r, 5));
  const tail = after();
  const at = (name, pid) => tail.findIndex((l) => l[0] === name && l[1] === pid);
  assert.ok(at('resume', 200) >= 0);
  assert.ok(at('detach', 100) > at('resume', 200), JSON.stringify(tail));
  assert.ok(at('disableChildGating', 100) > at('resume', 200));
  assert.equal(t.handlers.size, 0);
  assert.deepEqual(detached, []); // a move is not an ended session
  assert.equal(t.svc.getState().currentPid, '200');
});

test('while the parent is held during a move, a new child of it is let run, not announced', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.report(t.child(200));
  await t.svc.resolveChild(200, 'attach');
  t.events.length = 0;
  t.report(t.child(300)); // parentPid 100: the held parent
  await new Promise((r) => setTimeout(r, 5));
  assert.deepEqual(t.events, []);
  assert.deepEqual(t.log.slice(-1), [['resume', 300]]);
});

test('catching can be switched on for the child before it is resumed, and stays on after the parent is let go', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.report(t.child(200));
  await t.svc.resolveChild(200, 'attach');
  assert.equal(await t.svc.setChildGating(true), true);
  assert.ok(t.log.some((l) => l[0] === 'enableChildGating' && l[1] === 200));
  assert.equal(t.handlers.size, 1);
  await t.svc.resume(200);
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(t.handlers.size, 1); // still listening, for the child's own children
  t.events.length = 0;
  t.report(t.child(400, { parentPid: 200 }));
  assert.deepEqual(t.events.map((e) => e.pid), [400]);
  // The old parent's children are nobody's business now.
  t.report(t.child(401, { parentPid: 100 }));
  assert.deepEqual(t.events.map((e) => e.pid), [400]);
});

test('a move that is abandoned (detach, or the child dies) lets the parent go, so nothing stays held', async () => {
  for (const end of ['detach', 'child-ended', 'parent-ended']) {
    const t = childService();
    await t.svc.attach(100);
    await t.svc.setChildGating(true);
    t.report(t.child(200));
    await t.svc.resolveChild(200, 'attach');
    if (end === 'detach') await t.svc.detach();
    if (end === 'child-ended') t.sessions[1].ended('process-terminated');
    if (end === 'parent-ended') t.sessions[0].ended('process-terminated');
    await new Promise((r) => setTimeout(r, 5));
    assert.equal(t.handlers.size, 0, end);
    if (end !== 'parent-ended') assert.ok(t.log.some((l) => l[0] === 'detach' && l[1] === 100), end + ': the parent was not let go');
    if (end === 'parent-ended') assert.equal(t.svc.getState().currentPid, '200', end); // the session on the child carries on
  }
});

test('resolveChild attach: if the child cannot be attached it is let go and the session stays where it was', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.report(t.child(200));
  t.device.attachFails = true;
  await assert.rejects(() => t.svc.resolveChild(200, 'attach'), /unable to attach/);
  assert.deepEqual(t.log.slice(-1), [['resume', 200]]);
  assert.equal(t.svc.getState().currentPid, '100');
});

// Nothing may be left frozen.
test('switching catching off, detaching, or the session ending lets every caught child run', async () => {
  for (const end of ['off', 'detach', 'ended']) {
    const t = childService();
    await t.svc.attach(100);
    await t.svc.setChildGating(true);
    t.report(t.child(200));
    t.report(t.child(201));
    if (end === 'off') assert.equal(await t.svc.setChildGating(false), false);
    if (end === 'detach') await t.svc.detach();
    if (end === 'ended') t.sessions[0].ended('process-terminated');
    await new Promise((r) => setTimeout(r, 5));
    assert.deepEqual(t.log.filter((l) => l[0] === 'resume').map((l) => l[1]).sort(), [200, 201], end);
    assert.equal(t.handlers.size, 0, end);
    await assert.rejects(() => t.svc.resolveChild(200, 'resume'), /no caught child|not attached/i, end);
  }
});

test('too many caught children at once: the extra ones are let go instead of piling up', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  for (let i = 0; i < 40; i++) t.report(t.child(1000 + i));
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(t.events.length, 32);
  assert.equal(t.log.filter((l) => l[0] === 'resume').length, 8);
});

test('a caught child with strange data is announced in a bounded, plain form', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.report(t.child(200, { path: null, argv: Array.from({ length: 500 }, () => 'x'.repeat(5000)) }));
  t.report(t.child(201, { argv: 'not a list' }));
  assert.equal(t.events[0].path, '');
  assert.equal(t.events[0].argv.length, 64);
  assert.equal(t.events[0].argv[0].length, 1024);
  assert.deepEqual(t.events[1].argv, []);
});

// ---- scripts that import packages ----
test('loadScript: without a preparer the script is loaded as written', async () => {
  const { svc, session } = attachedService();
  await svc.attach(1);
  assert.deepEqual(await svc.loadScript('send(1);'), { compiled: false, typescript: false });
  assert.equal(session.scripts[0].src, 'send(1);');
});

test('loadScript / reloadScript load what the preparer returns and say whether it was compiled', async () => {
  const { svc, session } = attachedService();
  svc.setScriptPreparer(async (src) => (src.includes('import') ? { code: 'BUNDLE:' + src, compiled: true } : { code: src, compiled: false }));
  await svc.attach(1);
  assert.deepEqual(await svc.loadScript('import a from "a";'), { compiled: true, typescript: false });
  assert.equal(session.scripts[0].src, 'BUNDLE:import a from "a";');
  assert.deepEqual(await svc.reloadScript('send(2);'), { compiled: false, typescript: false });
  assert.equal(session.scripts[1].src, 'send(2);');
  assert.equal(session.scripts[0].unloaded, true);
});

test('reloadScript: a script that does not compile leaves the running one in place', async () => {
  const { svc, session } = attachedService();
  svc.setScriptPreparer(async (src) => { if (src.includes('broken')) throw new Error('The script did not compile:\nscript.js:1:1: nope'); return { code: src, compiled: false }; });
  await svc.attach(1);
  await svc.loadScript('send(1);');
  await assert.rejects(() => svc.reloadScript('broken'), /did not compile/);
  assert.equal(session.scripts.length, 1);
  assert.equal(session.scripts[0].unloaded, false);
  await assert.rejects(() => svc.loadScript(5), /must be text/);
});

test('reloadScript without a session says so before compiling anything', async () => {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  let compiled = 0;
  svc.setScriptPreparer(async (src) => { compiled++; return { code: src, compiled: true }; });
  await assert.rejects(() => svc.reloadScript('import a from "a";'), /not attached/i);
  assert.equal(compiled, 0);
});

// ---- a process that replaces itself (exec) ----
// On Linux and macOS a new program starts as a fork (a copy of its parent)
// that then execs: the pid stays, the session on it ends with
// 'process-replaced', and with catching on Frida holds the new program and
// reports it as a child whose pid is its own parent's.
const execOf = (t, pid) => t.child(pid, { parentPid: pid, origin: 'exec', path: '/bin/cat', argv: ['/bin/cat', '/etc/hosts'] });
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

test('with catching on, a process that replaces itself is announced as its replacement and stays suspended', async () => {
  const t = childService();
  const ended = [];
  t.svc.on('detached', (r) => ended.push(r));
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.sessions[0].ended('process-replaced');
  assert.deepEqual(ended, ['process-replaced']);
  assert.equal(t.svc.getState().isAttached, false);
  assert.equal(t.handlers.size, 1); // still listening, for the replacement
  t.report(execOf(t, 100));
  await tick();
  assert.deepEqual(t.events, [{ pid: 100, parentPid: 100, path: '/bin/cat', argv: ['/bin/cat', '/etc/hosts'], replaced: true }]);
  assert.ok(!t.log.some((l) => l[0] === 'resume'), 'the new program was let run');
});

test('the replacement is announced the same when Frida reports it before the session ends', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.report(execOf(t, 100));
  assert.deepEqual(t.events, []);
  t.sessions[0].ended('process-replaced');
  await tick();
  assert.deepEqual(t.events.map((e) => [e.pid, e.replaced]), [[100, true]]);
  assert.ok(!t.log.some((l) => l[0] === 'resume'));
});

test('resolveChild attach on a replacement starts a session on it with nothing held; catching can be switched on again', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.sessions[0].ended('process-replaced');
  t.report(execOf(t, 100));
  assert.deepEqual(await t.svc.resolveChild(100, 'attach'), { pid: 100, action: 'attach' });
  assert.equal(t.svc.getState().currentPid, '100');
  assert.equal(t.svc.getState().isAttached, true);
  assert.equal(t.handlers.size, 0);
  assert.ok(!t.log.some((l) => l[0] === 'resume'), 'it ran before its script was in');
  assert.equal(await t.svc.setChildGating(true), true);
  assert.equal(t.handlers.size, 1);
  await t.svc.resume(100);
  assert.deepEqual(t.log.slice(-1), [['resume', 100]]);
  await assert.rejects(() => t.svc.resolveChild(100, 'attach'), /no caught child/i);
});

test('a replacement can be let run instead, and one that cannot be attached is let run', async () => {
  for (const how of ['resume', 'attach-fails']) {
    const t = childService();
    await t.svc.attach(100);
    await t.svc.setChildGating(true);
    t.sessions[0].ended('process-replaced');
    t.report(execOf(t, 100));
    if (how === 'resume') await t.svc.resolveChild(100, 'resume');
    else { t.device.attachFails = true; await assert.rejects(() => t.svc.resolveChild(100, 'attach'), /unable to attach/); }
    assert.ok(t.log.some((l) => l[0] === 'resume' && l[1] === 100), how);
    assert.equal(t.handlers.size, 0, how);
    assert.equal(t.svc.getState().isAttached, false, how);
  }
});

test('without catching, a process that replaces itself just ends the session', async () => {
  const t = childService();
  await t.svc.attach(100);
  t.sessions[0].ended('process-replaced');
  assert.equal(t.handlers.size, 0);
  await assert.rejects(() => t.svc.resolveChild(100, 'attach'), /not attached/i);
});

test('waiting for a replacement gives up: after a while nothing is listened for', async () => {
  const t = childService();
  t.svc._replacedWaitMs = 10;
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.sessions[0].ended('process-replaced');
  assert.equal(t.handlers.size, 1);
  await tick(40);
  assert.equal(t.handlers.size, 0);
});

test('a replacement nobody acted on is let run when another session starts', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.sessions[0].ended('process-replaced');
  t.report(execOf(t, 100));
  await t.svc.attach(500);
  await tick();
  assert.ok(t.log.some((l) => l[0] === 'resume' && l[1] === 100));
  assert.equal(t.handlers.size, 0);
});

test('an exec that is not the attached process is let run, not announced', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.report(execOf(t, 777));
  await tick();
  assert.deepEqual(t.events, []);
  assert.deepEqual(t.log.slice(-1), [['resume', 777]]);
});

test('any other end of the session lets a replacement that was reported early run', async () => {
  const t = childService();
  await t.svc.attach(100);
  await t.svc.setChildGating(true);
  t.report(execOf(t, 100));
  await t.svc.detach();
  await tick();
  assert.ok(t.log.some((l) => l[0] === 'resume' && l[1] === 100));
  assert.deepEqual(t.events, []);
});

// ---- TypeScript scripts ----
test('loadScript / reloadScript pass the script language to the preparer and report it back', async () => {
  const { svc, session } = attachedService();
  const seen = [];
  svc.setScriptPreparer(async (src, options) => { seen.push(options); return options.typescript ? { code: 'JS:' + src, compiled: true, typescript: true } : { code: src, compiled: false }; });
  await svc.attach(1);
  assert.deepEqual(await svc.loadScript('const n: number = 1;', { typescript: true }), { compiled: true, typescript: true });
  assert.equal(session.scripts[0].src, 'JS:const n: number = 1;');
  assert.deepEqual(await svc.reloadScript('send(2);'), { compiled: false, typescript: false });
  assert.deepEqual(await svc.reloadScript('let s: string;', { typescript: true }), { compiled: true, typescript: true });
  assert.deepEqual(seen, [{ typescript: true }, { typescript: false }, { typescript: true }]);
});

test('script options are validated: only { typescript: true/false }', async () => {
  const { svc } = attachedService();
  svc.setScriptPreparer(async (src) => ({ code: src, compiled: false }));
  await svc.attach(1);
  for (const bad of ['ts', 5, [], { typescript: 'yes' }, { typescript: 1 }]) {
    await assert.rejects(() => svc.loadScript('send(1);', bad), /script options/i);
    await assert.rejects(() => svc.reloadScript('send(1);', bad), /script options/i);
  }
  assert.deepEqual(await svc.loadScript('send(1);', {}), { compiled: false, typescript: false });
  assert.deepEqual(await svc.loadScript('send(1);', null), { compiled: false, typescript: false });
});

test('without a preparer a TypeScript script is refused, not loaded as it is', async () => {
  const { svc, session } = attachedService();
  await svc.attach(1);
  await assert.rejects(() => svc.loadScript('let s: string;', { typescript: true }), /cannot be compiled/i);
  assert.equal(session.scripts.length, 0);
});

// ---- writing memory ----
test('inspectWrite validates the address and bytes in main, and passes clean values to the agent', async () => {
  const { svc, session } = attachedService();
  await svc.attach(1);
  for (const bad of [[5, 'aa'], ['1000', 'aa'], ['0xzz', 'aa'], ['0x1000', ''], ['0x1000', 'a'], ['0x1000', 'aa bb'], ['0x1000', 'zz'], ['0x1000', 5], ['0x1000', 'aa'.repeat(4097)]]) {
    await assert.rejects(() => svc.inspectWrite(bad[0], bad[1]), /invalid address|hex bytes/);
  }
  assert.equal(session.scripts.length, 0); // nothing reached the target
  const calls = [];
  svc._getAgent = async () => ({ exports: { write: async (...a) => { calls.push(a); return { address: a[0], size: 2, original: '0000', written: a[1], protection: 'rw-' }; } } });
  assert.deepEqual(await svc.inspectWrite('0x7FF010', 'DEad'), { address: '0x7ff010', size: 2, original: '0000', written: 'dead', protection: 'rw-' });
  assert.deepEqual(calls, [['0x7ff010', 'dead']]);
});

test('inspectWrite is on the allow-list the window can call', () => {
  const { INVOKE_METHODS } = require('./frida-ipc.js');
  assert.ok(INVOKE_METHODS.has('inspectWrite'));
});

// ---- recording coverage ----
function coverService() {
  const { svc } = attachedService();
  const calls = [];
  const agent = { exports: {
    coverStart: async (...a) => { calls.push(['coverStart', ...a]); if (agent.rescope) { agent.rescope = false; throw new Error('FERMION_RESCOPE'); } return { recording: true, threads: 3 }; },
    coverStop: async () => { calls.push(['coverStop']); return agent.summary; },
    coverData: async (format) => { calls.push(['coverData', format]); return format === 'text' ? '# report' : new Uint8Array([1, 2, 250]).buffer; },
  } };
  agent.summary = { recorded: true, blocks: 5, modules: [{ name: 'app.exe', path: 'C:\\app.exe', blocks: 5, bytes: 9 }] };
  svc._getAgent = async () => agent;
  svc._dropAgent = async (name) => { calls.push(['drop', name]); };
  return { svc, agent, calls };
}

test('inspectCoverStart: all threads or one, with a checked scope; anything else is refused in main', async () => {
  const t = coverService();
  await t.svc.attach(1);
  assert.deepEqual(await t.svc.inspectCoverStart('all', { mode: 'app', junk: 1 }), { recording: true, threads: 3 });
  await t.svc.inspectCoverStart(11, { mode: 'module', module: 'app.exe' });
  assert.deepEqual(t.calls, [['coverStart', 'all', { mode: 'app', module: '' }], ['coverStart', 11, { mode: 'module', module: 'app.exe' }]]);
  for (const bad of ['ALL', 'every', -1, 1.5, null, undefined, {}, '11']) await assert.rejects(() => t.svc.inspectCoverStart(bad, { mode: 'all' }), /invalid thread/);
  await assert.rejects(() => t.svc.inspectCoverStart('all', { mode: 'nope' }), /scope/i);
  assert.equal(t.calls.length, 2);
});

test('inspectCoverStart: an agent that has excluded for another scope is replaced and asked again', async () => {
  const t = coverService();
  await t.svc.attach(1);
  t.agent.rescope = true;
  assert.deepEqual(await t.svc.inspectCoverStart('all', { mode: 'all' }), { recording: true, threads: 3 });
  assert.deepEqual(t.calls.map((c) => c[0]), ['coverStart', 'drop', 'coverStart']);
});

test('inspectCoverStop returns the summary and keeps the files in main; inspectCoverSave hands them to the saver', async () => {
  const t = coverService();
  const saved = [];
  t.svc.setCoverageSaver(async (file) => { saved.push(file); return 'C:/out/' + file.format; });
  await t.svc.attach(1);
  await assert.rejects(() => t.svc.inspectCoverSave('drcov'), /No coverage has been recorded/);
  assert.deepEqual(await t.svc.inspectCoverStop(), t.agent.summary);
  assert.deepEqual(t.calls.map((c) => c.join(':')), ['coverStop', 'coverData:drcov', 'coverData:text']);
  assert.deepEqual(await t.svc.inspectCoverSave('drcov'), { path: 'C:/out/drcov', format: 'drcov' });
  assert.deepEqual(await t.svc.inspectCoverSave('text'), { path: 'C:/out/text', format: 'text' });
  assert.ok(Buffer.isBuffer(saved[0].data));
  assert.deepEqual([...saved[0].data], [1, 2, 250]);
  assert.equal(saved[0].program, 'app.exe'); // the module with the most blocks names the file
  assert.equal(saved[1].data, '# report');
  // Saving does not need the session any more: the files are in main.
  await t.svc.detach();
  assert.deepEqual(await t.svc.inspectCoverSave('text'), { path: 'C:/out/text', format: 'text' });
});

test('inspectCoverSave: only the two known formats; a cancelled dialog is not an error; no saver is', async () => {
  const t = coverService();
  await t.svc.attach(1);
  await t.svc.inspectCoverStop();
  await assert.rejects(() => t.svc.inspectCoverSave('exe'), /format must be drcov or text/);
  await assert.rejects(() => t.svc.inspectCoverSave('drcov'), /cannot be saved here/);
  t.svc.setCoverageSaver(async () => null);
  assert.deepEqual(await t.svc.inspectCoverSave('drcov'), { path: null, format: 'drcov' });
});

test('a stop with nothing recorded keeps what was recorded before', async () => {
  const t = coverService();
  t.svc.setCoverageSaver(async (file) => 'p:' + file.data.length);
  await t.svc.attach(1);
  await t.svc.inspectCoverStop();
  t.agent.summary = { recorded: false };
  assert.deepEqual(await t.svc.inspectCoverStop(), { recorded: false });
  assert.equal((await t.svc.inspectCoverSave('text')).path, 'p:8');
  // A new recording replaces it.
  await t.svc.inspectCoverStart('all', { mode: 'all' });
  await assert.rejects(() => t.svc.inspectCoverSave('text'), /No coverage has been recorded/);
});

test('the three coverage operations are on the allow-list the window can call', () => {
  const { INVOKE_METHODS } = require('./frida-ipc.js');
  for (const m of ['inspectCoverStart', 'inspectCoverStop', 'inspectCoverSave']) assert.ok(INVOKE_METHODS.has(m), m);
});

// ---- watching memory ----
test('inspectWatchStart validates the address and size in main; hits and stop pass through', async () => {
  const { svc } = attachedService();
  const calls = [];
  const agent = { exports: {
    watchStart: async (...a) => { calls.push(['watchStart', ...a]); return { watching: true }; },
    watchHits: async (...a) => { calls.push(['watchHits', ...a]); return { watching: true, hits: 2 }; },
    watchStop: async (...a) => { calls.push(['watchStop', ...a]); return { watching: false, hits: 2 }; },
  } };
  svc._getAgent = async () => agent;
  await svc.attach(1);
  for (const bad of [['500000', 8], [0x500000, 8], ['0x50zz', 8], [null, 8]]) await assert.rejects(() => svc.inspectWatchStart(bad[0], bad[1]), /invalid address/);
  for (const size of [0, -1, 4097, 1.5, '8', null, undefined, NaN]) await assert.rejects(() => svc.inspectWatchStart('0x500000', size), /1\.\.4096 bytes/);
  assert.equal(calls.length, 0);
  assert.deepEqual(await svc.inspectWatchStart('0x50ABC0', 8), { watching: true });
  assert.deepEqual(await svc.inspectWatchHits('ignored'), { watching: true, hits: 2 });
  assert.deepEqual(await svc.inspectWatchStop('ignored'), { watching: false, hits: 2 });
  assert.deepEqual(calls, [['watchStart', '0x50abc0', 8, 'auto'], ['watchHits'], ['watchStop']]);
  // How to watch: exactly where possible (the default), exactly or not at all, or by trapping the page.
  calls.length = 0;
  for (const mode of ['auto', 'exact', 'sampled']) await svc.inspectWatchStart('0x500000', 8, mode);
  assert.deepEqual(calls.map((c) => c[3]), ['auto', 'exact', 'sampled']);
  for (const bad of ['fast', 'EXACT', 1, {}, null]) await assert.rejects(() => svc.inspectWatchStart('0x500000', 8, bad), /watch mode/);
  assert.equal(calls.length, 3);
});

test('the memory watch calls are on the allow-list the window can call', () => {
  const { INVOKE_METHODS } = require('./frida-ipc.js');
  for (const m of ['inspectWatchStart', 'inspectWatchHits', 'inspectWatchStop']) assert.ok(INVOKE_METHODS.has(m), m);
});

// ---- tracking the heap ----
test('heap tracking: sizes and the address are validated in main; status and stop pass through', async () => {
  const { svc } = attachedService();
  const calls = [];
  const agent = { exports: {} };
  for (const m of ['heapStart', 'heapStatus', 'heapFind', 'heapStop']) agent.exports[m] = async (...a) => { calls.push([m, ...a]); return { did: m }; };
  svc._getAgent = async () => agent;
  await svc.attach(1);
  for (const bad of ['all', 5, [], { min: -1 }, { min: 1.5 }, { max: '64' }, { min: 100, max: 50 }, { max: 2 ** 40 }, { min: NaN }]) await assert.rejects(() => svc.inspectHeapStart(bad), /sizes/);
  for (const bad of ['900000', 0x900000, '0x9z', null, undefined]) await assert.rejects(() => svc.inspectHeapFind(bad), /invalid address/);
  assert.equal(calls.length, 0);
  assert.deepEqual(await svc.inspectHeapStart(), { did: 'heapStart' });
  await svc.inspectHeapStart({ min: 32, max: 64, junk: 1 });
  await svc.inspectHeapStart({ min: 32 });
  assert.deepEqual(await svc.inspectHeapStatus('ignored'), { did: 'heapStatus' });
  assert.deepEqual(await svc.inspectHeapFind('0x90ABC0'), { did: 'heapFind' });
  assert.deepEqual(await svc.inspectHeapStop('ignored'), { did: 'heapStop' });
  assert.deepEqual(calls, [['heapStart', { min: 0, max: 0 }], ['heapStart', { min: 32, max: 64 }], ['heapStart', { min: 32, max: 0 }], ['heapStatus'], ['heapFind', '0x90abc0'], ['heapStop']]);
});

test('the heap tracking calls are on the allow-list the window can call', () => {
  const { INVOKE_METHODS } = require('./frida-ipc.js');
  for (const m of ['inspectHeapStart', 'inspectHeapStatus', 'inspectHeapFind', 'inspectHeapStop']) assert.ok(INVOKE_METHODS.has(m), m);
});
