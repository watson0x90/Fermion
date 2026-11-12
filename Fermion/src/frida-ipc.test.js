// Unit tests for the main-process IPC glue (allow-listed method dispatch).
const { test } = require('node:test');
const assert = require('node:assert');
const { createDispatch, wireServiceEvents } = require('./frida-ipc.js');

test('dispatch forwards allow-listed methods to the service', async () => {
  const calls = [];
  const fake = { attach: async (p) => { calls.push(['attach', p]); return 'ok'; } };
  const dispatch = createDispatch(fake);
  const r = await dispatch('attach', 4821);
  assert.deepEqual(calls, [['attach', 4821]]);
  assert.equal(r, 'ok');
});

test('dispatch rejects unknown / non-allow-listed methods', async () => {
  const dispatch = createDispatch({ evil: async () => 'nope', constructor: async () => 'x' });
  await assert.rejects(() => dispatch('evil'), /unknown method/);
  await assert.rejects(() => dispatch('constructor'), /unknown method/);
});

test('wireServiceEvents forwards message/log/detached with their payloads', () => {
  const sent = [];
  const handlers = {};
  const fakeService = { on: (ev, cb) => { handlers[ev] = cb; } };
  wireServiceEvents(fakeService, (...a) => sent.push(a));
  handlers.message({ type: 'send', payload: 1 });
  handlers.log('info', 'hello');
  handlers.detached('process-terminated');
  assert.deepEqual(sent, [
    ['message', { type: 'send', payload: 1 }],
    ['log', 'info', 'hello'],
    ['detached', 'process-terminated'],
  ]);
});

test('evaluate (REPL) is allow-listed and forwards its code argument', async () => {
  const calls = [];
  const dispatch = createDispatch({ evaluate: async (code) => { calls.push(code); return { ok: true }; } });
  assert.deepEqual(await dispatch('evaluate', 'Process.id'), { ok: true });
  assert.deepEqual(calls, ['Process.id']);
});

test('the Inspector read-only operations are allow-listed', async () => {
  const names = ['inspectModules', 'inspectExports', 'inspectImports', 'inspectThreads', 'inspectBacktrace', 'inspectRanges', 'inspectRead', 'inspectScan', 'inspectFollow', 'inspectUnfollow', 'inspectDisassemble'];
  const svc = {};
  for (const n of names) svc[n] = async (...a) => [n, ...a];
  const dispatch = createDispatch(svc);
  for (const n of names) assert.deepEqual(await dispatch(n, 'x'), [n, 'x']);
  // Nothing that writes to the target is exposed under an inspect* name.
  const { INVOKE_METHODS } = require('./frida-ipc.js');
  assert.deepEqual([...INVOKE_METHODS].filter((m) => m.startsWith('inspect')).sort(), names.slice().sort());
});

test('cancelEvaluate is allow-listed', async () => {
  const dispatch = createDispatch({ cancelEvaluate: async () => true });
  assert.equal(await dispatch('cancelEvaluate'), true);
});

test('the Hooks tab operations are allow-listed and forward their arguments', async () => {
  const names = ['hookSearch', 'hookAdd', 'hookUpdate', 'hookRemove', 'hookEnable', 'hookSymbolicate'];
  const { INVOKE_METHODS, createDispatch } = require('./frida-ipc.js');
  assert.deepEqual([...INVOKE_METHODS].filter((m) => m.startsWith('hook')).sort(), names.slice().sort());
  const seen = [];
  const service = Object.fromEntries(names.map((n) => [n, async (...a) => { seen.push([n, ...a]); return n; }]));
  const dispatch = createDispatch(service);
  assert.equal(await dispatch('hookSearch', 'exports', 'open'), 'hookSearch');
  assert.equal(await dispatch('hookEnable', 'hk-1', false), 'hookEnable');
  assert.deepEqual(seen, [['hookSearch', 'exports', 'open'], ['hookEnable', 'hk-1', false]]);
});
