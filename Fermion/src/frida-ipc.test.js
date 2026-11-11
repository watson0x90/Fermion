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
