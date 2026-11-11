// Unit tests for the pure preload api factory (no Electron needed).
const { test } = require('node:test');
const assert = require('node:assert');
const { buildApi } = require('./preload-api.js');

test('method calls invoke fermion:invoke with the method + args', async () => {
  const sent = [];
  const fake = { invoke: (...a) => { sent.push(a); return Promise.resolve('ok'); }, on: () => {} };
  const api = buildApi(fake);
  const r = await api.attach(4821);
  assert.deepEqual(sent, [['fermion:invoke', 'attach', 4821]]);
  assert.equal(r, 'ok');
  await api.spawn('C:/x.exe', 'a b');
  assert.deepEqual(sent[1], ['fermion:invoke', 'spawn', 'C:/x.exe', 'a b']);
});

test('onMessage routes only message events; onLog only log events', () => {
  let handler;
  const fake = { invoke: () => {}, on: (ch, cb) => { assert.equal(ch, 'fermion:event'); handler = cb; } };
  const api = buildApi(fake);
  const msgs = [];
  const logs = [];
  api.onMessage((m) => msgs.push(m));
  api.onLog((lvl, txt) => logs.push([lvl, txt]));
  handler({}, 'message', { x: 1 });
  handler({}, 'log', 'info', 'hi');
  handler({}, 'detached', 'done');
  assert.deepEqual(msgs, [{ x: 1 }]);
  assert.deepEqual(logs, [['info', 'hi']]);
});

test('subscribe returns an unsubscribe that stops delivery', () => {
  let handler;
  const fake = { invoke: () => {}, on: (ch, cb) => { handler = cb; } };
  const api = buildApi(fake);
  const got = [];
  const off = api.onMessage((m) => got.push(m));
  handler({}, 'message', 1);
  off();
  handler({}, 'message', 2);
  assert.deepEqual(got, [1]);
});
