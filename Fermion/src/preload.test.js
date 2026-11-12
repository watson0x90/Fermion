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

test('win controls invoke fermion:win with the action', async () => {
  const sent = [];
  const fake = { invoke: (...a) => { sent.push(a); return Promise.resolve(true); }, on: () => {} };
  const api = buildApi(fake);
  await api.win.minimize();
  await api.win.toggleMaximize();
  await api.win.close();
  await api.win.isMaximized();
  await api.win.setBackground('#112233');
  assert.deepEqual(sent, [
    ['fermion:win', 'minimize'],
    ['fermion:win', 'toggleMaximize'],
    ['fermion:win', 'close'],
    ['fermion:win', 'isMaximized'],
    ['fermion:win', 'setBackground', '#112233'],
  ]);
});

test('onMaximizeChange subscribes to the win-state relay channel', () => {
  let ch; let cb;
  const fake = { invoke: () => {}, on: (c, f) => { ch = c; cb = f; }, removeListener: () => {} };
  const api = buildApi(fake);
  const got = [];
  api.onMaximizeChange((m) => got.push(m));
  assert.equal(ch, 'fermion:win-state');
  cb({}, true);
  assert.deepEqual(got, [true]);
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

test('output detach/dock invoke fermion:output; relay sends and subscribes on its own channels', async () => {
  const invoked = []; const sent = []; const subs = {};
  const fake = {
    invoke: (...a) => { invoked.push(a); return Promise.resolve(true); },
    send: (...a) => sent.push(a),
    on: (c, f) => { subs[c] = f; },
    removeListener: () => {},
  };
  const api = buildApi(fake);
  await api.output.detach();
  await api.output.dock();
  api.output.send({ t: 'ready' });
  assert.deepEqual(invoked, [['fermion:output', 'detach'], ['fermion:output', 'dock']]);
  assert.deepEqual(sent, [['fermion:output-relay', { t: 'ready' }]]);

  const relayed = []; const states = [];
  api.output.onRelay((m) => relayed.push(m));
  api.output.onState((s) => states.push(s));
  subs['fermion:output-relay']({}, { t: 'line', kind: 'LOG', text: 'x' });
  subs['fermion:output-state']({}, true);
  assert.deepEqual(relayed, [{ t: 'line', kind: 'LOG', text: 'x' }]);
  assert.deepEqual(states, [true]);
});
