// Unit tests for the detached-Output window manager (node:test, no Electron).
const { test } = require('node:test');
const assert = require('node:assert');
const { createOutputWindowManager, buildOutputWindowOptions, isRelayMessage } = require('./output-window.js');

// Minimal BrowserWindow stand-in: records what the manager does to it.
function fakeElectron() {
  const created = [];
  class FakeWindow {
    constructor(opts) {
      this.opts = opts;
      this.handlers = {};
      this.sent = [];
      this.destroyed = false;
      this.focused = 0;
      this.loaded = null;
      this.webContents = { send: (...a) => this.sent.push(a), on: () => {}, setWindowOpenHandler: () => {} };
      created.push(this);
    }
    on(ev, cb) { this.handlers[ev] = cb; }
    once(ev, cb) { this.handlers[ev] = cb; }
    loadFile(p) { this.loaded = p; }
    show() {} focus() { this.focused++; }
    isDestroyed() { return this.destroyed; }
    isMinimized() { return false; }
    isMaximized() { return false; }
    close() { this.destroyed = true; if (this.handlers.closed) this.handlers.closed(); }
    destroy() { this.close(); }
  }
  return { FakeWindow, created };
}

function setup() {
  const { FakeWindow, created } = fakeElectron();
  const main = new FakeWindow({});
  created.length = 0;
  const hardened = [];
  const mgr = createOutputWindowManager({
    BrowserWindow: FakeWindow,
    getMainWindow: () => main,
    preload: '/app/src/preload.js',
    page: '/app/pages/output.html',
    harden: (w) => hardened.push(w),
  });
  return { mgr, main, created, hardened, FakeWindow };
}

test('the output window keeps the secured webPreferences and the shared preload', () => {
  const o = buildOutputWindowOptions('/app/src/preload.js');
  assert.equal(o.webPreferences.nodeIntegration, false);
  assert.equal(o.webPreferences.contextIsolation, true);
  assert.equal(o.webPreferences.sandbox, false);
  assert.equal(o.webPreferences.preload, '/app/src/preload.js');
  assert.equal(o.frame, false);
  assert.equal(o.show, false);
  assert.notEqual(o.resizable, false);
});

test('open: only the main window may detach; creates one hardened window on the fixed page', () => {
  const { mgr, main, created, hardened } = setup();
  assert.equal(mgr.open({ not: 'main' }), false);
  assert.equal(created.length, 0);

  assert.equal(mgr.open(main.webContents), true);
  assert.equal(created.length, 1);
  assert.equal(created[0].loaded, '/app/pages/output.html');
  assert.deepEqual(hardened, [created[0]]);
  assert.deepEqual(main.sent, [['fermion:output-state', true]]);

  // A second detach focuses the existing window instead of opening another,
  // and re-tells the main window (a reloaded main renderer has forgotten).
  main.sent.length = 0;
  assert.equal(mgr.open(main.webContents), true);
  assert.equal(created.length, 1);
  assert.equal(created[0].focused, 1);
  assert.deepEqual(main.sent, [['fermion:output-state', true]]);
});

test('closing the output window (dock, or its own close button) tells the main window', () => {
  const { mgr, main, created } = setup();
  mgr.open(main.webContents);
  main.sent.length = 0;
  assert.equal(mgr.close(main.webContents), true);
  assert.equal(created[0].destroyed, true);
  assert.deepEqual(main.sent, [['fermion:output-state', false]]);
  assert.equal(mgr.isOpen(), false);
  // Nothing to close now.
  assert.equal(mgr.close(main.webContents), false);
  // It can be detached again afterwards.
  assert.equal(mgr.open(main.webContents), true);
  assert.equal(created.length, 2);
});

test('close is refused for a sender that is neither window', () => {
  const { mgr, main, created } = setup();
  mgr.open(main.webContents);
  assert.equal(mgr.close({ stranger: true }), false);
  assert.equal(created[0].destroyed, false);
  assert.equal(mgr.close(created[0].webContents), true);
});

test('relay: main -> output and output -> main, each limited to its own message types', () => {
  const { mgr, main, created } = setup();
  mgr.open(main.webContents);
  const out = created[0];
  main.sent.length = 0;

  assert.equal(mgr.relay(main.webContents, { t: 'line', kind: 'LOG', text: 'hi' }), true);
  assert.deepEqual(out.sent, [['fermion:output-relay', { t: 'line', kind: 'LOG', text: 'hi' }]]);

  assert.equal(mgr.relay(out.webContents, { t: 'ready' }), true);
  assert.deepEqual(main.sent, [['fermion:output-relay', { t: 'ready' }]]);

  // Wrong direction, unknown type, unknown sender, malformed payload: dropped.
  assert.equal(mgr.relay(out.webContents, { t: 'line', kind: 'LOG', text: 'x' }), false);
  assert.equal(mgr.relay(main.webContents, { t: 'ready' }), false);
  assert.equal(mgr.relay(main.webContents, { t: 'nope' }), false);
  assert.equal(mgr.relay({ stranger: true }, { t: 'ready' }), false);
  assert.equal(mgr.relay(main.webContents, 'line'), false);
  assert.equal(mgr.relay(main.webContents, null), false);
  assert.equal(out.sent.length, 1);
  assert.equal(main.sent.length, 1);
});

test('relay is dropped when no output window is open', () => {
  const { mgr, main } = setup();
  assert.equal(mgr.relay(main.webContents, { t: 'line', kind: 'LOG', text: 'hi' }), false);
});

test('closeAll destroys the output window when the main window goes away', () => {
  const { mgr, main, created } = setup();
  mgr.open(main.webContents);
  mgr.closeAll();
  assert.equal(created[0].destroyed, true);
  assert.equal(mgr.isOpen(), false);
});

test('the output window reports its own maximize state to its title bar', () => {
  const { mgr, main, created } = setup();
  mgr.open(main.webContents);
  const out = created[0];
  out.isMaximized = () => true;
  out.handlers.maximize();
  assert.deepEqual(out.sent, [['fermion:win-state', true]]);
});

test('a stale window closing late does not report "docked" while a newer window is open', () => {
  const { mgr, main, created } = setup();
  mgr.open(main.webContents);
  const first = created[0];
  // Real Electron fires `closed` asynchronously: close now, deliver it later.
  const lateClosed = first.handlers.closed;
  first.handlers.closed = null;
  mgr.close(main.webContents);
  mgr.open(main.webContents);
  assert.equal(created.length, 2);
  main.sent.length = 0;
  lateClosed();
  assert.deepEqual(main.sent, []);
  assert.equal(mgr.isOpen(), true);
});

test('isRelayMessage accepts only plain objects with a known type for the direction', () => {
  assert.equal(isRelayMessage({ t: 'snapshot', entries: [] }, 'toOutput'), true);
  assert.equal(isRelayMessage({ t: 'theme', name: 'Monokai' }, 'toOutput'), true);
  assert.equal(isRelayMessage({ t: 'clear' }, 'toOutput'), true);
  assert.equal(isRelayMessage({ t: 'lines', items: [] }, 'toOutput'), true);
  assert.equal(isRelayMessage({ t: 'lines', items: [] }, 'toMain'), false);
  assert.equal(isRelayMessage({ t: 'filter', kind: 'LOG', on: false }, 'toMain'), true);
  assert.equal(isRelayMessage({ t: 'clear' }, 'toMain'), true);
  assert.equal(isRelayMessage({ t: 'follow', on: true }, 'toMain'), true);
  assert.equal(isRelayMessage({ t: 'snapshot' }, 'toMain'), false);
  assert.equal(isRelayMessage([], 'toMain'), false);
  assert.equal(isRelayMessage({ t: 'ready' }, 'sideways'), false);
});
