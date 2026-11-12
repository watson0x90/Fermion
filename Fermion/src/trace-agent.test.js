// Unit tests for the Graph tab's tracer (src/tools/trace.js). It runs inside
// the target under Frida; here it is loaded into a `vm` context with small
// fakes of Interceptor / Stalker / DebugSymbol so its logic is testable.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SOURCE = fs.readFileSync(path.join(__dirname, 'tools', 'trace.js'), 'utf8');

class Ptr {
  constructor(v) { this.v = BigInt(v); }
  toString() { return '0x' + this.v.toString(16); }
  equals(o) { return this.v === o.v; }
}
const P = (v) => new Ptr(v);

// addr -> [module, symbol]
const SYMBOLS = {
  0x1000: ['kernel32.dll', 'CreateFileW'],
  0x2000: ['KERNELBASE.dll', 'CreateFileInternal'],
  0x3000: ['ntdll.dll', 'NtCreateFile'],
  0x4000: ['frida-agent.dll', 'hook'],
  0x5000: ['evil.dll', 'a"b\\c\nd'],
};

function load(target, over = {}) {
  const sent = [];
  let hooks = null;
  let now = over.now || 0;
  const stalker = { following: [], unfollowed: [], opts: null, pending: [] };
  const kernel = { name: 'kernel32.dll', findExportByName: (n) => (n === 'CreateFileW' ? P(0x1000) : null) };
  const ctx = vm.createContext({
    FERMION_TRACE: target,
    send: (m) => sent.push(m),
    ptr: (v) => P(v),
    Process: {
      findModuleByName: (n) => (n === 'kernel32.dll' ? kernel : null),
      getCurrentThreadId: () => over.tid || 7,
    },
    Module: { findGlobalExportByName: (n) => (n === 'CreateFileW' ? P(0x1000) : null) },
    ModuleMap: class { find(p) { const s = SYMBOLS[Number(p.v)]; if (s) return { name: s[0] }; return p.v >= 0x100000n && p.v < 0x300000n ? { name: 'big.dll' } : null; } },
    DebugSymbol: { fromAddress: (p) => { const s = SYMBOLS[Number(p.v)]; return { name: s ? s[1] : null }; } },
    Interceptor: { attach: (p, cb) => { hooks = { at: p, cb }; } },
    Stalker: {
      follow: (tid, opts) => { stalker.following.push(tid); stalker.opts = opts; },
      unfollow: (tid) => { stalker.unfollowed.push(tid); },
      // Events are handed over in batches when flushed.
      flush: () => { const batches = stalker.pending; stalker.pending = []; for (const b of batches) stalker.opts.onReceive(b); },
      garbageCollect: () => {},
      parse: (batch) => batch,
    },
    Date: { now: () => now },
    JSON, Object, Array, String, Math,
  });
  vm.runInContext(SOURCE, ctx);
  const call = (batches) => {
    hooks.cb.onEnter.call({}, []);
    stalker.pending = batches;
    hooks.cb.onLeave.call({}, P(0));
  };
  return { sent, stalker, hooks: () => hooks, call, tick: (ms) => { now += ms; } };
}
const ev = (from, to) => ['call', P(from), P(to), 0];
const dots = (t) => t.sent.filter((m) => m.fermionTrace === 'dot');

test('resolves module!export with the Frida 17 API and reports ready with the address', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  assert.deepEqual(t.sent, [{ fermionTrace: 'ready', address: '0x1000', target: 'kernel32.dll!CreateFileW' }]);
  assert.equal(t.hooks().at.toString(), '0x1000');
});

test('no module given: looks the export up globally', () => {
  const t = load({ module: '', symbol: 'CreateFileW' });
  assert.equal(t.sent[0].fermionTrace, 'ready');
  assert.equal(t.sent[0].target, 'CreateFileW');
});

test('an unknown module or export is reported as an error message, and nothing is hooked', () => {
  const a = load({ module: 'nope.dll', symbol: 'CreateFileW' });
  assert.deepEqual(a.sent, [{ fermionTrace: 'error', message: 'Module not found: nope.dll' }]);
  assert.equal(a.hooks(), null);
  const b = load({ module: 'kernel32.dll', symbol: 'Nope' });
  assert.deepEqual(b.sent, [{ fermionTrace: 'error', message: 'Export not found: kernel32.dll!Nope' }]);
  const c = load({ module: '', symbol: 'Nope' });
  assert.match(c.sent[0].message, /Export not found: Nope/);
  const d = load({ module: 'kernel32.dll', symbol: '' });
  assert.match(d.sent[0].message, /symbol/i);
});

test('one call of the traced function produces a graph of the calls made inside it', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x1000, 0x2000), ev(0x2000, 0x3000)]]);
  assert.deepEqual(t.stalker.following, [7]);
  assert.deepEqual(t.stalker.unfollowed, [7]);
  const d = dots(t);
  assert.equal(d.length, 1);
  assert.equal(d[0].calls, 2);
  assert.equal(d[0].truncated, false);
  const dot = d[0].dot;
  assert.match(dot, /^digraph/);
  assert.ok(dot.includes('"kernel32.dll!CreateFileW" -> "KERNELBASE.dll!CreateFileInternal"'), dot);
  assert.ok(dot.includes('"KERNELBASE.dll!CreateFileInternal" -> "ntdll.dll!NtCreateFile"'), dot);
  // start and end are marked
  assert.match(dot, /"kernel32\.dll!CreateFileW" \[fillcolor="#cfe8c8"/);
  assert.match(dot, /"ntdll\.dll!NtCreateFile" \[fillcolor="#f3d0cb"/);
});

// The old tracer kept only the last batch Stalker delivered.
test('calls delivered in several batches are all kept', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x1000, 0x2000)], [ev(0x2000, 0x3000)]]);
  const d = dots(t)[0];
  assert.equal(d.calls, 2);
  assert.ok(d.dot.includes('CreateFileInternal') && d.dot.includes('NtCreateFile'));
});

test('a repeated call is drawn once, with how many times it happened', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x1000, 0x2000), ev(0x1000, 0x2000), ev(0x1000, 0x2000), ev(0x2000, 0x3000)]]);
  const d = dots(t)[0];
  assert.equal(d.calls, 4);
  assert.equal(d.edges, 2);
  assert.equal(d.dot.split('"kernel32.dll!CreateFileW" -> "KERNELBASE.dll!CreateFileInternal"').length - 1, 1);
  assert.match(d.dot, /-> "KERNELBASE\.dll!CreateFileInternal" \[label="×3"\]/);
});

test('calls made from Frida itself are left out', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x4000, 0x2000), ev(0x1000, 0x2000)]]);
  const d = dots(t)[0];
  assert.ok(!d.dot.includes('frida-agent'));
  assert.equal(d.edges, 1);
});

test('names from the target cannot break out of a label (quotes, backslashes, newlines)', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x1000, 0x5000)]]);
  const dot = dots(t)[0].dot;
  assert.ok(dot.includes('"evil.dll!a\\"b\\\\c d"'), dot);
  // every quote in the output is either a delimiter or escaped: quotes balance per line
  for (const line of dot.split('\n')) {
    const unescaped = line.replace(/\\\\/g, '').replace(/\\"/g, '');
    assert.equal((unescaped.match(/"/g) || []).length % 2, 0, line);
  }
});

// A node is a function, not a call site: two calls made from different places
// inside the same function share one node.
test('call sites inside the same function are one node, and the traced function is connected', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  SYMBOLS[0x1040] = ['kernel32.dll', 'CreateFileW'];
  SYMBOLS[0x1080] = ['kernel32.dll', 'CreateFileW'];
  try {
    t.call([[ev(0x1040, 0x2000), ev(0x1080, 0x3000)]]);
    const d = dots(t)[0];
    assert.ok(d.dot.includes('"kernel32.dll!CreateFileW" -> "KERNELBASE.dll!CreateFileInternal"'), d.dot);
    assert.ok(d.dot.includes('"kernel32.dll!CreateFileW" -> "ntdll.dll!NtCreateFile"'), d.dot);
    assert.ok(!d.dot.includes('0x1040') && !d.dot.includes('0x1080'), d.dot);
    assert.ok(d.dot.includes('"kernel32.dll!CreateFileW" [fillcolor="#cfe8c8"'), d.dot);
  } finally { delete SYMBOLS[0x1040]; delete SYMBOLS[0x1080]; }
});

test('an address outside every module, or without a symbol, still gets a node', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x1000, 0x9999)]]);
  assert.ok(dots(t)[0].dot.includes('"0x9999"'), dots(t)[0].dot);
});

test('a call that made no calls sends nothing rather than an empty graph', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([]);
  assert.equal(dots(t).length, 0);
});

test('a very busy call is capped and says so', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  const many = [];
  for (let i = 0; i < 3000; i++) many.push(ev(0x100000 + i, 0x200000 + i));
  t.call([many]);
  const d = dots(t)[0];
  assert.equal(d.truncated, true);
  assert.ok(d.edges <= 400, 'edges ' + d.edges);
  assert.equal(d.calls, 3000);
});

test('a function called in a tight loop is sampled, not traced every time', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x1000, 0x2000)]]);
  t.tick(100);
  t.call([[ev(0x1000, 0x2000)]]); // too soon: not stalked at all
  assert.equal(dots(t).length, 1);
  assert.deepEqual(t.stalker.following, [7]);
  t.tick(2000);
  t.call([[ev(0x1000, 0x3000)]]);
  assert.equal(dots(t).length, 2);
});

test('recursion: a nested call on the same thread does not start a second trace or end the first early', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  const h = t.hooks().cb;
  h.onEnter.call({}, []);            // outer
  h.onEnter.call({}, []);            // nested
  assert.deepEqual(t.stalker.following, [7]);
  t.stalker.pending = [];
  h.onLeave.call({}, P(0));          // nested returns: still tracing
  assert.deepEqual(t.stalker.unfollowed, []);
  t.stalker.pending = [[ev(0x1000, 0x2000)]];
  h.onLeave.call({}, P(0));          // outer returns
  assert.deepEqual(t.stalker.unfollowed, [7]);
  assert.equal(dots(t).length, 1);
});

// Stalker also sees calls made from Frida's own generated code (trampolines,
// its JavaScript runtime), which lives outside every module. Those are noise:
// they showed up as islands of bare addresses unconnected to the traced call.
test('calls made from code outside every module are left out', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x21b6ec6e903, 0x21b6ed67ca0), ev(0x21b6ec164e8, 0x2000), ev(0x1000, 0x2000)]]);
  const d = dots(t)[0];
  assert.equal(d.edges, 1);
  assert.ok(!d.dot.includes('0x21b6e'), d.dot);
});

test('the graph is laid out left to right (call depth across, callees down)', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x1000, 0x2000)]]);
  assert.match(dots(t)[0].dot, /rankdir=LR/);
});

// kernel32!CreateFileW is only a jump to KERNELBASE!CreateFileW: the first call
// Stalker sees is made from the function it jumped to. The traced function must
// still lead into the graph instead of sitting beside it.
test('a traced function that forwards elsewhere is linked to where the calls start', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x2000, 0x3000)]]); // first call comes from KERNELBASE, not from the hooked stub
  const dot = dots(t)[0].dot;
  assert.ok(dot.includes('"kernel32.dll!CreateFileW" -> "KERNELBASE.dll!CreateFileInternal" [style=dashed]'), dot);
  assert.ok(dot.includes('"KERNELBASE.dll!CreateFileInternal" -> "ntdll.dll!NtCreateFile"'), dot);
});

test('no extra link when the calls already start in the traced function', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x1000, 0x2000)]]);
  assert.ok(!dots(t)[0].dot.includes('style=dashed'));
});

test('the layout is compact: small nodes and tight spacing, so more of the graph is readable at once', () => {
  const t = load({ module: 'kernel32.dll', symbol: 'CreateFileW' });
  t.call([[ev(0x1000, 0x2000)]]);
  const dot = dots(t)[0].dot;
  assert.match(dot, /nodesep=0\.12/);
  assert.match(dot, /ranksep=0\.3/);
  assert.match(dot, /margin="0\.07,0\.03"/);
  assert.ok(!/shape=(inv)?house/.test(dot), 'house shapes waste space');
});
