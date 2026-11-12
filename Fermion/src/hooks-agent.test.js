// Unit tests for the Hooks agent (src/tools/hooks-agent.js), loaded into a
// `vm` context with small fakes of the Frida APIs it uses.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SOURCE = fs.readFileSync(path.join(__dirname, 'tools', 'hooks-agent.js'), 'utf8');

class Ptr {
  constructor(v) { this.v = BigInt(v instanceof Ptr ? v.v : v); }
  toString(radix) { return (radix === 16 ? '' : '0x') + this.v.toString(16); }
  toJSON() { return this.toString(); }
  sub(o) { return new Ptr(this.v - new Ptr(o).v); }
  add(o) { return new Ptr(this.v + new Ptr(o).v); }
}
// Number(ptr.toString()) must work for offsets, as it does with NativePointer.
const j = (v) => JSON.parse(JSON.stringify(v));

function load(over = {}) {
  const modules = [
    { name: 'kernel32.dll', base: new Ptr(0x7ff000), size: 0x10000 },
    { name: 'target.exe', base: new Ptr(0x400000), size: 0x10000 },
  ];
  const sent = [];
  const timers = [];
  const attached = []; // { target, callbacks, detached }
  const queries = [];
  const now = { t: 1000 };
  const ctx = vm.createContext({
    rpc: {}, ptr: (v) => new Ptr(v), JSON, Number, String, Math,
    Date: { now: () => now.t },
    send: (m) => sent.push(j(m)),
    setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    Process: {
      findModuleByName: (n) => modules.find((m) => m.name.toLowerCase() === String(n).toLowerCase()) || null,
      findModuleByAddress: (a) => modules.find((m) => a.v >= m.base.v && a.v < m.base.v + BigInt(m.size)) || null,
    },
    DebugSymbol: {
      fromAddress: (a) => (a.v === 0x400100n ? { name: 'parse_config', moduleName: 'target.exe' } : { name: null, moduleName: null }),
      findFunctionsMatching: (g) => { queries.push('symbols:' + g); return over.symbols || [new Ptr(0x400100), new Ptr(0x7ff200)]; },
    },
    ApiResolver: function (type) {
      this.enumerateMatches = (q) => {
        queries.push(type + ':' + q);
        return over.matches || [
          { name: 'C:\\Windows\\System32\\kernel32.dll!CreateFileW', address: new Ptr(0x7ff010) },
          { name: 'C:\\Windows\\System32\\kernel32.dll!CreateFileA', address: new Ptr(0x7ff020) },
          { name: 'C:\\x\\forwarder.dll!CreateFileW', address: new Ptr(0x7ff010) }, // same function again
        ];
      };
    },
    Interceptor: {
      attach: (target, callbacks) => {
        if (over.attachThrows) throw new Error('unable to intercept function');
        const l = { target: target.toString(), callbacks, detached: false, detach() { l.detached = true; } };
        attached.push(l);
        return l;
      },
    },
    Thread: { backtrace: () => { if (over.backtraceThrows) throw new Error('no unwind'); return Array.from({ length: over.frames || 3 }, (_, i) => new Ptr(0x7ff100 + i)); } },
    Backtracer: { ACCURATE: 'accurate' },
  });
  vm.runInContext(SOURCE, ctx);
  const api = ctx.rpc.exports;
  // Simulate the target calling the hooked function.
  const call = (listener, { tid = 7, depth = 0, args = [new Ptr(1), new Ptr(2)], retval = new Ptr(0) } = {}) => {
    const inv = { threadId: tid, depth, context: {} };
    listener.callbacks.onEnter.call(inv, args);
    listener.callbacks.onLeave.call(inv, retval);
  };
  const flush = () => { const t = timers.shift(); if (t) t.fn(); return sent[sent.length - 1]; };
  return { api, sent, timers, attached, queries, now, call, flush };
}

const HANDLER = '({ onEnter(log, args) { log("in", args[0]); }, onLeave(log, retval) { log("out", retval); } })';
const spec = (over = {}) => ({ id: 'h1', module: 'kernel32.dll', offset: 0x10, address: '0x7ff010', code: HANDLER, enabled: true, backtrace: true, ...over });

// ---- search ----
test('search exports: module!function with wildcards, case-insensitive, duplicates by address merged', () => {
  const a = load();
  const r = j(a.api.search('exports', 'kernel32*!CreateFile*'));
  assert.deepEqual(a.queries, ['module:exports:kernel32*!CreateFile*/i']);
  assert.deepEqual(r, {
    items: [
      { name: 'kernel32.dll!CreateFileW', module: 'kernel32.dll', offset: 0x10, address: '0x7ff010' },
      { name: 'kernel32.dll!CreateFileA', module: 'kernel32.dll', offset: 0x20, address: '0x7ff020' },
    ],
    total: 2, truncated: false,
  });
});

test('search: plain text is looked for anywhere in the name, in any module; imports use the imports resolver', () => {
  const a = load();
  a.api.search('exports', 'open');
  a.api.search('imports', 'target.exe!Reg');
  assert.deepEqual(a.queries, ['module:exports:*!*open*/i', 'module:imports:*target.exe*!*Reg*/i']);
});

test('search debug symbols: names come from the symbols, and a module in the query narrows the result', () => {
  const a = load();
  const all = j(a.api.search('symbols', 'parse*'));
  assert.deepEqual(a.queries, ['symbols:parse*']);
  assert.deepEqual(all.items.map((i) => i.name), ['target.exe!parse_config', 'kernel32.dll!0x200']);
  const one = j(a.api.search('symbols', 'target!parse*'));
  assert.deepEqual(one.items.map((i) => i.name), ['target.exe!parse_config']);
});

test('search: an address, or module!0xoffset, is one exact place', () => {
  const a = load();
  assert.deepEqual(j(a.api.search('exports', 'target.exe!0x100')).items, [{ name: 'target.exe!parse_config', module: 'target.exe', offset: 0x100, address: '0x400100' }]);
  assert.deepEqual(j(a.api.search('exports', '0x9000')).items, [{ name: '0x9000', module: '', offset: null, address: '0x9000' }]);
  assert.throws(() => a.api.search('exports', 'nope.dll!0x10'), /Module not found: nope\.dll/);
  assert.deepEqual(a.queries, []); // no resolver involved
});

test('search: results are capped and say so', () => {
  const matches = Array.from({ length: 700 }, (_, i) => ({ name: 'k!f' + i, address: new Ptr(0x7ff000 + i) }));
  const r = load({ matches }).api.search('exports', '*');
  assert.equal(r.items.length, 500);
  assert.equal(r.total, 700);
  assert.equal(r.truncated, true);
});

// ---- hooking ----
test('add: hooks module base + offset and reports where it landed', () => {
  const a = load();
  assert.deepEqual(j(a.api.add(spec())), { id: 'h1', address: '0x7ff010', enabled: true, calls: 0 });
  assert.equal(a.attached.length, 1);
  assert.equal(a.attached[0].target, '0x7ff010');
});

test('add: without a module the address is used; a module that is not loaded is an error', () => {
  const a = load();
  a.api.add(spec({ module: '', offset: null, address: '0x9000' }));
  assert.equal(a.attached[0].target, '0x9000');
  assert.throws(() => a.api.add(spec({ id: 'h2', module: 'gone.dll' })), /Module not loaded: gone\.dll/);
  assert.equal(a.attached.length, 1);
});

test('a call is reported in a batch: text, thread, depth, phase and a backtrace on entry', () => {
  const a = load();
  a.api.add(spec());
  a.now.t = 1250;
  a.call(a.attached[0], { tid: 42, depth: 2, args: [new Ptr(0xabc)], retval: new Ptr(5) });
  assert.equal(a.sent.length, 0); // nothing until the batch is flushed
  assert.equal(a.timers[0].ms, 100);
  const m = a.flush();
  assert.equal(m.fermionHooks, 'hits');
  assert.deepEqual(m.counts, { h1: 1 });
  assert.equal(m.dropped, 0);
  assert.deepEqual(m.hits, [
    { seq: 1, id: 'h1', t: 250, tid: 42, depth: 2, phase: 'enter', text: 'in 0xabc', bt: ['0x7ff100', '0x7ff101', '0x7ff102'] },
    { seq: 2, id: 'h1', t: 250, tid: 42, depth: 2, phase: 'leave', text: 'out 0x5' },
  ]);
});

test('log prints strings as they are, plain data as JSON, and clips very long lines', () => {
  const a = load();
  a.api.add(spec({ code: '({ onEnter(log) { log("a", { n: 1, s: "x" }, [1, 2], null, undefined, 7); log("y".repeat(5000)); } })' }));
  a.call(a.attached[0]);
  const hits = a.flush().hits;
  assert.equal(hits[0].text, 'a {"n":1,"s":"x"} [1,2] null undefined 7');
  assert.equal(hits[1].text.length, 2001);
  assert.ok(hits[1].text.endsWith('…'));
});

test('a hook that logs nothing still has its calls counted', () => {
  const a = load();
  a.api.add(spec({ code: '({ onEnter() {} })' }));
  for (let i = 0; i < 5; i++) a.call(a.attached[0]);
  const m = a.flush();
  assert.deepEqual(m.hits, []);
  assert.deepEqual(m.counts, { h1: 5 });
});

test('the backtrace is taken once per call, capped, and can be switched off', () => {
  const a = load({ frames: 40 });
  a.api.add(spec({ code: '({ onEnter(log) { log(1); log(2); } })' }));
  a.api.add(spec({ id: 'h2', backtrace: false, code: '({ onEnter(log) { log(1); } })' }));
  a.call(a.attached[0]);
  a.call(a.attached[1]);
  const hits = a.flush().hits;
  assert.equal(hits[0].bt.length, 16);
  assert.equal(hits[1].bt, undefined);
  assert.equal(hits[2].bt, undefined);
});

test('a backtrace that cannot be taken does not lose the hit', () => {
  const a = load({ backtraceThrows: true });
  a.api.add(spec());
  a.call(a.attached[0]);
  const hits = a.flush().hits;
  assert.equal(hits[0].text, 'in 0x1');
  assert.equal(hits[0].bt, undefined);
});

test('a value stored on `this` in onEnter is there in onLeave', () => {
  const a = load();
  a.api.add(spec({ code: '({ onEnter(log, args) { this.name = "f:" + args[0]; }, onLeave(log) { log(this.name); } })' }));
  a.call(a.attached[0]);
  assert.equal(a.flush().hits[0].text, 'f:0x1');
});

test('a handler that throws is reported as an error line and the target carries on', () => {
  const a = load();
  a.api.add(spec({ code: '({ onEnter(log, args) { args[9].readUtf8String(); }, onLeave(log) { log("still here"); } })' }));
  assert.doesNotThrow(() => a.call(a.attached[0]));
  const hits = a.flush().hits;
  assert.equal(hits[0].error, true);
  assert.match(hits[0].text, /^onEnter threw: /);
  assert.equal(hits[1].text, 'still here');
});

// A hot function must not flood the app.
test('more hits than fit in a batch are dropped and counted; the call count stays exact', () => {
  const a = load();
  a.api.add(spec({ code: '({ onEnter(log) { log("x"); } })', backtrace: false }));
  for (let i = 0; i < 1000; i++) a.call(a.attached[0]);
  assert.equal(a.timers.length, 1); // one flush pending, not a thousand
  const m = a.flush();
  assert.equal(m.hits.length, 200);
  assert.equal(m.dropped, 800);
  assert.deepEqual(m.counts, { h1: 1000 });
  // The next batch starts clean.
  a.call(a.attached[0]);
  const next = a.flush();
  assert.equal(next.hits.length, 1);
  assert.equal(next.dropped, 0);
});

test('handlers are checked when the hook is added', () => {
  const a = load();
  assert.throws(() => a.api.add(spec({ code: '({ onEnter(log) { ' })), /does not compile/);
  assert.throws(() => a.api.add(spec({ code: '42' })), /handler must be/);
  assert.throws(() => a.api.add(spec({ code: '({})' })), /needs an onEnter or an onLeave/);
  assert.throws(() => a.api.add(spec({ code: '({ onEnter: 5 })' })), /onEnter must be a function/);
  assert.equal(a.attached.length, 0);
  // A bare function is an onEnter.
  a.api.add(spec({ code: 'function (log, args) { log("bare"); }' }));
  a.call(a.attached[0]);
  assert.equal(a.flush().hits[0].text, 'bare');
});

test('update: a new handler is used from the next call without re-hooking; a broken one leaves the old in place', () => {
  const a = load();
  a.api.add(spec());
  a.api.update('h1', { code: '({ onEnter(log) { log("new"); } })' });
  assert.equal(a.attached.length, 1);
  a.call(a.attached[0]);
  assert.deepEqual(a.flush().hits.map((h) => h.text), ['new']);
  assert.throws(() => a.api.update('h1', { code: '({' }), /does not compile/);
  a.call(a.attached[0]);
  assert.deepEqual(a.flush().hits.map((h) => h.text), ['new']);
  assert.throws(() => a.api.update('nope', { code: HANDLER }), /No such hook: nope/);
});

test('enable off detaches, on re-attaches; remove detaches and forgets', () => {
  const a = load();
  a.api.add(spec());
  assert.equal(j(a.api.enable('h1', false)).enabled, false);
  assert.equal(a.attached[0].detached, true);
  assert.equal(j(a.api.enable('h1', true)).enabled, true);
  assert.equal(a.attached.length, 2);
  assert.equal(a.api.remove('h1'), true);
  assert.equal(a.attached[1].detached, true);
  assert.equal(a.api.remove('h1'), false);
  assert.throws(() => a.api.enable('h1', true), /No such hook/);
});

test('add with enabled false prepares the hook without attaching it', () => {
  const a = load();
  assert.equal(j(a.api.add(spec({ enabled: false }))).enabled, false);
  assert.equal(a.attached.length, 0);
  a.api.enable('h1', true);
  assert.equal(a.attached.length, 1);
});

test('adding an id again replaces that hook instead of hooking twice', () => {
  const a = load();
  a.api.add(spec());
  a.api.add(spec({ code: '({ onEnter(log) { log("second"); } })' }));
  assert.equal(a.attached[0].detached, true);
  assert.equal(a.attached.length, 2);
});

test('a function that cannot be hooked is an error and leaves no hook behind', () => {
  const a = load({ attachThrows: true });
  assert.throws(() => a.api.add(spec()), /Could not hook 0x7ff010: unable to intercept function/);
  assert.equal(a.api.remove('h1'), false);
});

test('there is a limit on the number of hooks', () => {
  const a = load();
  for (let i = 0; i < 200; i++) a.api.add(spec({ id: 'h' + i }));
  assert.throws(() => a.api.add(spec({ id: 'one-more' })), /Too many hooks/);
  a.api.remove('h0');
  assert.doesNotThrow(() => a.api.add(spec({ id: 'one-more' })));
});

test('symbolicate: names for backtrace addresses, capped', () => {
  const a = load();
  assert.deepEqual(j(a.api.symbolicate(['0x400100', '0x7ff200', '0x9000'])), [
    { address: '0x400100', name: 'target.exe!parse_config', where: 'target.exe+0x100' },
    { address: '0x7ff200', name: '', where: 'kernel32.dll+0x200' },
    { address: '0x9000', name: '', where: '0x9000' },
  ]);
  assert.equal(a.api.symbolicate(Array.from({ length: 100 }, (_, i) => '0x' + (0x1000 + i).toString(16))).length, 64);
});
