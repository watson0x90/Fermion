// Unit tests for the REPL helper agent (src/tools/repl-agent.js). It normally
// runs inside the target process under Frida; here it is loaded into a plain
// `vm` context with a stub `rpc` so its evaluate/describe logic is testable.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SOURCE = fs.readFileSync(path.join(__dirname, 'tools', 'repl-agent.js'), 'utf8');

// Stand-ins for Frida's value types: they stringify like the real ones.
class NativePointer { constructor(v) { this.v = v; } toString() { return '0x' + this.v.toString(16); } toJSON() { return this.toString(); } }
class Int64 { constructor(v) { this.v = v; } toString() { return String(this.v); } }

function load() {
  const ctx = vm.createContext({ rpc: {}, NativePointer, Int64, ptr: (v) => new NativePointer(v), console });
  vm.runInContext(SOURCE, ctx);
  return (code) => ctx.rpc.exports.evaluate(code);
}

test('values come back as ok with a type and a printable text', async () => {
  const ev = load();
  assert.deepEqual(await ev('1 + 2'), { ok: true, type: 'number', text: '3' });
  assert.deepEqual(await ev('"hi"'), { ok: true, type: 'string', text: '"hi"' });
  assert.deepEqual(await ev('undefined'), { ok: true, type: 'undefined', text: 'undefined' });
  assert.deepEqual(await ev('null'), { ok: true, type: 'null', text: 'null' });
  assert.deepEqual(await ev('true'), { ok: true, type: 'boolean', text: 'true' });
  assert.equal((await ev('10n ** 20n')).text, '100000000000000000000n');
});

test('objects and arrays are pretty-printed; Frida value types print as themselves', async () => {
  const ev = load();
  const obj = await ev('({ name: "kernel32.dll", base: ptr(0x7ff0), n: [1, 2] })');
  assert.equal(obj.ok, true);
  assert.equal(obj.type, 'object');
  assert.equal(obj.text, '{\n  "name": "kernel32.dll",\n  "base": "0x7ff0",\n  "n": [\n    1,\n    2\n  ]\n}');
  assert.deepEqual(await ev('ptr(0x1000)'), { ok: true, type: 'NativePointer', text: '0x1000', tree: { t: 'ptr', v: '0x1000' } });
  assert.deepEqual(await ev('new Int64(5)'), { ok: true, type: 'Int64', text: '5' });
  assert.equal((await ev('[ptr(1), ptr(2)]')).text, '[\n  "0x1",\n  "0x2"\n]');
});

test('functions, symbols, and values JSON cannot represent still print', async () => {
  const ev = load();
  assert.equal((await ev('(function foo(a) { return a; })')).text, 'function foo(a) { return a; }');
  assert.equal((await ev('Symbol("s")')).text, 'Symbol(s)');
  const cyc = await ev('var a = {}; a.self = a; a');
  assert.equal(cyc.ok, true);
  assert.match(cyc.text, /\[Circular\]/);
  assert.equal((await ev('({ big: 5n, u: undefined, f: function () {} })')).text,
    '{\n  "big": "5n",\n  "u": "undefined",\n  "f": "[Function]"\n}');
});

test('state persists between entries (var and assignments to globals)', async () => {
  const ev = load();
  await ev('var counter = 41');
  assert.equal((await ev('counter + 1')).text, '42');
  await ev('globalThis.hooks = []');
  assert.equal((await ev('hooks.length')).text, '0');
});

test('a thrown error comes back as not-ok with its message and stack, not as a rejection', async () => {
  const ev = load();
  const r = await ev('null.x');
  assert.equal(r.ok, false);
  assert.match(r.error, /TypeError/);
  assert.equal(typeof r.stack, 'string');
  const syn = await ev('1 +');
  assert.equal(syn.ok, false);
  assert.match(syn.error, /SyntaxError/);
  const str = await ev('throw "plain string"');
  assert.deepEqual({ ok: str.ok, error: str.error }, { ok: false, error: 'plain string' });
});

test('a promise result is awaited; a rejected one is an error', async () => {
  const ev = load();
  assert.deepEqual(await ev('Promise.resolve(7)'), { ok: true, type: 'number', text: '7' });
  const r = await ev('Promise.reject(new Error("nope"))');
  assert.equal(r.ok, false);
  assert.match(r.error, /nope/);
});

test('huge results are truncated so they cannot flood the UI', async () => {
  const ev = load();
  const r = await ev('"x".repeat(500000)');
  assert.equal(r.ok, true);
  assert.ok(r.text.length < 70000, 'text length ' + r.text.length);
  assert.match(r.text, /truncated/);
});

test('an object referenced twice is printed twice, not flagged as circular', async () => {
  const ev = load();
  const r = await ev('var o = { n: 1 }; ({ a: o, b: o })');
  assert.equal(r.text, '{\n  "a": {\n    "n": 1\n  },\n  "b": {\n    "n": 1\n  }\n}');
  assert.match((await ev('var c = { k: {} }; c.k.back = c; c')).text, /\[Circular\]/);
});

test('a class instance prints its properties instead of "[object Object]"', async () => {
  const ev = load();
  const r = await ev('new (class Hook { constructor() { this.target = "open"; this.hits = 3; } })()');
  assert.equal(r.type, 'Hook');
  assert.equal(r.text, '{\n  "target": "open",\n  "hits": 3\n}');
  const nested = await ev('({ h: new (class Hook { constructor() { this.x = 1; } })() })');
  assert.equal(nested.text, '{\n  "h": {\n    "x": 1\n  }\n}');
});

test('a property getter that throws does not fail the whole result', async () => {
  const ev = load();
  const r = await ev('({ fine: 1, get bad() { throw new Error("boom"); } })');
  assert.equal(r.ok, true);
  assert.match(r.text, /"fine": 1/);
  assert.match(r.text, /"bad": "\[Thrown: boom\]"/);
});

test('very deep or very large structures are cut off rather than walked in full', async () => {
  const ev = load();
  const deep = await ev('var d = {}; var cur = d; for (var i = 0; i < 200; i++) { cur.next = {}; cur = cur.next; } d');
  assert.equal(deep.ok, true);
  assert.match(deep.text, /\[…\]/);
  const wide = await ev('Array.from({ length: 200000 }, function (_, i) { return { i: i }; })');
  assert.equal(wide.ok, true);
  assert.ok(wide.text.length < 70000);
});

// ---- tab completion + help introspection (called through evaluate) ----
// The REPL panel calls these as `__fermion.complete("…")` / `__fermion.inspect("…")`.
const names = (r) => JSON.parse(r.text).items.map((i) => i.name);

test('__fermion is a hidden global: usable, but not listed among the globals', async () => {
  const ev = load();
  assert.equal((await ev('typeof __fermion.complete')).text, '"function"');
  assert.equal((await ev('Object.keys(globalThis).indexOf("__fermion")')).text, '-1');
});

test('complete: members of an object by prefix, with where the replacement starts', async () => {
  const ev = load();
  await ev('var Proc = { id: 1, enumerateModules: function () {}, enumerateThreads: function () {}, arch: "x64" }');
  const r = JSON.parse((await ev('__fermion.complete("x = Proc.enum")')).text);
  assert.deepEqual(r.items, [{ name: 'enumerateModules', kind: 'function' }, { name: 'enumerateThreads', kind: 'function' }]);
  assert.equal(r.from, 'x = Proc.'.length);
  assert.deepEqual(names(await ev('__fermion.complete("Proc.")')), ['arch', 'enumerateModules', 'enumerateThreads', 'id']);
  assert.equal(JSON.parse((await ev('__fermion.complete("Proc.a")')).text).items[0].kind, 'property');
});

test('complete: global names by prefix; nothing for an empty prefix', async () => {
  const ev = load();
  await ev('var hookCount = 0; var hookTable = {}');
  assert.deepEqual(names(await ev('__fermion.complete("1 + hook")')), ['hookCount', 'hookTable']);
  assert.deepEqual(names(await ev('__fermion.complete("")')), []);
  assert.deepEqual(names(await ev('__fermion.complete("foo(")')), []);
});

test('complete: inherited members are offered; Object.prototype noise only when asked for by prefix', async () => {
  const ev = load();
  await ev('var inst = new (class Base { baseMethod() {} })(); inst.own = 1');
  const all = names(await ev('__fermion.complete("inst.")'));
  assert.ok(all.includes('own') && all.includes('baseMethod'));
  assert.ok(!all.includes('hasOwnProperty') && !all.includes('constructor'));
  assert.deepEqual(names(await ev('__fermion.complete("inst.hasOwn")')), ['hasOwnProperty']);
});

test('complete: never calls anything — a chain containing a call or index is not completed', async () => {
  const ev = load();
  await ev('var calls = 0; function sideEffect() { calls++; return { value: 1 }; } var arr = [{ v: 1 }]');
  assert.deepEqual(names(await ev('__fermion.complete("sideEffect().va")')), []);
  assert.deepEqual(names(await ev('__fermion.complete("arr[0].v")')), []);
  assert.equal((await ev('calls')).text, '0');
});

test('complete: an unknown or broken base gives no candidates rather than an error', async () => {
  const ev = load();
  assert.deepEqual(names(await ev('__fermion.complete("nope.x")')), []);
  await ev('var trap = { get boom() { throw new Error("no"); } }');
  assert.deepEqual(names(await ev('__fermion.complete("trap.boom.x")')), []);
  assert.deepEqual(names(await ev('__fermion.complete("undefinedThing.")')), []);
});

test('complete: the list is capped', async () => {
  const ev = load();
  await ev('var wide = {}; for (var i = 0; i < 2000; i++) wide["k" + i] = i');
  const r = JSON.parse((await ev('__fermion.complete("wide.k")')).text);
  assert.equal(r.items.length, 200);
  assert.equal(r.truncated, true);
});

test('inspect: what a name is, and its members with kind and argument count', async () => {
  const ev = load();
  await ev('var Proc = { id: 42, arch: "x64", enumerateModules: function () {}, findModuleByName: function (name) { return name; } }');
  const r = JSON.parse((await ev('__fermion.inspect("Proc")')).text);
  assert.equal(r.found, true);
  assert.equal(r.type, 'object');
  assert.deepEqual(r.members, [
    { name: 'arch', kind: 'property', type: 'string' },
    { name: 'enumerateModules', kind: 'function', arity: 0 },
    { name: 'findModuleByName', kind: 'function', arity: 1 },
    { name: 'id', kind: 'property', type: 'number' },
  ]);
  const fn = JSON.parse((await ev('__fermion.inspect("Proc.findModuleByName")')).text);
  assert.deepEqual({ found: fn.found, type: fn.type, arity: fn.arity }, { found: true, type: 'function', arity: 1 });
  const val = JSON.parse((await ev('__fermion.inspect("Proc.id")')).text);
  assert.deepEqual({ found: val.found, type: val.type, value: val.value }, { found: true, type: 'number', value: '42' });
});

test('inspect: unknown names and non-names are reported as not found, without evaluating code', async () => {
  const ev = load();
  await ev('var ran = 0; function go() { ran++; }');
  assert.equal(JSON.parse((await ev('__fermion.inspect("nope")')).text).found, false);
  assert.equal(JSON.parse((await ev('__fermion.inspect("go()")')).text).found, false);
  assert.equal(JSON.parse((await ev('__fermion.inspect("a; go()")')).text).found, false);
  assert.equal((await ev('ran')).text, '0');
});

test('globals: the names available at the prompt (for the help overview)', async () => {
  const ev = load();
  await ev('var mine = 1');
  const r = JSON.parse((await ev('__fermion.globals()')).text);
  assert.ok(r.includes('mine') && r.includes('ptr') && r.includes('NativePointer'));
  assert.ok(!r.includes('__fermion'));
});

// ---- structured results (the REPL's expandable values) ----
test('tree: an object comes with a tree of its values; pointers stay pointers, at any depth', async () => {
  const ev = load();
  const r = await ev('({ name: "kernel32.dll", base: ptr(0x7ff0), size: 4096, ok: true, none: null, missing: undefined, list: [1, ptr(2)] })');
  assert.deepEqual(r.tree, {
    t: 'obj', label: 'Object', n: 7, kids: [
      { k: 'name', v: { t: 'str', v: 'kernel32.dll' } },
      { k: 'base', v: { t: 'ptr', v: '0x7ff0' } },
      { k: 'size', v: { t: 'num', v: '4096' } },
      { k: 'ok', v: { t: 'bool', v: 'true' } },
      { k: 'none', v: { t: 'null', v: 'null' } },
      { k: 'missing', v: { t: 'undef', v: 'undefined' } },
      { k: 'list', v: { t: 'arr', n: 2, kids: [{ k: '0', v: { t: 'num', v: '1' } }, { k: '1', v: { t: 'ptr', v: '0x2' } }] } },
    ],
  });
  // The printed text is unchanged.
  assert.match(r.text, /"name": "kernel32.dll"/);
});

test('tree: plain values need no tree', async () => {
  const ev = load();
  for (const code of ['1 + 2', '"hi"', 'true', 'null', 'undefined', 'new Int64(5)', '(function f() {})']) {
    assert.equal((await ev(code)).tree, undefined, code);
  }
});

test('tree: class instances are named; functions, Frida numbers and big integers print as themselves', async () => {
  const ev = load();
  const r = await ev('(function () { class Mod { constructor() { this.n = new Int64(5); this.f = function go() {}; this.big = 10n; } } return new Mod(); })()');
  assert.equal(r.tree.label, 'Mod');
  assert.deepEqual(r.tree.kids, [
    { k: 'n', v: { t: 'other', v: '5' } },
    { k: 'f', v: { t: 'fn', v: 'go()' } },
    { k: 'big', v: { t: 'num', v: '10n' } },
  ]);
});

test('tree: containers list at most 100 children and say how many more there are', async () => {
  const ev = load();
  const arr = (await ev('Array.from({ length: 350 }, (_, i) => i)')).tree;
  assert.equal(arr.n, 350);
  assert.equal(arr.kids.length, 100);
  assert.equal(arr.more, 250);
  const obj = (await ev('Object.fromEntries(Array.from({ length: 130 }, (_, i) => ["k" + i, i]))')).tree;
  assert.equal(obj.kids.length, 100);
  assert.equal(obj.more, 30);
});

test('tree: cycles, great depth and a getter that throws end a branch instead of the result', async () => {
  const ev = load();
  const cyc = (await ev('(function () { var a = { name: "a" }; a.self = a; return a; })()')).tree;
  assert.deepEqual(cyc.kids[1], { k: 'self', v: { t: 'cut', v: '[Circular]' } });
  const deep = (await ev('(function () { var root = {}, cur = root; for (var i = 0; i < 40; i++) { cur.next = {}; cur = cur.next; } return root; })()')).tree;
  let node = deep; let depth = 0;
  while (node.t === 'obj') { node = node.kids[0].v; depth++; }
  assert.deepEqual(node, { t: 'cut', v: '…' });
  assert.ok(depth <= 8, 'depth ' + depth);
  const thrower = (await ev('({ get bad() { throw new Error("nope"); }, fine: 1 })')).tree;
  assert.deepEqual(thrower.kids, [{ k: 'bad', v: { t: 'other', v: '[Thrown: nope]' } }, { k: 'fine', v: { t: 'num', v: '1' } }]);
});

test('tree: a huge structure is cut to a bounded number of nodes, and long strings are clipped', async () => {
  const ev = load();
  const r = await ev('Array.from({ length: 90 }, () => Array.from({ length: 90 }, () => ({ a: 1 })))');
  const count = (n) => 1 + (n.kids ? n.kids.reduce((s, k) => s + count(k.v), 0) : 0);
  assert.ok(count(r.tree) <= 6000, 'nodes ' + count(r.tree));
  assert.ok(JSON.stringify(r.tree).length < 400000);
  const long = (await ev('({ s: "x".repeat(50000) })')).tree;
  assert.equal(long.kids[0].v.v.length, 2001);
});
