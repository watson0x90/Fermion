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
  assert.deepEqual(await ev('ptr(0x1000)'), { ok: true, type: 'NativePointer', text: '0x1000' });
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
