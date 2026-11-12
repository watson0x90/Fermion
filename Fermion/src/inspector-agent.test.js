// Unit tests for the Inspector agent (src/tools/inspector-agent.js), loaded
// into a `vm` context with small fakes of the Frida APIs it reads from.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SOURCE = fs.readFileSync(path.join(__dirname, 'tools', 'inspector-agent.js'), 'utf8');

class Ptr {
  constructor(v) { this.v = BigInt(v); }
  // Like NativePointer: toString() is '0x…', toString(16) is bare hex.
  toString(radix) { return (radix === 16 ? '' : '0x') + this.v.toString(16); }
  toJSON() { return this.toString(); }
  sub(o) { return new Ptr(this.v - o.v); }
  readByteArray(n) {
    if (Ptr.unreadableFrom !== null && this.v + BigInt(n) > Ptr.unreadableFrom) throw new Error('access violation');
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = Number((this.v + BigInt(i)) & 0xffn);
    return b.buffer;
  }
}
Ptr.unreadableFrom = null;

// Like Frida's CpuContext: registers are reachable by name and through toJSON,
// but are not own enumerable properties (for-in finds none).
function cpuContext(regs) {
  const c = Object.create({ toJSON() { return regs; } });
  for (const k of Object.keys(regs)) Object.defineProperty(c, k, { get: () => regs[k], enumerable: false });
  return c;
}

function load(over = {}) {
  const kernel = {
    name: 'kernel32.dll', base: new Ptr(0x7ff000), size: 0x1000, path: 'C:\\Windows\\kernel32.dll',
    enumerateExports: () => [{ type: 'function', name: 'CreateFileW', address: new Ptr(0x7ff010) }, { type: 'variable', name: 'g', address: new Ptr(0x7ff800) }],
    enumerateImports: () => [{ type: 'function', name: 'NtCreateFile', module: 'ntdll.dll', address: new Ptr(0x7fe000) }, { name: 'noType', address: null }],
  };
  const threads = [
    { id: 11, state: 'waiting', context: cpuContext({ pc: new Ptr(0x7ff123), sp: new Ptr(0x10000), rax: new Ptr(1) }) },
    { id: 12, state: 'running', name: 'worker', context: { pc: new Ptr(0x500), sp: new Ptr(0x20000) } },
  ];
  const Process = {
    enumerateModules: () => [kernel],
    findModuleByName: (n) => (n === 'kernel32.dll' ? kernel : null),
    findModuleByAddress: (a) => (a.v >= 0x7ff000n && a.v < 0x800000n ? kernel : null),
    enumerateThreads: () => threads,
    enumerateRanges: (prot) => [
      { base: new Ptr(0x1000), size: 0x1000, protection: prot, file: { path: 'C:\\a.dll' } },
      { base: new Ptr(0x9000), size: 0x2000, protection: prot },
      { base: new Ptr(0xdead000), size: 0x1000, protection: prot },
    ],
    ...over.Process,
  };
  const Memory = {
    scanSync: (base, size, pattern) => {
      if (base.v === 0xdead000n) throw new Error('access violation');
      return base.v === 0x1000n ? [{ address: new Ptr(0x1010), size: pattern.split(' ').length }] : [];
    },
    ...over.Memory,
  };
  const ctx = vm.createContext({
    rpc: {}, Process, Memory, ptr: (v) => new Ptr(v),
    Thread: { backtrace: (context, mode) => { if (mode === 'accurate' && over.accurateFails) throw new Error('no unwind info'); return [new Ptr(0x7ff123), new Ptr(0x500)]; } },
    Backtracer: { ACCURATE: 'accurate', FUZZY: 'fuzzy' },
    DebugSymbol: { fromAddress: (a) => (a.v === 0x500n ? { address: a, name: null, moduleName: null } : { address: a, name: 'CreateFileW', moduleName: 'kernel32.dll' }) },
    JSON,
    Date, Uint8Array, Math,
  });
  vm.runInContext(SOURCE, ctx);
  return ctx.rpc.exports;
}
// Results cross rpc as JSON; compare them the same way.
const j = (v) => JSON.parse(JSON.stringify(v));

test('modules: name, base (hex string), size, path', () => {
  assert.deepEqual(j(load().modules()), {
    items: [{ name: 'kernel32.dll', base: '0x7ff000', size: 0x1000, path: 'C:\\Windows\\kernel32.dll' }],
    total: 1, truncated: false,
  });
});

test('exports and imports of a module; an unknown module is an error', () => {
  const a = load();
  assert.deepEqual(j(a.exports('kernel32.dll')).items[0], { type: 'function', name: 'CreateFileW', address: '0x7ff010' });
  assert.deepEqual(j(a.imports('kernel32.dll')).items, [
    { type: 'function', name: 'NtCreateFile', module: 'ntdll.dll', address: '0x7fe000' },
    { type: '', name: 'noType', module: '', address: null },
  ]);
  assert.throws(() => a.exports('nope.dll'), /Module not found: nope\.dll/);
});

test('long lists are capped and say so', () => {
  const many = Array.from({ length: 20005 }, (_, i) => ({ type: 'function', name: 'f' + i, address: new Ptr(i) }));
  const a = load({ Process: { findModuleByName: () => ({ enumerateExports: () => many }) } });
  const r = a.exports('big.dll');
  assert.equal(r.items.length, 20000);
  assert.equal(r.total, 20005);
  assert.equal(r.truncated, true);
});

test('threads: id, state, pc, where (module+offset or bare address), registers as strings', () => {
  const r = j(load().threads());
  assert.deepEqual(r.items[0], {
    id: 11, name: '', state: 'waiting', pc: '0x7ff123', where: 'kernel32.dll+0x123',
    registers: { pc: '0x7ff123', sp: '0x10000', rax: '0x1' },
  });
  assert.equal(r.items[1].where, '0x500');
  assert.equal(r.items[1].name, 'worker');
});

test('backtrace: frames with where + symbol; falls back to the fuzzy backtracer; unknown thread is an error', () => {
  const frames = j(load().backtrace(11)).items;
  assert.deepEqual(frames, [
    { address: '0x7ff123', where: 'kernel32.dll+0x123', symbol: 'kernel32.dll!CreateFileW' },
    { address: '0x500', where: '0x500', symbol: '' },
  ]);
  assert.equal(j(load({ accurateFails: true }).backtrace(11)).items.length, 2);
  assert.throws(() => load().backtrace(999), /Thread not found: 999/);
});

test('ranges: base, size, protection, backing file', () => {
  const r = j(load().ranges('r--'));
  assert.deepEqual(r.items[0], { base: '0x1000', size: 0x1000, protection: 'r--', file: 'C:\\a.dll' });
  assert.equal(r.items[1].file, '');
});

test('read: bytes as hex; size is clamped to 1..4096', () => {
  const a = load();
  assert.deepEqual(j(a.read('0x10', 4)), { address: '0x10', size: 4, requested: 4, hex: '10111213' });
  assert.equal(a.read('0x0', 999999).size, 4096);
  assert.equal(a.read('0x0', 0).size, 1);
});

test('read: at the edge of unreadable memory it returns what is readable; wholly unreadable is an error', () => {
  const a = load();
  try {
    Ptr.unreadableFrom = 0x1040n; // readable up to 0x1040
    const r = a.read('0x1000', 256);
    assert.equal(r.size, 64);
    assert.equal(r.requested, 256);
    Ptr.unreadableFrom = 0n;
    assert.throws(() => a.read('0x1000', 256), /Cannot read memory at 0x1000/);
  } finally { Ptr.unreadableFrom = null; }
});

test('scan: matches across ranges, skipping ranges that fault', () => {
  const r = j(load().scan('4d 5a ?? 00', 'r--'));
  assert.deepEqual(r.items, [{ address: '0x1010', size: 4, where: '0x1010' }]);
  assert.equal(r.rangesTotal, 3);
  assert.equal(r.rangesScanned, 2); // the third range threw and was skipped
  assert.equal(r.truncated, false);
});

test('scan: stops at the match limit and says so', () => {
  const lots = Array.from({ length: 400 }, (_, i) => ({ address: new Ptr(0x1000 + i), size: 1 }));
  const r = load({ Memory: { scanSync: () => lots } }).scan('00', 'r--');
  assert.equal(r.items.length, 500);
  assert.equal(r.truncated, true);
  assert.equal(r.stopped, 'limit');
});
