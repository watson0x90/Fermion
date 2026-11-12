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
  sub(o) { return new Ptr(this.v - (o instanceof Ptr ? o.v : BigInt(o))); }
  add(o) { return new Ptr(this.v + (o instanceof Ptr ? o.v : BigInt(o))); }
  readByteArray(n) {
    Ptr.reads.push([this.toString(), n]);
    if (Ptr.unreadableFrom !== null && this.v + BigInt(n) > Ptr.unreadableFrom) throw new Error('access violation');
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = Number((this.v + BigInt(i)) & 0xffn);
    return b.buffer;
  }
}
Ptr.unreadableFrom = null;
Ptr.reads = [];

// Like Frida's CpuContext: registers are reachable by name and through toJSON,
// but are not own enumerable properties (for-in finds none).
function cpuContext(regs) {
  const c = Object.create({ toJSON() { return regs; } });
  for (const k of Object.keys(regs)) Object.defineProperty(c, k, { get: () => regs[k], enumerable: false });
  return c;
}

// `over.matchesFor(base, size, pattern)` decides what a scan of one chunk finds;
// `over.clock` replaces Date.now so the time budget can be exercised.
function load(over = {}) {
  const kernel = {
    name: 'kernel32.dll', base: new Ptr(0x7ff000), size: 0x1000, path: 'C:/Windows/kernel32.dll',
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
    // By default every address is inside one big readable range.
    findRangeByAddress: () => ({ base: new Ptr(0), size: 2 ** 40, protection: 'rw-' }),
    enumerateThreads: () => threads,
    enumerateRanges: (prot) => [
      { base: new Ptr(0x1000), size: 0x1000, protection: prot, file: { path: 'C:/a.dll' } },
      { base: new Ptr(0x9000), size: 0x2000, protection: prot },
      { base: new Ptr(0xdead000), size: 0x1000, protection: prot },
    ],
    ...over.Process,
  };
  const scans = [];
  const matchesFor = over.matchesFor || ((base, size, pattern) => {
    if (base.v === 0xdead000n) throw new Error('access violation');
    return base.v === 0x1000n ? [{ address: new Ptr(0x1010), size: pattern.split(' ').length }] : [];
  });
  const Memory = {
    // Async scan: reports matches until the callback says 'stop'.
    scan: (base, size, pattern, cb) => {
      scans.push([base.toString(), size]);
      const found = matchesFor(base, size, pattern); // may throw synchronously
      Promise.resolve().then(() => {
        for (const m of found) { if (cb.onMatch(m.address, m.size) === 'stop') break; }
        cb.onComplete();
      });
    },
  };
  const ctx = vm.createContext({
    rpc: {}, Process, Memory, ptr: (v) => new Ptr(v),
    Thread: { backtrace: (context, mode) => { if (mode === 'accurate' && over.accurateFails) throw new Error('no unwind info'); return [new Ptr(0x7ff123), new Ptr(0x500)]; } },
    Backtracer: { ACCURATE: 'accurate', FUZZY: 'fuzzy' },
    DebugSymbol: { fromAddress: (a) => (a.v === 0x500n ? { address: a, name: null, moduleName: null } : { address: a, name: 'CreateFileW', moduleName: 'kernel32.dll' }) },
    JSON, Date: over.clock ? { now: over.clock } : Date, Uint8Array, Math, Promise,
  });
  vm.runInContext(SOURCE, ctx);
  return Object.assign({ scans }, ctx.rpc.exports);
}
// Results cross rpc as JSON; compare them the same way.
const j = (v) => JSON.parse(JSON.stringify(v));

test('modules: name, base (hex string), size, path', () => {
  assert.deepEqual(j(load().modules()), {
    items: [{ name: 'kernel32.dll', base: '0x7ff000', size: 0x1000, path: 'C:/Windows/kernel32.dll' }],
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
  assert.deepEqual(r.items[0], { base: '0x1000', size: 0x1000, protection: 'r--', file: 'C:/a.dll' });
  assert.equal(r.items[1].file, '');
});

test('read: bytes as hex; size is clamped to 1..4096', () => {
  const a = load();
  assert.deepEqual(j(a.read('0x10', 4)), { address: '0x10', size: 4, requested: 4, hex: '10111213' });
  assert.equal(a.read('0x0', 999999).size, 4096);
  assert.equal(a.read('0x0', 0).size, 1);
});

// Touching a Windows stack guard page clears its guard bit and the thread dies
// when its stack next grows. Frida does not list guard pages as ranges, so an
// address outside every readable range must be refused WITHOUT being read.
test('read: an address outside every readable range is refused without touching memory', () => {
  const a = load({ Process: { findRangeByAddress: () => null } });
  Ptr.reads.length = 0;
  assert.throws(() => a.read('0xc6327f1000', 256), /not readable/i);
  assert.deepEqual(Ptr.reads, []);
});

test('read: a range without read permission is refused without touching memory', () => {
  const a = load({ Process: { findRangeByAddress: () => ({ base: new Ptr(0x1000), size: 0x1000, protection: '---' }) } });
  Ptr.reads.length = 0;
  assert.throws(() => a.read('0x1000', 16), /not readable/i);
  assert.deepEqual(Ptr.reads, []);
});

test('read: never reads past the end of the range the address is in', () => {
  const a = load({ Process: { findRangeByAddress: () => ({ base: new Ptr(0x1000), size: 0x1000, protection: 'r--' }) } });
  Ptr.reads.length = 0;
  const r = a.read('0x1fc0', 256); // only 0x40 bytes left in the range
  assert.equal(r.size, 64);
  assert.equal(r.requested, 256);
  assert.deepEqual(Ptr.reads, [['0x1fc0', 64]]);
});

test('read: if memory faults anyway it returns the readable part; wholly unreadable is an error', () => {
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

test('scan: matches across ranges, skipping ranges that fault', async () => {
  const r = j(await load().scan('4d 5a ?? 00', 'r--'));
  assert.deepEqual(r.items, [{ address: '0x1010', size: 4, where: '0x1010' }]);
  assert.equal(r.rangesTotal, 3);
  assert.equal(r.rangesScanned, 2); // the third range threw and was skipped
  assert.equal(r.truncated, false);
});

// One enormous range full of matches must not be collected in full: the scan
// stops inside the range as soon as the cap is reached.
test('scan: stops inside a range at the match limit, without visiting every match', async () => {
  let visited = 0;
  const endless = { [Symbol.iterator]: function* () { for (let i = 0; i < 5000000; i++) { visited++; yield { address: new Ptr(0x1000 + i), size: 2 }; } } };
  const a = load({ matchesFor: () => endless });
  const r = await a.scan('00 00', 'r--');
  assert.equal(r.items.length, 500);
  assert.equal(r.truncated, true);
  assert.equal(r.stopped, 'limit');
  assert.ok(visited <= 501, 'visited ' + visited + ' matches');
  assert.equal(a.scans.length, 1); // and no further ranges were scanned
});

test('scan: a huge range is scanned in chunks, and the time budget is checked between chunks', async () => {
  let now = 0;
  const big = { Process: { enumerateRanges: (prot) => [{ base: new Ptr(0x100000000), size: 512 * 1024 * 1024, protection: prot }, { base: new Ptr(0x900000000), size: 4096, protection: prot }] } };
  const a = load({ ...big, clock: () => now, matchesFor: () => { now += 3000; return []; } }); // each chunk "takes" 3 s
  const r = await a.scan('4d 5a', 'r--');
  assert.equal(r.stopped, 'time');
  assert.equal(r.truncated, true);
  // 512 MB in one call would have been a single scan; chunking gives the
  // budget (8 s) a chance to stop it after 3 chunks.
  assert.equal(a.scans.length, 3);
  assert.ok(a.scans.every(([, size]) => size <= 17 * 1024 * 1024), 'chunk sizes ' + a.scans.map((s) => s[1]));
});

test('scan: chunks overlap by pattern length - 1 so a match across a chunk boundary is not missed', async () => {
  const big = { Process: { enumerateRanges: (prot) => [{ base: new Ptr(0x100000000), size: 40 * 1024 * 1024, protection: prot }] } };
  const a = load(big);
  await a.scan('4d 5a 90 00', 'r--');
  const CH = 16 * 1024 * 1024;
  assert.deepEqual(a.scans, [['0x100000000', CH + 3], ['0x101000000', CH + 3], ['0x102000000', 8 * 1024 * 1024]]);
});
