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
  compare(o) { return this.v < o.v ? -1 : this.v > o.v ? 1 : 0; }
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
  const mods = () => [kernel, ...(over.modules || [])]; // read each time: modules can load later
  const Process = {
    enumerateModules: () => mods(),
    findModuleByName: (n) => mods().find((m) => m.name.toLowerCase() === String(n).toLowerCase()) || null,
    findModuleByAddress: (a) => mods().find((m) => a.v >= m.base.v && a.v < m.base.v + BigInt(m.size)) || null,
    // By default every address is inside one big readable range.
    findRangeByAddress: () => ({ base: new Ptr(0), size: 2 ** 40, protection: 'rw-' }),
    enumerateThreads: () => threads,
    getCurrentThreadId: () => 99,
    enumerateRanges: (prot) => [
      { base: new Ptr(0x1000), size: 0x1000, protection: prot, file: { path: 'C:/a.dll' } },
      { base: new Ptr(0x9000), size: 0x2000, protection: prot },
      { base: new Ptr(0xdead000), size: 0x1000, protection: prot },
    ],
    ...over.Process,
  };
  const scans = [];
  const timers = [];
  const stalker = {
    followed: [], unfollowed: [], opts: null, flushed: 0, excluded: [],
    exclude: (range) => { stalker.excluded.push(range.base.toString() + '+' + range.size); },
    follow: (tid, opts) => { if (over.followThrows) throw new Error('unable to follow'); stalker.followed.push(tid); stalker.opts = opts; },
    unfollow: (tid) => { stalker.unfollowed.push(tid); },
    flush: () => { stalker.flushed++; },
    garbageCollect: () => {},
  };
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
    Instruction: { parse: (a) => {
      if (over.undecodableAt !== undefined && a.v === BigInt(over.undecodableAt)) throw new Error('invalid instruction');
      const n = Number(a.v & 0xffn);
      const insn = { address: a, next: a.add(4), size: 4, mnemonic: 'mov', opStr: 'rax, rbx', groups: [] };
      if (n === 0x08) { insn.mnemonic = 'call'; insn.opStr = '0x7ff123'; insn.groups = ['call']; }
      if (n === 0x0c) { insn.mnemonic = 'jne'; insn.opStr = '0x500'; insn.groups = ['jump', 'branch_relative']; }
      if (n === 0x10) { insn.mnemonic = 'call'; insn.opStr = 'qword ptr [rip + 0x20]'; insn.groups = ['call']; }
      if (n === 0x18) { insn.mnemonic = 'jmp'; insn.opStr = '0x7ff140'; insn.groups = ['jump']; }
      if (n === 0x14) { insn.mnemonic = 'ret'; insn.opStr = ''; insn.groups = ['ret']; }
      return insn;
    } },
    Stalker: stalker, setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].cancelled = true; },
  });
  vm.runInContext(SOURCE, ctx);
  return Object.assign({ scans, stalker, timers }, ctx.rpc.exports);
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

// ---- following a thread with Stalker ----
test('follow: starts Stalker on the thread, asking only for a summary of calls', () => {
  const a = load();
  assert.deepEqual(j(a.follow(11)), { following: true, threadId: 11, maxSeconds: 15, scope: { mode: 'all', module: '' }, excluded: 0 });
  assert.deepEqual(a.stalker.excluded, []);
  assert.deepEqual(a.stalker.followed, [11]);
  assert.deepEqual(j(a.stalker.opts.events), { call: true });
  assert.equal(typeof a.stalker.opts.onCallSummary, 'function');
  assert.equal(a.stalker.opts.onReceive, undefined); // no per-event stream
});

test('unfollow: stops, and returns the functions called, most-called first, with names', () => {
  const a = load();
  a.follow(11);
  a.stalker.opts.onCallSummary({ '0x7ff123': 3, '0x500': 1 });
  a.stalker.opts.onCallSummary({ '0x7ff123': 4, '0x7ff200': 2 });
  const r = j(a.unfollow());
  assert.deepEqual(a.stalker.unfollowed, [11]);
  assert.equal(a.stalker.flushed, 1);
  assert.equal(r.following, false);
  assert.equal(r.threadId, 11);
  assert.equal(r.calls, 10);
  assert.equal(r.total, 3);
  assert.equal(r.truncated, false);
  assert.deepEqual(r.items, [
    { address: '0x7ff123', name: 'kernel32.dll!CreateFileW', module: 'kernel32.dll', count: 7 },
    { address: '0x7ff200', name: 'kernel32.dll!CreateFileW', module: 'kernel32.dll', count: 2 },
    { address: '0x500', name: '0x500', module: '', count: 1 },
  ]);
  // Totals per module, most calls first; '' is code that belongs to no module.
  assert.deepEqual(r.modules, [{ name: 'kernel32.dll', calls: 9, functions: 2 }, { name: '', calls: 1, functions: 1 }]);
  assert.deepEqual(r.scope, { mode: 'all', module: '' });
});

test('follow: one thread at a time; an unknown thread and the agent\'s own thread are refused', () => {
  const a = load();
  a.follow(11);
  assert.throws(() => a.follow(12), /already following thread 11/i);
  const b = load();
  assert.throws(() => b.follow(404), /Thread not found: 404/);
  assert.throws(() => b.follow(99), /Frida's own thread/i);
  assert.deepEqual(b.stalker.followed, []);
});

test('unfollow with nothing being followed returns an empty result instead of throwing', () => {
  assert.deepEqual(j(load().unfollow()), { following: false, threadId: null, calls: 0, total: 0, truncated: false, items: [], modules: [], scope: null, endedBy: 'none' });
});

test('follow: a failure to start leaves nothing being followed', () => {
  const a = load({ followThrows: true });
  assert.throws(() => a.follow(11), /unable to follow/);
  assert.doesNotThrow(() => { a.followThrows = false; });
  assert.equal(j(a.unfollow()).threadId, null);
});

// A forgotten follow must not stalk the thread for ever.
test('follow: stops by itself after the time limit, and the result is still there to collect', () => {
  const a = load();
  a.follow(11);
  a.stalker.opts.onCallSummary({ '0x7ff123': 5 });
  assert.equal(a.timers.length, 1);
  assert.equal(a.timers[0].ms, 15000);
  a.timers[0].fn();                         // the limit fires
  assert.deepEqual(a.stalker.unfollowed, [11]);
  const r = j(a.unfollow());                // collect afterwards
  assert.equal(r.endedBy, 'limit');
  assert.equal(r.calls, 5);
  assert.deepEqual(a.stalker.unfollowed, [11]); // not unfollowed twice
  // and a new follow can start
  assert.equal(j(a.follow(12)).threadId, 12);
});

test('follow: a thread calling thousands of distinct functions is capped and says so', () => {
  const a = load();
  a.follow(11);
  const many = {};
  for (let i = 0; i < 6000; i++) many['0x' + (0x900000 + i).toString(16)] = 1;
  a.stalker.opts.onCallSummary(many);
  const r = a.unfollow();
  assert.equal(r.truncated, true);
  assert.ok(r.items.length <= 300, 'items ' + r.items.length);
  assert.equal(r.calls, 6000);
});

// ---- limiting what a follow covers ----
const APP = [
  { name: 'target.exe', base: new Ptr(0x400000), size: 0x10000, path: 'C:\\Tools\\target.exe' },
  // A folder merely named "windows" somewhere in the path is not the system directory.
  { name: 'plugin.dll', base: new Ptr(0x500000), size: 0x1000, path: 'C:/Tools/windows/plugin.dll' },
  { name: 'ntdll.dll', base: new Ptr(0x600000), size: 0x1000, path: 'C:\\WINDOWS\\SYSTEM32\\ntdll.dll' },
  { name: 'libc.so.6', base: new Ptr(0x700000), size: 0x1000, path: '/usr/lib/x86_64-linux-gnu/libc.so.6' },
  { name: 'libSystem.B.dylib', base: new Ptr(0x710000), size: 0x1000, path: '/usr/lib/libSystem.B.dylib' },
  { name: 'Foundation', base: new Ptr(0x720000), size: 0x1000, path: '/System/Library/Frameworks/Foundation.framework/Foundation' },
];

test('follow, skipping system libraries: only those are excluded from Stalker', () => {
  const a = load({ modules: APP });
  const r = j(a.follow(11, { mode: 'app', module: '' }));
  assert.deepEqual(r.scope, { mode: 'app', module: '' });
  assert.equal(r.excluded, 5);
  assert.deepEqual(a.stalker.excluded, ['0x7ff000+4096', '0x600000+4096', '0x700000+4096', '0x710000+4096', '0x720000+4096']);
  assert.deepEqual(a.stalker.followed, [11]);
  assert.deepEqual(j(a.unfollow()).scope, { mode: 'app', module: '' });
});

test('follow, one module only: every other module is excluded; the name is matched as the target does', () => {
  const a = load({ modules: APP });
  const r = j(a.follow(11, { mode: 'module', module: 'TARGET.EXE' }));
  assert.deepEqual(r.scope, { mode: 'module', module: 'target.exe' });
  assert.equal(r.excluded, 6);
  assert.ok(!a.stalker.excluded.includes('0x400000+65536'));
  assert.equal(a.stalker.excluded.length, 6);
});

test('follow, one module only: a module that is not loaded is refused before anything is excluded or followed', () => {
  const a = load({ modules: APP });
  assert.throws(() => a.follow(11, { mode: 'module', module: 'nope.dll' }), /Module not found: nope\.dll/);
  assert.deepEqual(a.stalker.excluded, []);
  assert.deepEqual(a.stalker.followed, []);
});

// Stalker cannot un-exclude a range, so a script that has excluded for one
// scope must not be used for a different one: it asks to be replaced.
test('follow: the same scope again excludes nothing twice; a different scope asks for a fresh agent', () => {
  const a = load({ modules: APP });
  a.follow(11, { mode: 'app', module: '' });
  a.unfollow();
  assert.equal(j(a.follow(11, { mode: 'app', module: '' })).excluded, 5);
  assert.equal(a.stalker.excluded.length, 5);
  a.unfollow();
  for (const other of [{ mode: 'all', module: '' }, { mode: 'module', module: 'target.exe' }, undefined]) {
    assert.throws(() => a.follow(11, other), /FERMION_RESCOPE/);
  }
  assert.deepEqual(a.stalker.followed, [11, 11]);
  assert.equal(a.stalker.excluded.length, 5);
  assert.equal(j(a.unfollow()).threadId, null); // nothing was left being followed
});

test('follow: everything first, then a narrower scope, needs no fresh agent', () => {
  const a = load({ modules: APP });
  a.follow(11);
  a.unfollow();
  assert.equal(j(a.follow(11, { mode: 'module', module: 'plugin.dll' })).excluded, 6);
});

test('follow: a module loaded since the last follow of the same scope is excluded too', () => {
  const mods = APP.slice(0, 3);
  const a = load({ modules: mods });
  a.follow(11, { mode: 'app', module: '' });
  a.unfollow();
  mods.push(APP[3]);
  assert.equal(j(a.follow(11, { mode: 'app', module: '' })).excluded, 3);
  assert.deepEqual(a.stalker.excluded, ['0x7ff000+4096', '0x600000+4096', '0x700000+4096']);
});

test('unfollow: module totals cover every function counted, not only the ones listed', () => {
  const a = load({ modules: APP });
  a.follow(11);
  const many = {};
  for (let i = 0; i < 500; i++) many['0x' + (0x400000 + i * 16).toString(16)] = 2;
  many['0x600010'] = 5000;
  a.stalker.opts.onCallSummary(many);
  const r = j(a.unfollow());
  assert.equal(r.items.length, 300);
  assert.deepEqual(r.modules, [{ name: 'ntdll.dll', calls: 5000, functions: 1 }, { name: 'target.exe', calls: 1000, functions: 500 }]);
});

// ---- disassembly ----
test('disassemble: instructions with address, bytes and text; direct call and jump targets are named', () => {
  const a = load();
  const r = j(a.disassemble('0x7ff100', 7));
  assert.equal(r.address, '0x7ff100');
  assert.equal(r.next, '0x7ff11c');
  assert.equal(r.stopped, '');
  assert.equal(r.where, 'kernel32.dll+0x100');
  assert.deepEqual(r.items.map((i) => [i.address, i.size, i.text]), [
    ['0x7ff100', 4, 'mov rax, rbx'], ['0x7ff104', 4, 'mov rax, rbx'], ['0x7ff108', 4, 'call 0x7ff123'],
    ['0x7ff10c', 4, 'jne 0x500'], ['0x7ff110', 4, 'call qword ptr [rip + 0x20]'], ['0x7ff114', 4, 'ret'], ['0x7ff118', 4, 'jmp 0x7ff140'],
  ]);
  assert.equal(r.items[0].bytes, '00010203');
  assert.deepEqual([r.items[2].kind, r.items[2].target, r.items[2].targetName], ['call', '0x7ff123', 'kernel32.dll!CreateFileW']);
  assert.deepEqual([r.items[3].kind, r.items[3].target, r.items[3].targetName], ['jump', '0x500', '0x500']);
  // A jump says where it lands, not which function it is in (usually its own).
  assert.deepEqual([r.items[6].kind, r.items[6].target, r.items[6].targetName], ['jump', '0x7ff140', 'kernel32.dll+0x140']);
  // An indirect call has no target to follow.
  assert.deepEqual([r.items[4].kind, r.items[4].target], ['call', null]);
  assert.equal(r.items[5].kind, 'ret');
  assert.equal(r.items[0].kind, '');
});

test('disassemble: stops at the end of the readable range instead of reading past it', () => {
  const a = load({ Process: { findRangeByAddress: () => ({ base: new Ptr(0x7ff000), size: 0x110, protection: 'r-x' }) } });
  const r = j(a.disassemble('0x7ff100', 50));
  assert.equal(r.items.length, 4);
  assert.equal(r.stopped, 'end');
  assert.equal(r.next, '0x7ff110');
});

test('disassemble: bytes that are not an instruction end the listing and say so', () => {
  const r = j(load({ undecodableAt: 0x7ff108 }).disassemble('0x7ff100', 50));
  assert.equal(r.items.length, 2);
  assert.equal(r.stopped, 'undecodable');
  assert.equal(r.next, '0x7ff108');
});

test('disassemble: unmapped or unreadable memory is refused before anything is read', () => {
  Ptr.reads.length = 0;
  assert.throws(() => load({ Process: { findRangeByAddress: () => null } }).disassemble('0x10', 5), /not in readable memory/i);
  assert.throws(() => load({ Process: { findRangeByAddress: () => ({ base: new Ptr(0), size: 0x1000, protection: '---' }) } }).disassemble('0x10', 5), /not in readable memory/i);
  assert.equal(Ptr.reads.length, 0);
});

test('disassemble: the count is capped', () => {
  assert.equal(j(load().disassemble('0x7ff100', 100000)).items.length, 200);
});
