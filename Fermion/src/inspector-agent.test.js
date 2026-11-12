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
  writeByteArray(bytes) {
    if (Ptr.unwritable) throw new Error('access violation');
    Ptr.writes.push([this.toString(), Array.from(bytes)]);
  }
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
Ptr.writes = [];
Ptr.unwritable = false;

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
  const intervals = [];
  const stalker = {
    followed: [], unfollowed: [], opts: null, flushed: 0, excluded: [],
    exclude: (range) => { stalker.excluded.push(range.base.toString() + '+' + range.size); },
    follow: (tid, opts) => { if (over.followThrows || (over.unfollowable || []).includes(tid)) throw new Error('unable to follow'); stalker.followed.push(tid); stalker.opts = opts; stalker.optsBy[tid] = opts; },
    optsBy: {}, collected: 0,
    parse: (raw) => raw,
    unfollow: (tid) => { stalker.unfollowed.push(tid); },
    flush: () => { stalker.flushed++; },
    garbageCollect: () => { stalker.collected++; },
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
    ...over.Memory,
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
    setInterval: (fn, ms) => { intervals.push({ fn, ms }); return intervals.length; }, clearInterval: (id) => { if (intervals[id - 1]) intervals[id - 1].cancelled = true; },
    Stalker: stalker, setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].cancelled = true; },
  });
  vm.runInContext(SOURCE, ctx);
  return Object.assign({ scans, stalker, timers, intervals }, ctx.rpc.exports);
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

// ---- writing memory ----
// What was done to the fake target, in order.
function writer(protection, over = {}) {
  Ptr.writes = []; Ptr.reads = []; Ptr.unwritable = false;
  const log = [];
  const a = load({
    Process: { findRangeByAddress: () => (protection === null ? null : { base: new Ptr(0x1000), size: 0x1000, protection }) },
    Memory: {
      patchCode: (p, size, apply) => { log.push(['patchCode', p.toString(), size]); apply(p); },
      protect: (p, size, prot) => { log.push(['protect', p.toString(), size, prot]); return over.protectFails ? false : true; },
    },
  });
  return { a, log };
}

test('write: bytes go to writable memory as they are, and what was there comes back', () => {
  const { a, log } = writer('rw-');
  assert.deepEqual(j(a.write('0x1010', 'deadbeef')), { address: '0x1010', size: 4, original: '10111213', written: 'deadbeef', protection: 'rw-' });
  assert.deepEqual(Ptr.writes, [['0x1010', [0xde, 0xad, 0xbe, 0xef]]]);
  assert.deepEqual(log, []); // no protection change needed
  assert.deepEqual(Ptr.reads[0], ['0x1010', 4]); // read before it is overwritten
});

test('write: code is patched through Memory.patchCode, whatever its write permission', () => {
  for (const prot of ['r-x', 'rwx']) {
    const { a, log } = writer(prot);
    assert.equal(a.write('0x1020', '9090').protection, prot);
    assert.deepEqual(log, [['patchCode', '0x1020', 2]]);
    assert.deepEqual(Ptr.writes, [['0x1020', [0x90, 0x90]]]);
  }
});

test('write: read-only data is made writable for the write and put back as it was', () => {
  const { a, log } = writer('r--');
  a.write('0x1030', '00');
  assert.deepEqual(log, [['protect', '0x1030', 1, 'rw-'], ['protect', '0x1030', 1, 'r--']]);
  assert.deepEqual(Ptr.writes, [['0x1030', [0]]]);
});

test('write: the protection is put back even when the write faults', () => {
  const { a, log } = writer('r--');
  Ptr.unwritable = true;
  assert.throws(() => a.write('0x1030', '00'), /Cannot write memory at 0x1030: access violation/);
  assert.deepEqual(log.map((l) => l[3]), ['rw-', 'r--']);
  Ptr.unwritable = false;
});

test('write: memory whose protection cannot be changed is refused, untouched', () => {
  const { a } = writer('r--', { protectFails: true });
  assert.throws(() => a.write('0x1030', '00'), /could not be made writable/);
  assert.deepEqual(Ptr.writes, []);
});

test('write: outside every range, unreadable memory, or past the end of the range is refused, untouched', () => {
  assert.throws(() => writer(null).a.write('0x1010', '00'), /is not in mapped memory/);
  assert.throws(() => writer('---').a.write('0x1010', '00'), /is not readable/);
  const { a } = writer('rw-');
  assert.throws(() => a.write('0x1ffe', '000000'), /crosses the end of its range/);
  a.write('0x1ffe', '0000'); // exactly to the end is fine
  assert.deepEqual(Ptr.writes, [['0x1ffe', [0, 0]]]);
});

test('write: only 1..4096 whole hex bytes', () => {
  const { a } = writer('rw-');
  for (const bad of ['', 'd', 'xyz1', 'dead beef', 5, null, '00'.repeat(4097)]) assert.throws(() => a.write('0x1010', bad), /hex bytes/);
  assert.equal(a.write('0x1000', '00'.repeat(4096)).size, 4096);
  assert.equal(Ptr.writes.length, 1);
});

// ---- recording coverage ----
// Stalker reports compiled blocks as [start, end] pairs.
const blk = (start, size) => [new Ptr(start), new Ptr(start + size)];
// coverStop waits a moment for Stalker's last events: let that timer fire.
async function stopCover(a) {
  const p = a.coverStop();
  const settle = a.timers.filter((t) => t.ms === 150 && !t.cancelled).pop();
  if (settle) settle.fn();
  return j(await p);
}
const ntdll = { name: 'ntdll.dll', base: new Ptr(0x7fe000), size: 0x1000, path: 'C:/Windows/System32/ntdll.dll', enumerateExports: () => [], enumerateImports: () => [] };

test('coverStart: every thread but Frida\'s own is followed for compiled blocks; new threads are picked up', () => {
  const threads = [{ id: 11, state: 'waiting', context: {} }, { id: 12, state: 'running', context: {} }, { id: 99, state: 'running', context: {} }];
  const a = load({ Process: { enumerateThreads: () => threads } });
  assert.deepEqual(j(a.coverStart('all', { mode: 'all' })), { recording: true, threads: 2, all: true, maxSeconds: 600, maxBlocks: 2000000, scope: { mode: 'all', module: '' }, excluded: 0 });
  assert.deepEqual(a.stalker.followed, [11, 12]); // 99 is the agent's own thread
  assert.deepEqual(a.stalker.opts.events, { compile: true });
  assert.equal(a.intervals.length, 1);
  threads.push({ id: 13, state: 'running', context: {} });
  a.intervals[0].fn();
  a.intervals[0].fn(); // not followed twice
  assert.deepEqual(a.stalker.followed, [11, 12, 13]);
});

test('coverStart: one thread only; unknown threads, Frida\'s own thread and a second recording are refused', () => {
  const a = load();
  assert.throws(() => a.coverStart(404, { mode: 'all' }), /thread/i);
  assert.throws(() => a.coverStart(99, { mode: 'all' }), /Frida's own thread/);
  assert.equal(a.coverStart(11, { mode: 'all' }).threads, 1);
  assert.deepEqual(a.stalker.followed, [11]);
  assert.equal(a.intervals.length, 0); // one thread: nothing to pick up
  assert.throws(() => a.coverStart('all', { mode: 'all' }), /already being recorded/);
  assert.throws(() => a.follow(12, { mode: 'all' }), /Coverage is being recorded/);
});

test('coverStart: a follow in progress is not disturbed; a thread Stalker cannot take is skipped; none at all is an error', () => {
  const a = load();
  a.follow(11, { mode: 'all' });
  assert.throws(() => a.coverStart('all', { mode: 'all' }), /being followed/);
  const b = load({ unfollowable: [11] });
  assert.equal(b.coverStart('all', { mode: 'all' }).threads, 1);
  const c = load({ followThrows: true });
  assert.throws(() => c.coverStart('all', { mode: 'all' }), /No thread could be followed/);
  assert.deepEqual(j(await_(c)), { recorded: false });
});
function await_(a) { return a.coverStop(); } // nothing recorded: answers at once

test('coverStart: the scope excludes modules like a follow, and a different scope needs a fresh agent', () => {
  const a = load({ modules: [ntdll] });
  assert.equal(a.coverStart('all', { mode: 'app' }).excluded, 2); // both fakes live under C:/Windows
  a.coverStop();
  a.timers.filter((t) => t.ms === 150).pop().fn();
  assert.throws(() => a.coverStart('all', { mode: 'all' }), /FERMION_RESCOPE/);
  assert.throws(() => load().coverStart('all', { mode: 'module', module: 'nope.dll' }), /Module not found/);
});

test('coverStop: blocks are counted once, sorted into modules, and summarised', async () => {
  const a = load({ modules: [ntdll] });
  a.coverStart('all', { mode: 'all' });
  a.stalker.optsBy[11].onReceive([blk(0x7ff010, 4), blk(0x7ff020, 6), blk(0x7fe100, 2)]);
  a.stalker.optsBy[12].onReceive([blk(0x7ff010, 4), blk(0x500, 3)]); // one again, one outside every module
  const r = await stopCover(a);
  assert.deepEqual(a.stalker.unfollowed, [11, 12]);
  assert.equal(a.stalker.collected, 1);
  assert.equal(a.intervals[0].cancelled, true);
  assert.equal(typeof r.seconds, 'number');
  delete r.seconds; delete r.drcovBytes;
  assert.deepEqual(r, {
    recorded: true, threads: 2, all: true, blocks: 3, bytes: 12, unmapped: 1, overflow: false, endedBy: 'stop', scope: { mode: 'all', module: '' }, moduleCount: 2,
    modules: [
      { name: 'kernel32.dll', path: 'C:/Windows/kernel32.dll', blocks: 2, bytes: 10 },
      { name: 'ntdll.dll', path: 'C:/Windows/System32/ntdll.dll', blocks: 1, bytes: 2 },
    ],
  });
  // The same summary is given again until another recording starts.
  assert.equal((await stopCover(a)).blocks, 3);
});

test('coverData: the drcov file has a module table and one 8-byte record per block', async () => {
  const a = load({ modules: [ntdll] });
  a.coverStart('all', { mode: 'all' });
  a.stalker.optsBy[11].onReceive([blk(0x7ff020, 6), blk(0x7ff010, 4), blk(0x7fe100, 2)]);
  const r = await stopCover(a);
  const file = Buffer.from(new Uint8Array(a.coverData('drcov')));
  assert.equal(file.length, r.drcovBytes);
  const marker = 'BB Table: 3 bbs\n';
  const at = file.indexOf(marker) + marker.length;
  assert.equal(file.subarray(0, at).toString('utf8'), [
    'DRCOV VERSION: 2',
    'DRCOV FLAVOR: fermion',
    'Module Table: version 2, count 2',
    'Columns: id, base, end, entry, checksum, timestamp, path',
    ' 0, 0x00000000007ff000, 0x0000000000800000, 0x0000000000000000, 0x00000000, 0x00000000, C:/Windows/kernel32.dll',
    ' 1, 0x00000000007fe000, 0x00000000007ff000, 0x0000000000000000, 0x00000000, 0x00000000, C:/Windows/System32/ntdll.dll',
    'BB Table: 3 bbs',
    '',
  ].join('\n'));
  const table = file.subarray(at);
  assert.equal(table.length, 24);
  const rec = (i) => [table.readUInt32LE(i * 8), table.readUInt16LE(i * 8 + 4), table.readUInt16LE(i * 8 + 6)];
  assert.deepEqual([rec(0), rec(1), rec(2)], [[0x10, 4, 0], [0x20, 6, 0], [0x100, 2, 1]]); // offset, size, module id; sorted
});

test('coverData: the text report names modules and functions, with the units explained', async () => {
  const a = load({ modules: [ntdll] });
  a.coverStart(11, { mode: 'all' });
  a.stalker.optsBy[11].onReceive([blk(0x7ff010, 4), blk(0x7ff020, 6), blk(0x7fe100, 2), blk(0x500, 3)]);
  await stopCover(a);
  const text = a.coverData('text');
  assert.match(text, /^# Code coverage recorded by Fermion \(Frida\)\n/);
  assert.match(text, /Recorded: [\d.]+ s on 1 thread; scope: every module; ended by: the operator/);
  assert.match(text, /Total: 3 basic blocks \(12 bytes of code\) in 2 modules; 1 more blocks ran outside every module \(generated code\)/);
  assert.match(text, /Every offset is hexadecimal and relative to the base address of its module/);
  assert.match(text, /\| kernel32\.dll \| 2 \| 10 \| C:\/Windows\/kernel32\.dll \|/);
  assert.match(text, /### kernel32\.dll: 2 blocks in 1 named function\n\n- CreateFileW \+0x10: 2 blocks, 10 bytes/);
  assert.match(text, /### ntdll\.dll: 1 blocks in 1 named function/);
});

test('coverData: nothing recorded yet is an error; an unknown format is the drcov file', async () => {
  const a = load();
  assert.throws(() => a.coverData('drcov'), /No coverage has been recorded/);
  a.coverStart(11, { mode: 'all' });
  assert.throws(() => a.coverData('text'), /No coverage has been recorded/); // not until it is stopped
  await stopCover(a);
  assert.equal(typeof a.coverData('text'), 'string');
});

test('a recording stops by itself at the time limit, and at the block limit, and is still there to collect', async () => {
  const a = load();
  a.coverStart(11, { mode: 'all' });
  a.stalker.optsBy[11].onReceive([blk(0x7ff010, 4)]);
  const limit = a.timers.find((t) => t.ms === 600000);
  limit.fn();
  assert.deepEqual(a.stalker.unfollowed, [11]);
  const r = await stopCover(a);
  assert.equal(r.endedBy, 'limit');
  assert.equal(r.blocks, 1);
  a.coverStart(11, { mode: 'all' }); // and another can start
  assert.equal((await stopCover(a)).blocks, 0);
});

test('coverStop: blocks inside a module the scope leaves out are dropped, wherever the thread happened to be', async () => {
  const app = { name: 'app.exe', base: new Ptr(0x400000), size: 0x1000, path: 'C:/Program Files/App/app.exe', enumerateExports: () => [], enumerateImports: () => [] };
  const a = load({ modules: [ntdll, app] });
  a.coverStart(11, { mode: 'app' });
  a.stalker.optsBy[11].onReceive([blk(0x400010, 4), blk(0x7fe100, 2), blk(0x7ff010, 4)]); // app, ntdll, kernel32
  const r = await stopCover(a);
  assert.deepEqual(r.modules.map((m) => [m.name, m.blocks]), [['app.exe', 1]]);
  assert.equal(r.blocks, 1);
  const b = load({ modules: [ntdll, app] });
  b.coverStart(11, { mode: 'module', module: 'ntdll.dll' });
  b.stalker.optsBy[11].onReceive([blk(0x400010, 4), blk(0x7fe100, 2)]);
  assert.deepEqual((await stopCover(b)).modules.map((m) => m.name), ['ntdll.dll']);
});
