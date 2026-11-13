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
  and(o) { return new Ptr(this.v & o.v); }
  not() { return new Ptr(~this.v & 0xffffffffffffffffn); }
  isNull() { return this.v === 0n; }
  readPointer() { return new Ptr(Ptr.pointers[this.toString()] ?? 0); }
  readU32() { return Ptr.pointers[this.toString()] ?? 0; }
  readU16() { return Ptr.pointers[this.toString()] ?? 0; }
  writeByteArray(bytes) {
    if (Ptr.unwritable) throw new Error('access violation');
    Ptr.writes.push([this.toString(), Array.from(bytes)]);
  }
  readByteArray(n) {
    Ptr.reads.push([this.toString(), n]);
    if (Ptr.unreadableFrom !== null && this.v + BigInt(n) > Ptr.unreadableFrom) throw new Error('access violation');
    // Real bytes, where a test has put some (Ptr.memory); a made-up pattern elsewhere.
    const region = (Ptr.memory || []).find((r) => this.v >= r.base && this.v + BigInt(n) <= r.base + BigInt(r.data.length));
    if (region) { const at = Number(this.v - region.base); return region.data.slice(at, at + n).buffer; }
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = Number((this.v + BigInt(i)) & 0xffn);
    return b.buffer;
  }
}
Ptr.unreadableFrom = null;
Ptr.reads = [];
Ptr.writes = [];
Ptr.memory = null; // [{ base, data }]: regions with real bytes
Ptr.pointers = {}; // address -> the pointer stored there
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
  Ptr.memory = null;
  const kernel = {
    name: 'kernel32.dll', base: new Ptr(0x7ff000), size: 0x1000, path: 'C:/Windows/kernel32.dll',
    enumerateExports: () => [{ type: 'function', name: 'CreateFileW', address: new Ptr(0x7ff010) }, { type: 'variable', name: 'g', address: new Ptr(0x7ff800) }],
    enumerateImports: () => [{ type: 'function', name: 'NtCreateFile', module: 'ntdll.dll', address: new Ptr(0x7fe000) }, { name: 'noType', address: null }],
  };
  const threads = [
    { id: 11, state: 'waiting', context: cpuContext({ pc: new Ptr(0x7ff123), sp: new Ptr(0x10000), rax: new Ptr(1) }) },
    { id: 12, state: 'running', name: 'worker', context: { pc: new Ptr(0x500), sp: new Ptr(0x20000) } },
  ];
  // Like Frida's Thread objects: hardware watchpoints are set per thread. What was
  // set and unset is noted, as is the exception handler and the thread 'running'.
  const cpu = { thread: 99, handler: null, handlers: 0, set: [], unset: [] };
  const withWatchpoints = (t) => {
    if (!t.setHardwareWatchpoint) {
      t.setHardwareWatchpoint = (id, address, size, conditions) => { if ((over.hwRefuses || []).includes(t.id)) throw new Error('unable to set'); cpu.set.push([t.id, id, address.toString(), size, conditions]); };
      t.unsetHardwareWatchpoint = (id) => { cpu.unset.push([t.id, id]); };
    }
    return t;
  };
  const mods = () => [kernel, ...(over.modules || [])]; // read each time: modules can load later
  const Process = {
    enumerateModules: () => mods(),
    findModuleByName: (n) => mods().find((m) => m.name.toLowerCase() === String(n).toLowerCase()) || null,
    findModuleByAddress: (a) => mods().find((m) => a.v >= m.base.v && a.v < m.base.v + BigInt(m.size)) || null,
    // By default every address is inside one big readable range.
    findRangeByAddress: () => ({ base: new Ptr(0), size: 2 ** 40, protection: 'rw-' }),
    enumerateThreads: () => (over.threads || threads).map(withWatchpoints),
    getCurrentThreadId: () => cpu.thread,
    platform: 'linux',
    arch: 'x64',
    pointerSize: 8,
    setExceptionHandler: (fn) => { cpu.handler = fn; cpu.handlers++; },
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
    // Like Memory.scanSync, over the regions with real bytes: a pattern of hex bytes.
    scanSync: (base, size, pattern) => {
      const want = pattern.split(' ').map((b) => parseInt(b, 16));
      const region = (Ptr.memory || []).find((r) => base.v >= r.base && base.v < r.base + BigInt(r.data.length));
      if (!region) return [];
      const from = Number(base.v - region.base);
      const found = [];
      for (let i = from; i + want.length <= Math.min(region.data.length, from + size); i++) {
        if (want.every((b, k) => region.data[i + k] === b)) found.push({ address: new Ptr(region.base + BigInt(i)), size: want.length });
      }
      return found;
    },
    alloc: (n) => { const at = nextAlloc; nextAlloc += Math.ceil(n / 16) * 16 + 16; return new Ptr(at); },
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
  // Like MemoryAccessMonitor: one set of ranges armed at a time.
  const monitor = {
    armed: null, enables: 0, disables: 0,
    enable: (ranges, cb) => { if (over.armThrows && over.armThrows(monitor.enables)) throw new Error('unable to protect'); monitor.armed = { ranges: ranges.map((r) => [r.base.toString(), r.size]), cb: cb.onAccess }; monitor.enables++; },
    disable: () => { monitor.disables++; monitor.armed = null; },
  };
  // Like Interceptor and the export lookups: a hooked function is known by name.
  const hooked = {};
  let nextExport = 0x6000000;
  const exported = (name) => Object.assign(new Ptr(nextExport += 16), { exportName: name });
  const ALLOCATORS = ['malloc', 'calloc', 'realloc', 'free', 'aligned_alloc', 'memalign', 'posix_memalign', 'RtlAllocateHeap', 'RtlReAllocateHeap', 'RtlFreeHeap'].filter((n) => !(over.missing || []).includes(n));
  for (const m of mods()) if (!m.findExportByName) m.findExportByName = (n) => (!over.noAllocators && /^Rtl/.test(n) && m.name === 'ntdll.dll' ? exported(n) : null);
  // kernel32's heap functions, when a test supplies them (over.winapi: name -> function).
  kernel.findExportByName = (n) => (over.winapi && over.winapi[n] ? exported(n) : null);
  let nextAlloc = 0x70000000;
  const ctx = vm.createContext({
    Interceptor: { attach: (address, cbs) => { const h = { cbs, detached: false }; hooked[address.exportName] = h; return { detach: () => { h.detached = true; } }; } },
    NativeFunction: function (address) { return over.winapi[address.exportName]; },
    Module: { findGlobalExportByName: (n) => (!over.noAllocators && ALLOCATORS.includes(n) && !/^Rtl/.test(n) ? exported(n) : null) },
    ModuleMap: function () { this.update = () => {}; this.find = (a) => Process.findModuleByAddress(a); },
    Map, Number, String, parseInt,
    MemoryAccessMonitor: monitor,
    rpc: {}, Process, Memory, ptr: (v) => new Ptr(v),
    Thread: { backtrace: (context, mode) => { if (mode === 'accurate' && over.accurateFails) throw new Error('no unwind info'); if (over.onBacktrace) over.onBacktrace(); return context && context.stack ? context.stack : [new Ptr(0x7ff123), new Ptr(0x500)]; } },
    Backtracer: { ACCURATE: 'accurate', FUZZY: 'fuzzy' },
    DebugSymbol: { fromAddress: (a) => (a.v === 0x500n ? { address: a, name: null, moduleName: null } : { address: a, name: 'CreateFileW', moduleName: 'kernel32.dll' }) },
    JSON, Date: over.clock ? { now: over.clock } : Date, Uint8Array, Math, Promise,
    Instruction: { parse: (a) => {
      if (over.insns) { // a test's own instructions: nothing else decodes
        const known = over.insns[Number(a.v)];
        if (!known) throw new Error('invalid instruction');
        return { address: a, next: a.add(known.size), size: known.size, mnemonic: known.mnemonic, opStr: known.opStr, groups: [] };
      }
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
  return Object.assign({ scans, stalker, timers, intervals, monitor, hooked, cpu }, ctx.rpc.exports);
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

// ---- watching memory ----
// A process with a heap (rw-), read-only data, code, and two thread stacks.
const WATCH_RANGES = [
  { base: new Ptr(0x10000 - 0x1000), size: 0x2000, protection: 'rw-' },   // thread 11's stack (sp 0x10000)
  { base: new Ptr(0x20000 - 0x1000), size: 0x2000, protection: 'rw-' },   // thread 12's stack
  { base: new Ptr(0x500000), size: 0x3000, protection: 'rw-' },            // heap
  { base: new Ptr(0x600000), size: 0x1000, protection: 'r--' },            // constants
  { base: new Ptr(0x7ff000), size: 0x1000, protection: 'r-x' },            // code
  { base: new Ptr(0x800000), size: 0x1000, protection: '---' },
];
function watchable(over = {}) {
  return load({ ...over, Process: { pageSize: 0x1000, findRangeByAddress: (a) => WATCH_RANGES.find((r) => a.v >= r.base.v && a.v < r.base.v + BigInt(r.size)) || null, ...(over.Process || {}) } });
}
const access = (a, op, from, address, thread = 11) => a.monitor.armed.cb({ operation: op, from: new Ptr(from), address: new Ptr(address), threadId: thread, context: {} });
const fire = (a, ms) => { const t = a.timers.filter((x) => x.ms === ms && !x.cancelled).pop(); t.cancelled = true; t.fn(); };

test('watchStart: the bytes are armed and described', () => {
  const a = watchable();
  assert.deepEqual(j(a.watchStart('0x500ff8', 8)), { watching: true, address: '0x500ff8', size: 8, mode: 'sampled', reason: 'hardware watchpoints are used on Windows only', threads: 0, pages: 1, pageSize: 4096, maxSeconds: 600, maxHits: 200000, protection: 'rw-' });
  assert.deepEqual(a.monitor.armed.ranges, [['0x500ff8', 8]]);
  assert.equal(watchable().watchStart('0x500ffc', 8).pages, 2); // the bytes cross a page edge
  assert.equal(watchable().watchStart('0x600010', 4).protection, 'r--'); // constants can be watched too
});

test('watchStart: what cannot be watched safely is refused before anything is armed', () => {
  const a = watchable();
  assert.throws(() => a.watchStart('0x900000', 8), /not in mapped memory/);
  assert.throws(() => a.watchStart('0x800000', 8), /not readable/);
  assert.throws(() => a.watchStart('0x7ff010', 8), /is code/);
  assert.throws(() => a.watchStart('0x502ffc', 8), /crosses the end of its range/);
  assert.throws(() => a.watchStart('0x10010', 8), /stack of thread 11/);
  assert.throws(() => a.watchStart('0x1f800', 8), /stack of thread 12/);
  for (const bad of [0, -1, 4097, 1.5, '8', null]) assert.throws(() => a.watchStart('0x500000', bad), /1\.\.4096 bytes/);
  assert.equal(a.monitor.enables, 0);
  a.watchStart('0x500000', 8);
  assert.throws(() => a.watchStart('0x500100', 8), /already being watched/i);
});

test('watch: an access is counted by the place it comes from, with thread, last address and call stack', () => {
  const a = watchable();
  a.watchStart('0x500010', 8);
  access(a, 'read', 0x7ff123, 0x500010, 11);
  fire(a, 5);
  access(a, 'read', 0x7ff123, 0x500014, 12);
  fire(a, 5);
  access(a, 'write', 0x7ff123, 0x500017, 11);
  const r = j(a.watchHits());
  assert.equal(r.watching, true);
  assert.equal(r.hits, 3);
  assert.equal(r.near, 0);
  assert.equal(r.places, 2);
  assert.deepEqual(r.items.map((i) => [i.op, i.from, i.hits, i.last, i.threads]), [['read', '0x7ff123', 2, '0x500014', [11, 12]], ['write', '0x7ff123', 1, '0x500017', [11]]]);
  assert.equal(r.items[0].where, 'kernel32.dll+0x123');
  assert.equal(r.items[0].symbol, 'kernel32.dll!CreateFileW');
  assert.deepEqual(r.items[0].frames, [{ address: '0x7ff123', where: 'kernel32.dll+0x123', symbol: 'kernel32.dll!CreateFileW' }, { address: '0x500', where: '0x500', symbol: '' }]);
});

test('watch: an access to other bytes on the same page is counted apart', () => {
  const a = watchable();
  a.watchStart('0x500010', 8);
  access(a, 'read', 0x7ff200, 0x50000f); // the byte before
  fire(a, 5);
  access(a, 'read', 0x7ff200, 0x500018); // the byte after
  fire(a, 5);
  access(a, 'write', 0x7ff300, 0x500010);
  const r = j(a.watchHits());
  assert.equal(r.hits, 1);
  assert.equal(r.near, 2);
  assert.deepEqual(r.items.map((i) => [i.op, i.hits, i.near]), [['write', 1, 0], ['read', 0, 2]]); // on the bytes first
  assert.deepEqual(r.items[1].frames, []); // no call stack is taken for those
});

test('watch: the page is armed again a moment after each access, and regularly in any case', () => {
  const a = watchable();
  a.watchStart('0x500010', 8);
  assert.equal(a.monitor.enables, 1);
  access(a, 'read', 0x7ff123, 0x500010);
  access(a, 'read', 0x7ff123, 0x500010); // a second page of the watch, before the timer
  assert.equal(a.timers.filter((t) => t.ms === 5 && !t.cancelled).length, 1);
  fire(a, 5);
  assert.equal(a.monitor.enables, 2);
  assert.equal(a.monitor.disables, 1);
  // Something that reads the page without the monitor seeing it (Frida's own
  // thread) uses the trap up: a regular re-arm brings it back.
  assert.equal(a.intervals[0].ms, 250);
  a.intervals[0].fn();
  assert.equal(a.monitor.enables, 3);
});

test('watchStop: the trap is removed, and the result stays until the next watch', () => {
  const a = watchable();
  assert.deepEqual(j(a.watchHits()), { watching: false, endedBy: 'none', mode: '', address: null, size: 0, seconds: 0, hits: 0, near: 0, places: 0, truncated: false, error: '', items: [] });
  a.watchStart('0x500010', 8);
  access(a, 'write', 0x7ff123, 0x500010);
  const r = j(a.watchStop());
  assert.equal(r.watching, false);
  assert.equal(r.endedBy, 'stop');
  assert.equal(r.hits, 1);
  assert.equal(a.monitor.armed, null);
  assert.equal(a.intervals[0].cancelled, true);
  assert.equal(a.timers.filter((t) => !t.cancelled).length, 0); // nothing left that would arm it again
  assert.equal(j(a.watchHits()).hits, 1);
  assert.equal(j(a.watchStop()).endedBy, 'stop'); // stopping twice changes nothing
  a.watchStart('0x500020', 4);
  assert.equal(j(a.watchHits()).hits, 0);
});

test('watch: it ends by itself at the time limit, and when the memory can no longer be armed', () => {
  const a = watchable();
  a.watchStart('0x500010', 8);
  fire(a, 600000);
  assert.equal(a.monitor.armed, null);
  assert.equal(j(a.watchHits()).endedBy, 'limit');
  const b = watchable({ armThrows: (n) => n >= 1 }); // freed while watched
  b.watchStart('0x500010', 8);
  access(b, 'read', 0x7ff123, 0x500010);
  fire(b, 5);
  const r = j(b.watchHits());
  assert.equal(r.watching, false);
  assert.equal(r.endedBy, 'lost');
  assert.match(r.error, /unable to protect/);
  assert.equal(r.hits, 1);
});

test('watch: the number of places is capped and says so; a late access after stop is ignored', () => {
  const a = watchable();
  a.watchStart('0x500010', 8);
  const cb = a.monitor.armed.cb;
  for (let i = 0; i < 505; i++) cb({ operation: 'read', from: new Ptr(0x7ff000 + i), address: new Ptr(0x500010), threadId: 11, context: {} });
  const r = j(a.watchHits());
  assert.equal(r.places, 500);
  assert.equal(r.items.length, 200);
  assert.equal(r.truncated, true);
  assert.equal(r.hits, 505); // still counted
  a.watchStop();
  cb({ operation: 'read', from: new Ptr(0x7ff000), address: new Ptr(0x500010), threadId: 11, context: {} });
  assert.equal(j(a.watchHits()).hits, 505);
});

test('watch: reading or writing the watched page through the Inspector is refused, with the reason', () => {
  const a = watchable();
  a.watchStart('0x500ffc', 8); // pages 0x500000 and 0x501000
  assert.throws(() => a.read('0x500100', 16), /being watched/);
  assert.throws(() => a.read('0x4ffff0', 32), /not readable|being watched/);
  assert.throws(() => a.write('0x501ff0', 'aa'), /being watched/);
  assert.equal(j(a.read('0x502000', 4)).size, 4); // the next page is not
  a.watchStop();
  assert.equal(j(a.read('0x500100', 4)).size, 4);
});

test('watch: a follow that needs a fresh agent is refused while a watch is running', () => {
  const a = watchable({ modules: [ntdll] });
  a.follow(11, { mode: 'app' });
  a.unfollow();
  a.watchStart('0x500010', 8);
  assert.throws(() => a.follow(11, { mode: 'all' }), /memory watch is running/);
  assert.throws(() => a.coverStart('all', { mode: 'all' }), /memory watch is running/);
  a.follow(11, { mode: 'app' }); // the same scope needs no fresh agent
});

test('watch: memory that is unmapped while watched ends the watch at the next regular re-arm', () => {
  // Windows reports freed address space as a range with no access; Linux reports none.
  for (const gone of [null, { base: new Ptr(0x400000), size: 2 ** 30, protection: '---' }]) unmapped(gone);
});
function unmapped(gone) {
  let mapped = true;
  const a = watchable({ Process: { pageSize: 0x1000, findRangeByAddress: (p) => (mapped ? WATCH_RANGES.find((r) => p.v >= r.base.v && p.v < r.base.v + BigInt(r.size)) || null : gone) } });
  a.watchStart('0x500010', 8);
  access(a, 'read', 0x7ff123, 0x500010);
  mapped = false;
  fire(a, 5); // the quick re-arm after an access does not look
  assert.equal(j(a.watchHits()).watching, true);
  a.intervals[0].fn();
  const r = j(a.watchHits());
  assert.equal(r.watching, false);
  assert.equal(r.endedBy, 'lost');
  assert.match(r.error, /no longer mapped/);
  assert.equal(r.hits, 1);
  assert.equal(a.monitor.armed, null);
}

// ---- tracking the heap ----
// One call of a hooked allocator function: enter, then leave with a result.
function enter(a, name, args, tid = 11, stack) {
  const ctx = { threadId: tid, context: stack ? { stack: stack.map((v) => new Ptr(v)) } : {} };
  const cbs = a.hooked[name].cbs;
  if (cbs.onEnter) cbs.onEnter.call(ctx, args.map((v) => new Ptr(v)));
  return ctx;
}
function leave(a, name, ctx, ret = 0) {
  const cbs = a.hooked[name].cbs;
  if (cbs.onLeave) cbs.onLeave.call(ctx, new Ptr(ret));
}
const run = (a, name, args, ret, tid, stack) => leave(a, name, enter(a, name, args, tid, stack), ret);
const NO_BLOCKS = { tracking: false, endedBy: 'none', seconds: 0, min: 0, max: 0, functions: [], allocs: 0, frees: 0, live: 0, liveBytes: 0, freedKept: 0, overflow: false, siteCount: 0, sites: [] };

test('heapStart: the allocator functions of the platform are hooked, and unhooked by heapStop', () => {
  const a = load();
  assert.deepEqual(j(a.heapStatus()), NO_BLOCKS);
  assert.deepEqual(j(a.heapStart({ min: 0, max: 0 })), { tracking: true, functions: ['malloc', 'calloc', 'realloc', 'aligned_alloc', 'memalign', 'posix_memalign', 'free'], min: 0, max: 0, maxSeconds: 600, maxLive: 200000, maxFreed: 20000 });
  assert.deepEqual(Object.keys(a.hooked), ['malloc', 'calloc', 'realloc', 'aligned_alloc', 'memalign', 'posix_memalign', 'free']);
  // A C library without some of them (macOS has no memalign): the rest are hooked.
  assert.deepEqual(j(load({ missing: ['memalign', 'aligned_alloc'] }).heapStart({ min: 0, max: 0 })).functions, ['malloc', 'calloc', 'realloc', 'posix_memalign', 'free']);
  assert.throws(() => a.heapStart({ min: 0, max: 0 }), /already being tracked/);
  const r = j(a.heapStop());
  assert.equal(r.tracking, false);
  assert.equal(r.endedBy, 'stop');
  assert.ok(Object.values(a.hooked).every((h) => h.detached));
  assert.equal(j(a.heapStop()).endedBy, 'stop'); // stopping twice changes nothing

  const win = load({ modules: [ntdll], Process: { platform: 'windows' } });
  assert.deepEqual(j(win.heapStart({ min: 0, max: 0 })).functions, ['RtlAllocateHeap', 'RtlReAllocateHeap', 'RtlFreeHeap']);
  assert.throws(() => load({ noAllocators: true }).heapStart({ min: 0, max: 0 }), /No allocator function was found/);
});

test('heap: blocks are recorded when allocated and move to the freed list when freed', () => {
  const a = load();
  a.heapStart({ min: 0, max: 0 });
  run(a, 'malloc', [64], 0x900000, 11);
  run(a, 'calloc', [4, 8], 0x900100, 12);
  run(a, 'malloc', [16], 0); // a failed allocation is nothing
  let s = j(a.heapStatus());
  assert.deepEqual([s.allocs, s.frees, s.live, s.liveBytes, s.freedKept], [2, 0, 2, 96, 0]);
  run(a, 'free', [0x900000], 0, 12);
  run(a, 'free', [0x123456]); // a block from before tracking began
  run(a, 'free', [0]);
  s = j(a.heapStatus());
  assert.deepEqual([s.allocs, s.frees, s.live, s.liveBytes, s.freedKept], [2, 1, 1, 32, 1]);
});

test('heapFind: the block an address is in, with who allocated it and who freed it', () => {
  const a = load();
  a.heapStart({ min: 0, max: 0 });
  run(a, 'malloc', [64], 0x900000, 11);
  let f = j(a.heapFind('0x900010'));
  assert.equal(f.address, '0x900010');
  assert.equal(f.live.address, '0x900000');
  assert.equal(f.live.size, 64);
  assert.equal(f.live.offset, 16);
  assert.equal(f.live.thread, 11);
  assert.equal(f.live.freed, null);
  assert.deepEqual(f.live.frames, [{ address: '0x7ff123', where: 'kernel32.dll+0x123', symbol: 'kernel32.dll!CreateFileW' }, { address: '0x500', where: '0x500', symbol: '' }]);
  assert.deepEqual(f.freed, []);
  assert.equal(j(a.heapFind('0x900040')).live, null); // one past the end
  assert.equal(j(a.heapFind('0x8fffff')).live, null);

  run(a, 'free', [0x900000], 0, 12);
  f = j(a.heapFind('0x900010'));
  assert.equal(f.live, null);
  assert.equal(f.freed.length, 1);
  assert.equal(f.freed[0].freed.thread, 12);
  assert.equal(f.freed[0].freed.frames.length, 2);

  // The same memory is handed out again: a stale pointer now lands in the new block.
  run(a, 'malloc', [48], 0x900000, 13);
  f = j(a.heapFind('0x900010'));
  assert.equal(f.live.size, 48);
  assert.equal(f.live.thread, 13);
  assert.equal(f.freed.length, 1);
  assert.equal(j(a.heapFind('0x900038')).live, null);   // past the new, smaller block
  assert.equal(j(a.heapFind('0x900038')).freed.length, 1); // but inside the old one
  a.heapStop();
  assert.equal(j(a.heapFind('0x900010')).live.size, 48); // what was recorded can still be asked about
});

test('heapFind: nothing tracked yet is an error; freed blocks are listed newest first and capped', () => {
  const a = load();
  assert.throws(() => a.heapFind('0x900000'), /Nothing has been tracked/);
  a.heapStart({ min: 0, max: 0 });
  for (let i = 0; i < 25; i++) { run(a, 'malloc', [8 + i], 0x900000); run(a, 'free', [0x900000]); }
  const f = j(a.heapFind('0x900000'));
  assert.equal(f.freed.length, 20);
  assert.equal(f.freedTotal, 25);
  assert.equal(f.freed[0].size, 32); // the last one freed
});

test('heap: only sizes in the range are recorded, and no call stack is taken for the others', () => {
  let stacks = 0;
  const a = load({ onBacktrace: () => { stacks++; } });
  a.heapStart({ min: 32, max: 64 });
  run(a, 'malloc', [16], 0x900000);
  run(a, 'malloc', [128], 0x900100);
  assert.equal(stacks, 0);
  run(a, 'malloc', [32], 0x900200);
  run(a, 'malloc', [64], 0x900300);
  run(a, 'free', [0x900000]); // not recorded: nothing to do, no stack
  assert.equal(stacks, 2);
  const s = j(a.heapStatus());
  assert.deepEqual([s.allocs, s.live, s.min, s.max], [2, 2, 32, 64]);
});

test('heap: realloc frees the old block and records the new one; in place, the block just changes size', () => {
  const a = load();
  a.heapStart({ min: 0, max: 0 });
  run(a, 'malloc', [64], 0x900000);
  run(a, 'realloc', [0x900000, 128], 0x900000); // grown in place
  let s = j(a.heapStatus());
  assert.deepEqual([s.live, s.liveBytes, s.frees], [1, 128, 0]);
  run(a, 'realloc', [0x900000, 256], 0x910000); // moved
  s = j(a.heapStatus());
  assert.deepEqual([s.live, s.liveBytes, s.frees, s.allocs], [1, 256, 1, 2]);
  assert.equal(j(a.heapFind('0x900000')).freed[0].size, 128);
  assert.equal(j(a.heapFind('0x910080')).live.size, 256);
  run(a, 'realloc', [0, 8], 0x920000); // realloc(NULL) is an allocation
  run(a, 'realloc', [0x920000, 4096], 0); // failed: the old block stays
  assert.equal(j(a.heapFind('0x920000')).live.size, 8);
});

test('heap: what an allocator function does inside itself is not recorded twice', () => {
  const a = load();
  a.heapStart({ min: 0, max: 0 });
  const outer = enter(a, 'realloc', [0, 64]);
  run(a, 'malloc', [64], 0x900000); // realloc getting its memory
  run(a, 'free', [0x900000]);       // and a free inside it
  leave(a, 'realloc', outer, 0x900000);
  const inner = enter(a, 'malloc', [32], 12);
  run(a, 'malloc', [4096], 0x950000, 12); // the heap growing itself
  leave(a, 'malloc', inner, 0x900100);
  run(a, 'malloc', [8], 0x900200, 13);    // another thread is not held back
  const s = j(a.heapStatus());
  assert.deepEqual([s.allocs, s.frees, s.live], [3, 0, 3]);
  assert.equal(j(a.heapFind('0x950000')).live, null);
});

test('heapStatus: live blocks are grouped by the code that asked for them, biggest first', () => {
  const app = { name: 'app.exe', base: new Ptr(0x400000), size: 0x10000, path: 'C:/app/app.exe', enumerateExports: () => [], enumerateImports: () => [] };
  const a = load({ modules: [app, ntdll] });
  a.heapStart({ min: 0, max: 0 });
  // The allocator's own modules are skipped: the place is the first caller outside them.
  run(a, 'malloc', [100], 0x900000, 11, [0x7fe010, 0x7ff020, 0x401000, 0x402000]);
  run(a, 'malloc', [100], 0x900100, 11, [0x7fe010, 0x401000, 0x402000]);
  run(a, 'malloc', [500], 0x900200, 11, [0x405000]);
  run(a, 'malloc', [7], 0x900300, 11, [0x7fe010]); // nothing outside: the first frame stands in
  const s = j(a.heapStatus());
  assert.equal(s.siteCount, 3);
  assert.equal(typeof a.hooked.malloc, 'object');
  assert.deepEqual(s.sites.map((x) => [x.frames.map((f) => f.where).join(' < '), x.blocks, x.bytes]), [['app.exe+0x5000', 1, 500], ['app.exe+0x1000 < app.exe+0x2000', 2, 200], ['ntdll.dll+0x10', 1, 7]]);
  assert.deepEqual(s.sites[0].frames[0], { address: '0x405000', where: 'app.exe+0x5000', symbol: 'kernel32.dll!CreateFileW' });
  // A place is up to three callers: one more caller is another place.
  run(a, 'malloc', [1], 0x900400, 11, [0x401000, 0x402000, 0x403000, 0x404000]);
  assert.equal(j(a.heapStatus()).sites.find((x) => x.bytes === 1).frames.length, 3);
  run(a, 'free', [0x900200]);
  assert.equal(j(a.heapStatus()).sites[0].frames[0].address, '0x401000');
});

test('heap: tracking stops by itself at the time limit; past the block limits it says so and keeps the newest frees', () => {
  const a = load();
  a.heapStart({ min: 0, max: 0 });
  run(a, 'malloc', [8], 0x900000);
  a.timers.find((t) => t.ms === 600000).fn();
  assert.equal(j(a.heapStatus()).endedBy, 'limit');
  assert.ok(Object.values(a.hooked).every((h) => h.detached));
  a.heapStart({ min: 0, max: 0 }); // a new one starts empty
  assert.equal(j(a.heapStatus()).live, 0);
  for (let i = 0; i < 20005; i++) { run(a, 'malloc', [8], 0xa00000 + i * 16); run(a, 'free', [0xa00000 + i * 16]); }
  let s = j(a.heapStatus());
  assert.deepEqual([s.frees, s.freedKept, s.overflow], [20005, 20000, false]);
  assert.equal(j(a.heapFind('0xa00000')).freed.length, 0);                   // the oldest fell out
  assert.equal(j(a.heapFind('0x' + (0xa00000 + 20004 * 16).toString(16))).freed.length, 1);
  for (let i = 0; i < 200003; i++) run(a, 'malloc', [8], 0x10000000 + i * 16);
  s = j(a.heapStatus());
  assert.deepEqual([s.live, s.overflow], [200000, true]);
});

test('heap: a follow that needs a fresh agent is refused while the heap is tracked', () => {
  const a = load({ modules: [ntdll] });
  a.follow(11, { mode: 'app' });
  a.unfollow();
  a.heapStart({ min: 0, max: 0 });
  assert.throws(() => a.follow(11, { mode: 'all' }), /Heap tracking is running/);
});

// ---- watching memory exactly (hardware watchpoints, Windows) ----
const exactable = (over = {}) => watchable({ ...over, Process: { platform: 'windows', arch: 'x64', ...(over.Process || {}) } });
// A debug trap as the exception handler sees it. dr6 says which watchpoints fired.
function trap(a, dr6, pc, tid = 11, type = 'single-step', offset = 0x68) {
  let value = dr6;
  const nativeContext = { add: (off) => ({ readU32: () => (off === offset ? value : 0xdead), writeU32: (v) => { if (off === offset) value = v; } }) };
  a.cpu.thread = tid;
  const handled = a.cpu.handler({ type, address: new Ptr(pc), context: { pc: new Ptr(pc) }, nativeContext });
  a.cpu.thread = 99;
  return { handled, dr6: value };
}

test('watchStart on Windows: a few aligned bytes get hardware watchpoints on every thread, and no page is trapped', () => {
  const a = exactable();
  assert.deepEqual(j(a.watchStart('0x500010', 8)), { watching: true, address: '0x500010', size: 8, mode: 'exact', reason: '', threads: 2, pages: 1, pageSize: 4096, maxSeconds: 600, maxHits: 200000, protection: 'rw-' });
  // Two per piece: one that fires on a write, one on any access, to tell the two apart.
  assert.deepEqual(a.cpu.set, [[11, 0, '0x500010', 8, 'w'], [11, 1, '0x500010', 8, 'rw'], [12, 0, '0x500010', 8, 'w'], [12, 1, '0x500010', 8, 'rw']]);
  assert.equal(a.monitor.enables, 0);
  assert.equal(j(a.watchHits()).mode, 'exact');
});

test('watchStart: bytes are split into aligned pieces; what needs more than two is sampled, or refused when exact was asked for', () => {
  const pieces = (address, size, arch = 'x64') => { const a = exactable({ Process: { arch } }); const r = a.watchStart(address, size); return r.mode === 'exact' ? a.cpu.set.filter((s) => s[0] === 11 && s[4] === 'w').map((s) => [s[1], s[2], s[3]]) : r.mode + ': ' + r.reason; };
  assert.deepEqual(pieces('0x500014', 8), [[0, '0x500014', 4], [2, '0x500018', 4]]);
  assert.deepEqual(pieces('0x500011', 3), [[0, '0x500011', 1], [2, '0x500012', 2]]);
  assert.deepEqual(pieces('0x500010', 1), [[0, '0x500010', 1]]);
  assert.deepEqual(pieces('0x500010', 8, 'ia32'), [[0, '0x500010', 4], [2, '0x500014', 4]]); // no 8-byte piece on 32-bit
  assert.deepEqual(pieces('0x500010', 16), [[0, '0x500010', 8], [2, '0x500018', 8]]); // two whole pieces: the most there is
  assert.match(pieces('0x500010', 24), /^sampled: .*two aligned pieces/);
  assert.match(pieces('0x500011', 8), /^sampled: /);
  assert.match(pieces('0x500010', 8, 'arm64'), /^sampled: /);
  assert.throws(() => exactable().watchStart('0x500010', 24, 'exact'), /cannot be watched exactly/);
  assert.equal(exactable().watchStart('0x500010', 8, 'sampled').mode, 'sampled');
  const linux = watchable();
  assert.match(linux.watchStart('0x500010', 8).reason, /Windows/);
  assert.throws(() => watchable().watchStart('0x500010', 8, 'exact'), /cannot be watched exactly.*Windows/);
  assert.throws(() => exactable().watchStart('0x500010', 8, 'fast'), /mode/);
});

test('exact watch: every access is counted, reads apart from writes, and only our own traps are taken', () => {
  const a = exactable();
  a.watchStart('0x500014', 8); // two pieces: slots 0,1 and 2,3
  assert.deepEqual(trap(a, 0xffff0ff2, 0x7ff123, 11), { handled: true, dr6: 0xffff0ff0 }); // any-access only: a read
  assert.equal(trap(a, 0xffff0ff2, 0x7ff123, 12).handled, true);
  assert.equal(trap(a, 0xffff0ff3, 0x7ff200, 11).handled, true); // the write one fired too
  assert.equal(trap(a, 0xffff0ffc, 0x7ff200, 11).handled, true); // a write to the second piece
  assert.equal(trap(a, 0xffff0ff8, 0x7ff300, 11).handled, true); // a read of the second piece
  // Not ours: a single step nobody's watchpoint caused, and other kinds of exception.
  assert.deepEqual(trap(a, 0xffff4ff0, 0x7ff400), { handled: false, dr6: 0xffff4ff0 });
  assert.equal(trap(a, 0xffff0ff2, 0x7ff400, 11, 'access-violation').handled, false);
  const r = j(a.watchHits());
  assert.deepEqual([r.hits, r.near, r.places, r.mode], [5, 0, 3, 'exact']);
  assert.deepEqual(r.items.map((i) => [i.op, i.from, i.hits, i.last, i.threads]), [['read', '0x7ff123', 2, '0x500014', [11, 12]], ['write', '0x7ff200', 2, '0x500018', [11]], ['read', '0x7ff300', 1, '0x500018', [11]]]);
  assert.equal(r.items[0].frames.length, 2); // call stack of the first access
  a.watchStop();
  assert.equal(trap(a, 0xffff0ff2, 0x7ff123).handled, false); // nothing is watched any more
  assert.equal(j(a.watchHits()).hits, 5);
});

test('exact watch: 32-bit reads the debug status where a 32-bit context keeps it', () => {
  const a = exactable({ Process: { arch: 'ia32', pointerSize: 4 } });
  a.watchStart('0x500010', 4);
  assert.equal(trap(a, 0x3, 0x7ff123, 11, 'single-step', 0x14).handled, true);
  assert.equal(j(a.watchHits()).items[0].op, 'write');
});

test('exact watch: without the thread-start hook, threads that start later are picked up now and then; stopping takes every watchpoint off', () => {
  const threads = [{ id: 11, context: { sp: new Ptr(0x10000) } }, { id: 99, context: {} }];
  const a = exactable({ threads });
  assert.equal(a.watchStart('0x500010', 8).threads, 1); // 99 is Frida's own thread
  threads.push({ id: 13, context: {} });
  const pick = a.intervals.find((i) => i.ms === 1000);
  pick.fn();
  pick.fn(); // not armed twice
  assert.deepEqual(a.cpu.set.filter((s) => s[4] === 'w').map((s) => s[0]), [11, 13]);
  threads.shift(); // thread 11 has ended meanwhile
  a.watchStop();
  assert.deepEqual(a.cpu.unset, [[13, 0], [13, 1]]);
  assert.equal(pick.cancelled, true);
  assert.equal(a.timers.filter((t) => !t.cancelled).length, 0);
});

test('exact watch: a stack is refused here too, and the Inspector can still read watched bytes', () => {
  const a = exactable();
  // Handling a trap uses the thread's stack: a watchpoint there fires inside its own handling.
  assert.throws(() => a.watchStart('0x10010', 8), /stack of thread 11/);
  assert.throws(() => a.watchStart('0x10010', 8, 'exact'), /stack of thread 11/);
  assert.equal(a.cpu.set.length, 0);
  a.watchStart('0x500010', 8);
  assert.equal(j(a.read('0x500010', 8)).size, 8);
});

test('exact watch: threads that take no watchpoint are skipped; with none at all the page trap is used, or exact is refused', () => {
  const some = exactable({ hwRefuses: [12] });
  assert.equal(some.watchStart('0x500010', 8).threads, 1);
  assert.deepEqual(some.cpu.unset, []); // thread 12 failed on its first slot: nothing to take back
  const none = exactable({ hwRefuses: [11, 12] });
  const r = none.watchStart('0x500010', 8);
  assert.equal(r.mode, 'sampled');
  assert.match(r.reason, /No thread/);
  assert.equal(none.monitor.enables, 1);
  assert.throws(() => exactable({ hwRefuses: [11, 12] }).watchStart('0x500010', 8, 'exact'), /No thread/);
});

test('exact watch: it ends at the hit limit, from outside the trap handler', () => {
  const a = exactable();
  a.watchStart('0x500010', 8);
  for (let i = 0; i < 200000; i++) trap(a, 0x2, 0x7ff123);
  assert.equal(j(a.watchHits()).watching, true);
  const later = a.timers.filter((t) => t.ms === 0 && !t.cancelled).pop();
  later.fn();
  const r = j(a.watchHits());
  assert.deepEqual([r.watching, r.endedBy, r.hits], [false, 'limit', 200000]);
  assert.equal(a.cpu.unset.length, 4);
});

test('exact watch: a thread is given the watchpoints as it starts, before it runs any of the program', () => {
  const threads = [{ id: 11, context: {} }, { id: 99, context: {} }];
  const a = exactable({ threads, modules: [ntdll] });
  a.watchStart('0x500010', 8);
  assert.equal(a.intervals.length, 0); // nothing to poll for
  threads.push({ id: 13, context: {} });
  // The listener is a plain function (entry only): this function never returns,
  // and a listener that traps the return there hangs the session on detach.
  assert.equal(typeof a.hooked.RtlUserThreadStart.cbs, 'function');
  a.hooked.RtlUserThreadStart.cbs.call({ threadId: 13 }, []);
  a.hooked.RtlUserThreadStart.cbs.call({ threadId: 13 }, []); // not twice
  a.hooked.RtlUserThreadStart.cbs.call({ threadId: 14 }, []); // not listed yet: left for later
  assert.deepEqual(a.cpu.set.filter((s) => s[4] === 'w').map((s) => s[0]), [11, 13]);
  a.watchStop();
  assert.equal(a.hooked.RtlUserThreadStart.detached, true);
  assert.deepEqual(a.cpu.unset.map((u) => u[0]), [11, 11, 13, 13]);
});

test('heap: aligned allocations are recorded too, whichever function made them', () => {
  const a = load();
  a.heapStart({ min: 0, max: 0 });
  run(a, 'aligned_alloc', [64, 256], 0x930000);
  run(a, 'memalign', [4096, 100], 0x931000);
  // posix_memalign hands the block back through its first argument and returns 0.
  Ptr.pointers['0x7000'] = 0x932000;
  run(a, 'posix_memalign', [0x7000, 64, 512], 0);
  Ptr.pointers['0x7008'] = 0x933000;
  run(a, 'posix_memalign', [0x7008, 64, 512], 12); // ENOMEM: nothing was allocated
  const s = j(a.heapStatus());
  assert.deepEqual([s.allocs, s.live, s.liveBytes], [3, 3, 868]);
  assert.equal(j(a.heapFind('0x9300ff')).live.size, 256);
  assert.equal(j(a.heapFind('0x931010')).live.size, 100);
  assert.equal(j(a.heapFind('0x932100')).live.size, 512);
  assert.equal(j(a.heapFind('0x933000')).live, null);
  run(a, 'free', [0x932000]);
  assert.equal(j(a.heapFind('0x932100')).freed.length, 1);
  // The size range applies to them as to any block.
  const b = load();
  b.heapStart({ min: 1000, max: 0 });
  run(b, 'aligned_alloc', [64, 256], 0x930000);
  assert.equal(j(b.heapStatus()).allocs, 0);
});

// ---- finding a block by walking the Windows heaps ----
// The four heap functions of kernel32, over heaps given as lists of entries
// [address, size, flags] (flags: 4 busy, 1 region, 2 uncommitted, 0 free).
function winHeaps(heaps, over = {}) {
  const log = { locks: 0, unlocks: 0, walks: 0 };
  const cursor = {};
  const cell = (p, off = 0) => '0x' + (p.v + BigInt(off)).toString(16);
  const winapi = {
    GetProcessHeaps: (n, buf) => { const hs = Object.keys(heaps); hs.slice(0, n).forEach((h, i) => { Ptr.pointers[cell(buf, i * 8)] = Number(h); }); return hs.length; },
    HeapLock: (h) => { log.locks++; return over.lockFails && over.lockFails.includes(Number(h.v)) ? 0 : 1; },
    HeapUnlock: () => { log.unlocks++; return 1; },
    HeapWalk: (h, e) => {
      log.walks++;
      if (over.walkThrows) throw new Error('access violation');
      const key = Number(h.v);
      const i = cursor[key] || 0;
      // The first call for a heap has an entry whose data pointer is NULL.
      const first = (Ptr.pointers[cell(e)] ?? 0) === 0;
      const at = first ? 0 : i;
      const entry = heaps[key][at];
      if (!entry) { cursor[key] = 0; return 0; }
      Ptr.pointers[cell(e)] = entry[0];
      Ptr.pointers[cell(e, 8)] = entry[1];
      Ptr.pointers[cell(e, 14)] = entry[2];
      cursor[key] = at + 1;
      return 1;
    },
  };
  const a = load({ winapi, Process: { platform: 'windows', arch: 'x64', pointerSize: 8 }, ...(over.load || {}) });
  return Object.assign(a, { log });
}
const HEAPS = {
  0x1000000: [[0x1000000, 0x10000, 1], [0x1000100, 64, 4], [0x1000140, 200, 0], [0x1000300, 4660, 4]],
  0x2000000: [[0x2000100, 24, 4], [0x2008000, 0x8000, 2]],
};

test('heapFind on Windows: with nothing tracked, the heaps are walked for the block', () => {
  const a = winHeaps(HEAPS);
  let f = j(a.heapFind('0x1000310'));
  assert.deepEqual(f, { address: '0x1000310', tracking: false, live: null, freed: [], freedTotal: 0, system: { state: 'live', address: '0x1000300', size: 4660, offset: 16, timedOut: false } });
  assert.equal(a.log.locks, 1);
  assert.equal(a.log.unlocks, 1); // every lock is given back
  f = j(a.heapFind('0x1000150'));
  assert.deepEqual(f.system, { state: 'free', address: '0x1000140', size: 200, offset: 16, timedOut: false });
  assert.equal(j(a.heapFind('0x2000117')).system.state, 'live');   // the last byte of a block in the second heap
  assert.equal(j(a.heapFind('0x2000118')).system.state, 'none');   // one past it
  assert.equal(j(a.heapFind('0x2009000')).system.state, 'none');   // uncommitted space is neither a block nor free memory
  assert.equal(j(a.heapFind('0x1000050')).system.state, 'none');   // inside the region but in no entry of it
  assert.equal(j(a.heapFind('0x5000000')).system.state, 'none');
  assert.equal(a.log.locks, a.log.unlocks);
});

test('heapFind on Windows: a recorded live block needs no walk; anything else gets one beside what was recorded', () => {
  const a = winHeaps(HEAPS, { load: { modules: [ntdll] } });
  a.heapStart({ min: 0, max: 0 });
  run(a, 'RtlAllocateHeap', [0x1000000, 0, 64], 0x1000100);
  let f = j(a.heapFind('0x1000110'));
  assert.equal(f.live.size, 64);
  assert.equal(f.system, null);
  assert.equal(a.log.walks, 0);
  run(a, 'RtlFreeHeap', [0x1000000, 0, 0x1000100]);
  f = j(a.heapFind('0x1000110'));
  assert.equal(f.live, null);
  assert.equal(f.freed.length, 1);
  assert.equal(f.system.state, 'live'); // the fake heap still lists it: the walk is reported as it is
  assert.equal(j(a.heapFind('0x1000310')).system.size, 4660); // a block from before tracking
});

test('heapFind: a heap that cannot be locked or walked is skipped; elsewhere than Windows there is no walk', () => {
  const locked = winHeaps(HEAPS, { lockFails: [0x1000000] });
  assert.equal(j(locked.heapFind('0x1000310')).system.state, 'none');
  assert.equal(j(locked.heapFind('0x2000100')).system.state, 'live');
  const broken = winHeaps(HEAPS, { walkThrows: true });
  assert.deepEqual(j(broken.heapFind('0x1000310')).system, { state: 'none', address: null, size: 0, offset: 0, timedOut: false });
  assert.equal(broken.log.locks, broken.log.unlocks);
  const linux = load();
  assert.throws(() => linux.heapFind('0x900000'), /Nothing has been tracked/);
  linux.heapStart({ min: 0, max: 0 });
  assert.equal(j(linux.heapFind('0x900000')).system, null);
});

test('heapFind: a walk that takes too long stops and says so', () => {
  let now = 1000;
  const many = { 0x1000000: Array.from({ length: 5000 }, (_, i) => [0x1000100 + i * 32, 16, 4]) };
  const a = winHeaps(many, { load: { clock: () => (now += 2000) } }); // two seconds pass between looks at the clock
  const s = j(a.heapFind('0x9999999')).system;
  assert.deepEqual([s.state, s.timedOut], ['none', true]);
  assert.equal(a.log.locks, a.log.unlocks);
});

// ---- strings and references ----
// A module with real bytes behind it: `data` at 0x400000 (r--), `code` at 0x410000 (r-x).
function imageModule(data, code = new Uint8Array(0x100), over = {}) {
  const ranges = [{ base: new Ptr(0x400000), size: data.length, protection: 'r--' }, { base: new Ptr(0x410000), size: code.length, protection: 'r-x' }];
  const m = { name: 'app.exe', base: new Ptr(0x400000), size: 0x20000, path: 'C:/app/app.exe', enumerateExports: () => [], enumerateImports: () => [], enumerateRanges: () => ranges };
  const loaded = load({ modules: [m], ...over });
  Ptr.memory = [{ base: 0x400000n, data }, { base: 0x410000n, data: code }];
  return loaded;
}
const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0));
const wide = (s) => Array.from(s, (c) => [c.charCodeAt(0), 0]).flat();
function bytesAt(size, parts) { // parts: [[offset, bytes], ...]; the rest is 0xff
  const b = new Uint8Array(size).fill(0xff);
  for (const [off, bytes] of parts) b.set(bytes, off);
  return b;
}
const le32 = (v) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];

test('strings: ASCII and UTF-16 strings of a module, with where they are; shorter runs are not strings', () => {
  const a = imageModule(bytesAt(0x400, [[0x10, ascii('GetProcAddress')], [0x40, wide('Software\\Fermion')], [0x100, ascii('abc')], [0x200, ascii('config.json')]]));
  const r = j(a.strings('app.exe', { text: '', min: 5 }));
  assert.deepEqual(r.items, [
    { address: '0x400010', where: 'app.exe+0x10', kind: 'ascii', length: 14, text: 'GetProcAddress' },
    { address: '0x400040', where: 'app.exe+0x40', kind: 'utf16', length: 16, text: 'Software\\Fermion' },
    { address: '0x400200', where: 'app.exe+0x200', kind: 'ascii', length: 11, text: 'config.json' },
  ]);
  assert.deepEqual([r.module, r.total, r.truncated, r.timedOut, r.scanned], ['app.exe', 3, false, false, 0x400]);
  assert.equal(j(a.strings('app.exe', { text: '', min: 3 })).total, 4); // "abc" counts when three is enough
  assert.throws(() => a.strings('nope.dll', { text: '', min: 5 }), /Module not found/);
});

test('strings: a search keeps the strings that contain the text, whatever the case', () => {
  const a = imageModule(bytesAt(0x400, [[0x10, ascii('GetProcAddress')], [0x40, wide('Software\\Fermion')], [0x200, ascii('config.json')]]));
  const r = j(a.strings('app.exe', { text: 'FERM', min: 5 }));
  assert.deepEqual(r.items.map((i) => i.text), ['Software\\Fermion']);
  assert.equal(r.total, 1);
  assert.equal(j(a.strings('app.exe', { text: 'nothing like it', min: 5 })).total, 0);
});

test('strings: code is not searched; a string that runs to the very end of a range is still found; long ones are cut', () => {
  const long = 'x'.repeat(300);
  const data = bytesAt(0x400, [[0x10, ascii(long)], [0x400 - 6, ascii('theEnd')]]);
  const a = imageModule(data, bytesAt(0x100, [[0x10, ascii('in the code')]]));
  const r = j(a.strings('app.exe', { text: '', min: 5 }));
  assert.deepEqual(r.items.map((i) => [i.address, i.length, i.text.length]), [['0x400010', 300, 200], ['0x4003fa', 6, 6]]);
});

test('strings: only the first 2,000 are returned, all are counted, and a slow scan stops at its time budget', () => {
  const parts = [];
  for (let i = 0; i < 2100; i++) parts.push([i * 8, ascii('str' + String(i).padStart(4, '0'))]);
  const a = imageModule(bytesAt(2100 * 8, parts));
  const r = j(a.strings('app.exe', { text: '', min: 5 }));
  assert.deepEqual([r.items.length, r.total, r.truncated], [2000, 2100, true]);
  let now = 0;
  const slow = imageModule(bytesAt(0x300000, [[0x10, ascii('early')], [0x2ff000, ascii('never reached')]]), new Uint8Array(16), { clock: () => (now += 5000) });
  const s = j(slow.strings('app.exe', { text: '', min: 5 }));
  assert.equal(s.timedOut, true);
  assert.deepEqual(s.items.map((i) => i.text), ['early']);
});

test('refs: pointers to an address, and the instructions that refer to it', () => {
  const target = 0x400200;
  // Data: a pointer to the target at +0x80. Code: at +0x20 an instruction whose
  // last four bytes are a displacement to the target (as lea/call/jmp have it).
  const data = bytesAt(0x400, [[0x80, [...le32(target), 0, 0, 0, 0]]]);
  const at = 0x410020; // instruction start; 3 bytes of opcode, then the displacement
  const disp = target - (at + 3 + 4);
  const code = bytesAt(0x100, [[0x20, [0x48, 0x8d, 0x0d, ...le32(disp)]]]);
  const a = imageModule(data, code, { insns: { 0x410020: { size: 7, mnemonic: 'lea', opStr: 'rcx, [rip - 0xfe27]' } } });
  const r = j(a.refs('0x400200', null));
  assert.deepEqual(r.pointers, [{ address: '0x400080', where: 'app.exe+0x80' }]);
  assert.deepEqual(r.code, [{ address: '0x410020', where: 'app.exe+0x10020', text: 'lea rcx, [rip - 0xfe27]' }]);
  assert.deepEqual([r.address, r.module, r.truncated, r.timedOut], ['0x400200', 'app.exe', false, false]);
});

test('refs: bytes that only look like a displacement, with no instruction around them, are not reported', () => {
  const target = 0x400200;
  const code = bytesAt(0x100, [[0x23, le32(target - (0x410023 + 4))]]);
  const a = imageModule(new Uint8Array(0x400).fill(0xff), code, { insns: {} }); // nothing decodes there
  const r = j(a.refs('0x400200', null));
  assert.deepEqual(r.code, []);
  assert.equal(r.unconfirmed, 1);
});

test('refs: an address outside every module needs the module to search named; an unknown module is an error', () => {
  const a = imageModule(bytesAt(0x400, [[0x80, [...le32(0x900000), 0, 0, 0, 0]]]));
  assert.throws(() => a.refs('0x900000', null), /not inside a module/);
  assert.deepEqual(j(a.refs('0x900000', 'app.exe')).pointers, [{ address: '0x400080', where: 'app.exe+0x80' }]);
  assert.throws(() => a.refs('0x900000', 'nope.dll'), /Module not found/);
});

test('refs: no more than 200 of each kind are returned, and it says when there were more', () => {
  const parts = [];
  for (let i = 0; i < 250; i++) parts.push([i * 8, [...le32(0x400f00), 0, 0, 0, 0]]);
  const a = imageModule(bytesAt(0x1000, parts));
  const r = j(a.refs('0x400f00', null));
  assert.deepEqual([r.pointers.length, r.truncated], [200, true]);
});

test('refs: of the instructions that could hold the bytes, the one that really refers to the target is taken', () => {
  const target = 0x400200;
  // 48 8d 15 <disp>: lea rdx, [rip + disp]. Its last five bytes also decode, as "adc eax, imm32".
  const at = 0x410020;
  const code = bytesAt(0x100, [[0x20, [0x48, 0x8d, 0x15, ...le32(target - (at + 7))]]]);
  const a = imageModule(new Uint8Array(0x400).fill(0xff), code, { insns: {
    0x410022: { size: 5, mnemonic: 'adc', opStr: 'eax, 0xfffe01d9' },
    0x410020: { size: 7, mnemonic: 'lea', opStr: 'rdx, [rip - 0xfe27]' },
  } });
  assert.deepEqual(j(a.refs('0x400200', null)).code, [{ address: '0x410020', where: 'app.exe+0x10020', text: 'lea rdx, [rip - 0xfe27]' }]);
  // A call or jump names its target outright.
  const call = bytesAt(0x100, [[0x40, [0xe8, ...le32(0x410080 - (0x410040 + 5))]]]);
  const b = imageModule(new Uint8Array(0x400).fill(0xff), call, { insns: { 0x410040: { size: 5, mnemonic: 'call', opStr: '0x410080' } } });
  assert.deepEqual(j(b.refs('0x410080', null)).code.map((c) => c.text), ['call 0x410080']);
  // Only the look-alike decodes: not a reference.
  const c = imageModule(new Uint8Array(0x400).fill(0xff), code, { insns: { 0x410022: { size: 5, mnemonic: 'adc', opStr: 'eax, 0xfffe01d9' } } });
  assert.deepEqual([j(c.refs('0x400200', null)).code.length, j(c.refs('0x400200', null)).unconfirmed], [0, 1]);
});

test('refs: 32-bit code names an address outright; such an instruction is listed as code, not as a pointer', () => {
  // 68 <addr>: push 0x400200, at 0x410030. And a pointer in data.
  const code = bytesAt(0x100, [[0x30, [0x68, ...le32(0x400200)]]]);
  const data = bytesAt(0x400, [[0x80, le32(0x400200)]]);
  const a = imageModule(data, code, { Process: { arch: 'ia32', pointerSize: 4 }, insns: { 0x410030: { size: 5, mnemonic: 'push', opStr: '0x400200' } } });
  const r = j(a.refs('0x400200', null));
  assert.deepEqual(r.code, [{ address: '0x410030', where: 'app.exe+0x10030', text: 'push 0x400200' }]);
  assert.deepEqual(r.pointers, [{ address: '0x400080', where: 'app.exe+0x80' }]);
});

test('refs: when the same bytes decode with and without a prefix, the longer instruction is the one reported', () => {
  // 48 8d 15 <disp> is "lea rdx, [rip+d]"; without the 48 it is "lea edx, [rip+d]", which also refers to the target.
  const target = 0x400200;
  const code = bytesAt(0x100, [[0x20, [0x48, 0x8d, 0x15, ...le32(target - 0x410027)]]]);
  const a = imageModule(new Uint8Array(0x400).fill(0xff), code, { insns: {
    0x410021: { size: 6, mnemonic: 'lea', opStr: 'edx, [rip - 0xfe27]' },
    0x410020: { size: 7, mnemonic: 'lea', opStr: 'rdx, [rip - 0xfe27]' },
  } });
  assert.deepEqual(j(a.refs('0x400200', null)).code.map((c) => [c.address, c.text]), [['0x410020', 'lea rdx, [rip - 0xfe27]']]);
});

// ---- limits handed over by the main process ----
test('limits: a recording uses the time and size limits it is started with, kept inside the bounds the agent accepts', () => {
  const threads = [{ id: 11, state: 'waiting', context: {} }];
  let a = load({ Process: { enumerateThreads: () => threads } });
  let r = j(a.coverStart('all', { mode: 'all' }, { ms: 120000, blocks: 500000 }));
  assert.deepEqual([r.maxSeconds, r.maxBlocks], [120, 500000]);
  assert.ok(a.timers.some((t) => t.ms === 120000));
  a = load({ Process: { enumerateThreads: () => threads } });
  r = j(a.coverStart('all', { mode: 'all' }, { ms: 1, blocks: 1e12 })); // out of bounds: brought in
  assert.deepEqual([r.maxSeconds, r.maxBlocks], [60, 5000000]);
  a = load({ Process: { enumerateThreads: () => threads } });
  r = j(a.coverStart('all', { mode: 'all' }, { ms: '120000', blocks: null })); // not numbers: the usual limits
  assert.deepEqual([r.maxSeconds, r.maxBlocks], [600, 2000000]);

  a = load();
  r = j(a.heapStart({ min: 0, max: 0 }, { ms: 1800000, live: 50000, freed: 5000 }));
  assert.deepEqual([r.maxSeconds, r.maxLive, r.maxFreed], [1800, 50000, 5000]);
  a = load();
  r = j(a.heapStart({ min: 0, max: 0 }, { ms: 1e12, live: 1e12, freed: 0 }));
  assert.deepEqual([r.maxSeconds, r.maxLive, r.maxFreed], [3600, 500000, 100]);
});

test('limits: heap tracking keeps no more freed blocks than its limit, the newest', () => {
  const a = load();
  a.heapStart({ min: 0, max: 0 }, { freed: 100 });
  for (let i = 0; i < 150; i++) { run(a, 'malloc', [64], 0x900000 + i * 0x100, 7, []); run(a, 'free', [0x900000 + i * 0x100], 0, 7, []); }
  const s = j(a.heapStatus());
  assert.equal(s.freedKept, 100);
  assert.equal(j(a.heapFind('0x900010')).freed.length, 0);            // the oldest was pushed out
  assert.equal(j(a.heapFind('0x' + (0x900000 + 149 * 0x100 + 16).toString(16))).freed.length, 1); // the newest is there
});
