// Playwright-Electron END-TO-END test: heap tracking. Attaches to a real
// process, tracks its heap, allocates, frees and reallocates blocks in it,
// and checks that the Heap view says which block an address is or was in.
//   node Fermion/scripts/ui-test-heap.js [screenshot-prefix]
// Exit 0 + HEAP_OK / HEAP_SKIP (cannot attach on this runner) ; 1 + HEAP_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-heap-'));
const shot = process.argv[2];
const T = { timeout: 30000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Run in the target through the REPL: the target's own allocator, callable.
const SETUP = String.raw`(function () {
  const g = (n) => Module.getGlobalExportByName(n);
  const malloc = new NativeFunction(g('malloc'), 'pointer', ['size_t']);
  const realloc = new NativeFunction(g('realloc'), 'pointer', ['pointer', 'size_t']);
  const free = new NativeFunction(g('free'), 'void', ['pointer']);
  globalThis.__h = { malloc: (n) => malloc(n).toString(), realloc: (p, n) => realloc(ptr(p), n).toString(), free: (p) => { free(ptr(p)); return 1; } };
  return 1;
})()`;

(async () => {
  let app; let step = 'launch';
  // A target that keeps allocating a little, so tracking every size has something to see.
  const target = spawn(process.execPath, ['-e', 'const zlib = require("zlib"); setInterval(() => { zlib.gzipSync(Buffer.from("x".repeat(500))); }, 50)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exitCode = code; setTimeout(() => process.exit(code), 200); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const output = () => win.evaluate(() => window.__fermion.terminal.getText());
    const inTarget = async (code) => {
      const r = await win.evaluate((c) => window.fermion.evaluate(c), code);
      if (!r || !r.ok) throw new Error('in the target, ' + code.slice(0, 40) + ' failed: ' + JSON.stringify(r).slice(0, 300));
      return r.text.replace(/^"|"$/g, '');
    };
    const text = (id) => win.evaluate((t) => document.querySelector('[data-testid="' + t + '"]')?.textContent ?? '', id);
    const lookUp = async (address, expect, what) => {
      await win.fill('[data-testid="heap-address"]', address);
      await win.click('[data-testid="heap-find"]');
      const end = Date.now() + 15000;
      let verdict = '';
      while (Date.now() < end) { verdict = await text('heap-verdict'); if (verdict.startsWith(address) && expect.test(verdict)) return verdict; await sleep(150); }
      throw new Error(what + '. Verdict: ' + verdict + ' | error: ' + await text('heap-error'));
    };
    const blocks = () => win.evaluate(() => [...document.querySelectorAll('[data-testid="heap-block"]')].map((b) => ({ kind: b.getAttribute('data-kind'), text: b.textContent, frames: b.querySelectorAll('[data-testid="heap-frame"]').length })));
    const attach = async () => win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);

    step = 'attach';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// heap test'));
    try {
      await attach();
    } catch (e) {
      console.log('HEAP_SKIP could not attach: ' + String(e && e.message ? e.message : e).split('\n')[0].slice(0, 160));
      await app.close(); return done(0);
    }
    await inTarget(SETUP);

    await win.click('role=tab[name="Inspector"]');
    await win.click('[data-testid="insp-heap"]');
    await win.waitForSelector('[data-testid="heap-empty"]', T);

    // Windows can be asked about an address with nothing tracked: it knows the block, not who made it.
    let untrackedSeen = '';
    if (process.platform === 'win32') {
      step = 'nothing tracked: Windows names the block an address is in';
      const old = await inTarget('__h.malloc(2457)');
      await lookUp('0x' + (BigInt(old) + 0x20n).toString(16), /is inside a live block that was not recorded/, 'a block from before tracking was not found');
      const sys = await text('heap-system');
      if (!sys.includes('2,457 bytes at ' + old) || !sys.includes('byte +0x20')) throw new Error('the block as Windows lists it: ' + sys);
      await inTarget('__h.free("' + old + '")');
      untrackedSeen = await lookUp(old, /free right now|is not inside any block in use/, 'a freed block from before tracking is still called live');
      if (await win.$('[data-testid="heap-block"]')) throw new Error('a call stack is shown for a block nothing was recorded about');
    }

    step = 'track one size';
    await win.fill('[data-testid="heap-min"]', '4660');
    await win.fill('[data-testid="heap-max"]', '4660');
    await win.click('[data-testid="heap-toggle"]');
    await win.waitForSelector('[data-testid="heap-status"]', T);
    const status = await text('heap-status');
    if (!/Tracking blocks of exactly 4,660 bytes through /.test(status)) throw new Error('status: ' + status);
    if (!/(RtlAllocateHeap|malloc)/.test(status)) throw new Error('no allocator function named: ' + status);

    step = 'a live block is found from an address inside it';
    const p = await inTarget('__h.malloc(4660)');
    const inside = '0x' + (BigInt(p) + 0x10n).toString(16);
    await lookUp(inside, /is inside a live block\.$/, 'the live block was not found');
    let got = await blocks();
    if (got.length !== 1 || got[0].kind !== 'live' || !got[0].text.includes('4,660 bytes at ' + p) || !got[0].text.includes('byte +0x10')) throw new Error('live block: ' + JSON.stringify(got));
    if (got[0].frames < 1) throw new Error('no call stack for the allocation');
    // One byte past it is not in this block (it may be in the next one, which nothing was recorded about).
    await lookUp('0x' + (BigInt(p) + 4660n).toString(16), /is not inside any block|was not recorded|free right now/, 'one byte past the block was taken to be inside it');
    if ((await blocks()).length) throw new Error('one byte past the block shows a recorded block: ' + JSON.stringify(await blocks()));

    step = 'after free it is a use after free, with who freed it';
    await inTarget('__h.free("' + p + '")');
    const verdict = await lookUp(inside, /has been freed|free right now/, 'the freed block was not found');
    if (!/use after free/.test(verdict)) throw new Error('verdict: ' + verdict);
    got = await blocks();
    if (got.length !== 1 || got[0].kind !== 'freed' || !/Allocated by thread \d+/.test(got[0].text) || !/Freed by thread \d+/.test(got[0].text)) throw new Error('freed block: ' + JSON.stringify(got));
    await win.waitForFunction(() => /^1 allocated, 1 freed, 0 live/.test(document.querySelector('[data-testid="heap-counts"]')?.textContent ?? ''), undefined, T);
    if (shot) await win.screenshot({ path: shot + '-freed.png' });

    step = 'the address menu looks an address up';
    await win.fill('[data-testid="heap-address"]', '');
    await win.click('[data-testid="heap-block"] .heap-block-head .mono', { button: 'right' });
    await win.click('[data-testid="addr-menu-heap"]');
    await win.waitForFunction((a) => document.querySelector('[data-testid="heap-address"]').value === a && (document.querySelector('[data-testid="heap-verdict"]')?.textContent ?? '').startsWith(a), p, T);

    step = 'stop keeps what was recorded';
    await win.click('[data-testid="heap-toggle"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="heap-toggle"]').textContent === 'Track', undefined, T);
    if (!/Heap tracking \(exactly 4,660 bytes\): 1 allocated, 1 freed, 0 live/.test((await output()).replace(/\r?\n/g, ''))) throw new Error('the result was not announced');
    await lookUp(inside, /has been freed|free right now/, 'the recording was lost at Stop');
    if (!(await blocks()).some((b) => b.kind === 'freed')) throw new Error('the recording was lost at Stop');
    const untracked = await inTarget('__h.malloc(4660)'); // after Stop: not recorded
    await lookUp(untracked, /has been freed|is not inside any block|was not recorded/, 'a block allocated after Stop was recorded');
    if ((await blocks()).some((b) => b.kind === 'live')) throw new Error('a block allocated after Stop is shown as live');

    step = 'track every size: counts, places, realloc';
    await win.fill('[data-testid="heap-min"]', '');
    await win.fill('[data-testid="heap-max"]', '');
    await win.click('[data-testid="heap-toggle"]');
    await win.waitForFunction(() => /Tracking blocks of any size/.test(document.querySelector('[data-testid="heap-status"]')?.textContent ?? ''), undefined, T);
    const small = await inTarget('__h.malloc(1024)');
    const big = await inTarget('__h.realloc("' + small + '", 1048576)');
    if (small === big) throw new Error('the reallocation did not move the block');
    await lookUp(big, /is inside a live block/, 'the reallocated block was not found');
    if (!(await blocks())[0].text.includes('1,048,576 bytes at ' + big)) throw new Error('reallocated block: ' + JSON.stringify(await blocks()));
    await lookUp(small, /freed|free right now|was not recorded/, 'the old block of the reallocation is not known as freed');
    if (!(await blocks()).some((b) => b.kind === 'freed')) throw new Error('the old block of the reallocation is not listed as freed');
    await win.waitForFunction(() => { const m = /^([\d,]+) allocated/.exec(document.querySelector('[data-testid="heap-counts"]')?.textContent ?? ''); return !!m && Number(m[1].replace(/,/g, '')) > 5 && document.querySelectorAll('[data-testid="heap-site"]').length > 0; }, undefined, T);
    const counts = await text('heap-counts');
    const sites = await win.evaluate(() => document.querySelectorAll('[data-testid="heap-site"]').length);
    if (shot) await win.screenshot({ path: shot + '-tracking.png' });

    step = 'call stacks the fast way, and none';
    const restart = async (how, size) => {
      await win.click('[data-testid="heap-toggle"]');
      await win.waitForFunction(() => document.querySelector('[data-testid="heap-toggle"]').textContent === 'Track', undefined, T);
      await win.selectOption('[data-testid="heap-stacks"]', how);
      await win.fill('[data-testid="heap-min"]', size ? String(size) : '');
      await win.fill('[data-testid="heap-max"]', size ? String(size) : '');
      await win.click('[data-testid="heap-toggle"]');
      await win.waitForFunction((want) => (document.querySelector('[data-testid="heap-status"]')?.textContent ?? '').includes(want), size ? 'exactly ' + size.toLocaleString('en-US') + ' bytes' : 'blocks of any size', T);
    };
    const taken = async (how, size) => {
      await restart(how, size);
      const q = await inTarget('__h.malloc(' + size + ')');
      await lookUp(q, /is inside a live block\.$/, 'a block tracked with ' + how + ' call stacks was not found');
      const b = await blocks();
      const notes = await win.evaluate(() => document.querySelectorAll('[data-testid="heap-stack-note"]').length);
      const status = await text('heap-status');
      await inTarget('__h.free("' + q + '")');
      return { frames: b[0].frames, text: b[0].text, notes, status };
    };
    const quick = await taken('fast', 4663);
    if (quick.frames < 1 || quick.notes !== 1 || !/fast way/.test(quick.status)) throw new Error('fast call stacks: ' + JSON.stringify(quick));
    const bare = await taken('none', 4664);
    if (bare.frames !== 0 || bare.notes !== 0 || !/Call stacks were not taken/.test(bare.text) || !/No call stacks are taken/.test(bare.status)) throw new Error('no call stacks: ' + JSON.stringify(bare));
    await restart('full', 0);

    step = 'an allocator of the program\'s own';
    // The C library's malloc and free stand in for a program's own allocator: on Windows they
    // sit on top of the system heap, so they are the outer call and the system's is inside.
    await win.click('[data-testid="heap-toggle"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="heap-toggle"]').textContent === 'Track', undefined, T);
    const crt = await inTarget('Process.findModuleByAddress(Module.getGlobalExportByName("malloc")).name');
    await win.click('[data-testid="heap-own-toggle"]');
    await win.click('[data-testid="heap-own-add"]');
    if (!(await win.isDisabled('[data-testid="heap-toggle"]'))) throw new Error('tracking can start with an unfinished allocator');
    await win.fill('[data-testid="heap-own-alloc"]', crt + '!malloc');
    await win.fill('[data-testid="heap-own-free"]', crt + '!free');
    await win.fill('[data-testid="heap-min"]', '4661');
    await win.fill('[data-testid="heap-max"]', '4661');
    await win.click('[data-testid="heap-toggle"]');
    let ownNote;
    if (process.platform === 'win32') {
      await win.waitForFunction((name) => (document.querySelector('[data-testid="heap-status"]')?.textContent ?? '').includes('through ' + name + '!malloc, ' + name + '!free, RtlAllocateHeap'), crt, T);
      const mine = await inTarget('__h.malloc(4661)');
      await lookUp('0x' + (BigInt(mine) + 8n).toString(16), /is inside a live block\.$/, 'a block from the named allocator was not found');
      const one = await blocks();
      if (one.length !== 1 || !one[0].text.includes('4,661 bytes at ' + mine) || one[0].frames < 1) throw new Error('block of the named allocator: ' + JSON.stringify(one));
      await inTarget('__h.free("' + mine + '")');
      await lookUp(mine, /has been freed|free right now/, 'the free through the named function was not seen');
      // Counted once: by the named allocator, not again by the system heap under it.
      await win.waitForFunction(() => /^1 allocated, 1 freed, 0 live/.test(document.querySelector('[data-testid="heap-counts"]')?.textContent ?? ''), undefined, T);
      await win.click('[data-testid="heap-toggle"]');
      await win.waitForFunction(() => document.querySelector('[data-testid="heap-toggle"]').textContent === 'Track', undefined, T);
      ownNote = 'own allocator (' + crt + '!malloc): block found, freed, counted once';
    } else {
      // Here malloc is the system's own, which is tracked already: naming it again is refused, in words.
      await win.waitForFunction(() => /already tracked as malloc/.test(document.querySelector('[data-testid="heap-error"]')?.textContent ?? ''), undefined, T);
      ownNote = 'naming an allocator that is already tracked is refused';
    }
    await win.fill('[data-testid="heap-own-alloc"]', 'no-such-module.dll!pool_alloc');
    await win.fill('[data-testid="heap-own-free"]', '');
    await win.click('[data-testid="heap-toggle"]');
    await win.waitForFunction(() => /The module no-such-module\.dll is not loaded/.test(document.querySelector('[data-testid="heap-error"]')?.textContent ?? ''), undefined, T);
    await win.click('[data-testid="heap-own-remove"]');
    await win.click('[data-testid="heap-own-toggle"]');
    await win.fill('[data-testid="heap-min"]', '');
    await win.fill('[data-testid="heap-max"]', '');
    await win.click('[data-testid="heap-toggle"]');
    await win.waitForFunction(() => /Tracking blocks of any size/.test(document.querySelector('[data-testid="heap-status"]')?.textContent ?? ''), undefined, T);

    step = 'detaching while tracking leaves the target running';
    await win.click('[data-testid="detach"]');
    await win.waitForFunction(() => !document.querySelector('[data-testid="heap-status"]'), undefined, T);
    await sleep(500);
    try { process.kill(target.pid, 0); } catch (_) { throw new Error('the target died'); }
    await attach();
    await inTarget(SETUP);
    const after = await inTarget('__h.malloc(64)');
    if (!/^0x[0-9a-f]+$/.test(after)) throw new Error('the target cannot allocate after detaching mid-tracking: ' + after);

    console.log('HEAP_OK ' + (untrackedSeen ? 'nothing tracked: Windows names a live block and then says: ' + untrackedSeen.replace(/^0x[0-9a-f]+ /, '').split('.')[0] + ' + ' : '') + 'fast call stacks (' + quick.frames + ' frames, marked) and none + ' + ownNote + ' + one size tracked + live block found from an inner address, with its call stack + one past the end is outside + freed block called a use after free, with who freed it + address menu looks up + stop keeps the record + every size: ' + counts + ', ' + sites + ' places + realloc moves the block + detach mid-tracking leaves the target unharmed');
    await app.close();
    done(0);
  } catch (e) {
    console.log('HEAP_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await Promise.race([app.close(), sleep(15000)]); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
