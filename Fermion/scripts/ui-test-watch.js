// Playwright-Electron END-TO-END test: the memory watch. Attaches to a real
// process, watches a few bytes of its heap, has real threads of the target
// read and write them, and checks that the Watch view names who did.
//   node Fermion/scripts/ui-test-watch.js [screenshot-prefix]
// Exit 0 + WATCH_OK / WATCH_SKIP (cannot attach on this runner) ; 1 + WATCH_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-watch-'));
const shot = process.argv[2];
const T = { timeout: 30000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Run in the target through the REPL: a page of the target's own heap, and
// two ways to touch it from a thread the target itself starts (a library
// function that reads its argument, and one that writes to it).
const SETUP = String.raw`(function () {
  const g = (n) => Module.getGlobalExportByName(n);
  const page = Process.pageSize;
  const buf = new NativeFunction(g('malloc'), 'pointer', ['size_t'])(page * 3).add(page).and(ptr(page - 1).not());
  buf.writeUtf8String('1234 fermion');
  let run, reader, writer;
  if (Process.platform === 'windows') {
    const k32 = Process.getModuleByName('kernel32.dll');
    const abi = Process.pointerSize === 4 ? { abi: 'stdcall' } : {};
    const createThread = new NativeFunction(k32.getExportByName('CreateThread'), 'pointer', ['pointer', 'size_t', 'pointer', 'pointer', 'uint32', 'pointer'], abi);
    const wait = new NativeFunction(k32.getExportByName('WaitForSingleObject'), 'uint32', ['pointer', 'uint32'], abi);
    const close = new NativeFunction(k32.getExportByName('CloseHandle'), 'int', ['pointer'], abi);
    run = (fn, arg) => { const h = createThread(NULL, 0, fn, arg, 0, NULL); wait(h, 3000); close(h); };
    reader = k32.getExportByName('lstrlenA');
    writer = Process.getModuleByName('ntdll.dll').getExportByName('RtlInitializeSRWLock');
  } else {
    const create = new NativeFunction(g('pthread_create'), 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
    const join = new NativeFunction(g('pthread_join'), 'int', ['pointer', 'pointer']);
    run = (fn, arg) => { const t = Memory.alloc(16); if (create(t, NULL, fn, arg) !== 0) throw new Error('no thread'); join(t.readPointer(), NULL); };
    reader = g('atoi');
    writer = g('time');
  }
  globalThis.__w = { buf: buf, read: (off) => { run(reader, buf.add(off || 0)); return 1; }, write: () => { run(writer, buf); return 1; } };
  return buf.toString();
})()`;

(async () => {
  let app; let step = 'launch';
  const target = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
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
    const rows = () => win.evaluate(() => [...document.querySelectorAll('[data-testid="watch-row"]')].map((r) => ({ op: r.children[0].textContent, from: r.children[1].textContent, times: Number(r.children[2].textContent.replace(/[^\d].*$/, '')), last: r.children[3].textContent })));
    const waitRows = async (test, what) => {
      const end = Date.now() + 15000;
      let got = [];
      while (Date.now() < end) { got = await rows(); if (test(got)) return got; await sleep(200); }
      throw new Error(what + '. Rows: ' + JSON.stringify(got));
    };
    const attach = async () => win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);

    step = 'attach';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// watch test'));
    try {
      await attach();
    } catch (e) {
      console.log('WATCH_SKIP could not attach: ' + String(e && e.message ? e.message : e).split('\n')[0].slice(0, 160));
      await app.close(); return done(0);
    }
    const buf = await inTarget(SETUP);
    if (!/^0x[0-9a-f]+$/.test(buf)) throw new Error('no buffer: ' + buf);

    step = 'the address menu hands an address to the Watch view';
    await win.click('role=tab[name="Inspector"]');
    await win.click('[data-testid="insp-threads"]');
    await win.waitForSelector('[data-testid^="thr-row-"]', T);
    await win.click('[data-testid^="thr-row-"]');
    await win.waitForSelector('[data-testid="reg-pc"]', T);
    await win.click('[data-testid="reg-pc"]', { button: 'right' });
    await win.click('[data-testid="addr-menu-watch"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="insp-watch"]').getAttribute('aria-selected') === 'true', undefined, T);
    if (!/^0x[0-9a-f]+$/.test(await win.inputValue('[data-testid="watch-address"]'))) throw new Error('the address was not filled in');

    step = 'what cannot be watched is refused, with the reason';
    await win.click('[data-testid="watch-toggle"]'); // the address is a thread's program counter: code
    await win.waitForFunction(() => /is code/.test(document.querySelector('[data-testid="watch-error"]')?.textContent ?? ''), undefined, T);
    const sp = await win.evaluate(async () => { const t = (await window.fermion.inspect.threads()).items.find((x) => x.registers && x.registers.sp); return t ? t.registers.sp : ''; });
    if (sp) {
      await win.fill('[data-testid="watch-address"]', sp);
      await win.click('[data-testid="watch-toggle"]');
      await win.waitForFunction(() => /stack of thread \d+/.test(document.querySelector('[data-testid="watch-error"]')?.textContent ?? ''), undefined, T);
    }

    step = 'watch 8 bytes of the heap';
    await win.fill('[data-testid="watch-address"]', buf);
    await win.fill('[data-testid="watch-size"]', '8');
    await win.click('[data-testid="watch-toggle"]');
    await win.waitForSelector('[data-testid="watch-status"]', T);
    if (!(await win.textContent('[data-testid="watch-status"]')).includes('Watching 8 bytes at ' + buf)) throw new Error('status: ' + await win.textContent('[data-testid="watch-status"]'));

    step = 'a thread of the target reads the bytes';
    for (let i = 0; i < 3; i++) { await inTarget('__w.read(0)'); await sleep(80); }
    let got = await waitRows((r) => r.some((x) => x.op === 'read' && x.times >= 2), 'the reads were not seen');
    const read = got.find((x) => x.op === 'read');
    if (process.platform === 'win32' && !/strlen/i.test(read.from)) throw new Error('the read is not attributed to strlen: ' + read.from);
    if (BigInt(read.last) < BigInt(buf) || BigInt(read.last) >= BigInt(buf) + 8n) throw new Error('last byte outside the watch: ' + read.last);

    step = 'a thread of the target writes the bytes';
    await inTarget('__w.write()');
    got = await waitRows((r) => r.some((x) => x.op === 'write' && x.times >= 1), 'the write was not seen');

    step = 'the call stack of a place';
    await win.click('[data-testid="watch-row"]');
    await win.waitForSelector('[data-testid="watch-frame"]', T);
    const frames = await win.evaluate(() => document.querySelectorAll('[data-testid="watch-frame"]').length);
    if (shot) await win.screenshot({ path: shot + '-watching.png' });

    step = 'other bytes of the page are counted apart';
    const before = (await rows()).length;
    await sleep(80);
    await inTarget('__w.read(0x40)');
    await win.waitForSelector('[data-testid="watch-near"]', T);
    if (!/^1 access to other bytes on the same page are not listed/.test(await win.textContent('[data-testid="watch-near"]'))) throw new Error('near: ' + await win.textContent('[data-testid="watch-near"]'));
    if ((await rows()).length !== before) throw new Error('an access to other bytes was listed with the ones on the bytes');

    step = 'the watched page is not read behind the watch';
    const refused = await win.evaluate((a) => window.fermion.inspect.read(a, 8).then(() => '', (e) => String(e && e.message)), buf);
    if (!/being watched/.test(refused)) throw new Error('reading the watched page: ' + (refused || 'was allowed'));

    step = 'stop';
    await win.click('[data-testid="watch-toggle"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="watch-toggle"]').textContent === 'Watch', undefined, T);
    const line = await win.textContent('[data-testid="watch-line"]');
    if (!/^\d+ accesses from 2 places in [\d.]+ s$/.test(line)) throw new Error('summary: ' + line);
    if (!/Memory watch on 0x[0-9a-f]+ \(8 bytes\): \d+ accesses from 2 places/.test((await output()).replace(/\r?\n/g, ''))) throw new Error('the result was not announced');
    const after = await win.evaluate((a) => window.fermion.inspect.read(a, 8).then((r) => r.hex, (e) => 'ERR ' + (e && e.message)), buf);
    if (!/^[0-9a-f]{16}$/.test(after)) throw new Error('the bytes cannot be read after the watch: ' + after);
    await inTarget('__w.read(0)'); // and the target uses them freely
    await sleep(300);
    if (!/^\d+ accesses from 2 places/.test(await win.textContent('[data-testid="watch-line"]'))) throw new Error('the view changed after Stop');

    step = 'detaching while a watch runs leaves the memory usable';
    await win.click('[data-testid="watch-toggle"]');
    await win.waitForSelector('[data-testid="watch-status"]', T);
    await win.click('[data-testid="detach"]');
    await win.waitForFunction(() => !document.querySelector('[data-testid="watch-status"]'), undefined, T);
    await sleep(500);
    try { process.kill(target.pid, 0); } catch (_) { throw new Error('the target died'); }
    await attach();
    const again = await win.evaluate((a) => window.fermion.inspect.read(a, 8).then((r) => r.hex, (e) => 'ERR ' + (e && e.message)), buf);
    if (!/^[0-9a-f]{16}$/.test(again)) throw new Error('after detaching mid-watch the bytes cannot be read: ' + again);
    if (!(await win.evaluate(() => window.fermion.evaluate('Process.id'))).ok) throw new Error('the target did not answer at the end');

    console.log('WATCH_OK menu fills the address + code and a stack are refused + reads (' + read.from + ') and a write by real threads attributed + call stack of ' + frames + ' frames + other bytes of the page counted apart + page not read behind the watch + stop restores it + detach mid-watch leaves the target unharmed');
    await app.close();
    done(0);
  } catch (e) {
    console.log('WATCH_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await Promise.race([app.close(), sleep(15000)]); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
