// Playwright-Electron END-TO-END test: strings and references. Attaches to a
// real process, searches the strings of one of its modules, asks what refers
// to a string from the address menu, and follows a reference into the
// Disassembly view, where the instruction must be the one that was listed.
//   node Fermion/scripts/ui-test-strings.js [screenshot-prefix]
// Exit 0 + STRINGS_OK / STRINGS_SKIP (cannot attach on this runner) ; 1 + STRINGS_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-strings-'));
const shot = process.argv[2];
const T = { timeout: 45000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// A small system library on Windows (quick to search); elsewhere the program itself.
const WINDOWS = process.platform === 'win32';
const MODULE = WINDOWS ? 'kernel32.dll' : path.basename(process.execPath);
const SEARCH = WINDOWS ? 'kernel' : 'NODE_OPTIONS';

(async () => {
  let app; let step = 'launch';
  const target = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exitCode = code; setTimeout(() => process.exit(code), 200); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const strings = () => win.evaluate(() => [...document.querySelectorAll('[data-testid="str-row"]')].map((r) => ({ kind: r.children[0].textContent, text: r.children[1].textContent, address: r.children[2].textContent })));

    step = 'attach';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// strings test'));
    try {
      await win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
    } catch (e) {
      console.log('STRINGS_SKIP could not attach: ' + String(e && e.message ? e.message : e).split('\n')[0].slice(0, 160));
      await app.close(); return done(0);
    }

    step = 'the strings of a module';
    await win.click('role=tab[name="Inspector"]');
    await win.waitForSelector('[data-testid^="mod-row-"]', T);
    const row = await win.evaluate((name) => [...document.querySelectorAll('[data-testid^="mod-row-"]')].map((r) => r.getAttribute('data-testid')).find((id) => id.slice(8).toLowerCase() === name.toLowerCase()), MODULE);
    if (!row) throw new Error(MODULE + ' is not among the modules');
    await win.click('[data-testid="' + row + '"]');
    await win.click('[data-testid="sym-kind-strings"]');
    await win.waitForSelector('[data-testid="str-row"]', T);
    const all = await strings();
    if (all.length < 50) throw new Error('only ' + all.length + ' strings in ' + MODULE);
    if (!all.every((s) => /^0x[0-9a-f]+$/.test(s.address) && s.text.length >= 5 && /^[aw]$/.test(s.kind))) throw new Error('a row is malformed: ' + JSON.stringify(all.find((s) => s.text.length < 5 || !/^[aw]$/.test(s.kind))));
    const countAll = await win.textContent('[data-testid="sym-count"]');

    step = 'searching them';
    await win.fill('[data-testid="sym-filter"]', SEARCH);
    await win.waitForFunction((needle) => {
      const rows = [...document.querySelectorAll('[data-testid="str-row"]')];
      return rows.length > 0 && rows.every((r) => r.children[1].textContent.toLowerCase().includes(needle.toLowerCase()));
    }, SEARCH, T);
    const found = await strings();
    // What is listed is really there: the bytes at the address spell the string.
    const probe = found[0];
    const mem = await win.evaluate((a) => window.fermion.inspect.read(a, 64), probe.address);
    const bytes = mem.hex.match(/../g).map((h) => parseInt(h, 16));
    const spelled = probe.kind === 'w' ? bytes.filter((_, i) => i % 2 === 0) : bytes;
    const inMemory = String.fromCharCode(...spelled.slice(0, Math.min(probe.text.length, 30)));
    if (inMemory !== probe.text.slice(0, inMemory.length)) throw new Error('memory at ' + probe.address + ' reads ' + JSON.stringify(inMemory) + ', the list says ' + JSON.stringify(probe.text.slice(0, 30)));
    if (shot) await win.screenshot({ path: shot + '-strings.png' });

    step = 'what refers to a string';
    // Not every string is referred to from its own module: try a few.
    let refs = null;
    for (let i = 0; i < Math.min(found.length, 15) && !refs; i++) {
      await win.click('[data-testid="insp-modules"]');
      await win.click(`[data-testid="str-row"] >> nth=${i} >> [data-testid="str-addr"]`, { button: 'right' });
      await win.click('[data-testid="addr-menu-refs"]');
      await win.waitForFunction(() => document.querySelector('[data-testid="insp-refs"]').getAttribute('aria-selected') === 'true', undefined, T);
      await win.waitForFunction((a) => (document.querySelector('[data-testid="refs-line"]')?.textContent ?? '').includes(a) || !!document.querySelector('[data-testid="refs-error"]'), found[i].address, T);
      const got = await win.evaluate(() => ({
        line: document.querySelector('[data-testid="refs-line"]')?.textContent ?? '',
        code: [...document.querySelectorAll('[data-testid="refs-code"]')].map((r) => ({ text: r.children[0].textContent, address: r.children[2].textContent })),
        pointers: document.querySelectorAll('[data-testid="refs-pointer"]').length,
      }));
      if (got.code.length) refs = { string: found[i], ...got };
    }
    if (!refs) throw new Error('none of the first strings found has a reference from code in ' + MODULE);
    if (!new RegExp('^\\d+ instructions? and \\d+ pointers? in .+ refer to ' + refs.string.address).test(refs.line)) throw new Error('summary: ' + refs.line);
    if (shot) await win.screenshot({ path: shot + '-refs.png' });

    step = 'a reference opens in Disassembly, at the instruction that was listed';
    await win.click('[data-testid="refs-code"]');
    await win.waitForFunction((a) => document.querySelector('[data-testid="insp-code"]').getAttribute('aria-selected') === 'true'
      && document.querySelector('[data-testid="code-row"] .ca')?.textContent === a, refs.code[0].address, T);
    const first = await win.evaluate(() => document.querySelector('[data-testid="code-row"] .cx').getAttribute('title'));
    if (first !== refs.code[0].text) throw new Error('listed as ' + JSON.stringify(refs.code[0].text) + ' but disassembles as ' + JSON.stringify(first));

    step = 'target unharmed';
    if (!(await win.evaluate(() => window.fermion.evaluate('Process.id'))).ok) throw new Error('the target did not answer at the end');

    console.log('STRINGS_OK ' + MODULE + ': ' + countAll + ' + search "' + SEARCH + '" gives ' + found.length + ', each containing it + a listed string is what memory holds + references to ' + JSON.stringify(refs.string.text.slice(0, 24)) + ': ' + refs.code.length + ' instruction(s), ' + refs.pointers + ' pointer(s) + the reference disassembles as listed (' + refs.code[0].text + ') + target unharmed');
    await app.close();
    done(0);
  } catch (e) {
    console.log('STRINGS_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await Promise.race([app.close(), sleep(15000)]); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
