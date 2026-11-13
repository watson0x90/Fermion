// Playwright-Electron END-TO-END test: names for addresses. Attaches to a real
// process, gives a name to an address taken from a real backtrace, and checks
// that the backtrace, the Disassembly view and the Bookmarks list then show
// that name, also after detaching and attaching again.
//   node Fermion/scripts/ui-test-names.js [screenshot-prefix]
// Exit 0 + NAMES_OK / NAMES_SKIP (cannot attach on this runner) ; 1 + NAMES_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-names-'));
const shot = process.argv[2];
const T = { timeout: 30000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const NAME = 'fermion_named_here';

(async () => {
  let app; let step = 'launch';
  const target = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exitCode = code; setTimeout(() => process.exit(code), 200); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const attach = async () => win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
    // The frames of the selected thread: what is shown, and the address and place behind it.
    const frames = () => win.evaluate(() => [...document.querySelectorAll('[data-testid="bt-row"] .fsym')].map((b, i) => {
      const m = /^(0x[0-9a-f]+) · (\S+)/.exec(b.getAttribute('title') || '');
      return { i, text: b.textContent, address: m ? m[1] : '', where: m ? m[2] : '' };
    }));
    const openThread = async () => {
      await win.click('role=tab[name="Inspector"]');
      await win.click('[data-testid="insp-threads"]');
      await win.waitForSelector('[data-testid^="thr-row-"]', T);
      await win.click('[data-testid^="thr-row-"]');
      await win.waitForSelector('[data-testid="bt-row"]', T);
    };

    step = 'attach';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// names test'));
    try {
      await attach();
    } catch (e) {
      console.log('NAMES_SKIP could not attach: ' + String(e && e.message ? e.message : e).split('\n')[0].slice(0, 160));
      await app.close(); return done(0);
    }

    step = 'pick a frame inside a module';
    await openThread();
    const before = await frames();
    const frame = before.find((f) => /\+0x[0-9a-f]+$/.test(f.where));
    if (!frame) throw new Error('no frame inside a module: ' + JSON.stringify(before.slice(0, 4)));
    if (frame.text.includes(NAME)) throw new Error('the name is there before it was given');

    step = 'name it from the address menu';
    await win.click(`[data-testid="bt-row"] >> nth=${frame.i} >> .fsym`, { button: 'right' });
    await win.click('[data-testid="addr-menu-name"]');
    await win.waitForSelector('[data-testid="addr-menu-name-input"]', T);
    await win.fill('[data-testid="addr-menu-name-input"]', NAME);
    await win.press('[data-testid="addr-menu-name-input"]', 'Enter');
    await win.waitForFunction(() => !document.querySelector('[data-testid="addr-menu"]'), undefined, T);

    step = 'the backtrace shows the name';
    await win.waitForFunction(([i, name]) => document.querySelectorAll('[data-testid="bt-row"] .fsym')[i]?.textContent === name, [frame.i, NAME], T);
    // Other frames of the same module that are not just after it keep what they had.
    const after = await frames();
    const changed = after.filter((f, i) => f.text !== before[i].text);
    if (!changed.every((f) => f.text.startsWith(NAME))) throw new Error('a frame changed to something else: ' + JSON.stringify(changed));
    if (shot) await win.screenshot({ path: shot + '-backtrace.png' });

    step = 'the disassembly shows it as a label and in its heading';
    await win.click(`[data-testid="bt-row"] >> nth=${frame.i} >> .fsym`, { button: 'right' });
    await win.click('[data-testid="addr-menu-code"]');
    await win.waitForFunction((name) => document.querySelector('[data-testid="code-row"] [data-testid="code-label"]')?.textContent === name + ':', NAME, T);
    const heading = await win.textContent('[data-testid="code-where"]');
    if (!heading.startsWith(NAME + ' ')) throw new Error('heading: ' + heading);
    if ((await win.evaluate(() => document.querySelectorAll('[data-testid="code-label"]').length)) !== 1) throw new Error('more than one instruction carries the label');
    if (shot) await win.screenshot({ path: shot + '-code.png' });

    step = 'it is a bookmark, and renaming it there renames it everywhere';
    await win.click('[data-testid="insp-bookmarks"]');
    await win.waitForFunction((name) => document.querySelector('[data-testid="bm-label"]')?.value === name, NAME, T);
    const renamed = NAME + '_2';
    await win.fill('[data-testid="bm-label"]', renamed);
    await win.press('[data-testid="bm-label"]', 'Enter');
    await win.click('[data-testid="insp-code"]');
    await win.waitForFunction((name) => document.querySelector('[data-testid="code-label"]')?.textContent === name + ':', renamed, T);

    step = 'after detaching and attaching again the name is still there';
    await sleep(600); // the set is saved a moment after a change
    await win.click('[data-testid="detach"]');
    await win.waitForFunction(() => /Attach to a process/.test(document.querySelector('[data-testid="inspector-panel"]').textContent) || !!document.querySelector('[data-testid="insp-bookmarks"][aria-selected="true"]'), undefined, T);
    await attach();
    await win.click('[data-testid="insp-code"]');
    await win.fill('[data-testid="code-addr"]', frame.address);
    await win.click('[data-testid="code-go"]');
    await win.waitForFunction((name) => document.querySelector('[data-testid="code-label"]')?.textContent === name + ':', renamed, T);
    if (!(await win.evaluate(() => window.fermion.evaluate('Process.id'))).ok) throw new Error('the target did not answer at the end');

    console.log('NAMES_OK named ' + frame.where + ' from the address menu + backtrace shows the name + disassembly label and heading + renaming the bookmark renames it + kept across detach and attach');
    await app.close();
    done(0);
  } catch (e) {
    console.log('NAMES_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await Promise.race([app.close(), sleep(15000)]); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
