// Playwright-Electron END-TO-END test: hooks and bookmarks are saved and come
// back when Fermion is started again, and then work in a different process
// (found by module + offset, not by the old address).
//   node Fermion/scripts/ui-test-workspace.js [screenshot-prefix]
// Exit 0 + WORKSPACE_OK / WORKSPACE_SKIP (cannot attach on this runner) ; 1 + WORKSPACE_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-ws-'));
const shot = process.argv[2];
const T = { timeout: 20000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const TARGET = 'const fs = require("fs"); setInterval(() => { try { fs.statSync(process.execPath); } catch (e) {} }, 120)';

(async () => {
  let app; let step = 'launch';
  const targets = [spawn(process.execPath, ['-e', TARGET], { stdio: 'ignore' }), spawn(process.execPath, ['-e', TARGET], { stdio: 'ignore' })];
  const done = (code) => { targets.forEach((t) => { try { t.kill(); } catch (_) { /* gone */ } }); process.exit(code); };
  const start = async () => {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// workspace test'));
    return win;
  };
  const attach = async (win, pid) => {
    await win.evaluate((p) => window.__fermion.triggerAttach(p), pid);
    await win.waitForFunction(() => window.__fermion.service.isAttached, undefined, T);
  };
  try {
    let win = await start();
    const snap = async (name) => { if (shot) await win.screenshot({ path: shot + '-' + name + '.png' }); };

    step = 'attach';
    try {
      await attach(win, targets[0].pid);
    } catch (e) {
      console.log('WORKSPACE_SKIP could not attach: ' + String(e && e.message ? e.message : e).split('\n')[0]);
      await app.close(); return done(0);
    }

    step = 'add a hook and give it a handler';
    await win.click('role=tab[name="Hooks"]');
    await win.selectOption('[data-testid="hook-kind"]', 'symbols');
    await win.fill('[data-testid="hook-query"]', 'uv_fs_stat');
    await win.press('[data-testid="hook-query"]', 'Enter');
    await win.waitForFunction(() => [...document.querySelectorAll('[data-testid="hook-result"] .nm')].some((e) => /!uv_fs_stat$/.test(e.textContent)), undefined, T);
    const idx = await win.evaluate(() => [...document.querySelectorAll('[data-testid="hook-result"] .nm')].findIndex((e) => /!uv_fs_stat$/.test(e.textContent)));
    await win.locator('[data-testid="hook-result"]').nth(idx).locator('[data-testid="hook-add"]').click();
    await win.waitForFunction(() => document.querySelector('[data-testid="hook-status"]')?.textContent === 'hooked', undefined, T);
    await win.click('[data-testid="hook-results-close"]');
    await win.click('[data-testid="hook-echo"]'); // keep Output quiet
    await win.click('[data-testid="hook-tab-handler"]');
    const HANDLER = '({ onEnter(log, args) { log("SAVED_HANDLER " + args[2].readUtf8String()); } })';
    await win.fill('[data-testid="hook-code"]', HANDLER);
    await win.click('[data-testid="hook-apply"]');
    await win.waitForFunction(() => /^Handler$/.test(document.querySelector('[data-testid="hook-tab-handler"]').textContent), undefined, T);
    const firstAddress = await win.evaluate(() => document.querySelector('[data-testid^="hook-row-"] .nm').getAttribute('title').split(' · ')[1]);

    step = 'bookmark it';
    await win.click('[data-testid^="hook-row-"]', { button: 'right' });
    await win.waitForSelector('[data-testid="addr-menu"]', T);
    await win.click('[data-testid="addr-menu-bookmark"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="insp-bookmarks"]')?.getAttribute('aria-selected') === 'true'
      && document.querySelectorAll('[data-testid="bm-row"]').length === 1, undefined, T);
    if (!/!uv_fs_stat$/.test(await win.inputValue('[data-testid="bm-label"]'))) throw new Error('bookmark name: ' + await win.inputValue('[data-testid="bm-label"]'));
    await win.fill('[data-testid="bm-label"]', 'stat entry');
    await win.fill('[data-testid="bm-note"]', 'path is the third argument');
    await snap('bookmarks');

    step = 'close and reopen';
    await sleep(900); // the save is written a moment after the last change
    await app.close();
    const file = path.join(userDataDir, 'workspace.json');
    if (!fs.existsSync(file)) throw new Error('nothing was saved to ' + file);
    const onDisk = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (onDisk.hooks.length !== 1 || onDisk.hooks[0].code !== HANDLER || onDisk.bookmarks.length !== 1 || onDisk.bookmarks[0].label !== 'stat entry') {
      throw new Error('saved file: ' + JSON.stringify(onDisk).slice(0, 400));
    }
    if ('status' in onDisk.hooks[0] || 'calls' in onDisk.hooks[0]) throw new Error('session state was saved');
    win = await start();

    step = 'they are back, before any session';
    await win.click('role=tab[name="Hooks"]');
    await win.waitForSelector('[data-testid^="hook-row-"]', T);
    if ((await win.textContent('[data-testid="hook-status"]')) !== 'placed on attach') throw new Error('restored hook status: ' + await win.textContent('[data-testid="hook-status"]'));
    await win.click('[data-testid="hook-tab-handler"]');
    if ((await win.inputValue('[data-testid="hook-code"]')) !== HANDLER) throw new Error('the handler was not restored');
    await win.click('role=tab[name="Inspector"]');
    await win.click('[data-testid="insp-bookmarks"]');
    await win.waitForSelector('[data-testid="bm-row"]', T);
    if ((await win.inputValue('[data-testid="bm-label"]')) !== 'stat entry' || (await win.inputValue('[data-testid="bm-note"]')) !== 'path is the third argument') throw new Error('the bookmark was not restored');
    if (!(await win.evaluate(() => document.querySelector('[data-testid="bm-open-code"]').disabled))) throw new Error('a bookmark should not open without a session');

    step = 'they work in another process';
    await attach(win, targets[1].pid);
    await win.click('role=tab[name="Hooks"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="hook-status"]')?.textContent === 'hooked', undefined, T);
    await win.click('[data-testid="hook-tab-hits"]');
    await win.waitForFunction(() => [...document.querySelectorAll('[data-testid="hook-hit"] .hx')].some((e) => e.textContent.includes('SAVED_HANDLER ')), undefined, T);
    await win.click('role=tab[name="Inspector"]');
    await win.waitForFunction(() => /uv_fs_stat|\+0x[0-9a-f]+ · 0x[0-9a-f]+/.test(document.querySelector('[data-testid="bm-where"]')?.textContent ?? '')
      && !document.querySelector('[data-testid="bm-open-code"]').disabled, undefined, T);
    const whereNow = await win.textContent('[data-testid="bm-where"]');
    const nowAddress = (/ · (0x[0-9a-f]+)/.exec(whereNow) || [])[1];
    if (!nowAddress) throw new Error('the bookmark has no address in this session: ' + whereNow);
    await win.click('[data-testid="bm-open-code"]');
    await win.waitForFunction((a) => document.querySelector('[data-testid="insp-code"]').getAttribute('aria-selected') === 'true'
      && document.querySelector('[data-testid="code-row"] .ca')?.textContent === a, nowAddress, T);
    if (!/uv_fs_stat/.test(await win.textContent('[data-testid="code-where"]'))) throw new Error('the bookmark opened somewhere else: ' + await win.textContent('[data-testid="code-where"]'));
    await snap('restored');

    step = 'the set belongs to the program';
    await win.click('role=tab[name="Hooks"]');
    const setName = await win.inputValue('[data-testid="set-pick"]:visible');
    if (!/^node(\.exe)?$/i.test(setName)) throw new Error('the set in use is "' + setName + '", not the attached program');
    // The general set is empty: choosing it takes the hook out of the process...
    await win.selectOption('[data-testid="set-pick"]:visible', '');
    await win.waitForSelector('[data-testid="hook-empty"]', T);
    await win.click('role=tab[name="Inspector"]');
    await win.click('[data-testid="insp-bookmarks"]');
    if (await win.evaluate(() => document.querySelectorAll('[data-testid="bm-row"]').length)) throw new Error('the general set shows another program\'s bookmark');
    // ...and choosing the program's set again puts it back, hooked.
    await win.selectOption('[data-testid="set-pick"]:visible', setName);
    await win.waitForSelector('[data-testid="bm-row"]', T);
    await win.click('role=tab[name="Hooks"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="hook-status"]')?.textContent === 'hooked', undefined, T);
    await sleep(900);
    const sets = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (sets.version !== 2 || sets.set !== setName || sets.hooks.length !== 1 || sets.others.length !== 0) throw new Error('saved sets: ' + JSON.stringify(sets).slice(0, 300));

    step = 'removing is saved too';
    await win.click('role=tab[name="Inspector"]');
    await win.click('[data-testid="insp-bookmarks"]');
    await win.click('[data-testid="bm-remove"]');
    await win.click('role=tab[name="Hooks"]');
    await win.click('[data-testid="hook-remove"]');
    await win.waitForSelector('[data-testid="hook-empty"]', T);
    await sleep(900);
    const after = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (after.hooks.length || after.bookmarks.length) throw new Error('removals were not saved: ' + JSON.stringify(after).slice(0, 200));

    console.log('WORKSPACE_OK hook + handler + bookmark saved, restored after a restart, working in another process, kept as a set per program (was ' + firstAddress + ', now ' + nowAddress + ')');
    await app.close();
    done(0);
  } catch (e) {
    console.log('WORKSPACE_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await app.close(); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
