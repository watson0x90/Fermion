// Playwright-Electron END-TO-END test: the Hooks tab finds a function in a real
// attached process, hooks it, lists its calls with callers, takes a new
// handler, survives a script reload, and places the hook again after a
// detach + attach.
//   node Fermion/scripts/ui-test-hooks.js [screenshot-prefix]
// Exit 0 + HOOKS_OK / HOOKS_SKIP (cannot attach on this runner) ; 1 + HOOKS_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-hooks-'));
const shot = process.argv[2];
const T = { timeout: 20000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  let app; let step = 'launch';
  // The target stats its own executable several times a second: libuv's
  // uv_fs_stat is called each time, with the path as its third argument.
  const target = spawn(process.execPath, ['-e', 'const fs = require("fs"); setInterval(() => { try { fs.statSync(process.execPath); } catch (e) {} }, 120)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exit(code); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const snap = async (name) => { if (shot) await win.screenshot({ path: shot + '-' + name + '.png' }); };
    const text = (id) => win.evaluate((i) => { const el = document.querySelector('[data-testid="' + i + '"]'); return el ? el.textContent : null; }, id);
    const calls = async () => Number((await text('hook-calls')).replace(/,/g, ''));
    const hitTexts = () => win.evaluate(() => [...document.querySelectorAll('[data-testid="hook-hit"] .hx')].map((e) => e.textContent));
    const waitStatus = (re) => win.waitForFunction((src) => new RegExp(src).test(document.querySelector('[data-testid="hook-status"]')?.textContent ?? ''), re.source, T);

    step = 'not attached';
    await win.click('role=tab[name="Hooks"]');
    await win.waitForSelector('[data-testid="hook-detached"]', T);
    if (!(await win.evaluate(() => document.querySelector('[data-testid="hook-query"]').disabled))) throw new Error('search should be unavailable before attaching');

    step = 'attach';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// hooks test'));
    try {
      await win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
      await win.waitForFunction(() => window.__fermion.service.isAttached, undefined, T);
    } catch (e) {
      console.log('HOOKS_SKIP could not attach: ' + String(e && e.message ? e.message : e).split('\n')[0]);
      await app.close(); return done(0);
    }

    step = 'search exports';
    await win.fill('[data-testid="hook-query"]', 'GetFileAttributes');
    await win.click('[data-testid="hook-search"]');
    await win.waitForSelector('[data-testid="hook-search-status"]', T);
    const exportsFound = await win.evaluate(() => document.querySelectorAll('[data-testid="hook-result"]').length);

    step = 'search debug symbols';
    await win.selectOption('[data-testid="hook-kind"]', 'symbols');
    await win.fill('[data-testid="hook-query"]', 'uv_fs_stat');
    await win.press('[data-testid="hook-query"]', 'Enter');
    await win.waitForFunction(() => [...document.querySelectorAll('[data-testid="hook-result"] .nm')].some((e) => /!uv_fs_stat$/.test(e.textContent)), undefined, T);
    await snap('search');

    step = 'hook';
    const idx = await win.evaluate(() => [...document.querySelectorAll('[data-testid="hook-result"] .nm')].findIndex((e) => /!uv_fs_stat$/.test(e.textContent)));
    await win.locator('[data-testid="hook-result"]').nth(idx).locator('[data-testid="hook-add"]').click();
    await waitStatus(/^hooked$/);
    if ((await win.locator('[data-testid="hook-result"]').nth(idx).locator('[data-testid="hook-add"]').textContent()) !== 'Hooked') throw new Error('the result was not marked as hooked');
    await win.click('[data-testid="hook-results-close"]');

    step = 'calls with the default handler';
    await win.waitForFunction(() => document.querySelectorAll('[data-testid="hook-hit"]').length >= 4, undefined, T);
    const first = await hitTexts();
    if (!first.some((t) => /^→\(0x[0-9a-f]+, /.test(t)) || !first.some((t) => /^←=> /.test(t))) throw new Error('default handler lines: ' + JSON.stringify(first.slice(0, 4)));
    if (!((await calls()) > 0)) throw new Error('the call count did not move');
    const out = await win.evaluate(() => window.__fermion.terminal.getText());
    if (!/\[hook\] \S+!uv_fs_stat -> \(0x/.test(out)) throw new Error('hook lines did not reach Output');

    step = 'new handler';
    await win.click('[data-testid="hook-tab-handler"]');
    await win.fill('[data-testid="hook-code"]', '({\n  onEnter(log, args) {\n    this.path = args[2].readUtf8String();\n  },\n  onLeave(log, retval) {\n    log("stat " + this.path + " = " + retval.toInt32());\n  }\n})');
    await win.click('[data-testid="hook-apply"]');
    await win.waitForFunction(() => /^Handler$/.test(document.querySelector('[data-testid="hook-tab-handler"]').textContent), undefined, T);
    await snap('handler');
    await win.click('[data-testid="hook-tab-hits"]');
    const exeName = path.basename(process.execPath);
    await win.waitForFunction((name) => [...document.querySelectorAll('[data-testid="hook-hit"] .hx')].some((e) => e.textContent.startsWith('←stat ') && e.textContent.includes(name) && / = 0$/.test(e.textContent)), exeName, T);

    step = 'a handler that does not compile';
    await win.click('[data-testid="hook-tab-handler"]');
    const good = await win.inputValue('[data-testid="hook-code"]');
    await win.fill('[data-testid="hook-code"]', '({ onEnter(log, args) {');
    await win.click('[data-testid="hook-apply"]');
    await win.waitForFunction(() => /does not compile/.test(document.querySelector('[data-testid="hook-code-error"]')?.textContent ?? ''), undefined, T);
    const before = await calls();
    await sleep(700);
    if (!((await calls()) > before)) throw new Error('the hook stopped after a rejected handler');
    await win.click('[data-testid="hook-revert"]');
    if ((await win.inputValue('[data-testid="hook-code"]')) !== good) throw new Error('Revert did not restore the applied handler');

    step = 'callers';
    // Callers are recorded on entry, so log there too.
    await win.fill('[data-testid="hook-code"]', '({ onEnter(log, args) { log("enter " + args[2].readUtf8String()); } })');
    await win.click('[data-testid="hook-apply"]');
    await win.waitForFunction(() => /^Handler$/.test(document.querySelector('[data-testid="hook-tab-handler"]').textContent), undefined, T);
    await win.click('[data-testid="hook-tab-hits"]');
    await win.click('[data-testid="hook-hits-clear"]');
    await win.waitForSelector('[data-testid="hook-hit"].has-bt', T);
    await win.click('[data-testid="hook-hit"].has-bt .hit-line');
    await win.waitForSelector('[data-testid="hook-frame"]', T);
    const frames = await win.evaluate(() => [...document.querySelectorAll('[data-testid="hook-frame"] .mono')].map((e) => e.textContent));
    if (!frames.length || !frames.some((f) => f.includes('!'))) throw new Error('callers were not named: ' + JSON.stringify(frames.slice(0, 5)));
    await snap('calls');

    step = 'switch off and on';
    await win.click('[data-testid="hook-toggle"]');
    await waitStatus(/^off$/);
    await sleep(300);
    const off1 = await calls();
    await sleep(700);
    if ((await calls()) !== off1) throw new Error('a switched-off hook is still counting calls');
    await win.click('[data-testid="hook-toggle"]');
    await waitStatus(/^hooked$/);
    await win.waitForFunction((n) => Number(document.querySelector('[data-testid="hook-calls"]').textContent.replace(/,/g, '')) > n, off1, T);

    step = 'survives a script reload';
    await win.evaluate(() => window.fermion.reloadScript('// reloaded'));
    const r1 = await calls();
    await win.waitForFunction((n) => Number(document.querySelector('[data-testid="hook-calls"]').textContent.replace(/,/g, '')) > n, r1, T);

    step = 'detach keeps the hook';
    await win.click('[data-testid="detach"]');
    await win.waitForFunction(() => !window.__fermion.service.isAttached, undefined, T);
    await waitStatus(/^placed on attach$/);
    if (!/Your hooks are kept/.test(await text('hook-detached'))) throw new Error('no note about kept hooks');

    step = 'attach places it again';
    await win.click('[data-testid="hook-hits-clear"]');
    await win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
    await waitStatus(/^hooked$/);
    await win.waitForFunction((name) => [...document.querySelectorAll('[data-testid="hook-hit"] .hx')].some((e) => e.textContent.startsWith('→enter ') && e.textContent.includes(name)), exeName, T);

    step = 'remove';
    await win.click('[data-testid="hook-remove"]');
    await win.waitForSelector('[data-testid="hook-empty"]', T);
    await sleep(400);
    if (target.exitCode !== null) throw new Error('the target died');

    console.log('HOOKS_OK search (' + exportsFound + ' exports, debug symbols) + hook + calls + Output + new handler + rejected handler + callers + off/on + survives reload + re-placed after detach + remove');
    await app.close();
    done(0);
  } catch (e) {
    console.log('HOOKS_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await app.close(); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
