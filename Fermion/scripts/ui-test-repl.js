// Playwright-Electron END-TO-END test: the REPL evaluates entries in a real
// attached process.
//   node Fermion/scripts/ui-test-repl.js [screenshot.png]
// Exit 0 + REPL_OK / REPL_SKIP (cannot attach on this runner) ; 1 + REPL_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-repl-'));
const shot = process.argv[2];

(async () => {
  let app; let step = 'launch';
  const target = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 120000)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exit(code); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });

    step = 'not attached';
    await win.click('role=tab[name="REPL"]');
    if (!(await win.isDisabled('[data-testid="repl-input"]'))) throw new Error('REPL input enabled while not attached');

    step = 'attach';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// user script\nvar fromUserScript = 1;'));
    try {
      await win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
      await win.waitForFunction(() => window.__fermion.service.isAttached && window.__fermion.service.hasScript, undefined, { timeout: 20000 });
    } catch (e) {
      console.log('REPL_SKIP could not attach: ' + String(e && e.message ? e.message : e).split('\n')[0]);
      await app.close(); return done(0);
    }
    await win.waitForFunction(() => !document.querySelector('[data-testid="repl-input"]').disabled, undefined, { timeout: 15000 });

    // Type an entry, press Enter, and return the text of its result.
    const entry = async (code) => {
      const n = await win.evaluate(() => document.querySelectorAll('[data-testid="repl-entry"]').length);
      await win.click('[data-testid="repl-input"]');
      await win.keyboard.type(code);
      await win.keyboard.press('Enter');
      await win.waitForFunction((k) => {
        const rs = document.querySelectorAll('[data-testid="repl-result"]');
        return rs.length === k + 1 && !rs[k].classList.contains('run');
      }, n, { timeout: 20000 });
      return win.evaluate((k) => {
        const r = document.querySelectorAll('[data-testid="repl-result"]')[k];
        return { text: r.textContent, err: r.classList.contains('err') };
      }, n);
    };

    step = 'evaluate';
    const pid = await entry('Process.id');
    if (pid.err || pid.text !== String(target.pid)) throw new Error('Process.id -> ' + JSON.stringify(pid) + ', expected ' + target.pid);

    step = 'object result';
    const mod = await entry('({ arch: Process.arch, n: Process.enumerateModules().length > 0 })');
    if (mod.err || !/"arch": "/.test(mod.text) || !/"n": true/.test(mod.text)) throw new Error('object result: ' + JSON.stringify(mod));

    step = 'persistence';
    await entry('var kept = 20');
    const kept = await entry('kept + 1');
    if (kept.text !== '21') throw new Error('state did not persist: ' + JSON.stringify(kept));

    step = 'error';
    const bad = await entry('noSuchThing.x');
    if (!bad.err || !/ReferenceError/.test(bad.text)) throw new Error('error result: ' + JSON.stringify(bad));

    step = 'own scope';
    const scope = await entry('typeof fromUserScript');
    if (scope.text !== '"undefined"') throw new Error('REPL shares the user script scope: ' + JSON.stringify(scope));

    step = 'output mirror + console';
    await entry('console.log("REPL_CONSOLE_MARK"); 5');
    await win.waitForFunction(() => {
      const t = window.__fermion.terminal.getText();
      return t.includes('frida> Process.id') && t.includes('REPL_CONSOLE_MARK') && t.includes('ReferenceError');
    }, undefined, { timeout: 15000 });

    step = 'survives script reload';
    await win.evaluate(() => window.fermion.reloadScript('// reloaded'));
    const after = await entry('kept');
    if (after.text !== '20') throw new Error('REPL state lost on script reload: ' + JSON.stringify(after));

    step = 'history';
    await win.click('[data-testid="repl-input"]');
    await win.keyboard.press('ArrowUp');
    const recalled = await win.inputValue('[data-testid="repl-input"]');
    if (recalled !== 'kept') throw new Error('ArrowUp recalled "' + recalled + '"');
    await win.keyboard.press('ArrowDown');

    if (shot) await win.screenshot({ path: shot });

    step = 'entry that never finishes';
    // Must time out (20 s) and give the prompt back instead of locking it.
    const n0 = await win.evaluate(() => document.querySelectorAll('[data-testid="repl-entry"]').length);
    await win.click('[data-testid="repl-input"]');
    await win.keyboard.type('new Promise(function () {})');
    await win.keyboard.press('Enter');
    await win.waitForFunction((k) => {
      const r = document.querySelectorAll('[data-testid="repl-result"]')[k];
      return r && r.classList.contains('err') && /Timed out/.test(r.textContent);
    }, n0, { timeout: 40000 });
    await win.waitForFunction(() => !document.querySelector('[data-testid="repl-input"]').disabled, undefined, { timeout: 15000 });
    const again = await entry('1 + 1');
    if (again.text !== '2') throw new Error('REPL did not recover after a timeout: ' + JSON.stringify(again));

    step = 'detach';
    await win.click('[data-testid="detach"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="repl-input"]').disabled, undefined, { timeout: 15000 });

    console.log('REPL_OK evaluate + objects + persistence + errors + own scope + Output mirror + survives reload + history + timeout recovery');
    await app.close();
    done(0);
  } catch (e) {
    console.log('REPL_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
