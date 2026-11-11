// Playwright-Electron regression: console.log/warn/error output is captured
// faithfully (not mislabeled as a runtime error). Drives the shared handler
// directly via the test handle (a full headless attach is impractical in CI);
// the real attach path is covered by the manual Windows verify step.
//   node Fermion/scripts/ui-test-console-log.js
// Exit 0 + CONSOLE_OK / 1 + CONSOLE_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-clog-'));

(async () => {
  let app;
  try {
    app = await electron.launch({
      executablePath: electronPath,
      args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir],
      cwd: APP_DIR,
    });
    const win = await app.firstWindow();
    await win.waitForLoadState('domcontentloaded');
    await win.waitForSelector('.xterm', { timeout: 60000 });

    // Feed the handler the exact messages Frida emits for console.log/warn/error
    // and send(). Before the fix these hit the "runtime error" branch.
    await win.evaluate(() => {
      const h = window.__fermion.handleScriptMessage;
      h({ type: 'log', level: 'info', payload: 'DROP_IN_OK pid 4821' });
      h({ type: 'log', level: 'warning', payload: 'warn-line' });
      h({ type: 'log', level: 'error', payload: 'err-line' });
      h({ type: 'send', payload: { event: 'open' } });
    });

    await win.waitForFunction(() => {
      const t = document.querySelector('.xterm-rows');
      const s = t ? t.textContent : '';
      return s.includes('DROP_IN_OK') && s.includes('warn-line') &&
             s.includes('err-line') && s.includes('"event"');
    }, { timeout: 15000 });

    // And none of it should be mislabeled as a runtime error.
    const mislabeled = await win.evaluate(() =>
      (document.querySelector('.xterm-rows').textContent || '').includes('Runtime error'));
    if (mislabeled) throw new Error('console output mislabeled as Runtime error');

    console.log('CONSOLE_OK console.log/warn/error + send captured faithfully');
    await app.close();
    process.exit(0);
  } catch (e) {
    console.log('CONSOLE_FAIL ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    process.exit(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
