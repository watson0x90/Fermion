// Playwright-Electron test: terminal toolbar — level filtering, clear, and the
// search API are wired to the terminal.
//   node Fermion/scripts/ui-test-toolbar.js
// Exit 0 + TOOLBAR_OK / 1 + TOOLBAR_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-tb-'));
const rowsText = () => {
  const r = document.querySelector('.xterm-rows');
  return r ? r.textContent : '';
};

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

    await win.evaluate(() => {
      window.__fermion.terminal.write('LOG', 'alpha-line');
      window.__fermion.terminal.write('WARN', 'bravo-line');
    });
    await win.waitForFunction(() => {
      const r = document.querySelector('.xterm-rows').textContent;
      return r.includes('alpha-line') && r.includes('bravo-line');
    }, { timeout: 15000 });

    // Toggle WARN off -> bravo hidden, alpha stays.
    await win.click('#flt-warn');
    await win.waitForFunction(() => {
      const r = document.querySelector('.xterm-rows').textContent;
      return r.includes('alpha-line') && !r.includes('bravo-line');
    }, { timeout: 15000 });

    // Toggle WARN back on -> both visible.
    await win.click('#flt-warn');
    await win.waitForFunction(() => {
      const r = document.querySelector('.xterm-rows').textContent;
      return r.includes('alpha-line') && r.includes('bravo-line');
    }, { timeout: 15000 });

    // Search finds a present term.
    const found = await win.evaluate(() => window.__fermion.terminal.searchNext('alpha'));
    if (!found) throw new Error('searchNext did not find a present term');

    // An invalid regex must fail gracefully, not throw out of the handler.
    const threw = await win.evaluate(() => {
      try { window.__fermion.terminal.searchNext('['); return false; } catch (e) { return true; }
    });
    if (threw) throw new Error('invalid regex threw out of searchNext');

    // Clear empties the terminal.
    await win.click('#clear-output');
    await win.waitForFunction(() => {
      const r = document.querySelector('.xterm-rows').textContent;
      return !r.includes('alpha-line') && !r.includes('bravo-line');
    }, { timeout: 15000 });

    console.log('TOOLBAR_OK filter + search + clear wired');
    await app.close();
    process.exit(0);
  } catch (e) {
    console.log('TOOLBAR_FAIL ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    process.exit(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
