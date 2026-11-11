// Playwright-Electron regression: the Trace window has @electron/remote enabled.
// Reproduces the bug where remote.require("@electron/remote/main") failed in
// Electron 45, leaving the trace window with remote disabled.
//   node Fermion/scripts/ui-test-trace-remote.js
// Exit 0 + TRACE_OK / 1 + TRACE_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-trace-'));

(async () => {
  let app;
  try {
    app = await electron.launch({
      executablePath: electronPath,
      args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir],
      cwd: APP_DIR,
    });
    const win = await app.firstWindow();
    const pageErrors = [];
    win.on('pageerror', (e) => pageErrors.push(String(e && e.message ? e.message : e)));
    await win.waitForLoadState('domcontentloaded');
    await win.waitForSelector('.xterm', { timeout: 60000 });

    // Open the Trace tool window.
    await win.click('#FermionTools');
    await new Promise((r) => setTimeout(r, 3000));

    // The buggy code threw "Cannot find module '@electron/remote/main'" from the
    // renderer and the trace window never opened.
    const remoteErr = pageErrors.find((m) => m.includes('@electron/remote/main'));
    if (remoteErr) throw new Error('renderer threw: ' + remoteErr);

    const traceWin = app.windows().find((w) => w !== win);
    if (!traceWin) throw new Error('trace window did not open');
    await traceWin.waitForLoadState('domcontentloaded');

    // @electron/remote must be usable in the trace window.
    const result = await traceWin.evaluate(() => {
      try {
        const r = require('@electron/remote');
        return typeof r.getCurrentWindow().id === 'number' ? 'OK' : 'NOT_A_WINDOW';
      } catch (e) {
        return 'THREW: ' + (e && e.message ? e.message : e);
      }
    });
    if (result !== 'OK') throw new Error('remote not usable in trace window -> ' + result);

    console.log('TRACE_OK @electron/remote enabled in the trace window');
    await app.close();
    process.exit(0);
  } catch (e) {
    console.log('TRACE_FAIL ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    process.exit(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
