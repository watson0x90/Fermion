// Playwright-Electron regression: the remaining child windows open under the
// secured model (contextIsolation on, no Node) with the preload bridge present
// and no uncaught error. Guards Review Focus #5.
//
// In the React A/L1 shell the device/proc/instrument/trace/svg pop-ups are
// folded into the main window (Session sidebar + Graph panel), so only About
// and Docs remain as child windows. They open from the activity bar.
//
//   node scripts/ui-test-child-windows.js
// Exit 0 + CHILD_WINDOWS_OK   -> About + Docs open isolated with window.fermion
// Exit 1 + CHILD_WINDOWS_FAIL -> a window failed to open / is not isolated / errored
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const path = require('path');

const APP_DIR = path.join(__dirname, '..');
const CASES = [
  ['open-about', 'about.html'],
  ['open-docs', 'docs.html'],
];

(async () => {
  const errors = [];
  let app;
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox'], cwd: APP_DIR });
    app.on('window', (page) => page.on('pageerror', (e) =>
      errors.push(page.url() + ' :: ' + String(e && e.message ? e.message : e))));
    const main = await app.firstWindow();
    await main.waitForSelector('.monaco-editor', { timeout: 60000 });

    let ok = 0;
    for (const [testid, file] of CASES) {
      await main.click(`[data-testid="${testid}"]`);
      try {
        await app.waitForEvent('window', { timeout: 8000 });
        await new Promise((r) => setTimeout(r, 500));
        const win = app.windows().find((w) => w.url().endsWith(file));
        if (!win) { console.log('FAIL ' + file + ' did not open'); continue; }
        // Secured: no Node (window.require from the Monaco loader is absent in
        // child windows), and the preload bridge is present.
        const check = await win.evaluate(() => ({
          hasFermion: !!window.fermion,
          hasNodeRequire: typeof require !== 'undefined',
        }));
        const pass = check.hasFermion && !check.hasNodeRequire;
        console.log((pass ? 'OK  ' : 'FAIL') + ' ' + file + ' ' + JSON.stringify(check));
        if (pass) ok++;
      } catch (e) {
        console.log('FAIL ' + file + ' (' + (e && e.message ? e.message : e) + ')');
      }
    }

    if (errors.length) { console.log('CHILD_WINDOWS_FAIL pageerror: ' + errors[0]); process.exit(1); }
    const allOk = ok === CASES.length;
    console.log(allOk ? ('CHILD_WINDOWS_OK ' + ok + '/' + CASES.length)
                      : ('CHILD_WINDOWS_FAIL ' + ok + '/' + CASES.length));
    process.exit(allOk ? 0 : 1);
  } catch (e) {
    console.log('CHILD_WINDOWS_FAIL ' + (e && e.message ? e.message : e));
    process.exit(1);
  } finally {
    try { if (app) await app.close(); } catch {}
  }
})();
