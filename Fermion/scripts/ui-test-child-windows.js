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
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
// A throwaway profile: this test changes the theme, which must never touch the
// profile of a real installation.
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-child-'));
const CASES = [
  ['open-about', 'about.html'],
  ['open-docs', 'docs.html'],
];

(async () => {
  const errors = [];
  let app;
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    app.on('window', (page) => page.on('pageerror', (e) =>
      errors.push(page.url() + ' :: ' + String(e && e.message ? e.message : e))));
    const main = await app.firstWindow();
    await main.waitForSelector('.monaco-editor', { timeout: 60000 });
    // Pick a dark theme so "the dialog follows the theme" is observable.
    await main.click('[data-testid="open-settings"]');
    await main.click('[data-testid="theme-Monokai"]');
    await main.evaluate(() => document.querySelector('[data-testid="settings-scrim"]').click());

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
        let pass = check.hasFermion && !check.hasNodeRequire;
        // The dialogs follow the app theme (set to Monokai, dark, above).
        const themed = await win.evaluate(() => {
          const bg = getComputedStyle(document.querySelector('.dialog')).backgroundColor;
          const [r, g, b] = (bg.match(/\d+/g) || []).map(Number);
          return { bg, dark: r + g + b < 200, vars: getComputedStyle(document.documentElement).getPropertyValue('--bg').trim() };
        });
        if (!themed.dark) { pass = false; check.theme = 'not themed: ' + JSON.stringify(themed); }
        if (file === 'about.html') {
          await win.waitForFunction(() => /^v\d+\.\d+\.\d+ · Frida \d/.test(document.querySelector('[data-testid="about-version"]').textContent), undefined, { timeout: 10000 })
            .catch(() => { pass = false; check.version = 'version not shown'; });
        }
        if (file === 'docs.html') {
          // The reference is built from the installed Frida's definitions.
          await win.waitForFunction(() => document.querySelectorAll('[data-testid="docs-topics"] button').length > 100, undefined, { timeout: 15000 })
            .catch(() => { pass = false; check.docs = 'no topics listed'; });
          await win.fill('[data-testid="docs-search"]', 'enumerateModules');
          const found = await win.evaluate(() => [...document.querySelectorAll('[data-testid="docs-topics"] button')].map((b) => b.dataset.topic));
          // Several topics have an enumerateModules; open Process among them.
          if (found.includes('Process')) await win.click('[data-testid="docs-topics"] button[data-topic="Process"]');
          const hit = await win.evaluate(() => ({
            main: document.querySelector('[data-testid="docs-main"]').textContent,
            marked: document.querySelectorAll('[data-testid="docs-main"] .hit').length,
            oldApi: document.body.textContent.includes('Module.findExportByName('),
          }));
          if (!found.includes('Process') || found.length > 20 || !hit.main.includes('Process.enumerateModules') || !hit.main.includes('enumerateModules(): Module[]') || hit.marked < 1) {
            pass = false; check.docs = 'search did not lead to Process.enumerateModules: ' + JSON.stringify({ found: found.slice(0, 8), marked: hit.marked });
          }
          if (hit.oldApi) { pass = false; check.docs = 'reference still describes the removed Module.findExportByName'; }
        }
        console.log((pass ? 'OK  ' : 'FAIL') + ' ' + file + ' ' + JSON.stringify(check));
        if (pass) ok++;
        await win.click('[data-testid="dialog-close"]').catch(() => {});
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
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch {}
  }
})();
