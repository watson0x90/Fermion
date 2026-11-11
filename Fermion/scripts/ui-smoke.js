// Playwright-Electron UI smoke test — used by CI to prove a build actually
// LAUNCHES AND RENDERS, not merely that the process starts.
//
// Launches Fermion, then asserts:
//   * a window opens and finishes loading,
//   * the Monaco editor mounts (.monaco-editor in the DOM),
//   * the startup Frida version line reaches the output pane,
//   * no uncaught exception is raised in the renderer.
//
// Dev mode (default): launches the Electron binary against the source tree.
//   node scripts/ui-smoke.js
// Packaged mode: point FERMION_EXE at the packaged executable to smoke the
// actual release artifact.
//   FERMION_EXE=/path/to/fermion node scripts/ui-smoke.js
//
// Exit 0 + "UI_SMOKE_OK ..."   -> launched and rendered
// Exit 1 + "UI_SMOKE_FAIL ..." -> did not launch/render (fails the CI job)

const { _electron: electron } = require('playwright-core');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const packaged = !!process.env.FERMION_EXE;
const executablePath = process.env.FERMION_EXE || require('electron');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-smoke-'));
const args = packaged
  ? ['--user-data-dir=' + userDataDir]
  : ['.', '--user-data-dir=' + userDataDir];

(async () => {
  let app;
  const pageErrors = [];
  try {
    app = await electron.launch({
      executablePath,
      args,
      cwd: packaged ? undefined : APP_DIR,
    });

    const win = await app.firstWindow();
    win.on('pageerror', (err) => pageErrors.push(String(err && err.message ? err.message : err)));
    await win.waitForLoadState('domcontentloaded');

    // Monaco editor must actually mount.
    await win.waitForSelector('.monaco-editor', { timeout: 30000 });

    // The startup banner must reach the output pane (proves renderer + Frida
    // version lookup ran).
    await win.waitForFunction(() => {
      const el = document.getElementById('FridaOut');
      return el && /Frida v\d/.test(el.value);
    }, { timeout: 30000 });

    const fridaLine = await win.evaluate(() => {
      const el = document.getElementById('FridaOut');
      const m = el && el.value.match(/\[\+\] Fermion v\S+ -> Frida v\S+/);
      return m ? m[0] : '(version line not found)';
    });

    if (pageErrors.length) throw new Error('uncaught renderer error: ' + pageErrors[0]);

    console.log('UI_SMOKE_OK ' + (packaged ? 'packaged' : 'dev') + ' :: ' + fridaLine);
    await app.close();
    process.exit(0);
  } catch (e) {
    console.log('UI_SMOKE_FAIL ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    process.exit(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
