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

function launch(pageErrors) {
  return electron.launch({
    executablePath,
    args,
    cwd: packaged ? undefined : APP_DIR,
  }).then((app) => {
    // Attach the error listener as soon as any window is created — before
    // awaiting firstWindow() — so an exception thrown early in the renderer
    // (e.g. a bad require or the version IIFE) is still captured.
    app.on('window', (page) => {
      page.on('pageerror', (err) =>
        pageErrors.push(String(err && err.message ? err.message : err)));
    });
    return app;
  });
}

(async () => {
  let app;
  const pageErrors = [];
  try {
    // --- Phase 1: launches and renders ---
    app = await launch(pageErrors);
    let win = await app.firstWindow();
    await win.waitForLoadState('domcontentloaded');

    // Monaco editor and the xterm terminal must actually mount. Allow a
    // generous timeout: a cold CI runner (especially macOS, where Gatekeeper
    // assesses the freshly ad-hoc signed app on first launch) can be slow.
    await win.waitForSelector('.monaco-editor', { timeout: 60000 });
    await win.waitForSelector('.xterm', { timeout: 60000 });

    // The editor handle must be reachable (tests + layout + frida-service
    // read window.MonacoCodeEditor).
    await win.waitForFunction(() => !!window.MonacoCodeEditor, { timeout: 60000 });

    // The startup banner must reach the terminal (proves renderer + Frida
    // version lookup ran, and output routes to the terminal).
    await win.waitForFunction(() => {
      const rows = document.querySelector('.xterm-rows');
      return rows && /Frida v\d/.test(rows.textContent);
    }, { timeout: 60000 });

    const fridaLine = await win.evaluate(() => {
      const t = window.__fermion && window.__fermion.terminal;
      const text = t ? t.getText() : (document.querySelector('.xterm-rows') || {}).textContent || '';
      const m = text.match(/\[\+\] Fermion v\S+ -> Frida v\S+/);
      return m ? m[0] : '(version line not found)';
    });

    if (pageErrors.length) throw new Error('uncaught renderer error: ' + pageErrors[0]);
    console.log('UI_SMOKE_OK ' + (packaged ? 'packaged' : 'dev') + ' :: ' + fridaLine);

    // The React shell's own stylesheet must be applied (esbuild emits
    // renderer.bundle.css from the bundle's CSS imports; index.html links it).
    // A non-default body background proves the <link> resolved.
    const styled = await win.evaluate(() => getComputedStyle(document.body).backgroundColor);
    if (styled === 'rgba(0, 0, 0, 0)' || styled === 'rgb(255, 255, 255)' || !styled) {
      throw new Error('renderer stylesheet not applied (body background ' + styled + ')');
    }
    console.log('SMOKE_STYLE_OK renderer.bundle.css applied (body bg ' + styled + ')');

    // The custom title bar must render with the original wordmark image loaded.
    const tb = await win.evaluate(() => {
      const bar = document.querySelector('[data-testid="titlebar"]');
      const img = document.querySelector('.titlebar .wordmark');
      return { bar: !!bar, wordmark: !!img && img.complete && img.naturalWidth > 0, controls: !!document.querySelector('[data-testid="win-close"]') };
    });
    if (!tb.bar || !tb.wordmark || !tb.controls) throw new Error('title bar incomplete: ' + JSON.stringify(tb));
    console.log('SMOKE_TITLEBAR_OK wordmark + window controls present');

    // Seed a non-default (dark) theme, relaunch, and prove the whole app is
    // restored to it: dark chrome tokens AND a dark Monaco editor.
    await win.evaluate(() => { try { localStorage.setItem('fermion.theme', 'Monokai'); } catch (e) { /* ignore */ } });
    await app.close();

    app = await launch(pageErrors);
    win = await app.firstWindow();
    await win.waitForLoadState('domcontentloaded');
    await win.waitForSelector('.monaco-editor', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, { timeout: 60000 });
    await new Promise((r) => setTimeout(r, 1500));
    const themed = await win.evaluate(() => {
      const root = getComputedStyle(document.documentElement);
      const ed = document.querySelector('.monaco-editor .monaco-editor-background') || document.querySelector('.monaco-editor');
      return { saved: (() => { try { return localStorage.getItem('fermion.theme'); } catch (e) { return null; } })(), bg: root.getPropertyValue('--bg').trim(), editorBg: ed ? getComputedStyle(ed).backgroundColor : '' };
    });
    // Monokai is dark: editor background ~ rgb(39,40,34).
    if (themed.saved !== 'Monokai' || !/rgb\(3[0-9], 4[0-9], 3[0-9]\)/.test(themed.editorBg)) {
      throw new Error('saved theme not restored whole-app: ' + JSON.stringify(themed));
    }
    if (pageErrors.length) throw new Error('uncaught renderer error: ' + pageErrors[0]);
    console.log('SMOKE_THEME_OK saved theme (Monokai) re-skins chrome + editor after restart');

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
