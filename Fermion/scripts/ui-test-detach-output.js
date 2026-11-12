// Playwright-Electron test: the Output pane detaches into its own window and
// docks back, without losing output either way.
//   node Fermion/scripts/ui-test-detach-output.js
// Exit 0 + DETACH_OK / 1 + DETACH_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-detach-'));

const termText = () => window.__fermion.terminal.getText();
const rowsText = () => (document.querySelector('.xterm-rows') || {}).textContent || '';
const emit = (win, level, text) =>
  win.evaluate(([l, t]) => window.__fermion.handleScriptMessage({ type: 'log', level: l, payload: t }), [level, text]);

(async () => {
  let app;
  let step = 'launch';
  try {
    app = await electron.launch({
      executablePath: electronPath,
      args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir],
      cwd: APP_DIR,
    });
    const main = await app.firstWindow();
    await main.waitForLoadState('domcontentloaded');
    await main.waitForSelector('.xterm', { timeout: 60000 });
    await main.waitForFunction(() => !!window.MonacoCodeEditor, { timeout: 60000 });

    step = 'seed history';
    // History that exists before detaching, and a filter the user already set.
    await emit(main, 'info', 'before-detach-line');
    await emit(main, 'warning', 'hidden-warn-line');
    await main.click('[data-testid="flt-WARN"]');
    const editorWidthDocked = await main.evaluate(() => document.querySelector('.toolbox').getBoundingClientRect().width);

    step = 'detach';
    // ---- detach ----
    const [out] = await Promise.all([
      app.waitForEvent('window', { timeout: 30000 }),
      main.click('[data-testid="detach-output"]'),
    ]);
    await out.waitForLoadState('domcontentloaded');
    await out.waitForSelector('[data-testid="output-window"] .xterm', { timeout: 30000 });

    // The new window is isolated like every other Fermion window.
    const iso = await out.evaluate(() => ({ node: typeof window.require === 'function' || typeof window.process !== 'undefined', bridge: !!window.fermion }));
    if (iso.node || !iso.bridge) throw new Error('output window isolation wrong: ' + JSON.stringify(iso));

    step = 'snapshot';
    // It received the history, and the WARN filter came with it.
    await out.waitForFunction(() => window.__fermion.terminal.getText().includes('before-detach-line'), { timeout: 15000 });
    await out.waitForFunction(() => {
      const r = (document.querySelector('.xterm-rows') || {}).textContent || '';
      return r.includes('before-detach-line') && !r.includes('hidden-warn-line');
    }, { timeout: 15000 });

    const dup = await out.evaluate(() => ((document.querySelector('.xterm-rows') || {}).textContent || '').split('before-detach-line').length - 1);
    if (dup !== 1) throw new Error('history rendered ' + dup + ' times in the detached window');

    step = 'main layout while detached';
    // The main window gave the Output column to the editor and offers to dock.
    await main.waitForFunction(() => document.querySelector('[data-testid="app-root"]').classList.contains('output-detached'), { timeout: 15000 });
    const mainDetached = await main.evaluate(() => ({
      outputVisible: document.querySelector('[data-testid="output-pane"]').getBoundingClientRect().width > 0,
      toolboxWidth: document.querySelector('.toolbox').getBoundingClientRect().width,
      dockLink: !!document.querySelector('[data-testid="status-dock-output"]'),
    }));
    if (mainDetached.outputVisible) throw new Error('main Output pane still visible while detached');
    if (!(mainDetached.toolboxWidth > editorWidthDocked + 100)) throw new Error('toolbox did not take the freed width: ' + editorWidthDocked + ' -> ' + mainDetached.toolboxWidth);
    if (!mainDetached.dockLink) throw new Error('status bar has no dock link while detached');

    step = 'live line';
    // Live output written in the main window appears in the detached window.
    await emit(main, 'error', 'live-after-detach');
    await out.waitForFunction(() => ((document.querySelector('.xterm-rows') || {}).textContent || '').includes('live-after-detach'), { timeout: 15000 });

    step = 'filter relay';
    // A filter changed in the detached window is remembered by the main window.
    await out.click('[data-testid="flt-WARN"]');
    await out.waitForFunction(() => ((document.querySelector('.xterm-rows') || {}).textContent || '').includes('hidden-warn-line'), { timeout: 15000 });

    step = 'theme relay';
    // A theme change in the main window re-skins the detached window.
    const bgBefore = await out.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--bg').trim());
    await main.click('[data-testid="open-settings"]');
    await main.click('[data-testid="theme-Monokai"]');
    await main.evaluate(() => document.querySelector('[data-testid="settings-scrim"]').click()); // close Settings
    await out.waitForFunction((b) => getComputedStyle(document.documentElement).getPropertyValue('--bg').trim() !== b, bgBefore, { timeout: 15000 });

    step = 'dock';
    // ---- dock (from the detached window's own button) ----
    await Promise.all([
      out.waitForEvent('close', { timeout: 15000 }),
      out.click('[data-testid="dock-output"]'),
    ]);
    await main.waitForFunction(() => !document.querySelector('[data-testid="app-root"]').classList.contains('output-detached'), { timeout: 15000 });
    await main.waitForFunction(() => document.querySelector('[data-testid="output-pane"]').getBoundingClientRect().width > 0, { timeout: 15000 });

    step = 'history after dock';
    // Nothing was lost: everything from before and during the detach is here,
    // rendered, with the filter state the user left in the detached window.
    const text = await main.evaluate(termText);
    for (const want of ['before-detach-line', 'hidden-warn-line', 'live-after-detach']) {
      if (!text.includes(want)) throw new Error('docked terminal lost "' + want + '"');
    }
    await main.waitForFunction(() => {
      const r = (document.querySelector('.xterm-rows') || {}).textContent || '';
      return r.includes('before-detach-line') && r.includes('hidden-warn-line') && r.includes('live-after-detach');
    }, { timeout: 15000 });
    const rows = await main.evaluate(rowsText);
    if (!rows.includes('live-after-detach')) throw new Error('docked terminal did not re-render');

    // Output after docking stays in the main window only.
    await emit(main, 'info', 'after-dock-line');
    await main.waitForFunction(() => ((document.querySelector('.xterm-rows') || {}).textContent || '').includes('after-dock-line'), { timeout: 15000 });

    step = 'second detach + close button';
    // ---- detach again, then close the main window: the output window goes too ----
    const [out2] = await Promise.all([
      app.waitForEvent('window', { timeout: 30000 }),
      main.click('[data-testid="detach-output"]'),
    ]);
    await out2.waitForSelector('[data-testid="output-window"] .xterm', { timeout: 30000 });
    await out2.waitForFunction(() => window.__fermion.terminal.getText().includes('after-dock-line'), { timeout: 15000 });
    // Closing via the window's own close button docks as well.
    await Promise.all([
      out2.waitForEvent('close', { timeout: 15000 }),
      out2.click('[data-testid="win-close"]'),
    ]);
    await main.waitForFunction(() => !document.querySelector('[data-testid="app-root"]').classList.contains('output-detached'), { timeout: 15000 });

    step = 'clear stays in step';
    {
      const [o] = await Promise.all([
        app.waitForEvent('window', { timeout: 30000 }),
        main.click('[data-testid="detach-output"]'),
      ]);
      await o.waitForSelector('[data-testid="output-window"] .xterm', { timeout: 30000 });
      await o.waitForFunction(() => window.__fermion.terminal.getText().includes('after-dock-line'), { timeout: 15000 });
      // Alt-C in the main window clears the detached window too.
      await main.evaluate(() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'c', altKey: true, bubbles: true })));
      await o.waitForFunction(() => window.__fermion.terminal.getText() === '', { timeout: 15000 });
      // Clear in the detached window clears the main window's history too.
      await emit(main, 'info', 'clear-me-line');
      await o.waitForFunction(() => window.__fermion.terminal.getText().includes('clear-me-line'), { timeout: 15000 });
      await o.click('[data-testid="clear-output"]');
      await o.waitForFunction(() => window.__fermion.terminal.getText() === '', { timeout: 15000 });
      await main.waitForFunction(() => window.__fermion.terminal.getText() === '', { timeout: 15000 });
      await Promise.all([o.waitForEvent('close', { timeout: 15000 }), o.click('[data-testid="dock-output"]')]);
      await main.waitForFunction(() => !document.querySelector('[data-testid="app-root"]').classList.contains('output-detached'), { timeout: 15000 });
    }

    step = 'main close takes output window';
    const [out3] = await Promise.all([
      app.waitForEvent('window', { timeout: 30000 }),
      main.click('[data-testid="detach-output"]'),
    ]);
    await out3.waitForSelector('[data-testid="output-window"]', { timeout: 30000 });
    const closed = out3.waitForEvent('close', { timeout: 15000 });
    await main.click('[data-testid="win-close"]').catch(() => {});
    await closed;

    console.log('DETACH_OK history + live lines + filters + theme survive detach and dock; output window follows the main window');
    await app.close().catch(() => {});
    process.exit(0);
  } catch (e) {
    console.log('DETACH_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    process.exit(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
