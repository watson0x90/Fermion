// Playwright-Electron test: the output pane is an xterm.js terminal and the
// exported controller can write to it.
//   node Fermion/scripts/ui-test-terminal.js
// Exit 0 + TERM_OK / 1 + TERM_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-term-'));

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

    // The terminal must mount.
    await win.waitForSelector('.xterm', { timeout: 60000 });

    // The exported controller writes a line that shows in the rendered rows.
    await win.evaluate(() => window.__fermion.terminal.write('LOG', 'probe-123'));
    await win.waitForFunction(() => {
      const rows = document.querySelector('.xterm-rows');
      return rows && rows.textContent.includes('probe-123');
    }, { timeout: 15000 });

    // Output text must not touch the pane's edges, and the padded terminal must
    // still fit inside the pane (no rows or columns pushed out of view).
    await win.evaluate(() => { for (let i = 0; i < 80; i++) window.__fermion.terminal.write('LOG', 'fill-' + i); });
    await new Promise((r) => setTimeout(r, 500));
    const g = await win.evaluate(() => {
      const pane = document.querySelector('.obody').getBoundingClientRect();
      const rows = document.querySelector('.xterm-rows').getBoundingClientRect();
      const screen = document.querySelector('.xterm-screen').getBoundingClientRect();
      return {
        left: rows.left - pane.left, top: rows.top - pane.top,
        right: pane.right - screen.right, bottom: pane.bottom - screen.bottom,
      };
    });
    if (g.left < 8 || g.top < 6) throw new Error('output text touches the pane edge: ' + JSON.stringify(g));
    if (g.right < 0 || g.bottom < 0) throw new Error('padded terminal overflows the pane: ' + JSON.stringify(g));

    console.log('TERM_OK terminal mounted and write() rendered');
    await app.close();
    process.exit(0);
  } catch (e) {
    console.log('TERM_FAIL ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    process.exit(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
