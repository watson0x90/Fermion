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
