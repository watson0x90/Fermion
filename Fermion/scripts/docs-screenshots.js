// Regenerates the README screenshots (../Images/fermion-*.png) by driving the
// real app against a throwaway target process.
//   node Fermion/scripts/docs-screenshots.js
// Needs a machine where Frida can attach (not the Linux CI runner). The target
// is a child `node` we start ourselves, so nothing about the machine's other
// processes ends up in the pictures.
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const OUT = path.join(APP_DIR, '..', 'Images');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-shots-'));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

const SCRIPT = [
  '// Log every file the process opens.',
  "const CreateFileW = Process.getModuleByName('kernel32.dll').getExportByName('CreateFileW');",
  '',
  'Interceptor.attach(CreateFileW, {',
  '  onEnter(args) {',
  "    console.log('CreateFileW  ' + args[0].readUtf16String());",
  '  },',
  '  onLeave(retval) {',
  "    if (retval.toInt32() === -1) console.warn('  -> failed');",
  '  },',
  '});',
  '',
  "send({ event: 'hooked', target: 'kernel32!CreateFileW', pid: Process.id });",
  '',
].join('\n');

(async () => {
  if (process.platform !== 'win32') { console.log('docs-screenshots: the example script targets Windows (kernel32!CreateFileW).'); process.exit(1); }
  const target = spawn(process.execPath, ['-e',
    'const fs = require("fs"); let n = 0; setInterval(() => { try { fs.closeSync(fs.openSync(n++ % 3 ? process.execPath : "C:/Windows/no-such-file.ini", "r")); } catch (e) {} }, 700)'], { stdio: 'ignore' });
  let app;
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const shot = async (name, page = win) => { await wait(500); await page.screenshot({ path: path.join(OUT, name) }); console.log('wrote Images/' + name); };
    const repl = async (code) => {
      const n = await win.evaluate(() => document.querySelectorAll('[data-testid="repl-entry"]').length);
      await win.click('[data-testid="repl-input"]');
      await win.keyboard.type(code);
      await win.keyboard.press('Enter');
      await win.waitForFunction((k) => { const r = document.querySelectorAll('[data-testid="repl-result"]'); return r.length === k + 1 && !r[k].classList.contains('run'); }, n, { timeout: 30000 });
    };

    // 1. Editor + Output, attached, with hook output streaming.
    await win.evaluate((s) => window.MonacoCodeEditor.setValue(s), SCRIPT);
    await win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
    await win.waitForFunction(() => (window.__fermion.terminal.getText().match(/CreateFileW/g) || []).length >= 6, undefined, { timeout: 30000 });
    await shot('fermion-overview.png');

    // 2. REPL: an expression, help, and Tab completion on offer.
    await win.click('role=tab[name="REPL"]');
    await repl('Process.enumerateModules().length');
    await repl('help Process.enumerateModules');
    await win.click('[data-testid="repl-input"]');
    await win.keyboard.type('Process.enum');
    await win.keyboard.press('Tab');
    await win.waitForSelector('[data-testid="repl-choice"]', { timeout: 15000 });
    await shot('fermion-repl.png');
    await win.fill('[data-testid="repl-input"]', '');

    // 3. Inspector: a thread's registers and backtrace.
    await win.click('role=tab[name="Inspector"]');
    await win.click('[data-testid="insp-threads"]');
    await win.waitForSelector('[data-testid^="thr-row-"]', { timeout: 20000 });
    await win.click('[data-testid^="thr-row-"]');
    await win.waitForSelector('[data-testid="bt-row"]', { timeout: 90000 }).catch(async (e) => {
      console.log('DEBUG thr-detail: ' + await win.evaluate(() => (document.querySelector('[data-testid="thr-detail"]') || {}).textContent));
      throw e;
    });
    await shot('fermion-inspector.png');

    // 4. Inspector: memory, a text scan and its hit in the hex view.
    await win.click('[data-testid="insp-memory"]');
    await win.click('[data-testid="mem-mode-scan"]');
    await win.selectOption('[data-testid="scan-as"]', 'text');
    await win.fill('[data-testid="scan-pattern"]', 'This program cannot be run in DOS mode');
    await win.click('[data-testid="scan-run"]');
    await win.waitForSelector('[data-testid="scan-row"]', { timeout: 30000 });
    await win.click('[data-testid="scan-row"]');
    await win.waitForSelector('[data-testid="hex-row"] .hl', { timeout: 20000 });
    await shot('fermion-memory.png');

    // 5. Graph, with Output detached so the graph has the room.
    await win.click('role=tab[name="Graph"]');
    const [out] = await Promise.all([app.waitForEvent('window', { timeout: 30000 }), win.click('[data-testid="detach-output"]')]);
    await out.waitForSelector('[data-testid="output-window"] .xterm', { timeout: 30000 });
    await win.fill('[data-testid="graph-module"]', 'kernel32.dll');
    await win.fill('[data-testid="graph-symbol"]', 'CreateFileW');
    await win.click('[data-testid="graph-trace"]');
    await win.waitForSelector('[data-testid="graph-img"]', { timeout: 40000 });
    await wait(1500);
    await shot('fermion-graph.png');
    await win.click('[data-testid="graph-stop"]');
    await win.waitForFunction(() => /trace: off/.test(document.querySelector('[data-testid="status-bar"]').textContent), undefined, { timeout: 20000 });

    // 6. The detached Output window on its own.
    await out.waitForFunction(() => (window.__fermion.terminal.getText().match(/CreateFileW/g) || []).length >= 6, undefined, { timeout: 30000 });
    await shot('fermion-output-window.png', out);
    await Promise.all([out.waitForEvent('close', { timeout: 15000 }), out.click('[data-testid="dock-output"]')]);

    // 7. A dark theme, whole app.
    await win.click('role=tab[name="Editor"]');
    await win.click('[data-testid="open-settings"]');
    await win.click('[data-testid="theme-Monokai"]');
    await wait(600);
    await shot('fermion-themes.png');

    await app.close();
    target.kill();
    process.exit(0);
  } catch (e) {
    console.log('docs-screenshots failed: ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) { /* closing */ }
    target.kill();
    process.exit(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) { /* temp dir */ }
  }
})();
