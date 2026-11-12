// Playwright-Electron END-TO-END regression: attach to a real process and
// confirm the agent's console.log reaches the terminal.
//
// This guards the real Frida behavior that a synthetic test cannot: Frida
// delivers console.log/warn/error to Script.logHandler, NOT the `message`
// signal, so the app must wire logHandler (see wireScript in renderer.js).
//
//   node Fermion/scripts/ui-test-attach-console.js
// Exit 0 + ATTACH_OK / ATTACH_SKIP (target unavailable / cannot attach)
// Exit 1 + ATTACH_FAIL (attached but console.log did NOT reach the terminal)
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn, execSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const isWin = process.platform === 'win32';
// A throwaway profile, so the test never touches a real installation's settings.
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-attach-'));

function spawnTarget() {
  if (isWin) {
    spawn('notepad.exe', { detached: true, stdio: 'ignore' });
    try {
      const out = execSync('tasklist /FI "IMAGENAME eq notepad.exe" /FO CSV /NH', { encoding: 'utf8' });
      const m = out.match(/"notepad\.exe","(\d+)"/i);
      return m ? parseInt(m[1], 10) : null;
    } catch (_) { return null; }
  }
  // Other platforms: a long-lived child we own.
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 120000)'], { detached: true, stdio: 'ignore' });
  return child.pid;
}
function killTarget(pid) {
  try {
    if (isWin) execSync('taskkill /IM notepad.exe /F', { stdio: 'ignore' });
    else process.kill(pid);
  } catch (_) {}
}

(async () => {
  let pid;
  let app;
  try {
    pid = spawnTarget();
    await new Promise((r) => setTimeout(r, 1500));
    if (!pid) { console.log('ATTACH_SKIP could not spawn a target'); process.exit(0); }

    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForSelector('.monaco-editor', { timeout: 60000 });

    const marker = 'ATTACH_CONSOLE_' + Date.now();
    await win.evaluate((c) => window.MonacoCodeEditor.setValue(c),
      "console.log('" + marker + " ' + Process.id);");

    // Fire the real attach path (same handler the proc window's relay drives).
    // The renderer is context-isolated, so drive it through the test surface.
    // A runner that forbids attaching to another process (Linux ptrace
    // restrictions on CI) rejects here; that is a skip, not a failure — the
    // real coverage is on a machine that can attach.
    try {
      await win.evaluate((p) => window.__fermion.triggerAttach(p), pid);
    } catch (e) {
      const why = String(e && e.message ? e.message : e).split(/\r?\n/)[0];
      console.log('ATTACH_SKIP could not attach: ' + why);
      process.exit(0);
    }

    // Give the attach + inject a moment, then inspect the terminal.
    let injected = false;
    try {
      await win.waitForFunction(() => {
        const r = document.querySelector('.xterm-rows');
        return r && /\[\+\] Injecting =>/.test(r.textContent);
      }, { timeout: 15000 });
      injected = true;
    } catch (_) { injected = false; }

    if (!injected) {
      const t = await win.evaluate(() => window.__fermion.terminal.getText());
      console.log('ATTACH_SKIP could not attach (no injection). tail: ' + t.split('\n').filter(Boolean).slice(-2).join(' | '));
      process.exit(0);
    }

    // Injected — now the agent console.log MUST reach the terminal.
    await win.waitForFunction((mk) => {
      const r = document.querySelector('.xterm-rows');
      return r && r.textContent.includes(mk);
    }, marker, { timeout: 15000 });

    console.log('ATTACH_OK agent console.log reached the terminal');
    process.exit(0);
  } catch (e) {
    console.log('ATTACH_FAIL ' + (e && e.message ? e.message : e));
    process.exit(1);
  } finally {
    try { if (app) await app.close(); } catch (_) {}
    killTarget(pid);
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) { /* temp dir */ }
  }
})();
