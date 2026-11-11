// Playwright-Electron regression: trace mode must not "stick" across a detach.
//
// Reproduces the bug where traceMode was a persistent global flag not tied to
// the active script: enter trace -> detach -> re-attach -> a normal send() was
// still routed to the trace window instead of the terminal. Routing must follow
// the loaded script (re-attaching the user script => SEND goes to the terminal).
//
//   node scripts/ui-test-trace-detach.js
// Exit 0 + TRACE_DETACH_OK   -> after detach+re-attach, send() reaches terminal
// Exit 0 + TRACE_DETACH_SKIP -> target unavailable / could not attach
// Exit 1 + TRACE_DETACH_FAIL -> send() misrouted (terminal missing the marker)
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn, execSync } = require('child_process');
const path = require('path');

const APP_DIR = path.join(__dirname, '..');
const isWin = process.platform === 'win32';

function spawnTarget() {
  if (isWin) {
    spawn('notepad.exe', { detached: true, stdio: 'ignore' });
    try {
      const out = execSync('tasklist /FI "IMAGENAME eq notepad.exe" /FO CSV /NH', { encoding: 'utf8' });
      const m = out.match(/"notepad\.exe","(\d+)"/i);
      return m ? parseInt(m[1], 10) : null;
    } catch { return null; }
  }
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 120000)'], { detached: true, stdio: 'ignore' });
  return child.pid;
}
function killTarget(pid) {
  try { if (isWin) execSync('taskkill /IM notepad.exe /F', { stdio: 'ignore' }); else process.kill(pid); } catch {}
}

async function attachAndWait(win, pid) {
  await win.evaluate((p) => require('electron').ipcRenderer.send('attach-process', p), pid);
  await win.waitForFunction(() => {
    const s = window.__fermion && window.__fermion.service;
    return s && s.isAttached && s.hasScript;
  }, { timeout: 15000 });
}

(async () => {
  let pid, app;
  try {
    pid = spawnTarget();
    await new Promise(r => setTimeout(r, 1500));
    if (!pid) { console.log('TRACE_DETACH_SKIP no target'); process.exit(0); }

    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox'], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForSelector('.monaco-editor', { timeout: 60000 });

    // Phase 1: attach with a benign script.
    await win.evaluate(() => window.MonacoCodeEditor.setValue("/* idle */"));
    try {
      await attachAndWait(win, pid);
    } catch {
      console.log('TRACE_DETACH_SKIP could not attach');
      process.exit(0);
    }

    // Enter trace mode. The real Graphviz tracer send()s DOT on a function hit
    // (post-load, never on load), so emulate that with a post-load setTimeout.
    // Capture what the trace bus receives to assert DOT routes to the trace
    // window (not the terminal) while trace mode is on.
    const dotMark = 'DOTMARK_' + Date.now();
    await win.evaluate((dm) => {
      window.__traceBusGot = [];
      const bus = new BroadcastChannel('trace-data-send');
      bus.onmessage = (e) => window.__traceBusGot.push(e.data);
      window.__traceBusProbe = bus;
      bus.postMessage("setTimeout(function(){ send('" + dm + "'); }, 150);");
    }, dotMark);
    // Let trace mode engage.
    await win.waitForFunction(() => {
      const t = document.querySelector('.xterm-rows');
      return t && /Graphviz tracer loaded/.test(t.textContent);
    }, { timeout: 10000 });
    // The post-load tracer send() must route to the trace bus, not the terminal.
    let dotRouted = false;
    try {
      await win.waitForFunction((dm) => (window.__traceBusGot || []).includes(dm), dotMark, { timeout: 8000 });
      dotRouted = true;
    } catch { dotRouted = false; }
    const dotInTerminal = await win.evaluate((dm) => {
      const t = document.querySelector('.xterm-rows');
      return !!(t && t.textContent.includes(dm));
    }, dotMark);
    await win.evaluate(() => { try { window.__traceBusProbe.close(); } catch {} });
    if (!dotRouted || dotInTerminal) {
      console.log('TRACE_DETACH_FAIL trace-mode DOT misrouted: routed=' + dotRouted + ' inTerminal=' + dotInTerminal);
      process.exit(1);
    }

    // Detach.
    await win.evaluate(() => document.getElementById('FridaDetach').click());
    await win.waitForFunction(() => {
      const s = window.__fermion && window.__fermion.service;
      return s && !s.isAttached;
    }, { timeout: 10000 });

    // Re-attach with a user script that send()s a fresh marker. Its output MUST
    // reach the terminal, not the trace window.
    const marker = 'POSTDETACH_' + Date.now();
    await win.evaluate((mk) => window.MonacoCodeEditor.setValue("send('" + mk + "');"), marker);

    // Capture what the trace bus receives (it must NOT get the marker).
    await win.evaluate(() => { window.__traceBusGot = []; const b = new BroadcastChannel('trace-data-send'); b.onmessage = (e) => window.__traceBusGot.push(e.data); window.__traceBusProbe = b; });

    try {
      await attachAndWait(win, pid);
    } catch {
      console.log('TRACE_DETACH_SKIP could not re-attach');
      process.exit(0);
    }

    // The marker must land in the terminal.
    let inTerminal = false;
    try {
      await win.waitForFunction((mk) => {
        const t = document.querySelector('.xterm-rows');
        return t && t.textContent.includes(mk);
      }, marker, { timeout: 10000 });
      inTerminal = true;
    } catch { inTerminal = false; }

    const misrouted = await win.evaluate((mk) => (window.__traceBusGot || []).includes(mk), marker);

    if (inTerminal && !misrouted) {
      console.log('TRACE_DETACH_OK send() reached terminal after detach+re-attach');
      process.exit(0);
    }
    console.log('TRACE_DETACH_FAIL inTerminal=' + inTerminal + ' misroutedToTrace=' + misrouted);
    process.exit(1);
  } catch (e) {
    console.log('TRACE_DETACH_FAIL ' + (e && e.message ? e.message : e));
    process.exit(1);
  } finally {
    try { if (app) await app.close(); } catch {}
    killTarget(pid);
  }
})();
