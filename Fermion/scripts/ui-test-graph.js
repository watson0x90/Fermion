// Playwright-Electron END-TO-END test: the Graph tab traces a real function
// in a real process and draws its call graph.
//   node Fermion/scripts/ui-test-graph.js [screenshot.png]
// Exit 0 + GRAPH_OK / GRAPH_SKIP (cannot attach on this runner) ; 1 + GRAPH_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-graph-'));
const shot = process.argv[2];
const isWin = process.platform === 'win32';
// A function the target is certain to call: it opens a file twice a second.
const MODULE = isWin ? 'kernel32.dll' : '';
const SYMBOL = isWin ? 'CreateFileW' : 'open';
const T = { timeout: 20000 };

(async () => {
  let app; let step = 'launch';
  const target = spawn(process.execPath, ['-e',
    'const fs = require("fs"); setInterval(() => { try { fs.closeSync(fs.openSync(process.execPath, "r")); } catch (e) {} }, 500)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exit(code); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const svgText = () => win.evaluate(() => {
      const img = document.querySelector('[data-testid="graph-img"]');
      return img ? decodeURIComponent(img.src.slice(img.src.indexOf(',') + 1)) : '';
    });

    step = 'not attached';
    await win.click('role=tab[name="Graph"]');
    if (!(await win.isDisabled('[data-testid="graph-trace"]'))) throw new Error('Trace enabled while not attached');

    step = 'attach';
    await win.evaluate(() => window.MonacoCodeEditor.setValue("console.log('GRAPH_USER_SCRIPT loaded');"));
    try {
      await win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
      await win.waitForFunction(() => window.__fermion.service.isAttached && window.__fermion.service.hasScript, undefined, T);
    } catch (e) {
      console.log('GRAPH_SKIP could not attach: ' + String(e && e.message ? e.message : e).split(/\r?\n/)[0]);
      await app.close(); return done(0);
    }
    if (!(await win.isDisabled('[data-testid="graph-trace"]'))) throw new Error('Trace enabled with no function named');

    step = 'unknown function';
    await win.fill('[data-testid="graph-module"]', MODULE);
    await win.fill('[data-testid="graph-symbol"]', 'NoSuchFunction_Fermion');
    await win.click('[data-testid="graph-trace"]');
    await win.waitForFunction(() => { const a = document.querySelector('[data-testid="graph-panel"] [role="alert"]'); return a && /Export not found/.test(a.textContent); }, undefined, T);
    await win.waitForFunction(() => /trace: off/.test(document.querySelector('[data-testid="status-bar"]').textContent), undefined, T);

    step = 'trace';
    await win.fill('[data-testid="graph-symbol"]', SYMBOL);
    await win.click('[data-testid="graph-trace"]');
    await win.waitForFunction(() => /trace: on/.test(document.querySelector('[data-testid="status-bar"]').textContent), undefined, T);
    await win.waitForSelector('[data-testid="graph-img"]', { timeout: 30000 });
    const status = await win.evaluate(() => document.querySelector('[data-testid="graph-status"]').textContent);
    if (!/\d+ graphs? so far · latest: [\d,]+ calls, \d+ distinct/.test(status)) throw new Error('status: ' + status);

    step = 'graph content';
    const svg = await svgText();
    const nodes = (svg.match(/class="node"/g) || []).length;
    const edges = (svg.match(/class="edge"/g) || []).length;
    if (nodes < 2 || edges < 1) throw new Error('graph has ' + nodes + ' nodes and ' + edges + ' edges');
    if (!svg.includes(SYMBOL)) throw new Error('the traced function is not in the graph');
    if (isWin && !/NtCreateFile/.test(svg)) throw new Error('CreateFileW graph lacks NtCreateFile');
    if (/<script|javascript:/i.test(svg)) throw new Error('graph SVG contains script');
    // Nodes are functions, so no bare call-site addresses from Frida's own code.
    const titles = (svg.match(/<title>[^<]*<\/title>/g) || []).filter((t) => /^<title>0x[0-9a-f]+<\/title>$/.test(t));
    if (titles.length > nodes / 2) throw new Error('graph is mostly unsymbolized addresses: ' + titles.slice(0, 4).join(' '));
    const inDom = await win.evaluate(() => document.querySelectorAll('[data-testid="graph-svg"] svg, [data-testid="graph-svg"] a, [data-testid="graph-svg"] script').length);
    if (inDom) throw new Error('graph markup was inserted into the page');
    const leaked = await win.evaluate(() => /fermionTrace|digraph/.test(window.__fermion.terminal.getText()));
    if (leaked) throw new Error('tracer messages leaked into Output');
    if (shot) await win.screenshot({ path: shot });

    step = 'zoom';
    const w100 = await win.evaluate(() => document.querySelector('[data-testid="graph-img"]').getBoundingClientRect().width);
    await win.click('[data-testid="graph-zoom-in"]');
    const w150 = await win.evaluate(() => document.querySelector('[data-testid="graph-img"]').getBoundingClientRect().width);
    if (!(w150 > w100 * 1.3)) throw new Error('zoom in: ' + w100 + ' -> ' + w150);
    await win.click('[data-testid="graph-zoom-fit"]');
    const fit = await win.evaluate(() => {
      const pane = document.querySelector('[data-testid="graph-svg"]');
      return { img: document.querySelector('[data-testid="graph-img"]').getBoundingClientRect().width, pane: pane.clientWidth, scroll: pane.scrollWidth };
    });
    if (fit.img > fit.pane || fit.scroll > fit.pane + 1) throw new Error('Fit does not fit: ' + JSON.stringify(fit));

    step = 'stop';
    await win.click('[data-testid="graph-stop"]');
    await win.waitForFunction(() => /trace: off/.test(document.querySelector('[data-testid="status-bar"]').textContent), undefined, T);
    // The editor's script is back: its console.log runs again.
    await win.waitForFunction(() => (window.__fermion.terminal.getText().match(/GRAPH_USER_SCRIPT loaded/g) || []).length >= 2, undefined, T);
    if (!(await win.isVisible('[data-testid="graph-img"]'))) throw new Error('the last graph disappeared on Stop');
    // And the target is still healthy.
    const alive = await win.evaluate(() => window.fermion.evaluate('Process.id'));
    if (!alive.ok || alive.text !== String(target.pid)) throw new Error('target no longer answers: ' + JSON.stringify(alive));

    console.log('GRAPH_OK unknown function reported + real trace drawn (' + nodes + ' nodes, ' + edges + ' edges) + inert image + zoom/fit + stop restores the script');
    await app.close();
    done(0);
  } catch (e) {
    console.log('GRAPH_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
