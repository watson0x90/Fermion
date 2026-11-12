// Playwright-Electron test: the Process tree tab lists the local device's
// processes as a hierarchy, filters, and attaches from a row.
//   node Fermion/scripts/ui-test-process-tree.js [screenshot.png]
// Exit 0 + TREE_OK (attach part may report "attach skipped" where the runner
// cannot attach) / 1 + TREE_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn, execSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-tree-'));
const isWin = process.platform === 'win32';
const shot = process.argv[2];

// A target we own: a parent node process with one child, so the tree has a
// known parent -> child pair to find.
function spawnTarget() {
  const child = spawn(process.execPath, ['-e',
    "const c=require('child_process').spawn(process.execPath,['-e','setTimeout(()=>{},120000)'],{stdio:'ignore'});" +
    "console.log(c.pid);setTimeout(()=>{},120000)"], { stdio: ['ignore', 'pipe', 'ignore'] });
  return new Promise((resolve) => {
    child.stdout.once('data', (d) => resolve({ parent: child.pid, child: parseInt(String(d), 10), proc: child }));
    setTimeout(() => resolve({ parent: child.pid, child: null, proc: child }), 5000);
  });
}
function killTarget(t) {
  try {
    if (isWin) execSync('taskkill /PID ' + t.parent + ' /T /F', { stdio: 'ignore' });
    else { if (t.child) process.kill(t.child); process.kill(t.parent); }
  } catch (_) { /* already gone */ }
}

(async () => {
  let app; let target; let step = 'launch';
  try {
    target = await spawnTarget();
    if (!target.child) throw new Error('could not start the target processes');

    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });

    step = 'open tab';
    await win.click('role=tab[name="Process tree"]');
    await win.waitForSelector('[data-testid="tree-panel"] [role="treeitem"]', { timeout: 30000 });
    const total = await win.evaluate(() => document.querySelectorAll('[role="treeitem"]').length);
    if (total < 5) throw new Error('suspiciously few processes listed: ' + total);

    step = 'hierarchy';
    // Our child must sit one level below our parent, directly after it or its siblings.
    await win.waitForSelector('[data-testid="proc-' + target.child + '"]', { timeout: 15000 });
    const rel = await win.evaluate(([p, c]) => {
      const lvl = (id) => Number(document.querySelector('[data-testid="proc-' + id + '"]').getAttribute('aria-level'));
      return { parent: lvl(p), child: lvl(c) };
    }, [target.parent, target.child]);
    if (rel.child !== rel.parent + 1) throw new Error('child is not nested under its parent: ' + JSON.stringify(rel));

    step = 'filter';
    await win.fill('[data-testid="tree-filter"]', String(target.child));
    // The filter matches PIDs by substring, so a short PID can match several
    // processes; require only that the list narrowed and our row is a match.
    await win.waitForFunction(([c, all]) => {
      const rows = [...document.querySelectorAll('[role="treeitem"]')];
      return rows.length > 0 && rows.length < all && rows.some((r) => r.getAttribute('data-pid') === String(c) && r.classList.contains('match'));
    }, [target.child, total], { timeout: 15000 });
    const kept = await win.evaluate((p) => !!document.querySelector('[data-testid="proc-' + p + '"]'), target.parent);
    if (!kept) throw new Error('filter dropped the parent of the match');
    await win.fill('[data-testid="tree-filter"]', '');

    step = 'collapse';
    await win.click('[data-testid="proc-' + target.parent + '"] [data-testid="twisty"]');
    await win.waitForFunction((c) => !document.querySelector('[data-testid="proc-' + c + '"]'), target.child, { timeout: 15000 });
    await win.click('[data-testid="proc-' + target.parent + '"] [data-testid="twisty"]');
    await win.waitForSelector('[data-testid="proc-' + target.child + '"]', { timeout: 15000 });

    if (shot) await win.screenshot({ path: shot });

    step = 'attach from row';
    await win.evaluate(() => window.MonacoCodeEditor.setValue("console.log('TREE_ATTACHED ' + Process.id);"));
    await win.hover('[data-testid="proc-' + target.child + '"]');
    await win.click('[data-testid="proc-' + target.child + '"] [data-testid="row-attach"]');
    let attached = true;
    try {
      await win.waitForSelector('[data-testid="proc-' + target.child + '"].attached', { timeout: 20000 });
    } catch (_) { attached = false; }

    if (!attached) {
      // The failure must have been reported, not swallowed.
      const text = await win.evaluate(() => window.__fermion.terminal.getText());
      if (!/Attach to PID \d+ failed/.test(text)) throw new Error('attach neither succeeded nor reported a failure');
      console.log('TREE_OK hierarchy + filter + collapse (attach skipped: ' + text.split('\n').filter(Boolean).slice(-1)[0] + ')');
    } else {
      await win.waitForFunction((c) => window.__fermion.terminal.getText().includes('TREE_ATTACHED ' + c), target.child, { timeout: 20000 });
      const st = await win.evaluate(() => ({ pid: window.__fermion.service.currentPid, offered: document.querySelectorAll('[data-testid="row-attach"]').length }));
      if (String(st.pid) !== String(target.child)) throw new Error('session pid is ' + st.pid);
      if (st.offered) throw new Error('rows still offer Attach while attached');

      step = 'only ancestry';
      await win.click('[data-testid="tree-ancestry"]');
      await win.waitForFunction(([p, c]) => {
        const pids = [...document.querySelectorAll('[role="treeitem"]')].map((r) => r.getAttribute('data-pid'));
        return pids.includes(String(p)) && pids.includes(String(c)) && pids.length < 40;
      }, [target.parent, target.child], { timeout: 15000 });
      if (shot) await win.screenshot({ path: shot.replace(/\.png$/, '-attached.png') });
      console.log('TREE_OK hierarchy + filter + collapse + attach from row + only ancestry');
    }
    await app.close();
    killTarget(target);
    process.exit(0);
  } catch (e) {
    console.log('TREE_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    if (target) killTarget(target);
    process.exit(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
