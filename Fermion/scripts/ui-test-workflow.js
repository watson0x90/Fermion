// Playwright-Electron END-TO-END test: one working session that uses the
// features together, the way an operator would, to catch problems between
// them rather than inside one.
//
//   install a package -> script imports it -> spawn a program suspended, with
//   environment and arguments -> hook a function before it runs -> resume ->
//   REPL result tree -> pointer -> address menu -> Disassembly -> bookmark ->
//   the program starts a child -> catch it -> move the session to it (script
//   recompiled, hook placed again, bookmark still resolves) -> the child exits
//   -> the sidebar says so -> restart Fermion -> hook, bookmark and package
//   are all still there.
//
//   node Fermion/scripts/ui-test-workflow.js [screenshot-prefix]
// Exit 0 + WORKFLOW_OK / WORKFLOW_SKIP (cannot spawn on this runner) ; 1 + WORKFLOW_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-flow-'));
const workDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'fermion flow ')));
const parentJs = path.join(workDir, 'parent.js');
const childJs = path.join(workDir, 'child.js');
const parentMarker = path.join(workDir, 'parent.json');
const childMarker = path.join(workDir, 'child.txt');
const goFile = path.join(workDir, 'go');
fs.writeFileSync(childJs, `
  const fs = require('fs');
  fs.writeFileSync(${JSON.stringify(childMarker)}, String(process.pid));
  setInterval(() => { try { fs.statSync(process.execPath); } catch (e) {} }, 150);
`);
fs.writeFileSync(parentJs, `
  const fs = require('fs');
  const { spawn } = require('child_process');
  fs.writeFileSync(${JSON.stringify(parentMarker)}, JSON.stringify({ env: process.env.FLOW_TEST, args: process.argv.slice(2), cwd: process.cwd() }));
  let started = false;
  setInterval(() => {
    if (!started && fs.existsSync(${JSON.stringify(goFile)})) { started = true; spawn(process.execPath, [${JSON.stringify(childJs)}], { stdio: 'ignore' }); }
  }, 100);
`);
const shot = process.argv[2];
const T = { timeout: 20000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFile = async (file, ms = 15000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fs.existsSync(file)) { await sleep(150); return true; } await sleep(100); } return false; };
const kill = (pid) => { try { process.kill(Number(pid)); } catch (_) { /* gone */ } };

(async () => {
  let app; let step = 'launch';
  const pids = [];
  const notes = [];
  const done = (code) => { pids.forEach(kill); try { kill(fs.readFileSync(childMarker, 'utf8')); } catch (_) { /* never ran */ } process.exit(code); };
  const start = async () => {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    await app.evaluate(({ dialog }) => { dialog.showMessageBox = async () => ({ response: 0 }); }); // accept the install prompt
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    return win;
  };
  try {
    let win = await start();
    const snap = async (name) => { if (shot) await win.screenshot({ path: shot + '-' + name + '.png' }); };
    const output = () => win.evaluate(() => window.__fermion.terminal.getText());
    const inOutput = (text, timeout = 20000) => win.waitForFunction((t) => window.__fermion.terminal.getText().includes(t), text, { timeout });
    const currentPid = () => win.evaluate(() => window.__fermion.service.currentPid);
    const hookCalls = () => win.evaluate(() => Number(document.querySelector('[data-testid="hook-calls"]').textContent.replace(/,/g, '')));

    // ---- a package, and a script that imports it ----
    step = 'install a package';
    let withPackage = true;
    await win.click('[data-testid="editor-packages"]');
    await win.fill('[data-testid="pkg-query"]', 'frida-fs');
    await win.press('[data-testid="pkg-query"]', 'Enter');
    await win.waitForFunction(() => document.querySelectorAll('[data-testid="pkg-result"]').length > 0 || !!document.querySelector('[data-testid="pkg-error"]'), undefined, { timeout: 40000 });
    if (await win.evaluate(() => !!document.querySelector('[data-testid="pkg-error"]'))) {
      withPackage = false;
    } else {
      await win.locator('[data-testid="pkg-result"]').first().locator('[data-testid="pkg-install"]').click();
      await win.waitForFunction(() => document.querySelectorAll('[data-testid="pkg-row"]').length === 1 || !!document.querySelector('[data-testid="pkg-error"]'), undefined, { timeout: 180000 });
      withPackage = await win.evaluate(() => document.querySelectorAll('[data-testid="pkg-row"]').length === 1);
    }
    if (!withPackage) notes.push('no package (' + (await win.evaluate(() => document.querySelector('[data-testid="pkg-error"]')?.textContent ?? 'unavailable')).slice(0, 80) + ')');
    await win.evaluate(() => window.MonacoCodeEditor.setValue('console.log("FLOW_SCRIPT " + Process.id + " " + (typeof fs === "undefined" ? "plain" : fs.readdirSync(Process.getTmpDir()).length > 0));\n'));
    if (withPackage) await win.click('[data-testid="pkg-import"]');
    await win.click('[data-testid="pkg-close"]');

    // ---- spawn suspended, with options, catching children ----
    step = 'spawn suspended';
    await win.click('[data-testid="child-gating"]');
    await win.fill('[aria-label="spawn path"]', process.execPath);
    await win.fill('[aria-label="spawn args"]', '"' + parentJs + '" --mode "two words"');
    await win.click('[data-testid="spawn-options-toggle"]');
    await win.fill('[aria-label="environment"]', 'FLOW_TEST=from fermion');
    await win.fill('[aria-label="working directory"]', workDir);
    await win.click('[data-testid="spawn-suspended"]');
    await win.click('[data-testid="spawn"]');
    await win.waitForFunction(() => !!document.querySelector('[data-testid="session-suspended"]') || /Spawn failed/.test(window.__fermion.terminal.getText()), undefined, { timeout: 60000 });
    if (/Spawn failed/.test(await output())) {
      console.log('WORKFLOW_SKIP could not spawn: ' + ((/Spawn failed: (.*)/.exec(await output()) || [])[1] || '').slice(0, 160));
      await app.close(); return done(0);
    }
    const parentPid = await currentPid();
    pids.push(parentPid);
    if (withPackage) await inOutput('Script compiled with the packages it imports');
    await inOutput('FLOW_SCRIPT ' + parentPid + (withPackage ? ' true' : ' plain'));

    // ---- a hook, placed before the program has run ----
    step = 'hook while suspended';
    await win.click('role=tab[name="Hooks"]');
    await win.selectOption('[data-testid="hook-kind"]', 'symbols');
    await win.fill('[data-testid="hook-query"]', 'uv_fs_stat');
    await win.press('[data-testid="hook-query"]', 'Enter');
    await win.waitForFunction(() => [...document.querySelectorAll('[data-testid="hook-result"] .nm')].some((e) => /!uv_fs_stat$/.test(e.textContent)), undefined, T);
    const idx = await win.evaluate(() => [...document.querySelectorAll('[data-testid="hook-result"] .nm')].findIndex((e) => /!uv_fs_stat$/.test(e.textContent)));
    await win.locator('[data-testid="hook-result"]').nth(idx).locator('[data-testid="hook-add"]').click();
    await win.waitForFunction(() => document.querySelector('[data-testid="hook-status"]')?.textContent === 'hooked', undefined, T);
    await win.click('[data-testid="hook-results-close"]');
    await win.click('[data-testid="hook-echo"]'); // keep Output readable
    await sleep(800);
    if (fs.existsSync(parentMarker)) throw new Error('the program ran while it should be suspended');

    step = 'resume';
    await win.click('[data-testid="resume"]');
    if (!(await waitFile(parentMarker))) throw new Error('the program did not run after Resume');
    const ran = JSON.parse(fs.readFileSync(parentMarker, 'utf8'));
    if (ran.env !== 'from fermion' || JSON.stringify(ran.args) !== JSON.stringify(['--mode', 'two words']) || fs.realpathSync(ran.cwd).toLowerCase() !== workDir.toLowerCase()) throw new Error('launch options: ' + JSON.stringify(ran));
    // Node stats files while it starts: the hook, in place first, saw them.
    await win.waitForFunction(() => Number(document.querySelector('[data-testid="hook-calls"]').textContent.replace(/,/g, '')) > 0, undefined, T);
    const startupCalls = await hookCalls();

    // ---- REPL -> pointer -> address menu -> Disassembly -> bookmark ----
    step = 'repl tree to disassembly';
    await win.click('role=tab[name="REPL"]');
    await win.click('[data-testid="repl-input"]');
    await win.keyboard.type('Process.enumerateModules().slice(0, 2)');
    await win.keyboard.press('Enter');
    await win.waitForSelector('[data-testid="repl-result"] [data-testid="value-node"] [data-testid="value-node"] button.vhead', T);
    await win.click('[data-testid="repl-result"] [data-testid="value-node"] [data-testid="value-node"] button.vhead');
    const base = await win.textContent('[data-testid="value-pointer"]');
    await win.click('[data-testid="value-pointer"]');
    await win.waitForSelector('[data-testid="addr-menu"]', T);
    await win.click('[data-testid="addr-menu-memory"]');
    await win.waitForFunction((a) => document.querySelector('[data-testid="mem-addr"]')?.value === a && document.querySelectorAll('[data-testid="hex-row"]').length > 0, base, T);

    step = 'hook to disassembly to bookmark';
    await win.click('role=tab[name="Hooks"]');
    await win.click('[data-testid^="hook-row-"]', { button: 'right' });
    await win.waitForSelector('[data-testid="addr-menu"]', T);
    await win.click('[data-testid="addr-menu-code"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="insp-code"]')?.getAttribute('aria-selected') === 'true'
      && document.querySelectorAll('[data-testid="code-row"]').length >= 10, undefined, T);
    if (!/uv_fs_stat/.test(await win.textContent('[data-testid="code-where"]'))) throw new Error('disassembly is at ' + await win.textContent('[data-testid="code-where"]'));
    await win.click('[data-testid="code-row"] .ca', { button: 'right' });
    await win.waitForSelector('[data-testid="addr-menu"]', T);
    await win.click('[data-testid="addr-menu-bookmark"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="insp-bookmarks"]')?.getAttribute('aria-selected') === 'true'
      && document.querySelectorAll('[data-testid="bm-row"]').length === 1, undefined, T);
    await win.fill('[data-testid="bm-note"]', 'entry of the stat call');
    await snap('bookmark');

    // ---- the program starts a child: catch it and move to it ----
    step = 'catch the child';
    fs.writeFileSync(goFile, '');
    await win.waitForSelector('[data-testid="child-caught"]', T);
    if (!(await win.textContent('[data-testid="child-caught"]')).includes('child.js')) throw new Error('caught note: ' + await win.textContent('[data-testid="child-caught"]'));
    await sleep(700);
    if (fs.existsSync(childMarker)) throw new Error('the caught child ran before a decision');
    const childPid = /pid (\d+)/.exec(await win.textContent('[data-testid="child-caught"] .cmd'))[1];
    await snap('child');

    step = 'switch to the child';
    await win.click('[data-testid="child-switch"]');
    await win.waitForFunction((p) => window.__fermion.service.currentPid === p, childPid, T);
    if (!(await waitFile(childMarker))) throw new Error('the child did not run after the switch');
    if (fs.readFileSync(childMarker, 'utf8') !== childPid) throw new Error('session on ' + childPid + ' but the child is ' + fs.readFileSync(childMarker, 'utf8'));
    await inOutput('FLOW_SCRIPT ' + childPid + (withPackage ? ' true' : ' plain')); // the script, compiled again, in the child
    await inOutput('Now on child process ' + childPid);
    // The hook moved with the session and counts the child's calls.
    await win.click('role=tab[name="Hooks"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="hook-status"]')?.textContent === 'hooked', undefined, T);
    const c1 = await hookCalls();
    await win.waitForFunction((n) => Number(document.querySelector('[data-testid="hook-calls"]').textContent.replace(/,/g, '')) > n, c1, T);
    // The bookmark resolves in the new process and opens.
    await win.click('role=tab[name="Inspector"]');
    await win.click('[data-testid="insp-bookmarks"]');
    await win.waitForFunction(() => !document.querySelector('[data-testid="bm-open-code"]').disabled, undefined, T);
    await win.click('[data-testid="bm-open-code"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="insp-code"]')?.getAttribute('aria-selected') === 'true'
      && /uv_fs_stat/.test(document.querySelector('[data-testid="code-where"]')?.textContent ?? ''), undefined, T);
    // The REPL works in the new process too.
    await win.click('role=tab[name="REPL"]');
    await win.click('[data-testid="repl-input"]');
    await win.keyboard.type('Process.id');
    await win.keyboard.press('Enter');
    await win.waitForFunction((p) => [...document.querySelectorAll('[data-testid="repl-result"]')].pop()?.textContent === p, childPid, T);
    // The parent is still running, without Fermion.
    try { process.kill(Number(parentPid), 0); } catch (e) { throw new Error('the parent died when the session moved'); }

    // ---- the child exits ----
    step = 'the child exits';
    kill(childPid);
    await win.waitForSelector('[data-testid="session-ended"]', T);
    const ended = await win.textContent('[data-testid="session-ended"]');
    if (!/The process exited\./.test(ended)) throw new Error('ended note: ' + ended);
    if ((await win.textContent('[data-testid="reconnect"]')).trim() !== 'Attach again') throw new Error('reconnect offers: ' + await win.textContent('[data-testid="reconnect"]'));
    await win.click('role=tab[name="Hooks"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="hook-status"]')?.textContent === 'placed on attach', undefined, T);
    await snap('ended');

    // ---- restart: everything saved is still there ----
    step = 'restart';
    await sleep(900);
    // The spawned program inherited the app's output handles: while it lives,
    // closing the app from a test waits on them. It has done its part.
    kill(parentPid);
    await app.close();
    win = await start();
    await win.click('role=tab[name="Hooks"]');
    await win.waitForSelector('[data-testid^="hook-row-"]', T);
    if (!/!uv_fs_stat$/.test(await win.textContent('[data-testid^="hook-row-"] .nm'))) throw new Error('the hook did not come back');
    await win.click('role=tab[name="Inspector"]');
    await win.click('[data-testid="insp-bookmarks"]');
    await win.waitForSelector('[data-testid="bm-row"]', T);
    if ((await win.inputValue('[data-testid="bm-note"]')) !== 'entry of the stat call') throw new Error('the bookmark note did not come back');
    if (withPackage) {
      await win.click('role=tab[name="Editor"]');
      await win.click('[data-testid="editor-packages"]');
      await win.waitForFunction(() => document.querySelector('[data-testid="pkg-row"] .pn')?.textContent === 'frida-fs', undefined, T);
    }

    console.log('WORKFLOW_OK ' + (withPackage ? 'package + compiled script' : 'plain script') + ' + spawn suspended with options + hook before first instruction (' + startupCalls
      + ' startup calls seen) + REPL tree -> address menu -> Memory + Disassembly + bookmark + child caught + session moved (script, hook, bookmark, REPL all follow) + exit noted + all restored after restart'
      + (notes.length ? ' | ' + notes.join('; ') : ''));
    await app.close();
    done(0);
  } catch (e) {
    console.log('WORKFLOW_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await app.close(); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
    try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
