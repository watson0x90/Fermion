// Playwright-Electron END-TO-END test: catching the child processes of an
// attached process. A real parent starts children; Fermion holds each one
// before it runs, lets one go, and moves the session to another with the
// script and a hook in place before the child's first instruction.
//   node Fermion/scripts/ui-test-children.js [screenshot-prefix]
// Exit 0 + CHILDREN_OK / CHILDREN_SKIP (cannot attach on this runner) ; 1 + CHILDREN_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-children-'));
const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-kids-'));
const childJs = path.join(workDir, 'child.js');
const parentJs = path.join(workDir, 'parent.js');
const trigger = (n) => path.join(workDir, 'go-' + n);
const marker = (n) => path.join(workDir, 'child-' + n + '.txt');
// Each child records that it ran (and its pid), then stays alive.
fs.writeFileSync(childJs, `
  const fs = require('fs');
  fs.writeFileSync(process.argv[2], String(process.pid));
  setInterval(() => { try { fs.statSync(process.execPath); } catch (e) {} }, 150);
`);
// The parent starts child N when the file go-N appears.
fs.writeFileSync(parentJs, `
  const fs = require('fs');
  const { spawn } = require('child_process');
  let n = 1;
  setInterval(() => {
    if (fs.existsSync(${JSON.stringify(path.join(workDir, 'go-'))} + n)) {
      spawn(process.execPath, [${JSON.stringify(childJs)}, ${JSON.stringify(path.join(workDir, 'child-'))} + n + '.txt', '--child', String(n)], { stdio: 'ignore' });
      n++;
    }
  }, 100);
`);
const shot = process.argv[2];
const T = { timeout: 20000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFile = async (file, ms = 15000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fs.existsSync(file)) { await sleep(150); return true; } await sleep(100); } return false; };
const kill = (pid) => { try { process.kill(Number(pid)); } catch (_) { /* gone */ } };

(async () => {
  let app; let step = 'launch';
  const parent = spawn(process.execPath, [parentJs], { stdio: 'ignore' });
  const childPids = () => [1, 2, 3, 4].map((n) => { try { return fs.readFileSync(marker(n), 'utf8'); } catch (_) { return null; } }).filter(Boolean);
  const done = (code) => { childPids().forEach(kill); try { parent.kill(); } catch (_) { /* gone */ } process.exit(code); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const snap = async (name) => { if (shot) await win.screenshot({ path: shot + '-' + name + '.png' }); };
    const output = () => win.evaluate(() => window.__fermion.terminal.getText());
    // The script announces which process it was loaded into.
    await win.evaluate(() => window.MonacoCodeEditor.setValue('console.log("SCRIPT_IN " + Process.id);'));

    step = 'attach to the parent';
    await win.locator('[aria-label="process"]').focus();
    await win.waitForFunction((p) => !!document.querySelector('[aria-label="process"] option[value="' + p + '"]'), parent.pid, T);
    await win.selectOption('[aria-label="process"]', String(parent.pid));
    await win.click('[data-testid="attach"]');
    await win.waitForFunction(() => window.__fermion.service.isAttached || /Attach to PID \d+ failed/.test(window.__fermion.terminal.getText()), undefined, T);
    if (!(await win.evaluate(() => window.__fermion.service.isAttached))) {
      console.log('CHILDREN_SKIP could not attach: ' + ((/Attach to PID \d+ failed: (.*)/.exec(await output()) || [])[1] || 'unknown'));
      await app.close(); return done(0);
    }

    step = 'without catching, a child just runs';
    fs.writeFileSync(trigger(1), '');
    if (!(await waitFile(marker(1)))) throw new Error('child 1 did not run');
    if (await win.evaluate(() => !!document.querySelector('[data-testid="child-caught"]'))) throw new Error('a child was caught although catching is off');

    step = 'catch a child';
    await win.click('[data-testid="child-gating"]');
    await sleep(600);
    fs.writeFileSync(trigger(2), '');
    await win.waitForSelector('[data-testid="child-caught"]', T);
    const note = await win.textContent('[data-testid="child-caught"]');
    if (!note.includes('child.js') || !note.includes('--child 2')) throw new Error('caught note: ' + note);
    await sleep(1000);
    if (fs.existsSync(marker(2))) throw new Error('the caught child ran before a decision');
    if (!/Caught child process \d+/.test(await output())) throw new Error('the catch was not announced in Output');
    await snap('caught');

    step = 'let it run';
    await win.click('[data-testid="child-release"]');
    if (!(await waitFile(marker(2)))) throw new Error('child 2 did not run after Let it run');
    await win.waitForFunction(() => !document.querySelector('[data-testid="child-caught"]'), undefined, T);
    if ((await win.evaluate(() => window.__fermion.service.currentPid)) !== String(parent.pid)) throw new Error('the session left the parent');

    step = 'a hook to carry over';
    await win.click('role=tab[name="Hooks"]');
    await win.selectOption('[data-testid="hook-kind"]', 'symbols');
    await win.fill('[data-testid="hook-query"]', 'uv_fs_stat');
    await win.press('[data-testid="hook-query"]', 'Enter');
    await win.waitForFunction(() => [...document.querySelectorAll('[data-testid="hook-result"] .nm')].some((e) => /!uv_fs_stat$/.test(e.textContent)), undefined, T);
    const idx = await win.evaluate(() => [...document.querySelectorAll('[data-testid="hook-result"] .nm')].findIndex((e) => /!uv_fs_stat$/.test(e.textContent)));
    await win.locator('[data-testid="hook-result"]').nth(idx).locator('[data-testid="hook-add"]').click();
    await win.waitForFunction(() => document.querySelector('[data-testid="hook-status"]')?.textContent === 'hooked', undefined, T);
    await win.click('[data-testid="hook-results-close"]');
    // Keep hook lines out of Output: the child calls this function constantly.
    await win.click('[data-testid="hook-echo"]');
    // The parent never calls it, so any call counted later is the child's.
    if (Number(await win.textContent('[data-testid="hook-calls"]')) !== 0) throw new Error('the parent called the hooked function');

    step = 'switch to a child';
    fs.writeFileSync(trigger(3), '');
    await win.waitForSelector('[data-testid="child-caught"]', T);
    const pidText = /pid (\d+)/.exec(await win.textContent('[data-testid="child-caught"] .cmd'))[1];
    // Keep it suspended: the session moves, the script and hook go in, and the
    // child still has not run a single instruction of its own.
    await win.click('[data-testid="child-suspended"]');
    await win.click('[data-testid="child-switch"]');
    await win.waitForFunction((p) => window.__fermion.service.currentPid === p, pidText, T);
    await win.waitForSelector('[data-testid="session-suspended"]', T);
    await win.waitForFunction((p) => window.__fermion.terminal.getText().includes('SCRIPT_IN ' + p), pidText, T);
    await sleep(1500);
    if (fs.existsSync(marker(3))) throw new Error('the child ran before Resume, so the script and hooks were not in place first');
    await snap('child-suspended');
    await win.click('[data-testid="resume"]');
    if (!(await waitFile(marker(3)))) throw new Error('child 3 did not run after the switch');
    if (fs.readFileSync(marker(3), 'utf8') !== pidText) throw new Error('the session is on pid ' + pidText + ' but child 3 is ' + fs.readFileSync(marker(3), 'utf8'));
    await win.waitForFunction((p) => window.__fermion.terminal.getText().includes('SCRIPT_IN ' + p), pidText, T);
    // Announced once the resume has been acknowledged, a moment after the child is already running.
    await win.waitForFunction((p) => window.__fermion.terminal.getText().includes('Resumed PID ' + p), pidText, T);
    // The hook was placed in the child before it ran, and now counts its calls.
    await win.waitForFunction(() => document.querySelector('[data-testid="hook-status"]')?.textContent === 'hooked'
      && Number(document.querySelector('[data-testid="hook-calls"]').textContent.replace(/,/g, '')) > 0, undefined, T);
    if (await win.evaluate(() => !!document.querySelector('[data-testid="session-ended"]'))) throw new Error('the move was shown as an ended session');
    await snap('switched');

    step = 'the parent carries on, and its children are no longer caught';
    fs.writeFileSync(trigger(4), '');
    if (!(await waitFile(marker(4)))) throw new Error('the parent could not start child 4 after we left it');
    if (await win.evaluate(() => !!document.querySelector('[data-testid="child-caught"]'))) throw new Error('a child of the old process was caught');

    step = 'detach';
    await win.click('[data-testid="detach"]');
    await win.waitForFunction(() => !window.__fermion.service.isAttached, undefined, T);
    await sleep(300);
    for (const pid of childPids()) { try { process.kill(Number(pid), 0); } catch (e) { throw new Error('child ' + pid + ' died'); } }

    console.log('CHILDREN_OK child runs freely when off + caught before running + let run + switch (script and hook in place while still suspended) + resume + parent unaffected afterwards');
    await app.close();
    done(0);
  } catch (e) {
    console.log('CHILDREN_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await app.close(); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
    try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
