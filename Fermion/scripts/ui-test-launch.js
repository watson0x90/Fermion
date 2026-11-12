// Playwright-Electron END-TO-END test: spawning a real program with arguments
// (one with spaces), environment variables and a working directory, leaving it
// suspended until Resume, and starting it again after it exits; then attach,
// detach and "Attach again".
//   node Fermion/scripts/ui-test-launch.js [screenshot-prefix]
// Exit 0 + LAUNCH_OK / LAUNCH_SKIP (cannot spawn or attach on this runner) ; 1 + LAUNCH_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-launch-'));
// A directory with a space in its name: the working directory, and where the
// target script lives.
const workDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'fermion work ')));
const targetScript = path.join(workDir, 'target script.js');
const outFile = path.join(workDir, 'out.json');
fs.writeFileSync(targetScript, `
  const fs = require('fs');
  fs.writeFileSync(${JSON.stringify(outFile)}, JSON.stringify({ env: process.env.FERMION_TEST, other: process.env.FERMION_OTHER, cwd: process.cwd(), args: process.argv.slice(2) }));
  setInterval(() => {}, 1000);
`);
const shot = process.argv[2];
const T = { timeout: 20000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFile = async (file, ms = 15000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fs.existsSync(file)) { await sleep(150); return true; } await sleep(100); } return false; };
const kill = (pid) => { try { process.kill(Number(pid)); } catch (_) { /* gone */ } };

(async () => {
  let app; let step = 'launch'; let child = null;
  const pids = [];
  const done = (code) => { pids.forEach(kill); if (child) { try { child.kill(); } catch (_) { /* gone */ } } process.exit(code); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const snap = async (name) => { if (shot) await win.screenshot({ path: shot + '-' + name + '.png' }); };
    const output = () => win.evaluate(() => window.__fermion.terminal.getText());
    const currentPid = () => win.evaluate(() => window.__fermion.service.currentPid);
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// launch test'));

    step = 'spawn options';
    await win.fill('[aria-label="spawn path"]', process.execPath);
    await win.fill('[aria-label="spawn args"]', '"' + targetScript + '" --flag "two words"');
    await win.click('[data-testid="spawn-options-toggle"]');
    await win.fill('[aria-label="environment"]', 'FERMION_TEST=hello world\n# a comment\nnot a variable');
    await win.waitForSelector('[data-testid="spawn-env-error"]', T);
    if (!(await win.evaluate(() => document.querySelector('[data-testid="spawn"]').disabled))) throw new Error('Spawn should be blocked by a bad environment line');
    await win.fill('[aria-label="environment"]', 'FERMION_TEST=hello world\n# a comment\nFERMION_OTHER=a=b');
    await win.fill('[aria-label="working directory"]', workDir);
    await win.click('[data-testid="spawn-suspended"]');
    if (!/Options \(4 set\)/.test(await win.textContent('[data-testid="spawn-options-toggle"]'))) throw new Error('options count: ' + await win.textContent('[data-testid="spawn-options-toggle"]'));
    await snap('options');

    step = 'spawn suspended';
    await win.click('[data-testid="spawn"]');
    try {
      await win.waitForFunction(() => !!document.querySelector('[data-testid="session-suspended"]') || /Spawn failed/.test(window.__fermion.terminal.getText()), undefined, T);
    } catch (e) { throw new Error('neither suspended nor failed: ' + (await output()).slice(-300)); }
    if (/Spawn failed/.test(await output())) {
      console.log('LAUNCH_SKIP could not spawn: ' + (/Spawn failed: (.*)/.exec(await output()) || [])[1]);
      await app.close(); return done(0);
    }
    pids.push(await currentPid());
    await sleep(1200);
    if (fs.existsSync(outFile)) throw new Error('the program ran although it should be suspended');
    await snap('suspended');

    step = 'resume';
    await win.click('[data-testid="resume"]');
    if (!(await waitFile(outFile))) throw new Error('the program did not run after Resume');
    const got = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    if (got.env !== 'hello world' || got.other !== 'a=b') throw new Error('environment: ' + JSON.stringify(got));
    if (fs.realpathSync(got.cwd).toLowerCase() !== workDir.toLowerCase()) throw new Error('working directory: ' + got.cwd + ' vs ' + workDir);
    if (JSON.stringify(got.args) !== JSON.stringify(['--flag', 'two words'])) throw new Error('arguments: ' + JSON.stringify(got.args));
    await win.waitForFunction(() => !document.querySelector('[data-testid="session-suspended"]'), undefined, T);

    step = 'the process exits';
    kill(pids[0]);
    await win.waitForSelector('[data-testid="session-ended"]', T);
    const ended = await win.textContent('[data-testid="session-ended"]');
    if (!/The process exited\./.test(ended) || !ended.includes(path.basename(process.execPath))) throw new Error('ended note: ' + ended);
    if ((await win.textContent('[data-testid="reconnect"]')).trim() !== 'Spawn again') throw new Error('reconnect button: ' + await win.textContent('[data-testid="reconnect"]'));
    await snap('ended');

    step = 'spawn again';
    fs.rmSync(outFile, { force: true });
    await win.click('[data-testid="reconnect"]');
    await win.waitForSelector('[data-testid="session-suspended"]', T); // the same way: suspended again
    pids.push(await currentPid());
    await win.click('[data-testid="resume"]');
    if (!(await waitFile(outFile))) throw new Error('Spawn again did not run the program');
    const again = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    if (again.env !== 'hello world' || JSON.stringify(again.args) !== JSON.stringify(['--flag', 'two words'])) throw new Error('Spawn again lost its options: ' + JSON.stringify(again));
    await win.click('[data-testid="detach"]');
    await win.waitForFunction(() => /You detached\./.test(document.querySelector('[data-testid="session-ended"]')?.textContent ?? ''), undefined, T);
    kill(pids[1]);
    await win.click('[data-testid="ended-dismiss"]');

    step = 'attach, detach, attach again';
    child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
    await sleep(800);
    let attachNote = 'attach again';
    await win.locator('[aria-label="process"]').focus();
    await win.waitForFunction((p) => !!document.querySelector('[aria-label="process"] option[value="' + p + '"]'), child.pid, T);
    await win.selectOption('[aria-label="process"]', String(child.pid));
    await win.click('[data-testid="attach"]');
    await win.waitForFunction((p) => (window.__fermion.service.isAttached && window.__fermion.service.currentPid === String(p))
      || /Attach to PID \d+ failed/.test(window.__fermion.terminal.getText()), child.pid, T);
    if (!(await win.evaluate(() => window.__fermion.service.isAttached))) {
      attachNote = 'attach skipped (' + ((/Attach to PID \d+ failed: (.*)/.exec(await output()) || [])[1] || 'cannot attach').slice(0, 60) + ')';
    }
    if (attachNote === 'attach again') {
      await win.click('[data-testid="detach"]');
      await win.waitForSelector('[data-testid="session-ended"]', T);
      if ((await win.textContent('[data-testid="reconnect"]')).trim() !== 'Attach again') throw new Error('reconnect button: ' + await win.textContent('[data-testid="reconnect"]'));
      await win.click('[data-testid="reconnect"]');
      await win.waitForFunction((p) => window.__fermion.service.isAttached && window.__fermion.service.currentPid === String(p), child.pid, T);

      step = 'attach again after the program is gone';
      child.kill();
      await win.waitForFunction(() => /The process exited\./.test(document.querySelector('[data-testid="session-ended"]')?.textContent ?? ''), undefined, T);
      await sleep(400);
      await win.click('[data-testid="reconnect"]');
      await win.waitForSelector('[data-testid="reconnect-note"]', T);
      const note = await win.textContent('[data-testid="reconnect-note"]');
      if (!/is not running\.|processes are named/.test(note)) throw new Error('reconnect note: ' + note);
      if (await win.evaluate(() => window.__fermion.service.isAttached)) throw new Error('attached to some other process');
    }

    console.log('LAUNCH_OK arguments with spaces + environment + working directory + suspended until Resume + ended note + spawn again + ' + attachNote);
    await app.close();
    done(0);
  } catch (e) {
    console.log('LAUNCH_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await Promise.race([app.close(), sleep(15000)]); } catch (_) {} // a spawned program still alive must not hold the test open
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
    try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
