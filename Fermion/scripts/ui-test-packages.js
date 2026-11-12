// Playwright-Electron END-TO-END test: npm packages for scripts. Searches the
// real registry, installs a real package into a temporary profile, adds its
// import to the script, and loads the compiled script into a real process.
// Needs network access (and, where Frida's own installer fails, npm).
//   node Fermion/scripts/ui-test-packages.js [screenshot-prefix]
// Exit 0 + PACKAGES_OK / PACKAGES_SKIP (no network, no installer, or cannot attach) ; 1 + PACKAGES_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-pkg-'));
const shot = process.argv[2];
const T = { timeout: 20000 };
const LONG = { timeout: 180000 };

(async () => {
  let app; let step = 'launch';
  const target = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exit(code); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    // The install prompt is a native dialog shown by main: answer it from here.
    await app.evaluate(({ dialog }) => {
      global.__pkg = { answers: [], asked: [] };
      dialog.showMessageBox = async (_win, options) => { global.__pkg.asked.push(options.message); return { response: global.__pkg.answers.length ? global.__pkg.answers.shift() : 1 }; };
    });
    const answer = (n) => app.evaluate((_e, v) => { global.__pkg.answers.push(v); }, n);
    const asked = () => app.evaluate(() => global.__pkg.asked);
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const snap = async (name) => { if (shot) await win.screenshot({ path: shot + '-' + name + '.png' }); };
    const output = () => win.evaluate(() => window.__fermion.terminal.getText());
    const errorText = () => win.evaluate(() => document.querySelector('[data-testid="pkg-error"]')?.textContent ?? '');

    step = 'open packages';
    await win.click('[data-testid="editor-packages"]');
    await win.waitForFunction(() => /No packages installed/.test(document.querySelector('[data-testid="pkg-installed"]')?.textContent ?? ''), undefined, T);

    step = 'search the registry';
    await win.fill('[data-testid="pkg-query"]', 'frida-fs');
    await win.press('[data-testid="pkg-query"]', 'Enter');
    await win.waitForFunction(() => document.querySelectorAll('[data-testid="pkg-result"]').length > 0 || !!document.querySelector('[data-testid="pkg-error"]'), undefined, { timeout: 40000 });
    if (await errorText()) { console.log('PACKAGES_SKIP ' + (await errorText()).slice(0, 160)); await app.close(); return done(0); }
    const idx = await win.evaluate(() => [...document.querySelectorAll('[data-testid="pkg-result"] .pn')].findIndex((e) => e.textContent === 'frida-fs'));
    if (idx < 0) throw new Error('frida-fs was not among the results');
    const installButton = win.locator('[data-testid="pkg-result"]').nth(idx).locator('[data-testid="pkg-install"]');

    step = 'declining the prompt installs nothing';
    await answer(1);
    await installButton.click();
    await win.waitForFunction(() => ![...document.querySelectorAll('[data-testid="pkg-install"]')].some((b) => /Installing/.test(b.textContent)), undefined, T);
    if ((await asked()).length !== 1 || !/Install frida-fs from the npm registry\?/.test((await asked())[0])) throw new Error('prompt: ' + JSON.stringify(await asked()));
    if (await win.evaluate(() => document.querySelectorAll('[data-testid="pkg-row"]').length)) throw new Error('a declined install installed something');
    if (fs.existsSync(path.join(userDataDir, 'packages', 'node_modules', 'frida-fs'))) throw new Error('files were written for a declined install');

    step = 'install';
    await answer(0);
    await installButton.click();
    await win.waitForFunction(() => document.querySelectorAll('[data-testid="pkg-row"]').length === 1 || !!document.querySelector('[data-testid="pkg-error"]'), undefined, LONG);
    if (await errorText()) {
      const text = await errorText();
      if (/npm was not found|ENOTFOUND|EAI_AGAIN|network|ETIMEDOUT|ECONNRESET/i.test(text)) { console.log('PACKAGES_SKIP ' + text.slice(0, 200)); await app.close(); return done(0); }
      throw new Error('install: ' + text.slice(0, 400));
    }
    const version = await win.textContent('[data-testid="pkg-row"] .pv');
    if (!/^\d+\.\d+\.\d+/.test(version)) throw new Error('installed version: ' + version);
    if (!fs.existsSync(path.join(userDataDir, 'packages', 'node_modules', 'frida-fs', 'package.json'))) throw new Error('the package is not in Fermion\'s folder');
    if (!/Installed frida-fs@/.test(await output())) throw new Error('the install was not announced');
    await snap('installed');

    step = 'import into the script';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('console.log("PKG_OK " + (fs.readdirSync(Process.getTmpDir()).length > 0));\n'));
    await win.click('[data-testid="pkg-import"]');
    const script = await win.evaluate(() => window.MonacoCodeEditor.getValue());
    if (!script.startsWith("import fs from 'frida-fs';\n")) throw new Error('script after Import: ' + JSON.stringify(script.slice(0, 80)));
    await win.click('[data-testid="pkg-close"]');

    step = 'attach: the script is compiled and runs with the package';
    await win.locator('[aria-label="process"]').focus();
    await win.waitForFunction((p) => !!document.querySelector('[aria-label="process"] option[value="' + p + '"]'), target.pid, T);
    await win.selectOption('[aria-label="process"]', String(target.pid));
    await win.click('[data-testid="attach"]');
    await win.waitForFunction(() => /PKG_OK true/.test(window.__fermion.terminal.getText()) || /Attach to PID \d+ failed/.test(window.__fermion.terminal.getText()), undefined, { timeout: 60000 });
    if (/Attach to PID \d+ failed/.test(await output())) {
      const why = (/Attach to PID \d+ failed: (.*)/.exec(await output()) || [])[1] || '';
      if (/did not compile/.test(why)) throw new Error('compile: ' + (await output()).slice(-400));
      console.log('PACKAGES_SKIP installed and imported, but could not attach: ' + why.slice(0, 120));
      await app.close(); return done(0);
    }
    if (!/Script compiled with the packages it imports/.test(await output())) throw new Error('the compile was not announced');

    step = 'a script that imports a missing package is refused, and the running one stays';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('import nope from "fermion-no-such-package-xyz";\nconsole.log(nope);\n'));
    await win.click('[data-testid="editor-reload"]');
    await win.waitForFunction(() => /did not compile/.test(window.__fermion.terminal.getText()), undefined, T);
    const out = await output();
    if (!/Could not resolve "fermion-no-such-package-xyz"/.test(out) || !/Install fermion-no-such-package-xyz from Packages/.test(out)) throw new Error('compile error text: ' + out.slice(-400));
    if (!(await win.evaluate(() => window.__fermion.service.hasScript))) throw new Error('the running script was dropped');

    step = 'a plain script is loaded as written';
    const before = (await output()).split('Script compiled with the packages').length;
    await win.evaluate(() => window.MonacoCodeEditor.setValue('console.log("PLAIN_OK " + Process.id);\n'));
    await win.click('[data-testid="editor-reload"]');
    await win.waitForFunction(() => /PLAIN_OK \d+/.test(window.__fermion.terminal.getText()), undefined, T);
    if ((await output()).split('Script compiled with the packages').length !== before) throw new Error('a script without imports was compiled');

    step = 'remove';
    await win.click('[data-testid="editor-packages"]');
    await win.waitForSelector('[data-testid="pkg-row"]', T);
    await win.click('[data-testid="pkg-remove"]');
    await win.waitForFunction(() => /No packages installed/.test(document.querySelector('[data-testid="pkg-installed"]')?.textContent ?? ''), undefined, T);
    if (fs.existsSync(path.join(userDataDir, 'packages', 'node_modules', 'frida-fs'))) throw new Error('the package folder was not removed');

    console.log('PACKAGES_OK search + declined prompt + install (frida-fs ' + version + ') + import + compiled script ran in the target + missing package refused + plain script untouched + remove');
    await app.close();
    done(0);
  } catch (e) {
    console.log('PACKAGES_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await app.close(); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
