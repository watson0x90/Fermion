// Playwright-Electron END-TO-END test: the REPL evaluates entries in a real
// attached process.
//   node Fermion/scripts/ui-test-repl.js [screenshot.png]
// Exit 0 + REPL_OK / REPL_SKIP (cannot attach on this runner) ; 1 + REPL_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-repl-'));
const shot = process.argv[2];

(async () => {
  let app; let step = 'launch';
  const target = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 120000)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exit(code); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });

    step = 'not attached';
    await win.click('role=tab[name="REPL"]');
    if (!(await win.isDisabled('[data-testid="repl-input"]'))) throw new Error('REPL input enabled while not attached');

    step = 'attach';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// user script\nvar fromUserScript = 1;'));
    try {
      await win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
      await win.waitForFunction(() => window.__fermion.service.isAttached && window.__fermion.service.hasScript, undefined, { timeout: 20000 });
    } catch (e) {
      console.log('REPL_SKIP could not attach: ' + String(e && e.message ? e.message : e).split('\n')[0]);
      await app.close(); return done(0);
    }
    await win.waitForFunction(() => !document.querySelector('[data-testid="repl-input"]').disabled, undefined, { timeout: 15000 });

    // Type an entry, press Enter, and return the text of its result.
    const entry = async (code) => {
      const n = await win.evaluate(() => document.querySelectorAll('[data-testid="repl-entry"]').length);
      await win.click('[data-testid="repl-input"]');
      await win.keyboard.type(code);
      await win.keyboard.press('Enter');
      await win.waitForFunction((k) => {
        const rs = document.querySelectorAll('[data-testid="repl-result"]');
        return rs.length === k + 1 && !rs[k].classList.contains('run');
      }, n, { timeout: 20000 });
      return win.evaluate((k) => {
        const r = document.querySelectorAll('[data-testid="repl-result"]')[k];
        return { text: r.textContent, err: r.classList.contains('err') };
      }, n);
    };

    step = 'evaluate';
    const pid = await entry('Process.id');
    if (pid.err || pid.text !== String(target.pid)) throw new Error('Process.id -> ' + JSON.stringify(pid) + ', expected ' + target.pid);

    step = 'object result';
    const mod = await entry('({ arch: Process.arch, n: Process.enumerateModules().length > 0 })');
    if (mod.err || !/arch: "/.test(mod.text) || !/n: true/.test(mod.text)) throw new Error('object result: ' + JSON.stringify(mod));

    step = 'expandable result with pointers';
    {
      const n0 = await win.evaluate(() => document.querySelectorAll('[data-testid="repl-entry"]').length);
      const r = await entry('Process.enumerateModules().slice(0, 3)');
      if (r.err || !/^Array\(3\)/.test(r.text)) throw new Error('array result: ' + JSON.stringify(r).slice(0, 200));
      const result = win.locator('[data-testid="repl-result"]').nth(n0);
      // The modules start closed, each summed up on one line; opening one shows its parts.
      const closed = await result.locator('[data-testid="value-node"] [data-testid="value-node"] .vsum').first().textContent();
      if (!/^Module \{name: "/.test(closed) && !/^Object \{name: "/.test(closed)) throw new Error('closed module preview: ' + closed);
      if (await result.locator('[data-testid="value-pointer"]').count()) throw new Error('children should start closed');
      await result.locator('[data-testid="value-node"] [data-testid="value-node"] button.vhead').first().click();
      const pointer = result.locator('[data-testid="value-pointer"]').first();
      const base = await pointer.textContent();
      if (!/^0x[0-9a-f]+$/.test(base)) throw new Error('module base: ' + base);
      // A pointer in a result is an address: its menu opens it in the Inspector.
      await pointer.click();
      await win.waitForSelector('[data-testid="addr-menu"]', { timeout: 10000 });
      await win.click('[data-testid="addr-menu-memory"]');
      await win.waitForFunction((a) => document.querySelector('[role="tab"][aria-selected="true"]')?.textContent.includes('Inspector')
        && document.querySelector('[data-testid="mem-addr"]')?.value === a, base, { timeout: 20000 });
      await win.click('role=tab[name="REPL"]');
      // The printed form still goes to Output.
      const outText = await win.evaluate(() => window.__fermion.terminal.getText());
      if (!/"base": "0x/.test(outText)) throw new Error('the printed result did not reach Output');
    }

    step = 'persistence';
    await entry('var kept = 20');
    const kept = await entry('kept + 1');
    if (kept.text !== '21') throw new Error('state did not persist: ' + JSON.stringify(kept));

    step = 'error';
    const bad = await entry('noSuchThing.x');
    if (!bad.err || !/ReferenceError/.test(bad.text)) throw new Error('error result: ' + JSON.stringify(bad));

    step = 'own scope';
    const scope = await entry('typeof fromUserScript');
    if (scope.text !== '"undefined"') throw new Error('REPL shares the user script scope: ' + JSON.stringify(scope));

    step = 'output mirror + console';
    await entry('console.log("REPL_CONSOLE_MARK"); 5');
    await win.waitForFunction(() => {
      const t = window.__fermion.terminal.getText();
      return t.includes('frida> Process.id') && t.includes('REPL_CONSOLE_MARK') && t.includes('ReferenceError');
    }, undefined, { timeout: 15000 });

    step = 'survives script reload';
    await win.evaluate(() => window.fermion.reloadScript('// reloaded'));
    const after = await entry('kept');
    if (after.text !== '20') throw new Error('REPL state lost on script reload: ' + JSON.stringify(after));

    step = 'history';
    await win.click('[data-testid="repl-input"]');
    await win.keyboard.press('ArrowUp');
    const recalled = await win.inputValue('[data-testid="repl-input"]');
    if (recalled !== 'kept') throw new Error('ArrowUp recalled "' + recalled + '"');
    await win.keyboard.press('ArrowDown');

    if (shot) await win.screenshot({ path: shot });

    step = 'tab completion';
    const input = '[data-testid="repl-input"]';
    await win.click(input);
    await win.keyboard.type('Process.enumerateMod');
    await win.keyboard.press('Tab');
    await win.waitForFunction(() => document.querySelector('[data-testid="repl-input"]').value === 'Process.enumerateModules', undefined, { timeout: 15000 });
    await win.fill(input, '');
    await win.keyboard.type('Process.enum');
    await win.keyboard.press('Tab');
    await win.waitForFunction(() => document.querySelectorAll('[data-testid="repl-choice"]').length >= 3, undefined, { timeout: 15000 });
    const offered = await win.evaluate(() => ({
      value: document.querySelector('[data-testid="repl-input"]').value,
      names: [...document.querySelectorAll('[data-testid="repl-choice"]')].map((c) => c.textContent),
      focused: document.activeElement === document.querySelector('[data-testid="repl-input"]'),
    }));
    if (offered.value !== 'Process.enumerate') throw new Error('shared prefix not filled in: ' + offered.value);
    if (!offered.names.includes('enumerateModules()') || !offered.names.includes('enumerateThreads()')) throw new Error('choices: ' + offered.names.join(','));
    if (!offered.focused) throw new Error('Tab moved the focus out of the prompt');
    if (shot) await win.screenshot({ path: shot.replace(/\.png$/, '-complete.png') });
    await win.click('[data-testid="repl-choice"]:has-text("enumerateThreads")');
    if ((await win.inputValue(input)) !== 'Process.enumerateThreads') throw new Error('picking a choice gave ' + (await win.inputValue(input)));
    await win.fill(input, '');
    // Typing after Tab must continue where the caret is. (Tab on an already
    // complete name once left the caret jumping back on the next keystroke.)
    await win.keyboard.type('Process.id');
    await win.keyboard.press('Tab');
    await new Promise((r) => setTimeout(r, 400));
    await win.keyboard.type(' + 1');
    if ((await win.inputValue(input)) !== 'Process.id + 1') throw new Error('typing after Tab on a complete name gave "' + (await win.inputValue(input)) + '"');
    await win.fill(input, '');
    await win.keyboard.type('Process.enum');
    await win.keyboard.press('Tab');
    await win.waitForFunction(() => document.querySelector('[data-testid="repl-input"]').value === 'Process.enumerate', undefined, { timeout: 15000 });
    await win.keyboard.type('Mod');
    await win.keyboard.press('Tab');
    await win.waitForFunction(() => document.querySelector('[data-testid="repl-input"]').value === 'Process.enumerateModules', undefined, { timeout: 15000 });
    await win.keyboard.type('().length');
    if ((await win.inputValue(input)) !== 'Process.enumerateModules().length') throw new Error('typing after two completions gave "' + (await win.inputValue(input)) + '"');
    // Completing in the middle of an entry, then typing on.
    await win.fill(input, 'var n = Process.enumerateMod; n');
    await win.evaluate(() => { const el = document.querySelector('[data-testid="repl-input"]'); const at = 'var n = Process.enumerateMod'.length; el.setSelectionRange(at, at); });
    await win.keyboard.press('Tab');
    await win.waitForFunction(() => document.querySelector('[data-testid="repl-input"]').value === 'var n = Process.enumerateModules; n', undefined, { timeout: 15000 });
    await win.keyboard.type('()');
    if ((await win.inputValue(input)) !== 'var n = Process.enumerateModules(); n') throw new Error('typing after a mid-entry completion gave "' + (await win.inputValue(input)) + '"');
    await win.fill(input, '');
    // Completion left no trace in the transcript.
    const nBefore = await win.evaluate(() => document.querySelectorAll('[data-testid="repl-entry"]').length);

    step = 'help';
    const helpFn = await entry('help Process.enumerateModules');
    if (helpFn.err || !/enumerateModules\(\): Module\[\]/.test(helpFn.text) || !/modules/i.test(helpFn.text)) throw new Error('help for a function: ' + JSON.stringify(helpFn.text.slice(0, 300)));
    const helpNs = await entry('help Process');
    for (const want of ['Process — namespace', 'enumerateModules', 'id: number', 'help Process.<name>']) {
      if (!helpNs.text.includes(want)) throw new Error('help Process lacks "' + want + '": ' + helpNs.text.slice(0, 400));
    }
    const helpCls = await entry('help NativePointer');
    if (!/NativePointer — class/.test(helpCls.text) || !/Instances/.test(helpCls.text) || !/readByteArray/.test(helpCls.text)) throw new Error('help NativePointer: ' + helpCls.text.slice(0, 400));
    const overview = await entry('help');
    for (const want of ['help <name>', 'Interceptor', 'Process', 'Memory']) {
      if (!overview.text.includes(want)) throw new Error('help overview lacks "' + want + '"');
    }
    const unknown = await entry('help definitelyNotAThing');
    if (!/No help for/.test(unknown.text)) throw new Error('unknown topic: ' + unknown.text);
    const nAfter = await win.evaluate(() => document.querySelectorAll('[data-testid="repl-entry"]').length);
    if (nAfter !== nBefore + 5) throw new Error('transcript grew by ' + (nAfter - nBefore) + ' (completion must add nothing, help 5)');
    const outText = await win.evaluate(() => window.__fermion.terminal.getText());
    if (/frida> help/.test(outText) || outText.includes('__fermion')) throw new Error('help/completion leaked into Output');
    if (shot) await win.screenshot({ path: shot.replace(/\.png$/, '-help.png') });

    step = 'editor reload button';
    await win.click('role=tab[name="Editor"]');
    await win.evaluate(() => window.MonacoCodeEditor.setValue("console.log('EDITOR_RELOAD_MARK');"));
    await win.click('[data-testid="editor-reload"]');
    await win.waitForFunction(() => {
      const t = window.__fermion.terminal.getText();
      return t.includes('EDITOR_RELOAD_MARK') && t.includes('Script reloaded');
    }, undefined, { timeout: 20000 });
    if (shot) await win.screenshot({ path: shot.replace(/\.png$/, '-editor.png') });
    await win.click('role=tab[name="REPL"]');

    step = 'cancel a running entry';
    {
      const n1 = await win.evaluate(() => document.querySelectorAll('[data-testid="repl-entry"]').length);
      await win.click('[data-testid="repl-input"]');
      await win.keyboard.type('new Promise(function () {})');
      await win.keyboard.press('Enter');
      await win.waitForSelector('[data-testid="repl-cancel"]', { timeout: 10000 });
      const t0 = Date.now();
      await win.click('[data-testid="repl-cancel"]');
      await win.waitForFunction((k) => {
        const r = document.querySelectorAll('[data-testid="repl-result"]')[k];
        return r && r.classList.contains('err') && /Cancelled/.test(r.textContent);
      }, n1, { timeout: 10000 });
      if (Date.now() - t0 > 8000) throw new Error('Cancel took ' + (Date.now() - t0) + ' ms');
      await win.waitForFunction(() => !document.querySelector('[data-testid="repl-input"]').disabled && !document.querySelector('[data-testid="repl-cancel"]'), undefined, { timeout: 10000 });
      const after = await entry('2 + 2');
      if (after.text !== '4') throw new Error('REPL did not recover after Cancel: ' + JSON.stringify(after));
      // Escape cancels as well.
      await win.click('[data-testid="repl-input"]');
      await win.keyboard.type('new Promise(function () {})');
      await win.keyboard.press('Enter');
      await win.waitForSelector('[data-testid="repl-cancel"]', { timeout: 10000 });
      await win.keyboard.press('Escape');
      await win.waitForFunction(() => !document.querySelector('[data-testid="repl-cancel"]') && !document.querySelector('[data-testid="repl-input"]').disabled, undefined, { timeout: 10000 });
      const cancelledInOutput = await win.evaluate(() => window.__fermion.terminal.getText());
      if (!/\[REPL\] entry cancelled/.test(cancelledInOutput)) throw new Error('cancel was not noted in Output');
    }

    step = 'entry that never finishes';
    // Must time out (20 s) and give the prompt back instead of locking it.
    const n0 = await win.evaluate(() => document.querySelectorAll('[data-testid="repl-entry"]').length);
    await win.click('[data-testid="repl-input"]');
    await win.keyboard.type('new Promise(function () {})');
    await win.keyboard.press('Enter');
    await win.waitForFunction((k) => {
      const r = document.querySelectorAll('[data-testid="repl-result"]')[k];
      return r && r.classList.contains('err') && /Timed out/.test(r.textContent);
    }, n0, { timeout: 40000 });
    await win.waitForFunction(() => !document.querySelector('[data-testid="repl-input"]').disabled, undefined, { timeout: 15000 });
    const again = await entry('1 + 1');
    if (again.text !== '2') throw new Error('REPL did not recover after a timeout: ' + JSON.stringify(again));

    step = 'detach';
    await win.click('[data-testid="detach"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="repl-input"]').disabled, undefined, { timeout: 15000 });

    console.log('REPL_OK evaluate + objects + expandable values + persistence + errors + own scope + Output mirror + survives reload + history + Tab completion + help + editor Reload + Cancel + timeout recovery');
    await app.close();
    done(0);
  } catch (e) {
    console.log('REPL_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
