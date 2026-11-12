// Playwright-Electron END-TO-END test: TypeScript scripts. Opens a real .ts
// file, attaches to a real process, and checks that the script is compiled
// (types checked) and runs, that a type error is refused with its line while
// the running script stays, and that a .js file is still loaded as written.
//   node Fermion/scripts/ui-test-typescript.js [screenshot-prefix]
// Exit 0 + TYPESCRIPT_OK / TYPESCRIPT_SKIP (cannot attach on this runner) ; 1 + TYPESCRIPT_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-ts-'));
const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-ts-files-'));
const tsFile = path.join(workDir, 'modules.ts');
const jsFile = path.join(workDir, 'plain.js');
fs.writeFileSync(tsFile, [
  'interface Found { name: string; base: NativePointer }',
  'enum Kind { Main, Other }',
  'function describe(f: Found, kind: Kind = Kind.Main): string {',
  '  return Kind[kind] + ":" + f.name + "@" + f.base;',
  '}',
  'const first: Found = Process.enumerateModules().map((m): Found => ({ name: m.name, base: m.base }))[0];',
  'console.log("TS_OK " + describe(first));',
  '',
].join('\n'));
fs.writeFileSync(jsFile, 'console.log("JS_OK " + Process.id);\n');
const shot = process.argv[2];
const T = { timeout: 20000 };

(async () => {
  let app; let step = 'launch';
  const target = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exit(code); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    await app.evaluate(({ dialog }) => {
      global.__open = [];
      dialog.showOpenDialog = async () => { const p = global.__open.shift(); return { filePaths: p ? [p] : [] }; };
    });
    const openFile = async (win, file) => {
      await app.evaluate((_e, p) => { global.__open.push(p); }, file);
      await win.click('[data-testid="editor-open"]');
      await win.waitForFunction((name) => document.querySelector('[data-testid="editor-file"]')?.textContent.includes(name), path.basename(file), T);
    };
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const output = () => win.evaluate(() => window.__fermion.terminal.getText());
    const inOutput = (text) => win.waitForFunction((t) => window.__fermion.terminal.getText().includes(t), text, T);
    const count = async (text) => (await output()).split(text).length - 1;

    step = 'open a .ts file';
    if (await win.$('[data-testid="editor-lang"]')) throw new Error('an unsaved script is marked TypeScript');
    await openFile(win, tsFile);
    if ((await win.textContent('[data-testid="editor-lang"]')) !== 'TypeScript') throw new Error('the toolbar does not say TypeScript');

    step = 'attach: compiled, types checked, and it runs';
    try {
      await win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
    } catch (e) {
      const why = String(e && e.message ? e.message : e).split('\n')[0];
      if (/did not compile/.test(await output())) throw new Error('compile: ' + (await output()).slice(-400));
      console.log('TYPESCRIPT_SKIP could not attach: ' + why.slice(0, 160));
      await app.close(); return done(0);
    }
    await inOutput('TypeScript compiled, types checked');
    await win.waitForFunction(() => /TS_OK Main:\S+@0x[0-9a-f]+/.test(window.__fermion.terminal.getText()), undefined, T);
    if (shot) await win.screenshot({ path: shot + '-typescript.png' });

    step = 'a type error is refused with its line, and the running script stays';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('const pid: number = Process.id;\nconst name: number = "not a number";\nconsole.log(pid, name);\n'));
    await win.click('[data-testid="editor-reload"]');
    await inOutput('did not compile');
    const out = await output();
    if (!/script\.ts:2:\d+: Type 'string' is not assignable to type 'number'/.test(out)) throw new Error('type error text: ' + out.slice(-400));
    if (!(await win.evaluate(() => window.__fermion.service.hasScript))) throw new Error('the running script was dropped');

    step = 'a syntax-only TypeScript feature compiles and runs';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('type Pair = [number, string];\nconst p: Pair = [Process.id, Process.arch];\nconsole.log("TS_TUPLE " + p[0] + " " + p[1]);\n'));
    await win.click('[data-testid="editor-reload"]');
    await win.waitForFunction(() => /TS_TUPLE \d+ \w+/.test(window.__fermion.terminal.getText()), undefined, T);

    step = 'a .js file is loaded as written';
    const compiledBefore = await count('TypeScript compiled');
    await app.evaluate(({ dialog }) => { dialog.showMessageBox = async () => ({ response: 0 }); }); // discard the edits
    await openFile(win, jsFile);
    if (await win.$('[data-testid="editor-lang"]')) throw new Error('a .js file is marked TypeScript');
    await win.click('[data-testid="editor-reload"]');
    await win.waitForFunction(() => /JS_OK \d+/.test(window.__fermion.terminal.getText()), undefined, T);
    if ((await count('TypeScript compiled')) !== compiledBefore) throw new Error('a .js file was compiled as TypeScript');

    console.log('TYPESCRIPT_OK .ts opened and marked + compiled with types checked + ran in the target + type error refused with its line (running script kept) + .js loaded as written');
    await app.close();
    done(0);
  } catch (e) {
    console.log('TYPESCRIPT_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await app.close(); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
    try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
