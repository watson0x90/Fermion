// Playwright-Electron test: the Editor's file handling against the real app
// and real files — file name, unsaved-changes marker, Open / Save / Save As,
// the discard prompt, recent files (kept across a restart), and that saving
// the Output log never becomes the script file.
//   node Fermion/scripts/ui-test-editor-files.js
// Exit 0 + EDITOR_FILES_OK / 1 + EDITOR_FILES_FAIL
//
// Native dialogs cannot be driven from a test, so the main process's dialog
// functions are replaced with stand-ins that return the path the test queued.
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-edit-'));
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-edit-files-'));
const A = path.join(work, 'alpha.js');
const B = path.join(work, 'beta.js');
const C = path.join(work, 'gamma.js');
const LOG = path.join(work, 'frida-output.txt');
fs.writeFileSync(A, '// alpha\n');
const T = { timeout: 15000 };

async function launch() {
  const app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
  // Stand-in dialogs: each call takes the next queued answer.
  await app.evaluate(({ dialog }) => {
    global.__dlg = { open: [], save: [], box: [], calls: { open: 0, save: 0, box: 0 } };
    dialog.showOpenDialog = async () => { global.__dlg.calls.open++; const p = global.__dlg.open.shift(); return { filePaths: p ? [p] : [] }; };
    dialog.showSaveDialog = async () => { global.__dlg.calls.save++; return { filePath: global.__dlg.save.shift() }; };
    dialog.showMessageBox = async () => { global.__dlg.calls.box++; return { response: global.__dlg.box.length ? global.__dlg.box.shift() : 1 }; };
  });
  const win = await app.firstWindow();
  await win.waitForSelector('.xterm', { timeout: 60000 });
  await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
  return { app, win };
}

(async () => {
  let app; let step = 'launch';
  try {
    let win;
    ({ app, win } = await launch());
    const queue = (kind, value) => app.evaluate((_e, [k, v]) => { global.__dlg[k].push(v); }, [kind, value]);
    const calls = () => app.evaluate(() => global.__dlg.calls);
    // The file name shown, without the unsaved-changes dot.
    const label = () => win.evaluate(() => document.querySelector('[data-testid="editor-file"]').textContent.replace('●', ''));
    const dirty = () => win.evaluate(() => !!document.querySelector('[data-testid="editor-dirty"]'));
    const value = () => win.evaluate(() => window.MonacoCodeEditor.getValue());
    const typeInEditor = async (text) => { await win.click('.monaco-editor .view-lines'); await win.keyboard.press('Control+End'); await win.keyboard.type(text); };
    const waitClean = () => win.waitForFunction(() => !document.querySelector('[data-testid="editor-dirty"]'), undefined, T);
    const waitDirty = () => win.waitForSelector('[data-testid="editor-dirty"]', T);

    step = 'new script';
    if ((await label()) !== 'untitled.js' || (await dirty())) throw new Error('a new script should be "untitled.js" with no unsaved mark: ' + (await label()));

    step = 'typing marks unsaved';
    await typeInEditor('// typed-1');
    await waitDirty();

    step = 'save asks where, writes the file';
    await queue('save', B);
    await win.click('[data-testid="editor-save"]');
    await waitClean();
    if ((await label()) !== 'beta.js') throw new Error('label after save: ' + (await label()));
    if (!fs.readFileSync(B, 'utf8').includes('// typed-1')) throw new Error('beta.js does not hold the editor text');

    step = 'save again writes back without a dialog';
    await typeInEditor('// typed-2');
    await waitDirty();
    const before = await calls();
    await win.keyboard.press('Control+S');
    await waitClean();
    if ((await calls()).save !== before.save) throw new Error('Ctrl-S on a known file opened a dialog');
    if (!fs.readFileSync(B, 'utf8').includes('// typed-2')) throw new Error('Ctrl-S did not write beta.js');

    step = 'saving the Output log is not the script file';
    await queue('save', LOG);
    await win.click('[data-testid="save-output"]');
    await win.waitForFunction(() => true); // let the export finish
    await new Promise((r) => setTimeout(r, 600));
    if (!fs.existsSync(LOG)) throw new Error('the output log was not written');
    const logText = fs.readFileSync(LOG, 'utf8');
    await typeInEditor('// typed-3');
    await waitDirty();
    await win.keyboard.press('Control+S');
    await waitClean();
    if (fs.readFileSync(LOG, 'utf8') !== logText) throw new Error('Ctrl-S overwrote the saved output log with the script');
    if (!fs.readFileSync(B, 'utf8').includes('// typed-3')) throw new Error('Ctrl-S did not go to beta.js after an export');
    if ((await label()) !== 'beta.js') throw new Error('an export changed the script name to ' + (await label()));

    step = 'open';
    await queue('open', A);
    await win.keyboard.press('Control+O');
    await win.waitForFunction(() => document.querySelector('[data-testid="editor-file"]').textContent === 'alpha.js', undefined, T);
    if ((await value()) !== '// alpha\n' || (await dirty())) throw new Error('alpha.js did not load cleanly');

    step = 'open with unsaved changes asks; Cancel keeps the edits';
    await typeInEditor('// keep-me');
    await waitDirty();
    await queue('box', 1);           // Cancel
    await queue('open', B);
    await win.click('[data-testid="editor-open"]');
    await new Promise((r) => setTimeout(r, 700));
    if (!(await value()).includes('// keep-me') || (await label()) !== 'alpha.js') throw new Error('Cancel did not keep the unsaved edits: ' + JSON.stringify({ value: await value(), label: await label(), calls: await calls() }));
    if ((await calls()).box < 1) throw new Error('no discard prompt was shown');
    await app.evaluate(() => { global.__dlg.open.length = 0; });

    step = 'discard, then open another';
    await queue('box', 0);           // Discard changes
    await queue('open', B);
    await win.click('[data-testid="editor-open"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="editor-file"]').textContent === 'beta.js', undefined, T);
    if (fs.readFileSync(A, 'utf8') !== '// alpha\n') throw new Error('discarded edits were written to alpha.js');

    step = 'save as';
    await queue('save', C);
    await win.click('[data-testid="editor-save-as"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="editor-file"]').textContent === 'gamma.js', undefined, T);
    if (fs.readFileSync(C, 'utf8') !== fs.readFileSync(B, 'utf8')) throw new Error('gamma.js is not a copy of the editor text');

    step = 'recent menu';
    await win.click('[data-testid="editor-recent"]');
    await win.waitForSelector('[data-testid="editor-recent-item"]', T);
    const recent = await win.evaluate(() => [...document.querySelectorAll('[data-testid="editor-recent-item"]')].map((b) => b.querySelector('.mn').textContent));
    if (recent.join(',') !== 'gamma.js,beta.js,alpha.js') throw new Error('recent list: ' + recent.join(','));
    if (recent.includes('frida-output.txt')) throw new Error('the output log is listed as a recent script');
    await win.click('[data-testid="editor-recent-item"]:has-text("alpha.js")');
    await win.waitForFunction(() => document.querySelector('[data-testid="editor-file"]').textContent === 'alpha.js', undefined, T);
    if ((await value()) !== '// alpha\n') throw new Error('recent did not load alpha.js');

    step = 'a path that is not on the list is refused';
    const refused = await win.evaluate(async (p) => { try { await window.fermion.openRecent(p); return 'opened'; } catch (e) { return String(e.message); } }, LOG);
    if (!/Not a recent file/.test(refused)) throw new Error('openRecent on an arbitrary path: ' + refused);

    step = 'recent survives a restart';
    await app.close();
    ({ app, win } = await launch());
    await win.click('[data-testid="editor-recent"]');
    await win.waitForSelector('[data-testid="editor-recent-item"]', T);
    const again = await win.evaluate(() => [...document.querySelectorAll('[data-testid="editor-recent-item"]')].map((b) => b.querySelector('.mn').textContent));
    if (again.join(',') !== 'alpha.js,gamma.js,beta.js') throw new Error('recent after restart: ' + again.join(','));

    step = 'a deleted recent file is reported and dropped';
    fs.unlinkSync(C);
    await win.click('[data-testid="editor-recent-item"]:has-text("gamma.js")');
    await win.waitForFunction(() => /no longer exists/.test(window.__fermion.terminal.getText()), undefined, T);
    await win.click('[data-testid="editor-recent"]');
    await win.waitForSelector('[data-testid="editor-recent-item"]', T);
    const pruned = await win.evaluate(() => [...document.querySelectorAll('[data-testid="editor-recent-item"]')].map((b) => b.querySelector('.mn').textContent));
    if (pruned.includes('gamma.js')) throw new Error('the deleted file is still listed');

    console.log('EDITOR_FILES_OK name + unsaved mark + save/save-as + export is separate + open + discard prompt + recent (persisted, guarded, pruned)');
    await app.close();
    process.exit(0);
  } catch (e) {
    console.log('EDITOR_FILES_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) { /* closing */ }
    process.exit(1);
  } finally {
    for (const d of [userDataDir, work]) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) { /* temp */ } }
  }
})();
