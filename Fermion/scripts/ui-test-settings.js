// Playwright-Electron END-TO-END test: the preferences in Settings. Changes
// them in the real app, checks that the editor and the terminal follow at
// once, that the Inspector and the session start from them, and that they are
// still there after the app is closed and started again. No process is
// attached: preferences live in the window.
//   node Fermion/scripts/ui-test-settings.js [screenshot-prefix]
// Exit 0 + SETTINGS_OK ; 1 + SETTINGS_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-settings-'));
const shot = process.argv[2];
const T = { timeout: 30000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const launch = () => electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
async function ready(app) {
  const win = await app.firstWindow();
  await win.waitForSelector('.xterm', { timeout: 60000 });
  await win.waitForFunction(() => !!window.MonacoCodeEditor && !!window.__fermion && !!window.__fermion.terminal, undefined, { timeout: 60000 });
  return win;
}
// What the app is really using right now.
const live = (win) => win.evaluate(() => {
  const ed = window.MonacoCodeEditor;
  const opt = window.monaco.editor.EditorOption;
  return {
    editorFont: ed.getOption(opt.fontSize),
    minimap: ed.getOption(opt.minimap).enabled,
    wrap: ed.getOption(opt.wordWrap),
    outputFont: window.__fermion.terminal.getFontSize(),
    catching: document.querySelector('[data-testid="child-gating"]')?.checked ?? null,
  };
});
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

(async () => {
  let app; let step = 'launch';
  try {
    app = await launch();
    let win = await ready(app);

    step = 'defaults';
    const before = await live(win);
    const defaults = { editorFont: 14, minimap: true, wrap: 'off', outputFont: 13, catching: false };
    if (!same(before, defaults)) throw new Error('the app does not start with the defaults: ' + JSON.stringify(before));

    step = 'changing a preference takes effect at once';
    await win.click('[data-testid="open-settings"]');
    await win.waitForSelector('[data-testid="settings"]', T);
    await win.fill('[data-testid="pref-editor-font"]', '18');
    await win.uncheck('[data-testid="pref-editor-minimap"]');
    await win.check('[data-testid="pref-editor-wrap"]');
    await win.fill('[data-testid="pref-output-font"]', '16');
    await win.selectOption('[data-testid="pref-cover-scope"]', 'all');
    await win.selectOption('[data-testid="pref-watch-mode"]', 'sampled');
    await win.fill('[data-testid="pref-auto-refresh"]', '7');
    await win.check('[data-testid="pref-catch-children"]');
    await win.waitForFunction(() => window.MonacoCodeEditor.getOption(window.monaco.editor.EditorOption.fontSize) === 18 && window.__fermion.terminal.getFontSize() === 16, undefined, T);
    const changed = await live(win);
    if (changed.minimap !== false || changed.wrap !== 'on') throw new Error('the editor did not follow: ' + JSON.stringify(changed));
    if (shot) await win.screenshot({ path: shot + '-settings.png' });

    step = 'a number out of range is brought into range';
    await win.fill('[data-testid="pref-editor-font"]', '300');
    await win.waitForFunction(() => window.MonacoCodeEditor.getOption(window.monaco.editor.EditorOption.fontSize) === 24, undefined, T);
    if ((await win.inputValue('[data-testid="pref-editor-font"]')) !== '24') throw new Error('the field still shows ' + await win.inputValue('[data-testid="pref-editor-font"]'));
    await win.fill('[data-testid="pref-editor-font"]', '18');
    await win.click('[data-testid="settings-scrim"]');
    await sleep(300); // the save follows the change

    step = 'after a restart everything is as it was left';
    await app.close();
    app = await launch();
    win = await ready(app);
    const after = await live(win);
    const expected = { editorFont: 18, minimap: false, wrap: 'on', outputFont: 16, catching: true };
    if (!same(after, expected)) throw new Error('after a restart: ' + JSON.stringify(after));
    await win.click('[data-testid="open-settings"]');
    const shown = await win.evaluate(() => ({
      font: document.querySelector('[data-testid="pref-editor-font"]').value,
      cover: document.querySelector('[data-testid="pref-cover-scope"]').value,
      watch: document.querySelector('[data-testid="pref-watch-mode"]').value,
      refresh: document.querySelector('[data-testid="pref-auto-refresh"]').value,
    }));
    if (!same(shown, { font: '18', cover: 'all', watch: 'sampled', refresh: '7' })) throw new Error('Settings shows: ' + JSON.stringify(shown));

    step = 'a damaged store gives the defaults, not a broken app';
    await win.evaluate(() => localStorage.setItem('fermion.prefs', '{"editorFontSize":"huge","outputFontSize":99999,"coverScope":["x"]'));
    await app.close();
    app = await launch();
    win = await ready(app);
    if (!same(await live(win), defaults)) throw new Error('with a damaged store: ' + JSON.stringify(await live(win)));

    step = 'reset';
    await win.click('[data-testid="open-settings"]');
    await win.fill('[data-testid="pref-output-font"]', '20');
    await win.waitForFunction(() => window.__fermion.terminal.getFontSize() === 20, undefined, T);
    await win.click('[data-testid="pref-reset"]');
    await win.waitForFunction(() => window.__fermion.terminal.getFontSize() === 13, undefined, T);
    if (!(await win.isDisabled('[data-testid="pref-reset"]'))) throw new Error('Reset is still offered after resetting');

    console.log('SETTINGS_OK defaults at first start + editor font, minimap, wrap and output font follow at once + out-of-range number clamped + all kept across a restart (incl. catch children, coverage scope, watch mode, refresh) + damaged store falls back to defaults + reset');
    await app.close();
    process.exitCode = 0;
  } catch (e) {
    console.log('SETTINGS_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await Promise.race([app.close(), sleep(15000)]); } catch (_) {}
    process.exitCode = 1;
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
    setTimeout(() => process.exit(process.exitCode), 200);
  }
})();
