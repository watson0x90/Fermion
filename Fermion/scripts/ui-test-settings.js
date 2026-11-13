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
    editorFamily: ed.getOption(opt.fontFamily).split(',')[0].replace(/"/g, ''),
    numbers: ed.getOption(opt.lineNumbers).renderType !== 0,
    tab: ed.getModel().getOptions().tabSize,
    outputFamily: window.__fermion.terminal.getLook().fontFamily.split(',')[0].replace(/"/g, ''),
    outputCursor: window.__fermion.terminal.getLook().cursorStyle,
    dataFont: getComputedStyle(document.documentElement).getPropertyValue('--mono').split(',')[0].replace(/"/g, '').trim(),
    minimap: ed.getOption(opt.minimap).enabled,
    wrap: ed.getOption(opt.wordWrap),
    outputFont: window.__fermion.terminal.getFontSize(),
    catching: document.querySelector('[data-testid="child-gating"]')?.checked ?? null,
  };
});
const tab = (win, name) => win.click('[data-testid="settings-tab-' + name + '"]');
// A fixed-width font this platform always has, to choose in the font lists.
const FONT = process.platform === 'win32' ? 'Consolas' : process.platform === 'darwin' ? 'Menlo' : null;
const sorted = (o) => JSON.stringify(Object.keys(o).sort().map((k) => [k, o[k]]));
const same = (a, b) => sorted(a) === sorted(b);

(async () => {
  let app; let step = 'launch';
  try {
    app = await launch();
    let win = await ready(app);

    step = 'defaults';
    const before = await live(win);
    const defaults = { editorFont: 14, editorFamily: 'IBM Plex Mono', numbers: true, tab: 4, minimap: true, wrap: 'off', outputFont: 13, outputFamily: 'IBM Plex Mono', outputCursor: 'bar', dataFont: 'IBM Plex Mono', catching: false };
    if (!same(before, defaults)) throw new Error('the app does not start with the defaults: ' + JSON.stringify(before));

    step = 'changing a preference takes effect at once';
    await win.click('[data-testid="open-settings"]');
    await win.waitForSelector('[data-testid="settings"]', T);
    // A dialog in the middle of the window, not a menu in its corner.
    const box = await win.evaluate(() => { const r = document.querySelector('[data-testid="settings"]').getBoundingClientRect(); return { cx: r.left + r.width / 2, w: r.width, h: r.height, vw: innerWidth }; });
    if (Math.abs(box.cx - box.vw / 2) > 2 || box.w < 600 || box.h < 400) throw new Error('not a centred dialog: ' + JSON.stringify(box));
    if (!(await win.evaluate(() => document.activeElement?.getAttribute('role') === 'tab'))) throw new Error('focus did not move into the dialog');
    if (shot) await win.screenshot({ path: shot + '-appearance.png' });
    await tab(win, 'editor');
    await win.fill('[data-testid="pref-editor-font"]', '17');
    await win.click('[data-testid="pref-editor-font-plus"]');
    await win.uncheck('[data-testid="pref-editor-minimap"]');
    await win.check('[data-testid="pref-editor-wrap"]');
    await win.uncheck('[data-testid="pref-editor-numbers"]');
    await win.click('[data-testid="pref-editor-tab-2"]');
    if (FONT) {
      // The font is offered because it was found installed, by measuring.
      await win.selectOption('[data-testid="pref-editor-family"]', FONT);
      await win.waitForFunction((f) => window.MonacoCodeEditor.getOption(window.monaco.editor.EditorOption.fontFamily).startsWith('"' + f + '"'), FONT, T);
    }
    if (shot) await win.screenshot({ path: shot + '-editor.png' });
    await tab(win, 'output');
    await win.fill('[data-testid="pref-output-font"]', '16');
    await win.click('[data-testid="pref-output-cursor-block"]');
    // A family that is not installed is said so, and the built-in font stays in use.
    await win.selectOption('[data-testid="pref-output-family"]', { label: 'Another installed font\u2026' });
    await win.fill('[data-testid="pref-output-family-custom"]', 'No Such Font Xyzzy');
    await win.press('[data-testid="pref-output-family-custom"]', 'Enter');
    await win.waitForSelector('[data-testid="pref-output-family-missing"]', T);
    if (shot) await win.screenshot({ path: shot + '-output.png' });
    await win.click('[data-testid="pref-output-family-changed"]'); // the mark puts that one setting back
    await win.waitForFunction(() => document.querySelector('[data-testid="pref-output-family"]').value === 'IBM Plex Mono', undefined, T);
    await tab(win, 'inspector');
    await win.selectOption('[data-testid="pref-cover-scope"]', 'all');
    await win.selectOption('[data-testid="pref-watch-mode"]', 'sampled');
    await win.fill('[data-testid="pref-auto-refresh"]', '7');
    await tab(win, 'session');
    await win.check('[data-testid="pref-catch-children"]');
    await tab(win, 'appearance');
    if (FONT) await win.selectOption('[data-testid="pref-data-font"]', FONT);
    await win.waitForFunction(() => window.MonacoCodeEditor.getOption(window.monaco.editor.EditorOption.fontSize) === 18 && window.__fermion.terminal.getFontSize() === 16, undefined, T);
    const changed = await live(win);
    const want = { ...defaults, editorFont: 18, numbers: false, tab: 2, minimap: false, wrap: 'on', outputFont: 16, outputCursor: 'block', editorFamily: FONT || 'IBM Plex Mono', dataFont: FONT || 'IBM Plex Mono' };
    if (!same({ ...changed, catching: null }, { ...want, catching: null })) throw new Error('the app did not follow: ' + JSON.stringify(changed));

    step = 'a number out of range is brought into range';
    await tab(win, 'editor');
    await win.fill('[data-testid="pref-editor-font"]', '300');
    await win.press('[data-testid="pref-editor-font"]', 'Enter');
    await win.waitForFunction(() => window.MonacoCodeEditor.getOption(window.monaco.editor.EditorOption.fontSize) === 24, undefined, T);
    if ((await win.inputValue('[data-testid="pref-editor-font"]')) !== '24') throw new Error('the field still shows ' + await win.inputValue('[data-testid="pref-editor-font"]'));
    await win.fill('[data-testid="pref-editor-font"]', '18');

    step = 'Escape closes it, and Ctrl+, opens it where it was left';
    await win.press('[data-testid="pref-editor-minimap"]', 'Escape');
    await win.waitForSelector('[data-testid="settings"]', { state: 'detached', timeout: 5000 });
    await win.keyboard.press(process.platform === 'darwin' ? 'Meta+,' : 'Control+,');
    await win.waitForSelector('[data-testid="settings-pane-editor"]', T);
    await win.click('[data-testid="settings-close"]');
    await sleep(300); // the save follows the change

    step = 'after a restart everything is as it was left';
    await app.close();
    app = await launch();
    win = await ready(app);
    const after = await live(win);
    const expected = { ...want, catching: true };
    if (!same(after, expected)) throw new Error('after a restart: ' + JSON.stringify(after));
    await win.click('[data-testid="open-settings"]');
    await tab(win, 'editor');
    const font = await win.inputValue('[data-testid="pref-editor-font"]');
    await tab(win, 'inspector');
    const shown = await win.evaluate((font) => ({
      font,
      cover: document.querySelector('[data-testid="pref-cover-scope"]').value,
      watch: document.querySelector('[data-testid="pref-watch-mode"]').value,
      refresh: document.querySelector('[data-testid="pref-auto-refresh"]').value,
    }), font);
    if (!same(shown, { font: '18', cover: 'all', watch: 'sampled', refresh: '7' })) throw new Error('Settings shows: ' + JSON.stringify(shown));

    step = 'a damaged store gives the defaults, not a broken app';
    await win.evaluate(() => localStorage.setItem('fermion.prefs', '{"editorFontSize":"huge","outputFontSize":99999,"coverScope":["x"]'));
    await app.close();
    app = await launch();
    win = await ready(app);
    if (!same(await live(win), defaults)) throw new Error('with a damaged store: ' + JSON.stringify(await live(win)));

    step = 'reset';
    await win.click('[data-testid="open-settings"]');
    await tab(win, 'output');
    await win.fill('[data-testid="pref-output-font"]', '20');
    await win.waitForFunction(() => window.__fermion.terminal.getFontSize() === 20, undefined, T);
    await win.click('[data-testid="pref-reset"]');
    await win.waitForFunction(() => window.__fermion.terminal.getFontSize() === 13, undefined, T);
    if (!(await win.isDisabled('[data-testid="pref-reset"]'))) throw new Error('Reset is still offered after resetting');
    await win.click('[data-testid="pref-undo"]');
    await win.waitForFunction(() => window.__fermion.terminal.getFontSize() === 20, undefined, T);

    console.log('SETTINGS_OK defaults at first start + a centred dialog + ' + (FONT ? 'installed font ' + FONT + ' offered and applied' : 'no system font tried here') + ' + a missing font is said so + editor size, numbers, tab width, minimap, wrap and output size and cursor follow at once + Escape and Ctrl+, + undo of a reset + out-of-range number clamped + all kept across a restart (incl. catch children, coverage scope, watch mode, refresh) + damaged store falls back to defaults + reset');
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
