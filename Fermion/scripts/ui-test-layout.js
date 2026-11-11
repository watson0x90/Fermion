// Playwright-Electron regression test for layout persistence.
//
// Guards the fix for the enhanced-ui bug where a saved HORIZONTAL layout was
// never restored (loadSettings pre-set isVertical and cancelled toggleLayout's
// flip, then re-saved as vertical). Launches the app twice against a shared
// throwaway user-data dir (so real user settings are untouched): run 1 toggles
// to horizontal, run 2 must restore horizontal with isVertical still false.
//
//   Usage:  node scripts/ui-test-layout.js
//   Exit 0 + "PERSIST_OK"   -> horizontal layout survives a restart
//   Exit 1 + "PERSIST_FAIL" -> layout not restored / preference corrupted
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-uitest-'));

async function launch() {
  const app = await electron.launch({
    executablePath: electronPath,
    args: ['.', '--user-data-dir=' + userDataDir],
    cwd: APP_DIR,
  });
  const win = await app.firstWindow();
  await win.waitForLoadState('domcontentloaded');
  return { app, win };
}

async function layoutState(win) {
  return win.evaluate(() => {
    const saved = JSON.parse(localStorage.getItem('fermion_output_settings') || '{}');
    return {
      savedIsVertical: saved.isVertical,
      hasHorizontalGutter: !!document.querySelector('.gutter-horizontal'),
      hasVerticalGutter: !!document.querySelector('.gutter-vertical'),
    };
  });
}

(async () => {
  try {
    // Run 1: start vertical (default), toggle to horizontal.
    let { app, win } = await launch();
    await win.waitForSelector('.gutter', { timeout: 20000 });
    await win.click('#toggle-layout');
    await win.waitForSelector('.gutter-horizontal', { timeout: 10000 });
    const s1 = await layoutState(win);
    await app.close();

    // Run 2: relaunch, expect horizontal restored (loadSettings applies it via
    // a ~500ms timeout, then Split rebuilds after ~50ms).
    ({ app, win } = await launch());
    await win.waitForSelector('.gutter-horizontal', { timeout: 20000 });
    const s2 = await layoutState(win);
    await app.close();

    const pass =
      s1.savedIsVertical === false && s1.hasHorizontalGutter &&
      s2.savedIsVertical === false && s2.hasHorizontalGutter && !s2.hasVerticalGutter;

    console.log('RUN1', JSON.stringify(s1));
    console.log('RUN2', JSON.stringify(s2));
    console.log(pass ? 'PERSIST_OK horizontal restored after restart'
                     : 'PERSIST_FAIL layout not restored');
    process.exit(pass ? 0 : 1);
  } catch (e) {
    console.log('PERSIST_FAIL ' + (e && e.message ? e.message : e));
    process.exit(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
