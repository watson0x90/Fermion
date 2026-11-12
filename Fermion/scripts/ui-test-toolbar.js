// Playwright-Electron test: terminal toolbar — level filtering, clear, and the
// search API are wired to the terminal.
//   node Fermion/scripts/ui-test-toolbar.js
// Exit 0 + TOOLBAR_OK / 1 + TOOLBAR_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-tb-'));
(async () => {
  let app;
  try {
    app = await electron.launch({
      executablePath: electronPath,
      args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir],
      cwd: APP_DIR,
    });
    const win = await app.firstWindow();
    await win.waitForLoadState('domcontentloaded');
    await win.waitForSelector('.xterm', { timeout: 60000 });

    await win.evaluate(() => {
      window.__fermion.terminal.write('LOG', 'alpha-line');
      window.__fermion.terminal.write('WARN', 'bravo-line');
    });
    await win.waitForFunction(() => {
      const r = document.querySelector('.xterm-rows').textContent;
      return r.includes('alpha-line') && r.includes('bravo-line');
    }, { timeout: 15000 });

    // Toggle WARN off -> bravo hidden, alpha stays.
    await win.click('[data-testid="flt-WARN"]');
    await win.waitForFunction(() => {
      const r = document.querySelector('.xterm-rows').textContent;
      return r.includes('alpha-line') && !r.includes('bravo-line');
    }, { timeout: 15000 });

    // Toggle WARN back on -> both visible.
    await win.click('[data-testid="flt-WARN"]');
    await win.waitForFunction(() => {
      const r = document.querySelector('.xterm-rows').textContent;
      return r.includes('alpha-line') && r.includes('bravo-line');
    }, { timeout: 15000 });

    // Re-rendering must not duplicate lines: each line is on screen exactly once
    // (the filter re-render used to race the terminal's write queue).
    await new Promise((r) => setTimeout(r, 400));
    const copies = await win.evaluate(() => {
      const r = document.querySelector('.xterm-rows').textContent;
      return { alpha: r.split('alpha-line').length - 1, bravo: r.split('bravo-line').length - 1 };
    });
    if (copies.alpha !== 1 || copies.bravo !== 1) throw new Error('lines duplicated after filter re-render: ' + JSON.stringify(copies));

    // Search finds a present term.
    const found = await win.evaluate(() => window.__fermion.terminal.searchNext('alpha'));
    if (!found) throw new Error('searchNext did not find a present term');

    // Plain-text search (regex off) finds text that is not a valid regex, and
    // does not treat "." as a wildcard.
    await win.evaluate(() => window.__fermion.terminal.write('LOG', 'call open(fd) a.c'));
    await win.waitForFunction(() => document.querySelector('.xterm-rows').textContent.includes('call open(fd)'), undefined, { timeout: 15000 });
    const plain = await win.evaluate(() => ({
      paren: window.__fermion.terminal.searchNext('open(', { regex: false }),
      dotLiteral: window.__fermion.terminal.searchNext('a.c', { regex: false }),
      dotNotWild: window.__fermion.terminal.searchNext('al.ha', { regex: false }),
      dotWildInRegex: window.__fermion.terminal.searchNext('al.ha', { regex: true }),
    }));
    if (!plain.paren || !plain.dotLiteral || plain.dotNotWild || !plain.dotWildInRegex) {
      throw new Error('plain/regex search modes wrong: ' + JSON.stringify(plain));
    }

    // The search box is on its own row under the action icons, and is wider.
    const lay = await win.evaluate(() => {
      const b = (id) => document.querySelector('[data-testid="' + id + '"]').getBoundingClientRect();
      const ids = ['detach-output', 'follow-output', 'clear-output', 'save-output'];
      const tops = ids.map((i) => Math.round(b(i).top));
      return { sameRow: tops.every((t) => t === tops[0]), iconsBottom: b('save-output').bottom, searchTop: b('output-search').top, searchWidth: b('output-search').width };
    });
    if (!lay.sameRow) throw new Error('action icons are not on one row');
    if (!(lay.searchTop >= lay.iconsBottom)) throw new Error('search is not underneath the icons: ' + JSON.stringify(lay));
    if (!(lay.searchWidth >= 180)) throw new Error('search box too narrow: ' + lay.searchWidth);

    // Typing searches immediately (no Enter); the clear button drops the match.
    await win.click('[data-testid="output-search"]');
    await win.keyboard.type('bravo');
    await win.waitForFunction(() => window.__fermion.terminal._term.getSelection() === 'bravo', undefined, { timeout: 15000 });
    await win.click('[data-testid="search-clear"]');
    await win.waitForFunction(() => window.__fermion.terminal._term.getSelection() === ''
      && document.querySelector('[data-testid="output-search"]').value === ''
      && !document.querySelector('[data-testid="search-clear"]'), undefined, { timeout: 15000 });
    // Up recalls the cleared query and searches for it again.
    await win.keyboard.press('ArrowUp');
    await win.waitForFunction(() => document.querySelector('[data-testid="output-search"]').value === 'bravo'
      && window.__fermion.terminal._term.getSelection() === 'bravo', undefined, { timeout: 15000 });
    // Emptying the field by hand clears the match too.
    await win.keyboard.press('Control+A');
    await win.keyboard.press('Backspace');
    await win.waitForFunction(() => window.__fermion.terminal._term.getSelection() === '', undefined, { timeout: 15000 });

    // An invalid regex must fail gracefully, not throw out of the handler.
    const threw = await win.evaluate(() => {
      try { window.__fermion.terminal.searchNext('['); return false; } catch (e) { return true; }
    });
    if (threw) throw new Error('invalid regex threw out of searchNext');

    // Clear empties the terminal.
    await win.click('[data-testid="clear-output"]');
    await win.waitForFunction(() => {
      const r = document.querySelector('.xterm-rows').textContent;
      return !r.includes('alpha-line') && !r.includes('bravo-line');
    }, { timeout: 15000 });

    console.log('TOOLBAR_OK filter + search + clear wired');
    await app.close();
    process.exit(0);
  } catch (e) {
    console.log('TOOLBAR_FAIL ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    process.exit(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
