// Playwright-Electron END-TO-END test: the Inspector reads a real attached
// process — modules + exports, memory ranges + hex view + scan, threads +
// registers + backtrace.
//   node Fermion/scripts/ui-test-inspector.js [screenshot-prefix]
// Exit 0 + INSPECT_OK / INSPECT_SKIP (cannot attach on this runner) ; 1 + INSPECT_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-insp-'));
const shot = process.argv[2];
const T = { timeout: 20000 };

(async () => {
  let app; let step = 'launch';
  // The target holds a recognizable string in memory for the scan to find.
  const target = spawn(process.execPath, ['-e', 'globalThis.keep = Buffer.from("FERMION_SCAN_MARKER_7391"); const fs = require("fs"); setInterval(() => { try { fs.statSync(process.execPath); } catch (e) {} }, 150)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exit(code); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const snap = async (name) => { if (shot) await win.screenshot({ path: shot + '-' + name + '.png' }); };

    step = 'not attached';
    await win.click('role=tab[name="Inspector"]');
    await win.waitForFunction(() => /Attach to a process/.test(document.querySelector('[data-testid="inspector-panel"]').textContent), undefined, T);

    step = 'attach';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// inspector test'));
    try {
      await win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
      await win.waitForFunction(() => window.__fermion.service.isAttached, undefined, T);
    } catch (e) {
      console.log('INSPECT_SKIP could not attach: ' + String(e && e.message ? e.message : e).split('\n')[0]);
      await app.close(); return done(0);
    }

    step = 'modules';
    await win.waitForSelector('[data-testid^="mod-row-"]', T);
    const mods = await win.evaluate(() => [...document.querySelectorAll('[data-testid^="mod-row-"]')].map((r) => r.getAttribute('data-testid').slice(8)));
    if (mods.length < 5) throw new Error('only ' + mods.length + ' modules listed');
    const exe = mods[0];
    const lib = mods.find((m) => /^(ntdll\.dll|libc[.-].*|libsystem_kernel\.dylib)$/i.test(m)) || mods[1];

    step = 'exports';
    await win.fill('[data-testid="mod-filter"]', lib);
    await win.click('[data-testid="mod-row-' + lib + '"]');
    await win.waitForSelector('[data-testid="sym-row"]', T);
    const nExports = await win.evaluate(() => document.querySelectorAll('[data-testid="sym-row"]').length);
    if (nExports < 10) throw new Error(lib + ' shows only ' + nExports + ' exports');
    await snap('modules');

    step = 'imports';
    await win.fill('[data-testid="mod-filter"]', '');
    await win.click('[data-testid="mod-row-' + exe + '"]');
    await win.click('[data-testid="sym-kind-imports"]');
    await win.waitForFunction(() => /\d+ imports/.test(document.querySelector('[data-testid="sym-count"]').textContent), undefined, T);

    step = 'view module memory';
    await win.click('[data-testid="mod-view-memory"]');
    // 256 bytes: 16 rows of 16, or 32 rows of 8 when the pane is narrow.
    await win.waitForFunction(() => {
      const rows = document.querySelectorAll('[data-testid="hex-row"]');
      return rows.length > 0 && document.querySelectorAll('[data-testid="hex-row"] .hb > span').length === 256;
    }, undefined, T);
    const fits = await win.evaluate(() => {
      const pane = document.querySelector('[data-testid="hexview"]');
      return pane.scrollWidth <= pane.clientWidth + 1;
    });
    if (!fits) throw new Error('hex view rows are wider than the pane (text column cut off)');
    const first = await win.evaluate(() => document.querySelector('[data-testid="hex-row"]').textContent);
    // A module image starts with its executable header.
    if (!/MZ|ELF|\xcf\xfa\xed\xfe|cffaedfe/i.test(first) && !/4d\s*5a|7f\s*45\s*4c\s*46|cf\s*fa\s*ed\s*fe/i.test(first)) {
      throw new Error('module base does not look like an image header: ' + first);
    }

    step = 'ranges + paging';
    await win.waitForSelector('[data-testid="range-row"]', T);
    const before = await win.evaluate(() => document.querySelector('[data-testid="hex-row"] .ha').textContent);
    await win.click('[data-testid="mem-next"]');
    await win.waitForFunction((b) => { const a = document.querySelector('[data-testid="hex-row"] .ha'); return a && a.textContent !== b; }, before, T);
    const after = await win.evaluate(() => document.querySelector('[data-testid="hex-row"] .ha').textContent);
    if (BigInt(after) - BigInt(before) !== 256n) throw new Error('paging moved ' + before + ' -> ' + after);

    step = 'unreadable address';
    await win.fill('[data-testid="mem-addr"]', '0x10');
    await win.click('[data-testid="mem-go"]');
    await win.waitForSelector('[data-testid="hex-error"]', T);

    step = 'scan';
    await win.click('[data-testid="mem-mode-scan"]');
    await win.selectOption('[data-testid="range-prot"]', 'rw-');
    await win.selectOption('[data-testid="scan-as"]', 'text');
    await win.fill('[data-testid="scan-pattern"]', 'FERMION_SCAN_MARKER_7391');
    await win.click('[data-testid="scan-run"]');
    await win.waitForSelector('[data-testid="scan-status"]', { timeout: 30000 });
    const status = await win.evaluate(() => document.querySelector('[data-testid="scan-status"]').textContent);
    const nMatch = await win.evaluate(() => document.querySelectorAll('[data-testid="scan-row"]').length);
    if (nMatch < 1) throw new Error('scan found no match for a string the target holds (' + status + ')');
    await win.click('[data-testid="scan-row"]');
    await win.waitForFunction(() => document.querySelectorAll('[data-testid="hex-row"] .hl').length >= 16, undefined, T);
    const dump = await win.evaluate(() => [...document.querySelectorAll('[data-testid="hex-row"] .hc')].map((e) => e.textContent).join(''));
    if (!dump.includes('FERMION_SCAN_MARKER_7391')) throw new Error('hex view at the match does not show the marker: ' + dump.slice(0, 64));
    await snap('memory');

    step = 'threads';
    await win.click('[data-testid="insp-threads"]');
    await win.waitForSelector('[data-testid^="thr-row-"]', T);
    await win.click('[data-testid^="thr-row-"]');
    await win.waitForSelector('[data-testid="reg-pc"]', T);
    await win.waitForSelector('[data-testid="bt-row"]', T);
    const nReg = await win.evaluate(() => document.querySelectorAll('[data-testid="thr-registers"] .reg').length);
    if (nReg < 8) throw new Error('only ' + nReg + ' registers shown');
    await snap('threads');

    step = 'follow a thread';
    {
      // The first thread listed is the main thread, which runs the timer above.
      await win.click('[data-testid="thr-follow"]');
      await win.waitForFunction(() => /Stop/.test(document.querySelector('[data-testid="thr-follow"]').textContent), undefined, T);
      await new Promise((r) => setTimeout(r, 1800));
      await win.click('[data-testid="thr-follow"]');
      await win.waitForSelector('[data-testid="follow-row"]', T);
      const fol = await win.evaluate(() => ({
        status: document.querySelector('[data-testid="thr-follow-status"]').textContent,
        rows: document.querySelectorAll('[data-testid="follow-row"]').length,
        top: document.querySelector('[data-testid="follow-row"]').textContent,
        named: [...document.querySelectorAll('[data-testid="follow-row"] .fsym')].filter((b) => b.textContent.includes('!')).length,
      }));
      if (!/[\d,]+ calls to [\d,]+ functions/.test(fol.status)) throw new Error('follow status: ' + fol.status);
      if (fol.rows < 5 || fol.named < 3) throw new Error('follow results: ' + JSON.stringify(fol));
      // Stopping really stopped: nothing is being followed any more.
      const again = await win.evaluate(() => window.fermion.inspect.unfollow());
      if (again.threadId !== null) throw new Error('a thread was still being followed after Stop');
      await snap('follow');
      await win.click('[data-testid="thr-follow-dismiss"]');
      await win.waitForSelector('[data-testid="bt-row"]', T);
    }

    step = 'register -> memory';
    await win.click('[data-testid="reg-sp"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="insp-memory"]').getAttribute('aria-selected') === 'true'
      && document.querySelectorAll('[data-testid="hex-row"]').length > 0, undefined, T);

    step = 'target unharmed + detach';
    const alive = await win.evaluate(() => window.fermion.evaluate('Process.id'));
    if (!alive.ok || alive.text !== String(target.pid)) throw new Error('target no longer answers: ' + JSON.stringify(alive));
    await win.click('[data-testid="detach"]');
    await win.waitForFunction(() => /Attach to a process/.test(document.querySelector('[data-testid="inspector-panel"]').textContent), undefined, T);

    console.log('INSPECT_OK modules + exports/imports + hex view + paging + unreadable address + text scan (' + status.trim() + ') + threads/registers/backtrace + follow');
    await app.close();
    done(0);
  } catch (e) {
    console.log('INSPECT_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app) await app.close(); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
