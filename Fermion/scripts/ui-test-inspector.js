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

      // ---- working with the result: filter, group by module ----
      const groupsNow = () => win.evaluate(() => [...document.querySelectorAll('[data-testid="follow-group"]')].map((g) => {
        const m = /([\d,]+) calls? · ([\d,]+) functions?/.exec(g.querySelector('.gt').textContent);
        return { name: g.querySelector('.gn').textContent, calls: Number(m[1].replace(/,/g, '')), functions: Number(m[2].replace(/,/g, '')) };
      }));
      const followOnce = async () => {
        await win.click('[data-testid="thr-follow"]');
        await win.waitForFunction(() => /Stop/.test(document.querySelector('[data-testid="thr-follow"]').textContent), undefined, T);
        await new Promise((r) => setTimeout(r, 1800));
        await win.click('[data-testid="thr-follow"]');
        await win.waitForSelector('[data-testid="follow-row"]', T);
        const status = await win.evaluate(() => document.querySelector('[data-testid="thr-follow-status"]').textContent);
        await win.click('[data-testid="follow-bymodule"]');
        await win.waitForSelector('[data-testid="follow-group"]', T);
        return { status, groups: await groupsNow() };
      };
      await win.fill('[data-testid="follow-filter"]', 'ntdll');
      const filtered = await win.evaluate(() => ({
        rows: [...document.querySelectorAll('[data-testid="follow-row"] .fsym')].map((b) => b.textContent),
        shown: document.querySelector('[data-testid="follow-shown"]').textContent,
      }));
      if (!filtered.rows.length || filtered.rows.length >= fol.rows || !filtered.rows.every((t) => /ntdll/i.test(t))) throw new Error('filter: ' + JSON.stringify(filtered).slice(0, 300));
      if (!/^\d+ of \d+$/.test(filtered.shown)) throw new Error('filter count: ' + filtered.shown);
      await win.fill('[data-testid="follow-filter"]', '');
      await win.click('[data-testid="follow-bymodule"]');
      await win.waitForSelector('[data-testid="follow-group"]', T);
      const everything = await groupsNow();
      const sum = everything.reduce((n, g) => n + g.calls, 0);
      const stated = Number(/([\d,]+) calls to/.exec(fol.status)[1].replace(/,/g, ''));
      if (everything.length < 3 || sum !== stated) throw new Error('module totals ' + sum + ' do not add up to ' + stated + ': ' + JSON.stringify(everything).slice(0, 300));
      for (let i = 1; i < everything.length; i++) if (everything[i].calls > everything[i - 1].calls) throw new Error('groups are not ordered by calls');
      if (await win.evaluate(() => document.querySelectorAll('[data-testid="follow-row"]').length) !== 0) throw new Error('groups should start closed');
      await win.click('[data-testid="follow-group"]');
      await win.waitForSelector('[data-testid="follow-row"]', T);
      await snap('follow-by-module');
      const ntdllAll = everything.find((g) => /^ntdll/i.test(g.name));
      if (!ntdllAll) throw new Error('no ntdll group in a follow of everything');

      // ---- limiting the follow to one module ----
      step = 'follow one module only';
      await win.selectOption('[data-testid="thr-follow-scope"]', 'module');
      await win.waitForSelector('[data-testid="thr-follow-module"]', T);
      if (!(await win.evaluate(() => document.querySelector('[data-testid="thr-follow"]').disabled))) throw new Error('Follow should wait for a module name');
      await win.waitForFunction(() => document.querySelectorAll('#thr-follow-modules option').length > 5, undefined, T);
      await win.fill('[data-testid="thr-follow-module"]', 'no-such-module.dll');
      await win.click('[data-testid="thr-follow"]');
      await win.waitForFunction(() => /Module not found: no-such-module\.dll/.test(document.querySelector('[data-testid="thr-detail"]').textContent), undefined, T);
      const exeName = require('path').basename(process.execPath);
      await win.fill('[data-testid="thr-follow-module"]', exeName);
      const only = await followOnce();
      if (!only.status.includes('only ' + exeName + ' followed')) throw new Error('scoped status: ' + only.status);
      const ntdllOnly = only.groups.find((g) => /^ntdll/i.test(g.name)) || { functions: 0, calls: 0 };
      // Stalker stayed out of ntdll: only the functions the program calls
      // directly are seen, not everything ntdll calls inside itself.
      if (ntdllOnly.functions >= ntdllAll.functions) throw new Error('ntdll was still followed: ' + JSON.stringify({ ntdllOnly, ntdllAll }));
      await snap('follow-one-module');

      // ---- and back to everything: the exclusions are really gone ----
      step = 'follow everything again';
      await win.selectOption('[data-testid="thr-follow-scope"]', 'all');
      const back = await followOnce();
      if (/followed/.test(back.status.replace(/^Following/, ''))) throw new Error('status still names a scope: ' + back.status);
      const ntdllBack = back.groups.find((g) => /^ntdll/i.test(g.name)) || { functions: 0 };
      if (ntdllBack.functions <= ntdllOnly.functions) throw new Error('the earlier exclusions still apply: ' + JSON.stringify({ ntdllBack, ntdllOnly, ntdllAll }));
      console.log('FOLLOW_SCOPE ntdll functions: everything ' + ntdllAll.functions + ', one module ' + ntdllOnly.functions + ', everything again ' + ntdllBack.functions);
      // The other views still work on the fresh agent.
      await win.click('[data-testid="thr-refresh"]');
      await win.waitForFunction(() => /\d+ threads/.test(document.querySelector('[data-testid="thr-count"]').textContent), undefined, T);

      step = 'follow a thread';
      await win.click('[data-testid="thr-follow-dismiss"]');
      await win.waitForSelector('[data-testid="bt-row"]', T);
    }

    step = 'register -> memory';
    await win.click('[data-testid="reg-sp"]');
    await win.waitForFunction(() => document.querySelector('[data-testid="insp-memory"]').getAttribute('aria-selected') === 'true'
      && document.querySelectorAll('[data-testid="hex-row"]').length > 0, undefined, T);

    step = 'address menu -> disassembly';
    {
      const rowAddresses = () => win.evaluate(() => [...document.querySelectorAll('[data-testid="code-row"] .ca')].map((e) => e.textContent));
      await win.click('[data-testid="insp-threads"]');
      const pc = await win.evaluate(() => document.querySelector('[data-testid="reg-pc"]').textContent);
      await win.click('[data-testid="reg-pc"]', { button: 'right' });
      await win.waitForSelector('[data-testid="addr-menu"]', T);
      const items = await win.evaluate(() => [...document.querySelectorAll('[data-testid="addr-menu"] [role="menuitem"]')].map((b) => b.textContent));
      if (items.join('|') !== 'Copy address|Open in Memory|Open in Disassembly|Hook this address|Bookmark') throw new Error('menu items: ' + items.join('|'));
      await win.click('[data-testid="addr-menu-code"]');
      await win.waitForFunction(() => document.querySelector('[data-testid="insp-code"]').getAttribute('aria-selected') === 'true'
        && document.querySelectorAll('[data-testid="code-row"]').length >= 10, undefined, T);
      if (await win.evaluate(() => !!document.querySelector('[data-testid="addr-menu"]'))) throw new Error('the menu stayed open');
      const atPc = await rowAddresses();
      if (atPc[0] !== pc) throw new Error('disassembly starts at ' + atPc[0] + ', not at pc ' + pc);
      const texts = await win.evaluate(() => [...document.querySelectorAll('[data-testid="code-row"] .ct')].map((e) => e.textContent));
      if (!texts.every((t) => /^[a-z]/.test(t))) throw new Error('instructions look wrong: ' + JSON.stringify(texts.slice(0, 5)));
      for (let i = 1; i < atPc.length; i++) if (BigInt(atPc[i]) <= BigInt(atPc[i - 1])) throw new Error('addresses do not increase at row ' + i);

      step = 'disassembly: more';
      const before = atPc.length;
      if (await win.evaluate(() => !!document.querySelector('[data-testid="code-more"]'))) {
        await win.click('[data-testid="code-more"]');
        await win.waitForFunction((n) => document.querySelectorAll('[data-testid="code-row"]').length > n
          || !!document.querySelector('[data-testid="code-stopped"]'), before, T);
      }

      step = 'disassembly: a function, follow a call, back';
      const fn = await win.evaluate(async () => {
        const r = await window.fermion.hooks.search('symbols', 'uv_fs_stat');
        return (r.items || []).find((i) => /!uv_fs_stat$/.test(i.name)) || null;
      });
      let followed = 'no function with debug symbols to follow on this platform';
      if (fn) {
        await win.fill('[data-testid="code-addr"]', fn.address);
        await win.press('[data-testid="code-addr"]', 'Enter');
        await win.waitForFunction((a) => document.querySelector('[data-testid="code-row"] .ca')?.textContent === a, fn.address, T);
        const where = await win.evaluate(() => document.querySelector('[data-testid="code-where"]').textContent);
        if (!/uv_fs_stat/.test(where) || !/r-x/.test(where)) throw new Error('header: ' + where);
        for (let i = 0; i < 4 && !(await win.evaluate(() => !!document.querySelector('[data-testid="code-target"]'))); i++) {
          if (!(await win.evaluate(() => !!document.querySelector('[data-testid="code-more"]')))) break;
          const n = (await rowAddresses()).length;
          await win.click('[data-testid="code-more"]');
          await win.waitForFunction((k) => document.querySelectorAll('[data-testid="code-row"]').length > k || !!document.querySelector('[data-testid="code-stopped"]'), n, T);
        }
        const target = await win.evaluate(() => {
          const b = document.querySelector('[data-testid="code-target"]');
          return b ? { title: b.getAttribute('title'), name: b.textContent } : null;
        });
        if (!target) throw new Error('no direct call or jump found in uv_fs_stat');
        const to = /Go to (0x[0-9a-f]+)/.exec(target.title)[1];
        await win.click('[data-testid="code-target"]');
        await win.waitForFunction((a) => document.querySelector('[data-testid="code-row"] .ca')?.textContent === a, to, T);
        await snap('disassembly');
        await win.click('[data-testid="code-back"]');
        await win.waitForFunction((a) => document.querySelector('[data-testid="code-row"] .ca')?.textContent === a, fn.address, T);
        followed = 'followed ' + target.name;

        step = 'address menu -> hook';
        await win.click('[data-testid="code-row"] .ca', { button: 'right' });
        await win.waitForSelector('[data-testid="addr-menu"]', T);
        await win.click('[data-testid="addr-menu-hook"]');
        await win.waitForFunction(() => document.querySelector('[role="tab"][aria-selected="true"]')?.textContent.includes('Hooks')
          && document.querySelector('[data-testid="hook-status"]')?.textContent === 'hooked', undefined, T);
        const hookName = await win.evaluate(() => document.querySelector('[data-testid^="hook-row-"] .nm').textContent);
        if (!/!uv_fs_stat$/.test(hookName)) throw new Error('hooked ' + hookName);
        await win.waitForFunction(() => Number(document.querySelector('[data-testid="hook-calls"]').textContent.replace(/,/g, '')) > 0, undefined, T);
        await win.click('[data-testid="hook-remove"]');
        await win.waitForSelector('[data-testid="hook-empty"]', T);
        await win.click('role=tab[name="Inspector"]');
      }

      step = 'unreadable address in disassembly';
      await win.click('[data-testid="insp-code"]');
      await win.fill('[data-testid="code-addr"]', '0x10');
      await win.click('[data-testid="code-go"]');
      await win.waitForFunction(() => /not in readable memory/.test(document.querySelector('[data-testid="code-error"]')?.textContent ?? ''), undefined, T);
      console.log('DISASM ' + before + ' instructions at pc; ' + followed);
    }

    // ---- writing memory ----
    {
      const evalIn = async (code) => {
        const r = await win.evaluate((c) => window.fermion.evaluate(c), code);
        if (!r || !r.ok) throw new Error('evaluate failed: ' + JSON.stringify(r).slice(0, 200));
        // A string result is printed quoted, as the REPL shows it.
        try { return r.text.startsWith('"') ? JSON.parse(r.text) : r.text; } catch (_) { return r.text; }
      };
      const firstBytes = () => win.evaluate(() => [...document.querySelectorAll('[data-testid="hex-row"]')][0].querySelector('.hb').textContent.slice(0, 8));
      const gotoAddress = async (addr) => {
        await win.fill('[data-testid="mem-addr"]', addr);
        await win.click('[data-testid="mem-go"]');
        try {
          await win.waitForFunction((a) => document.querySelector('[data-testid="hex-row"] .ha')?.textContent === a, addr, T);
        } catch (_) {
          throw new Error('the hex view did not show ' + addr + ': ' + JSON.stringify(await win.evaluate(() => ({
            first: document.querySelector('[data-testid="hex-row"] .ha')?.textContent ?? null,
            error: document.querySelector('[data-testid="hex-error"]')?.textContent ?? null,
            input: document.querySelector('[data-testid="mem-addr"]')?.value ?? null,
          }))));
        }
      };
      const writeAt = async (index, text, as) => {
        await win.locator('[data-testid="hex-byte"]').nth(index).click();
        if (as) await win.selectOption('[data-testid="mem-edit-as"]', as);
        await win.fill('[data-testid="mem-edit-input"]', text);
        await win.click('[data-testid="mem-write"]');
      };

      step = 'memory: nothing writes until Edit is on';
      // A buffer from the target's own malloc (Frida hides memory it allocates itself): 0x100-aligned, so it is the top of a page of the view.
      const buf = await evalIn('const malloc = new NativeFunction(Module.getGlobalExportByName("malloc"), "pointer", ["size_t"]); globalThis.__fermionBuf = malloc(0x300); const p = globalThis.__fermionBuf.add(0x100).and(ptr(0xff).not()); globalThis.__fermionAt = p; p.writeByteArray([1,2,3,4,5,6,7,8]); p.toString()');
      if (!/^0x[0-9a-f]+00$/.test(buf)) throw new Error('test buffer address: ' + buf);
      const bufBefore = await evalIn('Array.from(new Uint8Array(globalThis.__fermionAt.readByteArray(10))).join(",")');
      await win.click('role=tab[name="Inspector"]');
      await win.click('[data-testid="insp-memory"]');
      await gotoAddress(buf);
      if ((await firstBytes()) !== '01020304') throw new Error('the buffer is not in the view: ' + await firstBytes());
      if (await win.$('[data-testid="hex-byte"]')) throw new Error('bytes can be picked while Edit is off');

      step = 'memory: write bytes, see them, and the target sees them';
      await win.click('[data-testid="mem-edit"]');
      await writeAt(1, 'de ad be');
      await win.waitForFunction(() => [...document.querySelectorAll('[data-testid="hex-row"]')][0].querySelector('.hb').textContent.startsWith('01deadbe05'), undefined, T);
      if ((await evalIn('Array.from(new Uint8Array(globalThis.__fermionAt.readByteArray(6))).join(",")')) !== '1,222,173,190,5,6') throw new Error('the target does not hold the written bytes');
      if (!/Wrote 3 bytes at 0x[0-9a-f]+01: de ad be \(was 02 03 04\)/.test(await win.evaluate(() => window.__fermion.terminal.getText()))) throw new Error('the write was not announced with what it replaced');

      step = 'memory: text is written as its bytes';
      await writeAt(8, 'Hi', 'text');
      await win.waitForFunction(() => [...document.querySelectorAll('[data-testid="hex-row"] .hc')].some((e) => e.textContent.includes('Hi')), undefined, T);
      if ((await evalIn('Array.from(new Uint8Array(globalThis.__fermionAt.add(8).readByteArray(2))).join(",")')) !== '72,105') throw new Error('the text was not written as its bytes');
      await win.selectOption('[data-testid="mem-edit-as"]', 'hex');

      await win.locator('[data-testid="hex-byte"]').nth(1).click();
      await win.fill('[data-testid="mem-edit-input"]', '90 90');
      if (shot) await win.screenshot({ path: shot + '-memory-edit.png' });
      await win.click('[data-testid="mem-edit-cancel"]');

      step = 'memory: revert, newest first';
      await win.click('[data-testid="mem-mode-writes"]');
      await win.waitForFunction(() => document.querySelectorAll('[data-testid="write-row"]').length === 2, undefined, T);
      await win.locator('[data-testid="write-revert"]').nth(1).click();
      await win.waitForFunction(() => document.querySelectorAll('[data-testid="write-row"]').length === 1, undefined, T);
      await win.locator('[data-testid="write-revert"]').first().click();
      await win.waitForFunction(() => document.querySelectorAll('[data-testid="write-row"]').length === 0, undefined, T);
      const afterRevert = await evalIn('Array.from(new Uint8Array(globalThis.__fermionAt.readByteArray(10))).join(",")');
      if (afterRevert !== bufBefore) throw new Error('revert did not restore the buffer: ' + afterRevert + ' (was ' + bufBefore + ')');

      step = 'memory: code can be patched and put back';
      // A function nobody calls here: overwrite its first byte, check, revert.
      const fnInfo = JSON.parse(await evalIn('const f = Process.getModuleByName(Process.platform === "windows" ? "kernel32.dll" : Process.mainModule.name).enumerateExports().filter((e) => e.type === "function" && /^(Beep|GetTapeStatus|SetTapePosition)$/.test(e.name))[0] || null; JSON.stringify(f ? { address: f.address.toString(), first: f.address.readU8() } : null)'));
      if (fnInfo) {
        await win.click('[data-testid="mem-mode-ranges"]');
        const page = '0x' + (BigInt(fnInfo.address) & ~0xffn).toString(16);
        const index = Number(BigInt(fnInfo.address) & 0xffn);
        await gotoAddress(page);
        await writeAt(index, 'cc');
        await win.waitForFunction(() => /Wrote 1 byte at /.test(window.__fermion.terminal.getText().split('\n').filter((l) => l.includes('Wrote')).pop() || ''), undefined, T);
        if ((await evalIn('ptr("' + fnInfo.address + '").readU8()')) !== '204') throw new Error('the code byte was not patched');
        await win.click('[data-testid="mem-mode-writes"]');
        await win.click('[data-testid="write-revert"]');
        await win.waitForFunction(() => document.querySelectorAll('[data-testid="write-row"]').length === 0, undefined, T);
        if ((await evalIn('ptr("' + fnInfo.address + '").readU8()')) !== String(fnInfo.first)) throw new Error('the code byte was not restored');
      }

      step = 'memory: Edit off again';
      await win.click('[data-testid="mem-edit"]');
      if (await win.$('[data-testid="mem-editbar"]')) throw new Error('the write bar stayed after Edit was switched off');
    }

    step = 'target unharmed + detach';
    const alive = await win.evaluate(() => window.fermion.evaluate('Process.id'));
    if (!alive.ok || alive.text !== String(target.pid)) throw new Error('target no longer answers: ' + JSON.stringify(alive));
    await win.click('[data-testid="detach"]');
    await win.waitForFunction(() => /Attach to a process/.test(document.querySelector('[data-testid="inspector-panel"]').textContent), undefined, T);

    console.log('INSPECT_OK modules + exports/imports + hex view + paging + memory write and revert (data, text, code) + unreadable address + text scan (' + status.trim() + ') + threads/registers/backtrace + follow (scope, filter, by module) + address menu + disassembly');
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
