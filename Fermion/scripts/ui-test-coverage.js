// Playwright-Electron END-TO-END test: coverage export. Attaches to a real
// process, records which code runs, saves the drcov file and the text report
// through main's Save dialog, and checks both files against the process.
//   node Fermion/scripts/ui-test-coverage.js [screenshot-prefix]
// Exit 0 + COVERAGE_OK / COVERAGE_SKIP (cannot attach on this runner) ; 1 + COVERAGE_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-cov-'));
const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-cov-out-'));
const shot = process.argv[2];
const T = { timeout: 30000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// drcov: a text header, then 8 bytes per block (u32 offset, u16 size, u16 module id).
function parseDrcov(file) {
  const buf = fs.readFileSync(file);
  const m = /BB Table: (\d+) bbs\n/.exec(buf.toString('latin1'));
  if (!m) throw new Error('no BB table in ' + file);
  const headEnd = m.index + m[0].length;
  const head = buf.subarray(0, headEnd).toString('utf8').split('\n');
  const count = Number(/count (\d+)/.exec(head[2])[1]);
  const modules = head.slice(4, 4 + count).map((line) => {
    const p = line.split(', ');
    return { id: Number(p[0]), base: BigInt(p[1]), end: BigInt(p[2]), path: p.slice(6).join(', ') };
  });
  const table = buf.subarray(headEnd);
  const blocks = [];
  for (let i = 0; i + 8 <= table.length; i += 8) blocks.push({ off: table.readUInt32LE(i), size: table.readUInt16LE(i + 4), mod: table.readUInt16LE(i + 6) });
  return { head, modules, blocks, declared: Number(m[1]), tableBytes: table.length };
}

(async () => {
  let app; let step = 'launch';
  // Busy enough to keep running new code paths while we record.
  const target = spawn(process.execPath, ['-e', 'const fs=require("fs"),zlib=require("zlib"); let i=0; setInterval(() => { try { fs.statSync(process.execPath); zlib.gzipSync(Buffer.from("x".repeat(100 + (i++ % 50)))); JSON.parse(JSON.stringify({ a: [i] })); } catch (e) {} }, 60)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exitCode = code; setTimeout(() => process.exit(code), 200); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    // The Save dialog is shown by main: answer it from here, and note what it offered.
    await app.evaluate(({ dialog }) => {
      global.__cov = { answers: [], asked: [] };
      dialog.showSaveDialog = async (...a) => { const o = a[a.length - 1]; global.__cov.asked.push({ title: o.title, defaultPath: o.defaultPath }); return { filePath: global.__cov.answers.shift() }; };
    });
    const answer = (p) => app.evaluate((_e, v) => { global.__cov.answers.push(v); }, p);
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const output = () => win.evaluate(() => window.__fermion.terminal.getText());

    step = 'attach';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// coverage test'));
    try {
      await win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
    } catch (e) {
      console.log('COVERAGE_SKIP could not attach: ' + String(e && e.message ? e.message : e).split('\n')[0].slice(0, 160));
      await app.close(); return done(0);
    }

    step = 'record everything except system libraries, on all threads';
    await win.click('role=tab[name="Inspector"]');
    await win.click('[data-testid="insp-coverage"]');
    await win.waitForSelector('[data-testid="cover-empty"]', T);
    await win.click('[data-testid="cover-toggle"]');
    await win.waitForSelector('[data-testid="cover-status"]', T);
    if (!/Recording on \d+ threads?\./.test(await win.textContent('[data-testid="cover-status"]'))) throw new Error('status: ' + await win.textContent('[data-testid="cover-status"]'));
    await sleep(3000);
    if (shot) await win.screenshot({ path: shot + '-recording.png' });
    await win.click('[data-testid="cover-toggle"]');
    await win.waitForSelector('[data-testid="cover-line"]', T);
    const line = await win.textContent('[data-testid="cover-line"]');
    const shown = Number((/^([\d,]+) basic blocks/.exec(line) || [])[1]?.replace(/,/g, ''));
    if (!(shown > 50)) throw new Error('too few blocks recorded: ' + line);
    const rows = await win.evaluate(() => [...document.querySelectorAll('[data-testid="cover-row"]')].map((r) => ({ name: r.children[0].textContent, blocks: Number(r.children[1].textContent.replace(/,/g, '')), path: r.children[3].textContent })));
    const exe = path.basename(process.execPath).toLowerCase();
    if (!rows.some((r) => r.name.toLowerCase() === exe)) throw new Error('the program itself is not among the modules: ' + rows.map((r) => r.name).join(','));
    if (process.platform === 'win32' && rows.some((r) => /^[a-z]:\\windows\\/i.test(r.path))) throw new Error('a system library was recorded despite the scope: ' + JSON.stringify(rows.find((r) => /windows/i.test(r.path))));
    if (shot) await win.screenshot({ path: shot + '-result.png' });

    step = 'the target is still running';
    if (!(await win.evaluate(() => window.fermion.evaluate('Process.id'))).ok) throw new Error('the target did not answer after recording');

    step = 'save drcov';
    const drcovFile = path.join(outDir, 'out.drcov');
    await answer(undefined); // first, cancel: nothing is written
    await win.click('[data-testid="cover-save-drcov"]');
    await sleep(500);
    if (fs.existsSync(drcovFile) || await win.$('[data-testid="cover-saved"]')) throw new Error('a cancelled save wrote something');
    await answer(drcovFile);
    await win.click('[data-testid="cover-save-drcov"]');
    await win.waitForFunction(() => /out\.drcov/.test(document.querySelector('[data-testid="cover-saved"]')?.textContent ?? ''), undefined, T);
    const asked = await app.evaluate(() => global.__cov.asked);
    if (!/^[A-Za-z0-9._-]+-coverage\.drcov$/.test(asked[1].defaultPath)) throw new Error('suggested name: ' + asked[1].defaultPath);
    const cov = parseDrcov(drcovFile);
    if (cov.head[0] !== 'DRCOV VERSION: 2' || !/^DRCOV FLAVOR: /.test(cov.head[1])) throw new Error('drcov header: ' + cov.head.slice(0, 2).join(' | '));
    if (cov.declared !== cov.blocks.length || cov.tableBytes !== cov.declared * 8) throw new Error('BB table: declared ' + cov.declared + ', ' + cov.tableBytes + ' bytes');
    if (cov.declared !== shown) throw new Error('the file has ' + cov.declared + ' blocks, the view says ' + shown);
    for (const b of cov.blocks) {
      const m = cov.modules[b.mod];
      if (!m) throw new Error('a block names module ' + b.mod + ' of ' + cov.modules.length);
      if (b.size < 1 || BigInt(b.off) + BigInt(b.size) > m.end - m.base) throw new Error('a block lies outside its module: ' + JSON.stringify(b));
    }
    // The module table matches the process: same base for the program's own module.
    const real = JSON.parse((await win.evaluate(() => window.fermion.evaluate('JSON.stringify(Process.enumerateModules().map((m) => ({ name: m.name, base: m.base.toString(), size: m.size })))'))).text.replace(/^"|"$/g, '').replace(/\\"/g, '"'));
    const mine = real.find((m) => m.name.toLowerCase() === exe);
    const inFile = cov.modules.find((m) => path.basename(m.path.replace(/\\/g, '/')).toLowerCase() === exe);
    if (!inFile || inFile.base !== BigInt(mine.base) || inFile.end !== BigInt(mine.base) + BigInt(mine.size)) throw new Error('module table does not match the process: ' + JSON.stringify(inFile, (k, v) => (typeof v === 'bigint' ? '0x' + v.toString(16) : v)) + ' vs ' + JSON.stringify(mine));
    // A block the file lists really is code: it disassembles in the target.
    const probe = cov.blocks.find((b) => cov.modules[b.mod] === inFile);
    const at = '0x' + (inFile.base + BigInt(probe.off)).toString(16);
    const insn = await win.evaluate((a) => window.fermion.inspect.disassemble(a, 1), at);
    if (!insn.items.length) throw new Error('a recorded block does not disassemble: ' + at);

    step = 'save the text report';
    const textFile = path.join(outDir, 'out.md');
    await answer(textFile);
    await win.click('[data-testid="cover-save-text"]');
    await win.waitForFunction(() => /out\.md/.test(document.querySelector('[data-testid="cover-saved"]')?.textContent ?? ''), undefined, T);
    const text = fs.readFileSync(textFile, 'utf8');
    for (const must of ['# Code coverage recorded by Fermion (Frida)', 'scope: everything except system libraries', 'How to read this:', '## Modules, most blocks first', '## Functions that ran, by module']) {
      if (!text.includes(must)) throw new Error('the report lacks "' + must + '"');
    }
    if (!new RegExp('Total: ' + shown.toLocaleString('en-US') + ' basic blocks').test(text)) throw new Error('the report total does not match: ' + (/Total: .*/.exec(text) || [''])[0]);
    const fnLines = text.split('\n').filter((l) => /^- \S.* \+0x[0-9a-f]+: \d+ blocks?, \d+ bytes$/.test(l));
    if (fnLines.length < 5) throw new Error('the report names too few functions (' + fnLines.length + ')');
    if (text.length > 600000) throw new Error('the report is too long to hand to a model: ' + text.length + ' characters');
    if (!/Coverage file \(drcov\) saved: /.test(await output()) || !/Coverage report saved: /.test(await output())) throw new Error('the saves were not announced');

    step = 'one module only';
    await win.selectOption('[data-testid="cover-scope"]', 'module');
    await win.fill('[data-testid="cover-module"]', path.basename(process.execPath));
    await win.click('[data-testid="cover-toggle"]');
    await win.waitForSelector('[data-testid="cover-status"]', T);
    await sleep(1500);
    await win.click('[data-testid="cover-toggle"]');
    await win.waitForSelector('[data-testid="cover-line"]', T);
    const only = await win.evaluate(() => [...document.querySelectorAll('[data-testid="cover-row"]')].map((r) => r.children[0].textContent.toLowerCase()));
    if (only.length !== 1 || only[0] !== exe) throw new Error('one-module scope recorded: ' + only.join(','));

    step = 'target unharmed';
    if (!(await win.evaluate(() => window.fermion.evaluate('Process.id'))).ok) throw new Error('the target did not answer at the end');
    try { process.kill(target.pid, 0); } catch (_) { throw new Error('the target died'); }

    console.log('COVERAGE_OK recorded ' + shown + ' blocks in ' + rows.length + ' modules (system libraries left out) + drcov file valid and matches the process (' + cov.modules.length + ' modules) + text report names ' + fnLines.length + ' functions (' + Math.round(text.length / 1024) + ' KB) + cancel writes nothing + one-module scope + target unharmed');
    await app.close();
    done(0);
  } catch (e) {
    console.log('COVERAGE_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await Promise.race([app.close(), sleep(15000)]); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
    if (process.env.FERMION_KEEP_OUT) console.log('kept ' + outDir); else { try { fs.rmSync(outDir, { recursive: true, force: true }); } catch (_) {} }
  }
})();
