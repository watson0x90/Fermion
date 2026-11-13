// Playwright-Electron END-TO-END test: the Windows API monitor presets. Adds
// each preset to a real process, makes real API calls in it with known
// arguments, and checks that the hooks decode them as the presets claim.
// Windows only: the presets are for Windows targets.
//   node Fermion/scripts/ui-test-presets.js [screenshot-prefix]
// Exit 0 + PRESETS_OK / PRESETS_SKIP (not Windows, or cannot attach) ; 1 + PRESETS_FAIL
const { _electron: electron } = require('playwright-core');
const electronPath = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const APP_DIR = path.join(__dirname, '..');
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-presets-'));
const shot = process.argv[2];
const T = { timeout: 30000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

if (process.platform !== 'win32') {
  console.log('PRESETS_SKIP the presets hook Windows APIs; this is ' + process.platform);
  process.exit(0);
}

// Code run in the target (through the REPL) to make one real call per preset.
// `fn(module, name, ret, args)` gives a callable export.
const PRELUDE = String.raw`
  const fn = (m, n, r, a) => new NativeFunction(Process.getModuleByName(m).getExportByName(n), r, a);
  const w = (s) => Memory.allocUtf16String(s);
`;
const CALLS = {
  files: String.raw`
    const name = w('C:\\fermion-preset-test\\no-such-file.txt');
    fn('kernel32.dll', 'CreateFileW', 'pointer', ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'pointer'])(name, 0x80000000, 0, NULL, 3, 0, NULL).toString();`,
  registry: String.raw`
    const out = Memory.alloc(8);
    const sub = w('SOFTWARE\\Microsoft');
    fn('advapi32.dll', 'RegOpenKeyExW', 'int', ['pointer', 'pointer', 'uint32', 'uint32', 'pointer'])(ptr('0xffffffff80000002'), sub, 0, 0x20019, out);`,
  processes: String.raw`
    fn('kernel32.dll', 'OpenProcess', 'pointer', ['uint32', 'int', 'uint32'])(0x1000, 0, Process.id).toString();`,
  ioctls: String.raw`
    const dev = w('\\\\.\\C:');
    const h = fn('kernel32.dll', 'CreateFileW', 'pointer', ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'pointer'])(dev, 0, 3, NULL, 3, 0, NULL);
    const out = Memory.alloc(64); const got = Memory.alloc(8);
    fn('kernel32.dll', 'DeviceIoControl', 'int', ['pointer', 'uint32', 'pointer', 'uint32', 'pointer', 'uint32', 'pointer', 'pointer'])(h, 0x70000, NULL, 0, out, 64, got, NULL);`,
  pipes: String.raw`
    const pipe = w('\\\\.\\pipe\\fermion-preset-test');
    fn('kernel32.dll', 'CreateNamedPipeW', 'pointer', ['pointer', 'uint32', 'uint32', 'uint32', 'uint32', 'uint32', 'uint32', 'pointer'])(pipe, 3, 0, 1, 512, 512, 0, NULL).toString();`,
  network: String.raw`
    const s = fn('ws2_32.dll', 'socket', 'pointer', ['int', 'int', 'int'])(2, 1, 6);
    const sa = Memory.alloc(16); sa.writeByteArray([2, 0, 0, 9, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    fn('ws2_32.dll', 'connect', 'int', ['pointer', 'pointer', 'int'])(s, sa, 16);
    fn('ws2_32.dll', 'closesocket', 'int', ['pointer'])(s);`,
  rpc: String.raw`
    fn('advapi32.dll', 'OpenSCManagerW', 'pointer', ['pointer', 'pointer', 'uint32'])(NULL, NULL, 1).toString();`,
};
// What must then appear among the hook lines.
const EXPECT = {
  files: /CreateFileW\("C:\\fermion-preset-test\\no-such-file\.txt", GENERIC_READ, OPEN_EXISTING\) = INVALID_HANDLE_VALUE/,
  registry: /RegOpenKeyExW\(HKLM, "SOFTWARE\\Microsoft"\) = ok/,
  processes: /OpenProcess\(pid \d+, PROCESS_QUERY_LIMITED_INFORMATION\) = handle 0x[0-9a-f]+/,
  ioctls: /NtDeviceIoControlFile\(handle 0x[0-9a-f]+, code 0x70000 \[device 0x7, function 0x0, BUFFERED, ANY\], in 0 bytes, out 64 bytes\) = 0x[0-9a-f]+/,
  pipes: /CreateNamedPipeW\("\\\\\.\\pipe\\fermion-preset-test", duplex, instances 1, default security\) = handle 0x[0-9a-f]+/,
  network: /connect\(socket \d+, 127\.0\.0\.1:9\) = /,
  // svcctl, the Service Control Manager's RPC interface.
  rpc: /RPC call out: interface 367abb81-9844-35f1-ad32-98f038001003 v2\.0, procedure \d+/,
};
const LABEL = { files: 'Files', registry: 'Registry', processes: 'Processes and injection', ioctls: 'Driver requests (IOCTLs)', pipes: 'Named pipes', network: 'Network', rpc: 'RPC' };

(async () => {
  let app; let step = 'launch';
  const target = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  const done = (code) => { try { target.kill(); } catch (_) { /* gone */ } process.exitCode = code; setTimeout(() => process.exit(code), 200); };
  try {
    app = await electron.launch({ executablePath: electronPath, args: ['.', '--no-sandbox', '--user-data-dir=' + userDataDir], cwd: APP_DIR });
    const win = await app.firstWindow();
    await win.waitForSelector('.xterm', { timeout: 60000 });
    await win.waitForFunction(() => !!window.MonacoCodeEditor, undefined, { timeout: 60000 });
    const output = () => win.evaluate(() => window.__fermion.terminal.getText().replace(/\r?\n/g, ''));

    step = 'attach';
    await win.evaluate(() => window.MonacoCodeEditor.setValue('// presets test'));
    try {
      await win.evaluate((p) => window.__fermion.triggerAttach(p), target.pid);
    } catch (e) {
      console.log('PRESETS_SKIP could not attach: ' + String(e && e.message ? e.message : e).split('\n')[0].slice(0, 160));
      await app.close(); return done(0);
    }
    await win.click('role=tab[name="Hooks"]');

    const seen = [];
    for (const id of Object.keys(CALLS)) {
      step = 'preset ' + id + ': add';
      await win.selectOption('[data-testid="hook-preset"]', id);
      await win.waitForFunction((label) => (document.querySelector('[data-testid="hook-preset-note"]')?.textContent ?? '').startsWith(label + ': '), LABEL[id], T);
      const note = await win.textContent('[data-testid="hook-preset-note"]');
      if (!/\d+ hooks? added/.test(note)) throw new Error('nothing was added: ' + note);
      if (/could not be placed/.test(note)) throw new Error(note);

      step = 'preset ' + id + ': a real call is decoded';
      const r = await win.evaluate((c) => window.fermion.evaluate(c), '(function () {' + PRELUDE + CALLS[id] + '})()');
      if (!r || !r.ok) throw new Error('the call in the target failed: ' + JSON.stringify(r).slice(0, 300));
      const end = Date.now() + 15000;
      let text = '';
      while (Date.now() < end) { text = await output(); if (EXPECT[id].test(text)) break; await sleep(200); }
      if (!EXPECT[id].test(text)) {
        const lines = (await win.evaluate(() => window.__fermion.terminal.getText())).split('\n').filter((l) => l.includes('[hook]')).slice(-6).join(' || ');
        throw new Error('not decoded as expected. Preset note: ' + note + ' Last hook lines: ' + lines.slice(0, 900));
      }
      seen.push(id + ' (' + (/(\d+) hooks? added/.exec(note) || [])[1] + ')');
    }
    if (shot) await win.screenshot({ path: shot + '-presets.png' });

    step = 'adding a preset again adds nothing';
    const before = await win.evaluate(() => document.querySelectorAll('[data-testid^="hook-row-"]').length);
    await win.selectOption('[data-testid="hook-preset"]', 'files');
    await win.waitForFunction(() => /already there/.test(document.querySelector('[data-testid="hook-preset-note"]')?.textContent ?? ''), undefined, T);
    if ((await win.evaluate(() => document.querySelectorAll('[data-testid^="hook-row-"]').length)) !== before) throw new Error('the same preset added hooks twice');

    step = 'a preset handler is ordinary hook code';
    await win.click('[data-testid^="hook-row-"]');
    await win.click('[data-testid="hook-tab-handler"]');
    await win.waitForFunction(() => !!window.MonacoHookEditor && /CreateFileW/.test(window.MonacoHookEditor.getValue()), undefined, T);
    if ((await win.evaluate(() => window.monaco.editor.getModelMarkers({ resource: window.MonacoHookEditor.getModel().uri }).filter((m) => m.severity === 8).length)) !== 0) throw new Error('the preset handler shows syntax errors in the editor');

    step = 'target unharmed';
    if (!(await win.evaluate(() => window.fermion.evaluate('Process.id'))).ok) throw new Error('the target did not answer at the end');

    console.log('PRESETS_OK ' + seen.join(' + ') + ' decoded real calls + no duplicates on re-add + handler opens clean in the editor + target unharmed');
    await app.close();
    done(0);
  } catch (e) {
    console.log('PRESETS_FAIL [' + step + '] ' + (e && e.message ? e.message : e));
    try { if (app && shot) await (await app.firstWindow()).screenshot({ path: shot + '-fail.png' }); } catch (_) {}
    try { if (app) await Promise.race([app.close(), sleep(15000)]); } catch (_) {}
    done(1);
  } finally {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
  }
})();
