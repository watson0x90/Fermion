// Unit tests for the main-owned npm packages module, with fakes for Frida's
// package manager and compiler and for the npm process.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { createPackages, createPackageHandlers, createScriptPreparer, parseSpec, needsCompile, formatDiagnostics } = require('./packages.js');

function setup(over = {}) {
  const dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-pkgs-')), 'packages');
  const log = [];
  // What an installer does: put the package in node_modules.
  const place = (name, version = '1.2.3', description = 'a package') => {
    const d = path.join(dir, 'node_modules', ...name.split('/'));
    fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name, version, description }));
  };
  const frida = {
    PackageManager: class {
      async search(q, opts) { log.push(['search', q, opts]); return over.searchResult || { packages: [{ name: 'frida-fs', version: '8.1.1', description: 'fs', url: 'u' }], total: 1 }; }
      async install(opts) {
        log.push(['frida-install', opts.specs, opts.projectRoot]);
        if (over.fridaInstall === 'ok') { place(opts.specs[0].split('@')[0] || opts.specs[0]); return { packages: [] }; }
        throw new Error('Error opening file node_modules/x/package.json: No such file or directory');
      }
    },
    Compiler: class {
      constructor() { this.handlers = new Set(); this.diagnostics = { connect: (cb) => this.handlers.add(cb), disconnect: (cb) => this.handlers.delete(cb) }; }
      async build(entry, opts) {
        log.push(['build', path.basename(entry), opts, fs.readFileSync(entry, 'utf8')]);
        if (over.diagnostics) { for (const cb of this.handlers) cb(over.diagnostics); throw new Error('Compilation failed'); }
        return 'BUNDLE(' + fs.readFileSync(entry, 'utf8') + ')';
      }
    },
  };
  const spawn = (...a) => {
    log.push(['spawn', ...a.map((x) => (x && typeof x === 'object' && !Array.isArray(x) ? { cwd: x.cwd, shell: x.shell } : x))]);
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => {};
    setImmediate(() => {
      if (over.npm === 'missing') { child.emit('error', Object.assign(new Error('spawn npm ENOENT'), { code: 'ENOENT' })); return; }
      if (over.npm === 'fail') { child.stderr.emit('data', 'npm error code E404\nnpm error 404 Not Found - no-such-pkg'); child.emit('close', 1); return; }
      const spec = typeof a[1] === 'object' && !Array.isArray(a[1]) ? a[0].split(' ').pop() : a[1][a[1].length - 1];
      place(spec.lastIndexOf('@') > 0 ? spec.slice(0, spec.lastIndexOf('@')) : spec);
      child.emit('close', 0);
    });
    return child;
  };
  const pkgs = createPackages({ dir, getFrida: () => frida, spawn, platform: over.platform || 'linux' });
  return { pkgs, dir, log, place };
}

test('parseSpec: npm names, scoped names and exact versions; nothing that could carry a command', () => {
  assert.deepEqual(parseSpec('frida-fs'), { name: 'frida-fs', version: '', spec: 'frida-fs' });
  assert.deepEqual(parseSpec('  @frida/tools@1.2.3-beta.1 '), { name: '@frida/tools', version: '1.2.3-beta.1', spec: '@frida/tools@1.2.3-beta.1' });
  assert.deepEqual(parseSpec('is-number@latest').version, 'latest');
  for (const bad of ['', ' ', 'Frida-FS', 'a b', 'a;rm -rf /', 'a&&calc', 'a|b', '../x', 'a/../b', './local', 'file:../x', 'git+https://x/y', 'https://x/y.tgz', 'a@^1.0.0', 'a@1 || 2', 'a@$(x)', '@scope', '@/x', 'a`b`', 'a"b', "a'b", 'x'.repeat(300), 5, null]) {
    assert.throws(() => parseSpec(bad), /valid|must be a string/, String(bad).slice(0, 30));
  }
});

test('needsCompile: only scripts that import or export are compiled', () => {
  for (const src of ['import fs from "frida-fs";', "  import { a, b as c } from 'x';", 'import * as os from "os"\nsend(1)', 'import "side-effect";', 'send(1);\nexport function f() {}', 'export default {};', 'const a = 1;\nimport ObjC from "frida-objc-bridge";']) {
    assert.equal(needsCompile(src), true, src);
  }
  for (const src of ['', 'send(1);', 'Interceptor.attach(ptr(1), {});', 'const s = "import x from \'y\'";', '// import x from "y" would need a package', 'const important = 1;', 'var exported = 2;', 'const m = await import_thing();', undefined]) {
    assert.equal(needsCompile(src), false, String(src));
  }
});

test('search asks the registry through Frida and returns only installable names, bounded', async () => {
  const t = setup({ searchResult: { total: 99, packages: [
    { name: 'frida-fs', version: '8.1.1', description: 'd'.repeat(900) }, { name: 'Bad Name', version: '1' }, { name: '../evil', version: '1' }, { name: '@frida/x', version: '2.0.0', description: null },
  ] } });
  const r = await t.pkgs.search('  frida  ');
  assert.deepEqual(t.log, [['search', 'frida', { limit: 30 }]]);
  assert.equal(r.total, 99);
  assert.deepEqual(r.items.map((i) => i.name), ['frida-fs', '@frida/x']);
  assert.equal(r.items[0].description.length, 300);
  await assert.rejects(() => t.pkgs.search(''), /empty/);
  await assert.rejects(() => t.pkgs.search('x'.repeat(200)), /too long/);
  await assert.rejects(() => t.pkgs.search(7), /empty/);
});

test("install: Frida's installer is tried first, in Fermion's own folder", async () => {
  const t = setup({ fridaInstall: 'ok' });
  const r = await t.pkgs.install('frida-fs');
  assert.deepEqual(r, { name: 'frida-fs', version: '1.2.3', description: 'a package', via: 'frida' });
  assert.deepEqual(t.log, [['frida-install', ['frida-fs'], t.dir]]);
  // The folder is a small npm project, and the package is recorded as asked for.
  const manifest = JSON.parse(fs.readFileSync(path.join(t.dir, 'package.json'), 'utf8'));
  assert.equal(manifest.private, true);
  assert.equal(manifest.type, 'module');
  assert.deepEqual(manifest.dependencies, { 'frida-fs': '1.2.3' });
});

test('install: when Frida cannot, npm is run with install scripts off and no shell', async () => {
  const t = setup();
  const r = await t.pkgs.install('@frida/tools@2.0.0');
  assert.equal(r.via, 'npm');
  assert.equal(r.name, '@frida/tools');
  assert.deepEqual(t.log[1], ['spawn', 'npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--no-progress', '--save', '@frida/tools@2.0.0'], { cwd: t.dir, shell: false }]);
});

test('install on Windows: npm is a .cmd, so it goes through the shell as one fixed command line', async () => {
  const t = setup({ platform: 'win32' });
  await t.pkgs.install('frida-fs');
  assert.deepEqual(t.log[1], ['spawn', 'npm install --ignore-scripts --no-audit --no-fund --no-progress --save frida-fs', { cwd: t.dir, shell: true }]);
});

test('install: a name that is not an npm name is refused before anything runs', async () => {
  const t = setup();
  for (const bad of ['a && calc', '../x', 'https://evil/x.tgz', 'a@^1']) await assert.rejects(() => t.pkgs.install(bad), /valid/);
  assert.deepEqual(t.log, []);
  assert.equal(fs.existsSync(t.dir), false);
});

test('install: failures say what happened, including when there is no npm', async () => {
  await assert.rejects(() => setup({ npm: 'missing' }).pkgs.install('frida-fs'), /Could not install frida-fs\. npm was not found on this machine\..*Frida's own installer said: Error opening file/);
  await assert.rejects(() => setup({ npm: 'fail' }).pkgs.install('no-such-pkg'), /npm failed \(exit 1\):.*404 Not Found/);
});

test('list shows the packages asked for, not what they pulled in; remove forgets and deletes one', async () => {
  const t = setup();
  await t.pkgs.install('zeta');
  await t.pkgs.install('alpha');
  t.place('transitive-dep');
  assert.deepEqual(t.pkgs.list().map((p) => p.name), ['alpha', 'zeta']);
  assert.equal(await t.pkgs.remove('alpha'), true);
  assert.deepEqual(t.pkgs.list().map((p) => p.name), ['zeta']);
  assert.equal(fs.existsSync(path.join(t.dir, 'node_modules', 'alpha')), false);
  await assert.rejects(() => t.pkgs.remove('alpha'), /alpha is not installed/);
  await assert.rejects(() => t.pkgs.remove('transitive-dep'), /not installed/); // not ours to remove
  await assert.rejects(() => t.pkgs.remove('../zeta'), /valid/);
  assert.equal(fs.existsSync(path.join(t.dir, 'node_modules', 'zeta')), true);
});

test('list: an empty or damaged folder is an empty list', () => {
  const t = setup();
  assert.deepEqual(t.pkgs.list(), []);
  fs.mkdirSync(t.dir, { recursive: true });
  fs.writeFileSync(path.join(t.dir, 'package.json'), '{ not json');
  assert.deepEqual(t.pkgs.list(), []);
  fs.writeFileSync(path.join(t.dir, 'package.json'), JSON.stringify({ dependencies: { '../x': '1', missing: '1' } }));
  assert.deepEqual(t.pkgs.list(), []);
});

test('installs run one at a time', async () => {
  const t = setup();
  await Promise.all([t.pkgs.install('one'), t.pkgs.install('two'), t.pkgs.install('three')]);
  const order = t.log.map((l) => l[0]);
  assert.deepEqual(order, ['frida-install', 'spawn', 'frida-install', 'spawn', 'frida-install', 'spawn']);
});

test("compile: the script is bundled with Frida's compiler from Fermion's folder, with source maps", async () => {
  const t = setup();
  const out = await t.pkgs.compile('import fs from "frida-fs";\nsend(1);');
  assert.equal(out, 'BUNDLE(import fs from "frida-fs";\nsend(1);)');
  const build = t.log.find((l) => l[0] === 'build');
  assert.equal(build[1], 'script.js');
  assert.deepEqual(build[2], { projectRoot: t.dir, typeCheck: 'none', sourceMaps: 'included' });
});

test('compile: errors come back with file, line and message, and name the package to install', async () => {
  const t = setup({ diagnostics: [
    { category: 'error', code: -1, file: { path: 'script.js', line: 0n, character: 14n }, text: 'Could not resolve "frida-objc-bridge"' },
    { category: 'error', code: -1, file: { path: 'script.js', line: 4, character: 6 }, text: 'Expected identifier but found "="' },
  ] });
  await assert.rejects(() => t.pkgs.compile('import ObjC from "frida-objc-bridge";'), (e) => {
    assert.equal(e.message, 'The script did not compile:\nscript.js:1:15: Could not resolve "frida-objc-bridge"\nscript.js:5:7: Expected identifier but found "="\nInstall frida-objc-bridge from Packages in the Editor toolbar.');
    return true;
  });
  await assert.rejects(() => t.pkgs.compile(5), /must be text/);
  await assert.rejects(() => t.pkgs.compile('x'.repeat(3 * 1024 * 1024)), /too long/);
});

test('formatDiagnostics tolerates odd shapes and caps the list', () => {
  assert.deepEqual(formatDiagnostics([null, 'x', [{ text: 'plain' }, { file: { path: 'a.js', line: 1, character: 2 } }]]), ['plain', 'a.js:2:3: error']);
  assert.equal(formatDiagnostics([Array.from({ length: 80 }, () => ({ text: 'e' }))]).length, 20);
});

test('handlers: an install is confirmed by the operator first; declining installs nothing', async () => {
  const t = setup();
  const asked = [];
  let answer = false;
  const h = createPackageHandlers({ packages: t.pkgs, confirm: async (spec) => { asked.push(spec); return answer; } });
  assert.deepEqual(await h.install('frida-fs'), { cancelled: true });
  assert.deepEqual(asked, ['frida-fs']);
  assert.deepEqual(t.log, []);
  answer = true;
  assert.equal((await h.install(' frida-fs@8.1.1 ')).name, 'frida-fs');
  assert.deepEqual(asked, ['frida-fs', 'frida-fs@8.1.1']); // asked about exactly what will be installed
});

test('handlers: a bad name is refused without asking the operator anything', async () => {
  const t = setup();
  const asked = [];
  const h = createPackageHandlers({ packages: t.pkgs, confirm: async (spec) => { asked.push(spec); return true; } });
  await assert.rejects(() => h.install('x && calc'), /valid/);
  assert.deepEqual(asked, []);
  assert.deepEqual(t.log, []);
});

test('preparer: a script that imports is compiled; any other script is left exactly as written', async () => {
  const t = setup();
  const prepare = createScriptPreparer(t.pkgs);
  assert.deepEqual(await prepare('send(1);'), { code: 'send(1);', compiled: false });
  assert.equal(t.log.length, 0);
  assert.deepEqual(await prepare('import a from "a";\nsend(a);'), { code: 'BUNDLE(import a from "a";\nsend(a);)', compiled: true });
});

// ---- TypeScript ----
test('compile: a TypeScript script is built as script.ts with its types checked', async () => {
  const t = setup();
  const out = await t.pkgs.compile('const n: number = 1;\nsend(n);', { typescript: true });
  assert.equal(out, 'BUNDLE(const n: number = 1;\nsend(n);)');
  const build = t.log.find((l) => l[0] === 'build');
  assert.equal(build[1], 'script.ts');
  assert.deepEqual(build[2], { projectRoot: t.dir, typeCheck: 'full', sourceMaps: 'included' });
});

test('compile: the entry of the other language is not left beside the one being built', async () => {
  const t = setup();
  await t.pkgs.compile('import a from "a";');
  assert.equal(fs.existsSync(path.join(t.dir, 'script.js')), true);
  await t.pkgs.compile('const n: number = 1;', { typescript: true });
  assert.equal(fs.existsSync(path.join(t.dir, 'script.js')), false);
  assert.equal(fs.existsSync(path.join(t.dir, 'script.ts')), true);
  await t.pkgs.compile('import a from "a";');
  assert.equal(fs.existsSync(path.join(t.dir, 'script.ts')), false);
});

test('preparer: a TypeScript script is always compiled, imports or not', async () => {
  const t = setup();
  const prepare = createScriptPreparer(t.pkgs);
  assert.deepEqual(await prepare('const n: number = 1;', { typescript: true }), { code: 'BUNDLE(const n: number = 1;)', compiled: true, typescript: true });
  assert.deepEqual(await prepare('send(1);', { typescript: false }), { code: 'send(1);', compiled: false });
  assert.deepEqual(await prepare('send(1);', undefined), { code: 'send(1);', compiled: false });
});
