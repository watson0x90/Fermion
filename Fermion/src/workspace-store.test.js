// Unit tests for the main-owned store of saved hooks and bookmarks.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createWorkspaceStore, cleanWorkspace } = require('./workspace-store.js');

const HOOK = { id: 'hk-1', name: 'kernel32.dll!CreateFileW', module: 'kernel32.dll', offset: 4096, address: '0x7FF010', code: '({ onEnter(log) { log(1); } })', enabled: true, backtrace: false };
const MARK = { id: 'bm-1', label: 'parser entry', module: 'app.exe', offset: 256, address: '0x400100', view: 'code', note: 'start here' };

function tmpFile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-ws-'));
  return { file: path.join(dir, 'workspace.json'), dir };
}

test('nothing saved yet: an empty workspace', () => {
  const { file } = tmpFile();
  assert.deepEqual(createWorkspaceStore(file).load(), { hooks: [], bookmarks: [] });
});

test('what is saved comes back, from a new store on the same file', () => {
  const { file } = tmpFile();
  assert.deepEqual(createWorkspaceStore(file).save({ hooks: [HOOK], bookmarks: [MARK] }), { hooks: 1, bookmarks: 1 });
  assert.deepEqual(createWorkspaceStore(file).load(), {
    hooks: [{ ...HOOK, address: '0x7ff010' }],
    bookmarks: [MARK],
  });
  assert.equal(fs.existsSync(file + '.tmp'), false);
});

test('only known fields are kept; state that belongs to a session is not saved', () => {
  const w = cleanWorkspace({ hooks: [{ ...HOOK, status: 'on', calls: 99, error: 'x', evil: '<img>' }], bookmarks: [{ ...MARK, extra: 1 }], other: 'dropped' });
  assert.deepEqual(Object.keys(w), ['hooks', 'bookmarks']);
  assert.deepEqual(Object.keys(w.hooks[0]), ['id', 'name', 'module', 'offset', 'address', 'code', 'enabled', 'backtrace']);
  assert.deepEqual(Object.keys(w.bookmarks[0]), ['id', 'label', 'module', 'offset', 'address', 'view', 'note']);
});

test('invalid entries are dropped, the rest are kept', () => {
  const w = cleanWorkspace({
    hooks: [
      null, 'x', { ...HOOK, id: '../x' }, { ...HOOK, id: 'a', code: '' }, { ...HOOK, id: 'b', code: 5 }, { ...HOOK, id: 'c', code: 'x'.repeat(70000) },
      { ...HOOK, id: 'd', offset: -1 }, { ...HOOK, id: 'e', offset: 1.5 }, { ...HOOK, id: 'f', module: '', offset: null, address: 'nope' },
      { ...HOOK, id: 'ok-1' }, { ...HOOK, id: 'ok-1' }, // the same id twice: once
      { ...HOOK, id: 'ok-2', module: '', offset: null, address: '0x9000', name: '' },
    ],
    bookmarks: [{ ...MARK, id: '' }, { ...MARK, id: 'x', module: '', offset: null, address: '' }, { ...MARK, id: 'ok', view: 'weird', label: '', note: 7 }],
  });
  assert.deepEqual(w.hooks.map((h) => h.id), ['ok-1', 'ok-2']);
  assert.equal(w.hooks[1].name, '0x9000'); // a missing name is filled in
  assert.deepEqual(w.bookmarks, [{ id: 'ok', label: 'app.exe+0x100', module: 'app.exe', offset: 256, address: '0x400100', view: 'memory', note: '' }]);
});

test('sizes are bounded', () => {
  const w = cleanWorkspace({
    hooks: Array.from({ length: 300 }, (_, i) => ({ ...HOOK, id: 'h' + i, name: 'n'.repeat(5000) })),
    bookmarks: Array.from({ length: 900 }, (_, i) => ({ ...MARK, id: 'b' + i, note: 'x'.repeat(9000), label: 'l'.repeat(900) })),
  });
  assert.equal(w.hooks.length, 200);
  assert.equal(w.hooks[0].name.length, 512);
  assert.equal(w.bookmarks.length, 500);
  assert.equal(w.bookmarks[0].note.length, 2000);
  assert.equal(w.bookmarks[0].label.length, 200);
});

test('anything that is not a workspace is an empty one', () => {
  for (const bad of [null, undefined, 'x', 5, [], { hooks: 'x', bookmarks: 7 }]) assert.deepEqual(cleanWorkspace(bad), { hooks: [], bookmarks: [] });
});

test('a corrupt or hostile file starts empty instead of throwing; saving repairs it', () => {
  const { file } = tmpFile();
  fs.writeFileSync(file, '{ not json');
  const store = createWorkspaceStore(file);
  assert.deepEqual(store.load(), { hooks: [], bookmarks: [] });
  fs.writeFileSync(file, JSON.stringify({ hooks: [{ id: 'x', code: 'c', module: 'm', offset: 1, __proto__: { polluted: true } }, HOOK] }));
  assert.deepEqual(store.load().hooks.map((h) => h.id), ['x', 'hk-1']);
  assert.equal(({}).polluted, undefined);
  store.save({ hooks: [HOOK] });
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')).version, 1);
});

test('a save that cannot be written throws (so the caller can say so) and leaves the old file intact', () => {
  const { file } = tmpFile();
  createWorkspaceStore(file).save({ hooks: [HOOK] });
  const failing = createWorkspaceStore(file, {
    readFileSync: fs.readFileSync,
    writeFileSync: () => { throw new Error('disk full'); },
    renameSync: fs.renameSync,
  });
  assert.throws(() => failing.save({ hooks: [] }), /disk full/);
  assert.equal(createWorkspaceStore(file).load().hooks.length, 1);
});
