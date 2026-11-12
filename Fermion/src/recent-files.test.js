// Unit tests for the main-process recent-files list. It is the only way the
// renderer can re-open a file without a dialog, so it must hold nothing but
// paths the user picked in a dialog, and survive a missing or corrupt file.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { RecentFiles } = require('./recent-files.js');

function tmp() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fermion-recent-'));
  return { dir, file: path.join(dir, 'recent-files.json') };
}
const P = (name) => path.join(os.tmpdir(), 'scripts', name);

test('add puts the newest first, without duplicates, and list returns a copy', () => {
  const { file } = tmp();
  const r = new RecentFiles(file);
  assert.deepEqual(r.list(), []);
  r.add(P('a.js')); r.add(P('b.js')); r.add(P('a.js'));
  assert.deepEqual(r.list(), [P('a.js'), P('b.js')]);
  r.list().push('injected');
  assert.equal(r.list().length, 2);
});

test('the list is capped at 10', () => {
  const { file } = tmp();
  const r = new RecentFiles(file);
  for (let i = 0; i < 14; i++) r.add(P('s' + i + '.js'));
  assert.equal(r.list().length, 10);
  assert.equal(r.list()[0], P('s13.js'));
  assert.equal(r.has(P('s0.js')), false);
});

test('has is true only for a path that was added; lookalikes are refused', () => {
  const { file } = tmp();
  const r = new RecentFiles(file);
  r.add(P('a.js'));
  assert.equal(r.has(P('a.js')), true);
  assert.equal(r.has(P('other.js')), false);
  // A different spelling of the same file is not on the list (no normalizing into a match).
  assert.equal(r.has(P('a.js').replace('scripts', ['scripts', '..', 'scripts'].join(path.sep))), false);
  assert.equal(r.has('a.js'), false);
  assert.equal(r.has(undefined), false);
  assert.equal(r.has(null), false);
  assert.equal(r.has(42), false);
  assert.equal(r.has({ toString: () => P('a.js') }), false);
});

test('only absolute path strings are accepted', () => {
  const { file } = tmp();
  const r = new RecentFiles(file);
  r.add('relative.js'); r.add(''); r.add(null); r.add(42);
  assert.deepEqual(r.list(), []);
});

test('the list persists across instances; remove forgets a path', () => {
  const { file } = tmp();
  const a = new RecentFiles(file);
  a.add(P('a.js')); a.add(P('b.js'));
  const b = new RecentFiles(file);
  assert.deepEqual(b.list(), [P('b.js'), P('a.js')]);
  b.remove(P('b.js'));
  assert.deepEqual(new RecentFiles(file).list(), [P('a.js')]);
});

test('a missing, corrupt or hostile store starts empty instead of throwing', () => {
  const { file } = tmp();
  assert.deepEqual(new RecentFiles(file).list(), []);
  fs.writeFileSync(file, '{not json');
  assert.deepEqual(new RecentFiles(file).list(), []);
  fs.writeFileSync(file, JSON.stringify({ paths: 'nope' }));
  assert.deepEqual(new RecentFiles(file).list(), []);
  // Entries that are not absolute path strings are dropped on load.
  fs.writeFileSync(file, JSON.stringify([P('ok.js'), 'relative.js', 7, null, P('ok.js')]));
  assert.deepEqual(new RecentFiles(file).list(), [P('ok.js')]);
});

test('a store that cannot be written does not break adding', () => {
  const { dir } = tmp();
  const r = new RecentFiles(path.join(dir, 'no-such-folder', 'deeper', 'recent.json'));
  assert.doesNotThrow(() => r.add(P('a.js')));
  assert.deepEqual(r.list(), [P('a.js')]);
});
