// Unit tests for the Docs window's model: the help index grouped into topics.
const { test } = require('node:test');
const assert = require('node:assert');
const { buildDocsModel, filterTopics } = require('./docs-model.js');

const INDEX = {
  Process: { kind: 'namespace', sigs: [], doc: 'Information about the process.' },
  'Process.id': { kind: 'property', sigs: ['id: number'], doc: 'PID.' },
  'Process.enumerateModules': { kind: 'function', sigs: ['enumerateModules(): Module[]'], doc: 'Enumerates modules.' },
  NativePointer: { kind: 'class', sigs: ['new NativePointer(v: string)'], doc: 'A pointer.' },
  'NativePointer.add': { kind: 'method', sigs: ['add(v: number): NativePointer'], doc: 'Adds.' },
  ptr: { kind: 'function', sigs: ['ptr(v: string): NativePointer'], doc: 'Short-hand.' },
  ModuleDetails: { kind: 'interface', sigs: [], doc: '' },
  'ModuleDetails.name': { kind: 'property', sigs: ['name: string'], doc: 'Name.' },
  'A.B.c': { kind: 'function', sigs: ['c(): void'], doc: 'Nested.' },
  'A.B': { kind: 'namespace', sigs: [], doc: '' },
  A: { kind: 'namespace', sigs: [], doc: '' },
};

test('topics are the top-level names, sorted, each with its members', () => {
  const m = buildDocsModel(INDEX);
  assert.deepEqual(m.map((t) => t.name), ['A', 'ModuleDetails', 'NativePointer', 'Process', 'ptr']);
  const proc = m.find((t) => t.name === 'Process');
  assert.equal(proc.kind, 'namespace');
  assert.equal(proc.doc, 'Information about the process.');
  assert.deepEqual(proc.members.map((x) => x.name), ['enumerateModules', 'id']);
  assert.deepEqual(proc.members[0], { name: 'enumerateModules', kind: 'function', sigs: ['enumerateModules(): Module[]'], doc: 'Enumerates modules.' });
  assert.deepEqual(m.find((t) => t.name === 'ptr').members, []);
});

test('nested names are listed under their top-level topic with the dotted path', () => {
  const a = buildDocsModel(INDEX).find((t) => t.name === 'A');
  assert.deepEqual(a.members.map((x) => x.name), ['B', 'B.c']);
});

test('filterTopics matches a topic name or any member name, case-insensitively', () => {
  const m = buildDocsModel(INDEX);
  assert.deepEqual(filterTopics(m, 'nativ').map((t) => t.name), ['NativePointer']);
  assert.deepEqual(filterTopics(m, 'ENUMERATE').map((t) => t.name), ['Process']);
  assert.deepEqual(filterTopics(m, 'name').map((t) => t.name), ['ModuleDetails']);
  assert.equal(filterTopics(m, '').length, m.length);
  assert.deepEqual(filterTopics(m, 'zzz'), []);
});

test('an empty or missing index gives no topics rather than throwing', () => {
  assert.deepEqual(buildDocsModel({}), []);
  assert.deepEqual(buildDocsModel(null), []);
});

// The definitions hard-wrap their comments at ~80 columns; shown as-is the
// text is ragged in a pane of any other width.
test('reflow joins hard-wrapped lines into paragraphs, keeping blank lines and @tags', () => {
  const { reflow } = require('./docs-model.js');
  const doc = 'Intercepts calls to function at `target`. It is important\nto specify a callback.\n\nThe target may be an address.\n\n@param target Address to intercept, optionally wrapped\nwith options.\n@param data User data.';
  assert.equal(reflow(doc),
    'Intercepts calls to function at `target`. It is important to specify a callback.\n\nThe target may be an address.\n\n@param target Address to intercept, optionally wrapped with options.\n@param data User data.');
  assert.equal(reflow(''), '');
  assert.equal(reflow('one line'), 'one line');
  // List items and indented example lines keep their own lines.
  assert.equal(reflow('Options:\n- first\n- second\n    code();'), 'Options:\n- first\n- second\n    code();');
});
