// Unit tests for saving a coverage recording from the main process.
const { test } = require('node:test');
const assert = require('node:assert');
const { createCoverageSaver, suggestedName } = require('./coverage-save.js');

function setup(answer) {
  const log = [];
  const dialog = { showSaveDialog: async (...a) => { log.push(['dialog', ...a]); return answer; } };
  const fs = { promises: { writeFile: async (p, d) => { log.push(['write', p, d]); } } };
  return { log, dialog, fs };
}

test('suggestedName is built from the program name, with nothing that could steer the path', () => {
  assert.equal(suggestedName('notepad.exe', 'drcov'), 'notepad-coverage.drcov');
  assert.equal(suggestedName('my app (x64).exe', 'md'), 'my_app_x64_-coverage.md');
  assert.equal(suggestedName('..\\..\\evil', 'drcov'), 'evil-coverage.drcov');
  assert.equal(suggestedName('C:/Windows/System32/cmd.exe', 'drcov'), 'C_Windows_System32_cmd-coverage.drcov');
  assert.equal(suggestedName('', 'drcov'), 'coverage-coverage.drcov');
  assert.equal(suggestedName(undefined, 'md'), 'coverage-coverage.md');
  assert.ok(suggestedName('x'.repeat(500), 'drcov').length < 80);
});

test('the drcov file is written as the bytes it was given, to the path the operator chose', async () => {
  const t = setup({ filePath: 'C:/out/app.drcov' });
  const save = createCoverageSaver({ dialog: t.dialog, fs: t.fs, getWindow: () => 'WIN' });
  const data = Buffer.from([1, 2, 3, 250]);
  assert.equal(await save({ format: 'drcov', data, program: 'app.exe' }), 'C:/out/app.drcov');
  assert.equal(t.log[0][1], 'WIN'); // the dialog belongs to the main window
  assert.equal(t.log[0][2].defaultPath, 'app-coverage.drcov');
  assert.deepEqual(t.log[0][2].filters[0].extensions, ['drcov']);
  assert.deepEqual(t.log[1], ['write', 'C:/out/app.drcov', data]);
});

test('the text report is offered as .md; without a window the dialog still opens', async () => {
  const t = setup({ filePath: '/tmp/r.md' });
  const save = createCoverageSaver({ dialog: t.dialog, fs: t.fs });
  assert.equal(await save({ format: 'text', data: '# report', program: 'cat' }), '/tmp/r.md');
  assert.equal(t.log[0][1].defaultPath, 'cat-coverage.md');
  assert.deepEqual(t.log[1], ['write', '/tmp/r.md', '# report']);
});

test('cancelling writes nothing; an unknown format is refused before any dialog', async () => {
  const t = setup({ filePath: undefined });
  const save = createCoverageSaver({ dialog: t.dialog, fs: t.fs });
  assert.equal(await save({ format: 'drcov', data: Buffer.alloc(1) }), null);
  assert.equal(t.log.length, 1);
  await assert.rejects(() => save({ format: 'exe', data: 'x' }), /unknown coverage format/);
  assert.equal(t.log.length, 1);
});
