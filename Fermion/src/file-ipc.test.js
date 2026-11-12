// Unit tests for the main-process file handlers (open / save / recent).
const { test } = require('node:test');
const assert = require('node:assert');
const fsReal = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createFileHandlers } = require('./file-ipc.js');
const { RecentFiles } = require('./recent-files.js');

const A = path.join(os.tmpdir(), 'fermion-scripts', 'a.js');
const B = path.join(os.tmpdir(), 'fermion-scripts', 'b.js');
const OUT = path.join(os.tmpdir(), 'fermion-scripts', 'frida-output.txt');

function setup() {
  const files = { [A]: 'A-CONTENT', [B]: 'B-CONTENT' };
  const fs = {
    promises: {
      readFile: async (p) => { if (!(p in files)) { const e = new Error('ENOENT: no such file'); e.code = 'ENOENT'; throw e; } return files[p]; },
      writeFile: async (p, c) => { files[p] = c; },
    },
  };
  const dialog = { open: [], save: [], showOpenDialog: async () => ({ filePaths: dialog.open.splice(0, 1) }), showSaveDialog: async () => ({ filePath: dialog.save.shift() }) };
  const dir = fsReal.mkdtempSync(path.join(os.tmpdir(), 'fermion-fileipc-'));
  const recent = new RecentFiles(path.join(dir, 'recent.json'));
  return { h: createFileHandlers({ dialog, fs, recent }), files, dialog, recent };
}

test('open: reads the chosen file, makes it the current file and remembers it', async () => {
  const { h, dialog, recent } = setup();
  dialog.open.push(A);
  assert.deepEqual(await h.openFile(), { path: A, content: 'A-CONTENT' });
  assert.deepEqual(recent.list(), [A]);
  assert.equal(await h.openFile(), null); // dialog cancelled
});

test('save as: writes, becomes the current file, is remembered; save writes back to it', async () => {
  const { h, dialog, files, recent } = setup();
  dialog.save.push(B);
  assert.equal(await h.saveFile('v1', { title: 'Fermion Save File' }), B);
  assert.equal(files[B], 'v1');
  assert.equal(await h.saveCurrent('v2'), B);
  assert.equal(files[B], 'v2');
  assert.deepEqual(recent.list(), [B]);
});

test('save with no current file does nothing', async () => {
  const { h } = setup();
  assert.equal(await h.saveCurrent('x'), null);
});

// Saving the Output pane or a graph used to become "the current file", so the
// next Ctrl-S wrote the script over the saved output.
test('an export (output log, graph) is written but does not become the script file or a recent file', async () => {
  const { h, dialog, files, recent } = setup();
  dialog.open.push(A);
  await h.openFile();
  dialog.save.push(OUT);
  assert.equal(await h.saveFile('LOG LINES', { title: 'Save Frida Output' }, 'export'), OUT);
  assert.equal(files[OUT], 'LOG LINES');
  assert.equal(await h.saveCurrent('SCRIPT v2'), A);   // still the script
  assert.equal(files[A], 'SCRIPT v2');
  assert.equal(files[OUT], 'LOG LINES');
  assert.deepEqual(recent.list(), [A]);
});

test('recent: lists the remembered files and re-opens one without a dialog', async () => {
  const { h, dialog } = setup();
  dialog.open.push(A); await h.openFile();
  dialog.open.push(B); await h.openFile();
  assert.deepEqual(await h.recentFiles(), [B, A]);
  assert.deepEqual(await h.openRecent(A), { path: A, content: 'A-CONTENT' });
  assert.deepEqual(await h.recentFiles(), [A, B]); // moved to the front
  assert.equal(await h.saveCurrent('edited'), A);  // and it is now the current file
});

test('recent: a path that was never chosen in a dialog is refused and not read', async () => {
  const { h, files } = setup();
  let read = 0;
  const secret = path.join(os.tmpdir(), 'secrets.txt');
  files[secret] = 'SECRET';
  const orig = h._fs.promises.readFile;
  h._fs.promises.readFile = async (p) => { read++; return orig(p); };
  await assert.rejects(() => h.openRecent(secret), /not a recent file/i);
  await assert.rejects(() => h.openRecent('../../etc/passwd'), /not a recent file/i);
  await assert.rejects(() => h.openRecent(undefined), /not a recent file/i);
  assert.equal(read, 0);
});

test('recent: a file that has since been deleted is reported and dropped from the list', async () => {
  const { h, dialog, files } = setup();
  dialog.open.push(A); await h.openFile();
  delete files[A];
  await assert.rejects(() => h.openRecent(A), /no longer exists|could not be read/i);
  assert.deepEqual(await h.recentFiles(), []);
});

test('only text is written', async () => {
  const { h, dialog } = setup();
  dialog.save.push(B);
  await assert.rejects(() => h.saveFile({ not: 'text' }, {}), /text/i);
  await assert.rejects(() => h.saveCurrent(42), /text/i);
});
