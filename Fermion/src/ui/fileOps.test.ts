import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session from './store/sessionSlice';
import output from './store/outputSlice';
import ui, { uiActions } from './store/uiSlice';
import { setTerminalSink } from './bridge';
import { openScript, saveScript, saveScriptAs, openRecentScript, noteEdit, fileLabel } from './fileOps';

/* eslint-disable @typescript-eslint/no-explicit-any */
let fermion: any;
let editor: any;
let lines: string[];
function setup() {
  lines = [];
  setTerminalSink({ write: (k: string, t: string) => { lines.push(k + ' ' + t); } });
  let value = 'INITIAL';
  // Like Monaco: setValue fires the change listener.
  editor = { getValue: () => value, setValue: vi.fn((v: string) => { value = v; noteEdit(store.dispatch); }) };
  (window as any).MonacoCodeEditor = editor;
  fermion = {
    openFile: vi.fn(async () => ({ path: 'C:\\scripts\\hook.js', content: 'OPENED' })),
    openRecent: vi.fn(async (p: string) => ({ path: p, content: 'RECENT' })),
    saveFile: vi.fn(async () => 'C:\\scripts\\new.js'),
    saveCurrentFile: vi.fn(async () => 'C:\\scripts\\hook.js'),
    messageBox: vi.fn(async () => ({ response: 0 })),
  };
  (window as any).fermion = fermion;
  const store = configureStore({ reducer: { session, output, ui } });
  return store;
}
afterEach(() => setTerminalSink(null));

test('fileLabel: the file name for a path on either kind of separator; "untitled" with none', () => {
  expect(fileLabel('C:\\scripts\\hook.js')).toBe('hook.js');
  expect(fileLabel('/home/me/scripts/hook.js')).toBe('hook.js');
  expect(fileLabel(null)).toBe('untitled.js');
});

test('typing marks the script as having unsaved changes', () => {
  const store = setup();
  expect(store.getState().ui.dirty).toBe(false);
  noteEdit(store.dispatch);
  expect(store.getState().ui.dirty).toBe(true);
});

test('open: loads the file into the editor, records its path, and it is not "unsaved"', async () => {
  const store = setup();
  expect(await openScript(store.dispatch, store.getState)).toBe(true);
  expect(editor.setValue).toHaveBeenCalledWith('OPENED');
  expect(store.getState().ui.filePath).toBe('C:\\scripts\\hook.js');
  expect(store.getState().ui.dirty).toBe(false); // loading a file is not an edit
  expect(lines).toContain('STATUS [+] File opened..');
});

test('open cancelled in the dialog changes nothing', async () => {
  const store = setup();
  fermion.openFile.mockResolvedValueOnce(null);
  expect(await openScript(store.dispatch, store.getState)).toBe(false);
  expect(editor.setValue).not.toHaveBeenCalled();
  expect(store.getState().ui.filePath).toBeNull();
});

test('open with unsaved changes asks first; Cancel keeps the edits', async () => {
  const store = setup();
  noteEdit(store.dispatch);
  fermion.messageBox.mockResolvedValueOnce({ response: 1 }); // Cancel
  expect(await openScript(store.dispatch, store.getState)).toBe(false);
  expect(fermion.messageBox).toHaveBeenCalledWith(expect.objectContaining({ buttons: ['Discard changes', 'Cancel'] }));
  expect(fermion.openFile).not.toHaveBeenCalled();
  expect(store.getState().ui.dirty).toBe(true);

  fermion.messageBox.mockResolvedValueOnce({ response: 0 }); // Discard
  expect(await openScript(store.dispatch, store.getState)).toBe(true);
  expect(editor.setValue).toHaveBeenCalledWith('OPENED');
});

test('save: a new script asks where; a known file is written back without a dialog; both clear "unsaved"', async () => {
  const store = setup();
  noteEdit(store.dispatch);
  expect(await saveScript(store.dispatch, store.getState)).toBe(true);
  expect(fermion.saveFile).toHaveBeenCalledWith('INITIAL', expect.objectContaining({ title: 'Fermion Save File' }));
  expect(store.getState().ui.filePath).toBe('C:\\scripts\\new.js');
  expect(store.getState().ui.dirty).toBe(false);

  noteEdit(store.dispatch);
  fermion.saveCurrentFile.mockResolvedValueOnce('C:\\scripts\\new.js');
  expect(await saveScript(store.dispatch, store.getState)).toBe(true);
  expect(fermion.saveCurrentFile).toHaveBeenCalledWith('INITIAL');
  expect(fermion.saveFile).toHaveBeenCalledTimes(1);
  expect(store.getState().ui.dirty).toBe(false);
});

test('save cancelled in the dialog leaves the script unsaved', async () => {
  const store = setup();
  noteEdit(store.dispatch);
  fermion.saveFile.mockResolvedValueOnce(null);
  expect(await saveScript(store.dispatch, store.getState)).toBe(false);
  expect(store.getState().ui.dirty).toBe(true);
  expect(store.getState().ui.filePath).toBeNull();
});

test('save as always asks, even for a known file', async () => {
  const store = setup();
  store.dispatch(uiActions.fileSaved('C:\\scripts\\hook.js'));
  expect(await saveScriptAs(store.dispatch)).toBe(true);
  expect(fermion.saveFile).toHaveBeenCalled();
  expect(fermion.saveCurrentFile).not.toHaveBeenCalled();
  expect(store.getState().ui.filePath).toBe('C:\\scripts\\new.js');
});

test('open recent: loads it like Open; a failure is reported and nothing changes', async () => {
  const store = setup();
  expect(await openRecentScript(store.dispatch, store.getState, 'C:\\scripts\\old.js')).toBe(true);
  expect(fermion.openRecent).toHaveBeenCalledWith('C:\\scripts\\old.js');
  expect(editor.setValue).toHaveBeenCalledWith('RECENT');
  expect(store.getState().ui.filePath).toBe('C:\\scripts\\old.js');
  expect(store.getState().ui.dirty).toBe(false);

  fermion.openRecent.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:openRecent': Error: That file no longer exists"));
  expect(await openRecentScript(store.dispatch, store.getState, 'C:\\scripts\\gone.js')).toBe(false);
  expect(lines.some((l) => l.startsWith('ERR') && l.includes('That file no longer exists') && !l.includes('remote method'))).toBe(true);
  expect(store.getState().ui.filePath).toBe('C:\\scripts\\old.js');
});

test('a failed save is reported in Output', async () => {
  const store = setup();
  fermion.saveFile.mockRejectedValueOnce(new Error('EACCES: permission denied'));
  expect(await saveScript(store.dispatch, store.getState)).toBe(false);
  expect(lines.some((l) => l.startsWith('ERR') && l.includes('permission denied'))).toBe(true);
});
