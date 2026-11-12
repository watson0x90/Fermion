// Script file operations for the Editor: Open, Save, Save As, Open Recent.
// Shared by the Editor toolbar and the keyboard shortcuts. The store holds the
// current file's path and whether the editor has unsaved changes; the main
// process holds the file itself (see src/file-ipc.js).
import { uiActions } from './store/uiSlice';
import { writeTerminal } from './bridge';
import { cleanIpcError } from './inspector/format';

/* eslint-disable @typescript-eslint/no-explicit-any */
type Dispatch = (a: any) => unknown;
type GetState = () => any;
const api = () => (window as any).fermion;
const editor = () => (window as any).MonacoCodeEditor;

export function fileLabel(path: string | null): string {
  return path ? path.split(/[\\/]/).pop() || path : 'untitled.js';
}

// The editor's content-change listener calls this. Loading a file into the
// editor is not an edit, so it is ignored while `loading` is set.
let loading = false;
export function noteEdit(dispatch: Dispatch): void {
  if (!loading) dispatch(uiActions.edited());
}

function load(dispatch: Dispatch, file: { path: string; content: string }) {
  loading = true;
  try { editor()?.setValue?.(file.content); } finally { loading = false; }
  dispatch(uiActions.fileOpened(file.path));
  writeTerminal('STATUS', '[+] File opened..');
  writeTerminal('STATUS', '    |-> Path: ' + file.path);
}

// With unsaved changes, replacing the editor's content needs a yes.
async function okToReplace(getState: GetState): Promise<boolean> {
  if (!getState().ui.dirty) return true;
  const r = await api().messageBox({
    type: 'question',
    title: 'Fermion',
    message: 'Discard unsaved changes to ' + fileLabel(getState().ui.filePath) + '?',
    detail: 'Opening another file replaces what is in the editor.',
    buttons: ['Discard changes', 'Cancel'],
    defaultId: 1,
    cancelId: 1,
  });
  return !!r && r.response === 0;
}

export async function openScript(dispatch: Dispatch, getState: GetState): Promise<boolean> {
  try {
    if (!(await okToReplace(getState))) return false;
    const file = await api().openFile();
    if (!file) return false;
    load(dispatch, file);
    return true;
  } catch (e) {
    writeTerminal('ERR', '[!] Error opening file: ' + cleanIpcError(e));
    return false;
  }
}

export async function openRecentScript(dispatch: Dispatch, getState: GetState, path: string): Promise<boolean> {
  try {
    if (!(await okToReplace(getState))) return false;
    load(dispatch, await api().openRecent(path));
    return true;
  } catch (e) {
    writeTerminal('ERR', '[!] Error opening file: ' + cleanIpcError(e));
    return false;
  }
}

async function finishSave(dispatch: Dispatch, pending: Promise<string | null | undefined>): Promise<boolean> {
  try {
    const savedPath = await pending;
    if (!savedPath) return false; // cancelled in the dialog
    dispatch(uiActions.fileSaved(savedPath));
    writeTerminal('STATUS', '[+] File saved..');
    writeTerminal('STATUS', '    |-> Path: ' + savedPath);
    return true;
  } catch (e) {
    writeTerminal('ERR', '[!] Error saving file: ' + cleanIpcError(e));
    return false;
  }
}

const content = (): string => editor()?.getValue?.() ?? '';

// Save: back to the file the script came from, or ask where for a new script.
export function saveScript(dispatch: Dispatch, getState: GetState): Promise<boolean> {
  const known = getState().ui.filePath;
  return finishSave(dispatch, Promise.resolve().then(() => (known
    ? api().saveCurrentFile(content())
    : api().saveFile(content(), { title: 'Fermion Save File', defaultPath: 'script.js' }))));
}

export function saveScriptAs(dispatch: Dispatch): Promise<boolean> {
  return finishSave(dispatch, Promise.resolve().then(() => api().saveFile(content(), { title: 'Fermion Save File' })));
}
