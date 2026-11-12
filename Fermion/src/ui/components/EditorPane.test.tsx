import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session, { sessionActions } from '../store/sessionSlice';
import { setTerminalSink } from '../bridge';
import output from '../store/outputSlice';
import ui from '../store/uiSlice';
import { EditorPane } from './EditorPane';

function makeStore() {
  return configureStore({ reducer: { session, output, ui } });
}

/* eslint-disable @typescript-eslint/no-explicit-any */
beforeEach(() => {
  const editor = { getValue: () => 'x', setValue: vi.fn(), updateOptions: vi.fn(), getRawOptions: () => ({ wordWrap: 'off' }), dispose: vi.fn() };
  (window as any).monaco = {
    editor: { create: () => editor, defineTheme: vi.fn(), setTheme: vi.fn() },
    languages: { typescript: {
      javascriptDefaults: { setDiagnosticsOptions: vi.fn() },
      typescriptDefaults: { setCompilerOptions: vi.fn(), addExtraLib: vi.fn() },
      ScriptTarget: { Latest: 1 }, ModuleResolutionKind: { NodeJs: 1 },
    } },
  };
  (window as any).FermionThemes = { Kuroir: {} };
  (window as any).fermion = { versions: async () => ({ fermion: '9.9', frida: '17.0' }) };
  const amd: any = (_mods: string[], cb: () => void) => cb();
  amd.config = vi.fn();
  (window as any).require = amd;
  (window as any).MonacoCodeEditor = undefined;
});

test('EditorPane resolves versions, mounts Monaco, and exposes window.MonacoCodeEditor', async () => {
  render(
    <Provider store={makeStore()}>
      <EditorPane />
    </Provider>,
  );
  await waitFor(() => expect((window as any).MonacoCodeEditor).toBeDefined());
  expect((window as any).MonacoCodeEditor.getValue()).toBe('x');
});

test('the editor toolbar has a Reload button: disabled until attached, then reloads the editor script', async () => {
  const lines: string[] = [];
  setTerminalSink({ write: (k: string, t: string) => { lines.push(k + ' ' + t); } });
  const reloadScript = vi.fn(async () => undefined);
  (window as any).fermion.reloadScript = reloadScript;
  const store = makeStore();
  render(<Provider store={store}><EditorPane /></Provider>);
  await waitFor(() => expect((window as any).MonacoCodeEditor).toBeDefined());

  const btn = screen.getByTestId('editor-reload');
  expect(btn).toBeDisabled();
  act(() => { store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '1' })); });
  expect(btn).not.toBeDisabled();

  fireEvent.click(btn);
  await waitFor(() => expect(reloadScript).toHaveBeenCalledWith('x')); // the editor's current text
  await waitFor(() => expect(store.getState().session.hasScript).toBe(true));
  expect(lines).toContain('STATUS [+] Script reloaded..');
  setTerminalSink(null);
});

test('a failed reload (script error) is reported in Output', async () => {
  const lines: string[] = [];
  setTerminalSink({ write: (k: string, t: string) => { lines.push(k + ' ' + t); } });
  (window as any).fermion.reloadScript = vi.fn(async () => { throw new Error('SyntaxError: unexpected token'); });
  const store = makeStore();
  store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '1' }));
  render(<Provider store={store}><EditorPane /></Provider>);
  await waitFor(() => expect((window as any).MonacoCodeEditor).toBeDefined());
  fireEvent.click(screen.getByTestId('editor-reload'));
  await waitFor(() => expect(lines.some((l) => l.startsWith('ERR') && l.includes('unexpected token'))).toBe(true));
  setTerminalSink(null);
});

test('the toolbar names the file, marks unsaved changes, and Save clears the mark', async () => {
  let onChange: () => void = () => {};
  const editor = { getValue: () => 'x', setValue: vi.fn(), updateOptions: vi.fn(), getRawOptions: () => ({ wordWrap: 'off' }), dispose: vi.fn(), onDidChangeModelContent: (cb: () => void) => { onChange = cb; } };
  (window as any).monaco.editor.create = () => editor;
  (window as any).fermion.saveFile = vi.fn(async () => 'C:/scripts/hook.js');
  (window as any).fermion.saveCurrentFile = vi.fn(async () => 'C:/scripts/hook.js');
  const store = makeStore();
  render(<Provider store={store}><EditorPane /></Provider>);
  await waitFor(() => expect((window as any).MonacoCodeEditor).toBeDefined());

  expect(screen.getByTestId('editor-file')).toHaveTextContent('untitled.js');
  expect(screen.queryByTestId('editor-dirty')).toBeNull();
  act(() => { onChange(); }); // the user types
  expect(screen.getByTestId('editor-dirty')).toBeInTheDocument();

  fireEvent.click(screen.getByTestId('editor-save'));
  await waitFor(() => expect(screen.getByTestId('editor-file')).toHaveTextContent('hook.js'));
  expect(screen.getByTestId('editor-file')).toHaveAttribute('title', 'C:/scripts/hook.js');
  expect(screen.queryByTestId('editor-dirty')).toBeNull();
  expect((window as any).fermion.saveFile).toHaveBeenCalledTimes(1);

  act(() => { onChange(); });
  fireEvent.click(screen.getByTestId('editor-save'));
  await waitFor(() => expect((window as any).fermion.saveCurrentFile).toHaveBeenCalledWith('x')); // no dialog the second time
  await waitFor(() => expect(screen.queryByTestId('editor-dirty')).toBeNull());
});

test('the recent menu lists files from the main process and opens the one picked', async () => {
  const editor = { getValue: () => 'x', setValue: vi.fn(), updateOptions: vi.fn(), getRawOptions: () => ({ wordWrap: 'off' }), dispose: vi.fn(), onDidChangeModelContent: () => {} };
  (window as any).monaco.editor.create = () => editor;
  (window as any).fermion.recentFiles = vi.fn(async () => ['C:/scripts/a.js', 'D:/work/b.js']);
  (window as any).fermion.openRecent = vi.fn(async (p: string) => ({ path: p, content: 'B-CONTENT' }));
  const store = makeStore();
  render(<Provider store={store}><EditorPane /></Provider>);
  await waitFor(() => expect((window as any).MonacoCodeEditor).toBeDefined());

  expect(screen.queryByTestId('editor-recent-menu')).toBeNull();
  fireEvent.click(screen.getByTestId('editor-recent'));
  const items = await screen.findAllByTestId('editor-recent-item');
  expect(items.map((i) => i.querySelector('.mn')!.textContent)).toEqual(['a.js', 'b.js']);
  expect(items[1]).toHaveAttribute('title', 'D:/work/b.js');

  fireEvent.click(items[1]);
  await waitFor(() => expect((window as any).fermion.openRecent).toHaveBeenCalledWith('D:/work/b.js'));
  await waitFor(() => expect(editor.setValue).toHaveBeenCalledWith('B-CONTENT'));
  expect(screen.queryByTestId('editor-recent-menu')).toBeNull(); // closed after picking
  expect(screen.getByTestId('editor-file')).toHaveTextContent('b.js');
});

test('an empty recent list says so', async () => {
  (window as any).fermion.recentFiles = vi.fn(async () => []);
  render(<Provider store={makeStore()}><EditorPane /></Provider>);
  await waitFor(() => expect((window as any).MonacoCodeEditor).toBeDefined());
  fireEvent.click(screen.getByTestId('editor-recent'));
  await waitFor(() => expect(screen.getByTestId('editor-recent-menu')).toHaveTextContent(/No recent scripts yet/));
});
