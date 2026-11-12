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
