import { render, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session from '../store/sessionSlice';
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
