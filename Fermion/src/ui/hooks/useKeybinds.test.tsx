import { render, fireEvent, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui from '../store/uiSlice';
import { sessionActions } from '../store/sessionSlice';
import { setTerminalSink, setOutputMirror } from '../bridge';
import { useKeybinds } from './useKeybinds';

/* eslint-disable @typescript-eslint/no-explicit-any */

function Harness() {
  useKeybinds();
  return <div />;
}

function setup(attached = true) {
  const store = configureStore({ reducer: { session, output, ui } });
  if (attached) {
    store.dispatch(sessionActions.attached('123'));
    store.dispatch(sessionActions.scriptLoaded());
  }
  const fermion = {
    saveFile: vi.fn(async () => 'C:/scripts/s.js'),
    saveCurrentFile: vi.fn(async () => 'C:/scripts/s.js'),
    openFile: vi.fn(async () => ({ path: 'C:/scripts/o.js', content: 'OPENED' })),
    reloadScript: vi.fn(async () => undefined),
  };
  (window as any).fermion = fermion;
  const ed = { getValue: () => 'SCRIPT', setValue: vi.fn() };
  (window as any).MonacoCodeEditor = ed;
  (window as any).__fermion = { terminal: { clear: vi.fn() } };
  render(<Provider store={store}><Harness /></Provider>);
  return { store, fermion, ed };
}

test('Ctrl-S saves the current script via saveFile', async () => {
  const { fermion } = setup();
  fireEvent.keyDown(document, { key: 's', ctrlKey: true });
  await waitFor(() => expect(fermion.saveFile).toHaveBeenCalledWith('SCRIPT', expect.anything()));
});

test('Ctrl-O opens a file and loads it into the editor', async () => {
  const { fermion, ed } = setup();
  fireEvent.keyDown(document, { key: 'o', ctrlKey: true });
  await waitFor(() => expect(ed.setValue).toHaveBeenCalledWith('OPENED'));
  expect(fermion.openFile).toHaveBeenCalled();
});

test('Ctrl-T reloads the script while attached', async () => {
  const { fermion } = setup(true);
  fireEvent.keyDown(document, { key: 't', ctrlKey: true });
  await waitFor(() => expect(fermion.reloadScript).toHaveBeenCalledWith('SCRIPT'));
});

test('Ctrl-T is a no-op when not attached', async () => {
  const { fermion } = setup(false);
  fireEvent.keyDown(document, { key: 't', ctrlKey: true });
  await new Promise((r) => setTimeout(r, 20));
  expect(fermion.reloadScript).not.toHaveBeenCalled();
});

test('Alt-C clears the output terminal, and the detached window with it', () => {
  setup();
  const clear = vi.fn();
  const mirrorClear = vi.fn();
  setTerminalSink({ write: () => {}, clear });
  setOutputMirror({ line: () => {}, clear: mirrorClear });
  fireEvent.keyDown(document, { key: 'c', altKey: true });
  setOutputMirror(null);
  setTerminalSink(null);
  expect(clear).toHaveBeenCalled();
  expect(mirrorClear).toHaveBeenCalled();
});

test('F5 and Ctrl-R are prevented (no page refresh)', () => {
  setup();
  const f5 = new KeyboardEvent('keydown', { key: 'F5', cancelable: true, bubbles: true });
  document.dispatchEvent(f5);
  expect(f5.defaultPrevented).toBe(true);
  const ctrlR = new KeyboardEvent('keydown', { key: 'r', ctrlKey: true, cancelable: true, bubbles: true });
  document.dispatchEvent(ctrlR);
  expect(ctrlR.defaultPrevented).toBe(true);
});
