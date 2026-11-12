import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session, { sessionActions } from '../../store/sessionSlice';
import output from '../../store/outputSlice';
import ui from '../../store/uiSlice';
import { setTerminalSink } from '../../bridge';
import { resetHelpIndexForTests } from '../../repl/help';
import { ReplPanel } from './ReplPanel';

/* eslint-disable @typescript-eslint/no-explicit-any */
// A stand-in for the REPL agent's helpers, reached the way the panel reaches
// them: through evaluate().
const MEMBERS: Record<string, { name: string; kind: string }[]> = {
  Process: [
    { name: 'arch', kind: 'property' }, { name: 'enumerateModules', kind: 'function' },
    { name: 'enumerateThreads', kind: 'function' }, { name: 'id', kind: 'property' },
  ],
};
const GLOBALS = ['Process', 'Promise', 'ptr'];
function fakeComplete(text: string) {
  const tail = /[\w$.]*$/.exec(text)![0];
  const dot = tail.lastIndexOf('.');
  const base = dot < 0 ? '' : tail.slice(0, dot);
  const partial = tail.slice(dot + 1);
  const pool = base ? (MEMBERS[base] ?? []) : (partial ? GLOBALS.map((name) => ({ name, kind: 'property' })) : []);
  return { from: text.length - partial.length, items: pool.filter((i) => i.name.startsWith(partial)), truncated: false };
}
function fakeInspect(name: string) {
  if (name === 'Process') return { found: true, name, type: 'object', members: [{ name: 'enumerateModules', kind: 'function', arity: 0 }, { name: 'id', kind: 'property', type: 'number' }] };
  if (name === 'Process.id') return { found: true, name, type: 'number', value: '4821' };
  return { found: false, name };
}
const INDEX = {
  Process: { kind: 'namespace', sigs: [], doc: 'Information about the current process.' },
  'Process.id': { kind: 'property', sigs: ['id: number'], doc: 'PID of the current process.' },
  'Process.enumerateModules': { kind: 'function', sigs: ['enumerateModules(): Module[]'], doc: 'Enumerates modules loaded right now.' },
  ptr: { kind: 'function', sigs: ['ptr(value: string | number): NativePointer'], doc: 'Short-hand.' },
};

let evaluate: any;
let lines: string[];
function setup({ attached = true, index = INDEX as any } = {}) {
  lines = [];
  setTerminalSink({ write: (k: string, t: string) => { lines.push(k + ' ' + t); } });
  resetHelpIndexForTests();
  (globalThis as any).fetch = vi.fn(async () => (index ? { ok: true, json: async () => index } : Promise.reject(new Error('no file'))));
  const arg = (code: string) => JSON.parse(code.slice(code.indexOf('(') + 1, -1));
  evaluate = vi.fn(async (code: string) => {
    if (code.startsWith('__fermion.complete(')) return { ok: true, type: 'object', text: JSON.stringify(fakeComplete(arg(code))) };
    if (code.startsWith('__fermion.inspect(')) return { ok: true, type: 'object', text: JSON.stringify(fakeInspect(arg(code))) };
    if (code === '__fermion.globals()') return { ok: true, type: 'Array', text: JSON.stringify(GLOBALS) };
    return { ok: true, type: 'number', text: 'ran(' + code + ')' };
  });
  (window as any).fermion = { evaluate };
  const store = configureStore({ reducer: { session, output, ui } });
  if (attached) store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '4821' }));
  render(<Provider store={store}><ReplPanel /></Provider>);
  const input = screen.getByTestId('repl-input') as HTMLTextAreaElement;
  // Put text in the box with the caret at `caret` (default: the end).
  const type = (v: string, caret = v.length) => { fireEvent.change(input, { target: { value: v } }); input.setSelectionRange(caret, caret); };
  const tab = () => fireEvent.keyDown(input, { key: 'Tab' });
  return { input, type, tab };
}
afterEach(() => setTerminalSink(null));
const choiceNames = () => screen.queryAllByTestId('repl-choice').map((c) => c.textContent);

test('Tab completes a unique match in place', async () => {
  const { input, type, tab } = setup();
  type('Process.enumerateM');
  tab();
  await waitFor(() => expect(input.value).toBe('Process.enumerateModules'));
  expect(screen.queryByTestId('repl-choices')).toBeNull();
});

test('Tab with several matches fills in what they share and lists them; picking one finishes it', async () => {
  const { input, type, tab } = setup();
  type('Process.enum');
  tab();
  await waitFor(() => expect(input.value).toBe('Process.enumerate'));
  expect(choiceNames()).toEqual(['enumerateModules()', 'enumerateThreads()']);
  fireEvent.click(screen.getAllByTestId('repl-choice')[1]);
  expect(input.value).toBe('Process.enumerateThreads');
  expect(screen.queryByTestId('repl-choices')).toBeNull();
  expect(document.activeElement).toBe(input);
});

test('Tab completes the name at the caret, leaving the rest of the entry alone', async () => {
  const { input, type, tab } = setup();
  type('x = Proce; y', 'x = Proce'.length);
  tab();
  await waitFor(() => expect(input.value).toBe('x = Process; y'));
  expect(input.selectionStart).toBe('x = Process'.length);
});

test('Tab with nothing to offer changes nothing; typing or Escape dismisses the list', async () => {
  const { input, type, tab } = setup();
  type('Process.zzz');
  tab();
  await waitFor(() => expect(evaluate).toHaveBeenCalled());
  expect(input.value).toBe('Process.zzz');
  expect(screen.queryByTestId('repl-choices')).toBeNull();

  type('Process.');
  tab();
  await waitFor(() => expect(choiceNames().length).toBe(4));
  fireEvent.keyDown(input, { key: 'Escape' });
  expect(screen.queryByTestId('repl-choices')).toBeNull();
  tab();
  await waitFor(() => expect(choiceNames().length).toBe(4));
  type('Process.i');
  expect(screen.queryByTestId('repl-choices')).toBeNull();
});

test('completion is silent: no transcript entry, no history, nothing written to Output', async () => {
  const { input, type, tab } = setup();
  type('Process.enumerateM');
  tab();
  await waitFor(() => expect(input.value).toBe('Process.enumerateModules'));
  expect(screen.queryAllByTestId('repl-entry').length).toBe(0);
  expect(lines).toEqual([]);
  fireEvent.change(input, { target: { value: '' } });
  fireEvent.keyDown(input, { key: 'ArrowUp' });
  expect(input.value).toBe('');
});

test('Tab does nothing when not attached', async () => {
  const { tab } = setup({ attached: false });
  tab();
  await new Promise((r) => setTimeout(r, 20));
  expect(evaluate).not.toHaveBeenCalled();
});

test('help <name> shows documentation plus the live members, in the transcript only', async () => {
  const { input, type } = setup();
  type('help Process');
  fireEvent.keyDown(input, { key: 'Enter' });
  const res = await screen.findByTestId('repl-result');
  await waitFor(() => expect(res).toHaveTextContent('Process — namespace'));
  expect(res).toHaveClass('help');
  expect(res).toHaveTextContent('Information about the current process.');
  expect(res).toHaveTextContent('enumerateModules(): Module[]');
  expect(res).toHaveTextContent('PID of the current process.');
  expect(evaluate).toHaveBeenCalledWith('__fermion.inspect("Process")');
  expect(evaluate).not.toHaveBeenCalledWith('help Process'); // never run as code
  expect(lines).toEqual([]);                                 // help is not hook output
  // It is in the history like any other entry.
  fireEvent.keyDown(input, { key: 'ArrowUp' });
  expect(input.value).toBe('help Process');
});

test('help <property> includes its current value', async () => {
  const { input, type } = setup();
  type('help Process.id');
  fireEvent.keyDown(input, { key: 'Enter' });
  await waitFor(() => expect(screen.getByTestId('repl-result')).toHaveTextContent('Current value: 4821'));
});

test('help on its own explains the REPL and lists the documented APIs present in the target', async () => {
  const { input, type } = setup();
  type('help');
  fireEvent.keyDown(input, { key: 'Enter' });
  const res = await screen.findByTestId('repl-result');
  await waitFor(() => expect(res).toHaveTextContent('help <name>'));
  expect(res).toHaveTextContent('Process, ptr');
  expect(res).not.toHaveTextContent('Promise'); // not a Frida API
});

test('help for something unknown, or that is not a name, says so without running it', async () => {
  const { input, type } = setup();
  type('help nope');
  fireEvent.keyDown(input, { key: 'Enter' });
  await waitFor(() => expect(screen.getByTestId('repl-result')).toHaveTextContent('No help for “nope”'));
  type('help launch()');
  fireEvent.keyDown(input, { key: 'Enter' });
  await waitFor(() => expect(screen.getAllByTestId('repl-result')[1]).toHaveTextContent('No help for “launch()”'));
  expect(evaluate.mock.calls.some((c: any[]) => String(c[0]).includes('launch'))).toBe(false);
});

test('help still works from the live value when the documentation index is missing', async () => {
  const { input, type } = setup({ index: null });
  type('help Process');
  fireEvent.keyDown(input, { key: 'Enter' });
  const res = await screen.findByTestId('repl-result');
  await waitFor(() => expect(res).toHaveTextContent('Process — object'));
  expect(res).toHaveTextContent('enumerateModules()');
});

// Regression: Tab on an already-complete name inserted nothing, but left a
// "move the caret here" request pending; the NEXT keystroke then yanked the
// caret back into the middle of the entry and scrambled the typing.
test('Tab on an already-complete name does not move the caret on later typing', async () => {
  const { input, type, tab } = setup();
  type('Process.id');
  tab();
  await waitFor(() => expect(evaluate).toHaveBeenCalled());
  await new Promise((r) => setTimeout(r, 20));
  expect(input.value).toBe('Process.id');
  // The user keeps typing; the browser puts the caret at the end.
  fireEvent.change(input, { target: { value: 'Process.id + 1' } });
  expect(input.selectionStart).toBe('Process.id + 1'.length);
});

test('a listed completion whose shared prefix is already typed does not move the caret later either', async () => {
  const { input, type, tab } = setup();
  type('Process.enumerate'); // exactly the shared prefix of both matches
  tab();
  await waitFor(() => expect(choiceNames().length).toBe(2));
  fireEvent.change(input, { target: { value: 'Process.enumerateM' } });
  expect(input.selectionStart).toBe('Process.enumerateM'.length);
});

test('picking a choice that is already fully typed leaves the caret alone afterwards', async () => {
  const { input, type, tab } = setup();
  MEMBERS.Process.push({ name: 'idle', kind: 'property' });
  try {
    type('Process.id');
    tab(); // matches: id, idle
    await waitFor(() => expect(choiceNames()).toEqual(['id', 'idle']));
    fireEvent.click(screen.getAllByTestId('repl-choice')[0]); // "id": nothing to insert
    expect(input.value).toBe('Process.id');
    fireEvent.change(input, { target: { value: 'Process.id.toString' } });
    expect(input.selectionStart).toBe('Process.id.toString'.length);
  } finally { MEMBERS.Process.pop(); }
});
