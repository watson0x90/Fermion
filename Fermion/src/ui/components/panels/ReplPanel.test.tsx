import { render, screen, fireEvent, waitFor, act, within } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session, { sessionActions } from '../../store/sessionSlice';
import output from '../../store/outputSlice';
import ui, { uiActions } from '../../store/uiSlice';
import { setTerminalSink } from '../../bridge';
import { onAddressMenu } from '../../addressMenu';
import { ReplPanel } from './ReplPanel';

/* eslint-disable @typescript-eslint/no-explicit-any */
let evaluate: any;
let lines: string[];
function setup({ attached = true } = {}) {
  lines = [];
  setTerminalSink({ write: (k: string, t: string) => { lines.push(k + ' ' + t); } });
  evaluate = vi.fn(async (code: string) => ({ ok: true, type: 'number', text: 'result(' + code + ')' }));
  (window as any).fermion = { evaluate };
  const store = configureStore({ reducer: { session, output, ui } });
  if (attached) store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '4821' }));
  render(<Provider store={store}><ReplPanel /></Provider>);
  const input = screen.getByTestId('repl-input') as HTMLTextAreaElement;
  const type = (v: string) => fireEvent.change(input, { target: { value: v } });
  const key = (k: string, extra = {}) => fireEvent.keyDown(input, { key: k, ...extra });
  const run = async (code: string) => {
    type(code); key('Enter');
    await waitFor(() => expect(screen.getByTestId('repl-input')).not.toBeDisabled());
  };
  return { store, input, type, key, run };
}
afterEach(() => setTerminalSink(null));

test('not attached: the input is disabled and says why', () => {
  const { input } = setup({ attached: false });
  expect(input).toBeDisabled();
  expect(screen.getByTestId('repl-panel')).toHaveTextContent(/Attach to a process/);
});

test('Enter evaluates the entry in the attached process and shows input + result', async () => {
  const { input, run } = setup();
  expect(input).not.toBeDisabled();
  await run('Process.id');
  expect(evaluate).toHaveBeenCalledWith('Process.id');
  const entries = screen.getAllByTestId('repl-entry');
  expect(entries.length).toBe(1);
  expect(entries[0]).toHaveTextContent('Process.id');
  expect(screen.getByTestId('repl-result')).toHaveTextContent('result(Process.id)');
  expect(screen.getByTestId('repl-result')).toHaveClass('ok');
  expect(input.value).toBe(''); // ready for the next entry
});

test('an error result is shown as an error, with its stack available', async () => {
  const { run } = setup();
  evaluate.mockResolvedValueOnce({ ok: false, error: 'TypeError: x is null', stack: 'TypeError: x is null\n    at <eval>' });
  await run('x.y');
  const res = screen.getByTestId('repl-result');
  expect(res).toHaveClass('err');
  expect(res).toHaveTextContent('TypeError: x is null');
  expect(res).toHaveAttribute('title', expect.stringContaining('at <eval>'));
});

test('a failed call (IPC rejected) is shown as an error and the input comes back', async () => {
  const { run, input } = setup();
  evaluate.mockRejectedValueOnce(new Error('Not attached to a process'));
  await run('1');
  expect(screen.getByTestId('repl-result')).toHaveClass('err');
  expect(screen.getByTestId('repl-result')).toHaveTextContent('Not attached to a process');
  expect(input).not.toBeDisabled();
});

test('blank entries are ignored; Shift+Enter adds a line instead of running', async () => {
  const { type, key, input } = setup();
  type('   '); key('Enter');
  expect(evaluate).not.toHaveBeenCalled();
  type('var a = 1;');
  key('Enter', { shiftKey: true });
  expect(evaluate).not.toHaveBeenCalled();
  expect(input.value).toBe('var a = 1;'); // the browser inserts the newline itself
});

test('while an entry is running the input is disabled, so entries cannot overlap', async () => {
  const { type, key, input } = setup();
  let finish: (v: unknown) => void = () => {};
  evaluate.mockImplementationOnce(() => new Promise((r) => { finish = r; }));
  type('slow()'); key('Enter');
  await waitFor(() => expect(input).toBeDisabled());
  expect(screen.getByTestId('repl-result')).toHaveTextContent(/running/);
  await act(async () => { finish({ ok: true, type: 'undefined', text: 'undefined' }); });
  await waitFor(() => expect(input).not.toBeDisabled());
  expect(screen.getByTestId('repl-result')).toHaveTextContent('undefined');
});

test('Up/Down walk the entry history; Down past the newest restores the draft', async () => {
  const { run, type, key, input } = setup();
  await run('first');
  await run('second');
  await run('second'); // no consecutive duplicate
  type('dra');
  key('ArrowUp'); expect(input.value).toBe('second');
  key('ArrowUp'); expect(input.value).toBe('first');
  key('ArrowUp'); expect(input.value).toBe('first');
  key('ArrowDown'); expect(input.value).toBe('second');
  key('ArrowDown'); expect(input.value).toBe('dra');
});

test('each entry and its result are also written to Output', async () => {
  const { run } = setup();
  await run('1+1');
  expect(lines).toContain('STATUS frida> 1+1');
  expect(lines).toContain('LOG result(1+1)');
  evaluate.mockResolvedValueOnce({ ok: false, error: 'boom', stack: '' });
  await run('bad');
  expect(lines).toContain('ERR boom');
});

test('Clear empties the transcript but keeps the history', async () => {
  const { run, key, input } = setup();
  await run('keep-me');
  fireEvent.click(screen.getByTestId('repl-clear'));
  expect(screen.queryAllByTestId('repl-entry').length).toBe(0);
  key('ArrowUp');
  expect(input.value).toBe('keep-me');
});

test('detaching disables the input again but keeps the transcript', async () => {
  const { run, store, input } = setup();
  await run('1');
  act(() => { store.dispatch(sessionActions.detached()); });
  expect(input).toBeDisabled();
  expect(screen.getAllByTestId('repl-entry').length).toBe(1);
});

test('a result that arrives after Clear does not resurrect the entry', async () => {
  const { type, key } = setup();
  let finish: (v: unknown) => void = () => {};
  evaluate.mockImplementationOnce(() => new Promise((r) => { finish = r; }));
  type('slow()'); key('Enter');
  await waitFor(() => expect(screen.getAllByTestId('repl-entry').length).toBe(1));
  fireEvent.click(screen.getByTestId('repl-clear'));
  await act(async () => { finish({ ok: true, type: 'number', text: '1' }); });
  expect(screen.queryAllByTestId('repl-entry').length).toBe(0);
});

test('a running entry can be cancelled with the Cancel button; the prompt comes back', async () => {
  const { type, key, input } = setup();
  let finish: (v: unknown) => void = () => {};
  evaluate.mockImplementationOnce(() => new Promise((r) => { finish = r; }));
  const cancelEvaluate = vi.fn(async () => {
    // The service ends the waiting entry as cancelled.
    finish({ ok: false, cancelled: true, error: 'Cancelled. The REPL was restarted, so its variables are gone.', stack: '' });
    return true;
  });
  (window as any).fermion.cancelEvaluate = cancelEvaluate;

  expect(screen.queryByTestId('repl-cancel')).toBeNull(); // nothing running
  type('while (true) {}'); key('Enter');
  const btn = await screen.findByTestId('repl-cancel');
  fireEvent.click(btn);
  expect(cancelEvaluate).toHaveBeenCalledTimes(1);
  await waitFor(() => expect(input).not.toBeDisabled());
  expect(screen.getByTestId('repl-result')).toHaveClass('err');
  expect(screen.getByTestId('repl-result')).toHaveTextContent(/Cancelled/);
  expect(screen.queryByTestId('repl-cancel')).toBeNull();
  // A cancelled entry is the user's own doing: it is not reported as an error in Output.
  expect(lines.some((l) => l.startsWith('ERR'))).toBe(false);
  expect(lines).toContain('STATUS [REPL] entry cancelled');
});

test('Escape cancels a running entry too; with nothing running it does nothing', async () => {
  const { type, key, store } = setup();
  act(() => { store.dispatch(uiActions.setActiveTab('repl')); }); // Escape only acts while the REPL is showing
  const cancelEvaluate = vi.fn(async () => true);
  (window as any).fermion.cancelEvaluate = cancelEvaluate;
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(cancelEvaluate).not.toHaveBeenCalled();
  evaluate.mockImplementationOnce(() => new Promise(() => {}));
  type('slow()'); key('Enter');
  await screen.findByTestId('repl-cancel');
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(cancelEvaluate).toHaveBeenCalledTimes(1);
});

// ---- expandable results ----
// The placeholder shown while an entry runs is replaced when its tree arrives.
const treeResult = async () => { await screen.findAllByTestId('value-node'); return screen.getByTestId('repl-result'); };
const MODULE_TREE = {
  t: 'obj', label: 'Object', n: 3, kids: [
    { k: 'name', v: { t: 'str', v: 'kernel32.dll' } },
    { k: 'base', v: { t: 'ptr', v: '0x7ff0' } },
    { k: 'exports', v: { t: 'arr', n: 2, kids: [{ k: '0', v: { t: 'str', v: 'CreateFileW' } }, { k: '1', v: { t: 'str', v: 'ReadFile' } }], more: 498 } },
  ],
};

test('a result with parts is shown as a tree: the top level open, containers inside it closed', async () => {
  const { type, key } = setup();
  evaluate.mockResolvedValueOnce({ ok: true, type: 'object', text: '{\n  "name": "kernel32.dll"\n}', tree: MODULE_TREE });
  type('mod'); key('Enter');
  const result = await treeResult();
  await waitFor(() => expect(result).toHaveTextContent('name: "kernel32.dll"'));
  expect(result).toHaveTextContent('base: 0x7ff0');
  expect(result).toHaveTextContent('exports: Array(2) ["CreateFileW", "ReadFile", …]');
  expect(result).not.toHaveTextContent('0: "CreateFileW"');
  // The printed form is what goes to Output.
  expect(lines).toContain('LOG {\n  "name": "kernel32.dll"\n}');
});

test('a closed container opens to show its children and how many were left out', async () => {
  const { type, key } = setup();
  evaluate.mockResolvedValueOnce({ ok: true, type: 'object', text: '{}', tree: MODULE_TREE });
  type('mod'); key('Enter');
  const result = await treeResult();
  const inner = within(result).getAllByRole('button', { expanded: false })[0];
  fireEvent.click(inner);
  expect(result).toHaveTextContent('0: "CreateFileW"');
  expect(result).toHaveTextContent('1: "ReadFile"');
  expect(result).toHaveTextContent('… 498 more not shown');
  fireEvent.click(within(result).getAllByRole('button', { expanded: true })[1]);
  expect(result).not.toHaveTextContent('0: "CreateFileW"');
});

test('a pointer in a result is an address: clicking it opens the address menu', async () => {
  const { type, key } = setup();
  const opened: string[] = [];
  const off = onAddressMenu((r) => { if (r) opened.push(r.address); });
  evaluate.mockResolvedValueOnce({ ok: true, type: 'object', text: '{}', tree: MODULE_TREE });
  type('mod'); key('Enter');
  const pointer = await screen.findByTestId('value-pointer');
  expect(pointer).toHaveTextContent('0x7ff0');
  fireEvent.click(pointer);
  fireEvent.contextMenu(pointer);
  expect(opened).toEqual(['0x7ff0', '0x7ff0']);
  off();
});

test('a tree the target sends in a shape we do not know is ignored: the text is shown', async () => {
  const { type, key } = setup();
  evaluate.mockResolvedValueOnce({ ok: true, type: 'object', text: 'plain text', tree: { t: 'html', v: '<img src=x>' } });
  type('x'); key('Enter');
  await waitFor(() => expect(screen.getByTestId('repl-result')).toHaveTextContent('plain text'));
  expect(screen.queryByTestId('value-node')).toBeNull();
});

test('text inside a tree is shown as text, never as markup', async () => {
  const { type, key } = setup();
  evaluate.mockResolvedValueOnce({ ok: true, type: 'object', text: '{}', tree: { t: 'obj', label: 'Object', n: 1, kids: [{ k: '<b>k</b>', v: { t: 'str', v: '<img src=x onerror=alert(1)>' } }] } });
  type('x'); key('Enter');
  const result = await treeResult();
  await waitFor(() => expect(result).toHaveTextContent('<b>k</b>: "<img src=x onerror=alert(1)>"'));
  expect(result.querySelector('img')).toBeNull();
  expect(result.querySelector('b')).toBeNull();
});
