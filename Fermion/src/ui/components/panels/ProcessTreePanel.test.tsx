import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import session, { sessionActions } from '../../store/sessionSlice';
import output from '../../store/outputSlice';
import ui, { uiActions } from '../../store/uiSlice';
import { setTerminalSink } from '../../bridge';
import { ProcessTreePanel } from './ProcessTreePanel';

/* eslint-disable @typescript-eslint/no-explicit-any */
const PROCS = [
  { pid: 4, name: 'System', parameters: { ppid: 0, user: 'SYSTEM' } },
  { pid: 1000, name: 'explorer.exe', parameters: { ppid: 900, user: 'me' } },
  { pid: 2000, name: 'chrome.exe', parameters: { ppid: 1000, user: 'me' } },
  { pid: 2001, name: 'chrome.exe', parameters: { ppid: 2000, user: 'me' } },
  { pid: 2100, name: 'notepad.exe', parameters: { ppid: 1000, user: 'me' } },
];

let calls: any[];
let procs: any[];
let lines: string[];
function setup({ active = true } = {}) {
  calls = [];
  procs = PROCS;
  lines = [];
  setTerminalSink({ write: (k: string, t: string) => { lines.push(k + ' ' + t); } });
  (window as any).MonacoCodeEditor = { getValue: () => 'SCRIPT' };
  (window as any).fermion = {
    enumerateProcesses: async () => { calls.push(['enumerateProcesses']); return procs; },
    attach: async (p: number) => { calls.push(['attach', p]); },
    getState: async () => ({ deviceId: 'local', isAttached: true, hasScript: false, currentPid: '2100' }),
    loadScript: async (s: string) => { calls.push(['loadScript', s]); },
  };
  const store = configureStore({ reducer: { session, output, ui } });
  if (active) store.dispatch(uiActions.setActiveTab('tree'));
  render(<Provider store={store}><ProcessTreePanel /></Provider>);
  return store;
}
const rowPids = () => screen.queryAllByRole('treeitem').map((r) => Number(r.getAttribute('data-pid')));
const row = (pid: number) => screen.getByTestId('proc-' + pid);

afterEach(() => setTerminalSink(null));

test('lists processes as a hierarchy once the tab is shown, with pid and user', async () => {
  setup();
  await waitFor(() => expect(rowPids()).toEqual([4, 1000, 2000, 2001, 2100]));
  expect(row(2001)).toHaveAttribute('aria-level', '3');
  expect(row(1000)).toHaveAttribute('aria-level', '1');
  expect(within(row(2100)).getByText('notepad.exe')).toBeInTheDocument();
  expect(within(row(2100)).getByText('2100')).toBeInTheDocument();
  expect(within(row(2100)).getByText('me')).toBeInTheDocument();
  expect(screen.getByTestId('tree-count')).toHaveTextContent('5 processes');
});

test('does not enumerate processes while its tab is hidden; loads when the tab is opened', async () => {
  const store = setup({ active: false });
  await new Promise((r) => setTimeout(r, 20));
  expect(calls).toEqual([]);
  act(() => { store.dispatch(uiActions.setActiveTab('tree')); });
  await waitFor(() => expect(rowPids().length).toBe(5));
});

test('refresh re-enumerates; changing device re-enumerates', async () => {
  const store = setup();
  await waitFor(() => expect(rowPids().length).toBe(5));
  procs = PROCS.slice(0, 2);
  fireEvent.click(screen.getByTestId('tree-refresh'));
  await waitFor(() => expect(rowPids()).toEqual([4, 1000]));
  procs = PROCS;
  act(() => { store.dispatch(sessionActions.setDevice('usb@1')); });
  await waitFor(() => expect(rowPids().length).toBe(5));
});

test('filter narrows to matches plus their parents; no match says so', async () => {
  setup();
  await waitFor(() => expect(rowPids().length).toBe(5));
  fireEvent.change(screen.getByTestId('tree-filter'), { target: { value: 'notepad' } });
  expect(rowPids()).toEqual([1000, 2100]);
  expect(row(2100)).toHaveClass('match');
  fireEvent.change(screen.getByTestId('tree-filter'), { target: { value: 'zzz' } });
  expect(rowPids()).toEqual([]);
  expect(screen.getByText(/No process matches/)).toBeInTheDocument();
});

test('a branch can be collapsed and expanded', async () => {
  setup();
  await waitFor(() => expect(rowPids().length).toBe(5));
  fireEvent.click(within(row(1000)).getByTestId('twisty'));
  expect(rowPids()).toEqual([4, 1000]);
  expect(row(1000)).toHaveAttribute('aria-expanded', 'false');
  fireEvent.click(within(row(1000)).getByTestId('twisty'));
  expect(rowPids().length).toBe(5);
});

test('attach from a row: attaches, loads the editor script, and marks the row attached', async () => {
  const store = setup();
  await waitFor(() => expect(rowPids().length).toBe(5));
  fireEvent.click(within(row(2100)).getByTestId('row-attach'));
  await waitFor(() => expect(store.getState().session.hasScript).toBe(true));
  expect(calls).toContainEqual(['attach', 2100]);
  expect(calls).toContainEqual(['loadScript', 'SCRIPT']);
  expect(store.getState().session.currentPid).toBe('2100');
  expect(row(2100)).toHaveClass('attached');
  // While attached, no row offers attach.
  expect(screen.queryByTestId('row-attach')).toBeNull();
});

test('double-clicking a row attaches too', async () => {
  setup();
  await waitFor(() => expect(rowPids().length).toBe(5));
  fireEvent.doubleClick(row(2000));
  await waitFor(() => expect(calls).toContainEqual(['attach', 2000]));
});

test('a failed attach is reported in Output and leaves the session unattached', async () => {
  const store = setup();
  (window as any).fermion.attach = async () => { throw new Error('access denied'); };
  await waitFor(() => expect(rowPids().length).toBe(5));
  fireEvent.click(within(row(4)).getByTestId('row-attach'));
  await waitFor(() => expect(lines.some((l) => l.startsWith('ERR') && l.includes('access denied'))).toBe(true));
  expect(store.getState().session.isAttached).toBe(false);
  expect(calls.find((c) => c[0] === 'loadScript')).toBeUndefined();
});

test('"only ancestry" is offered when attached and shows just the attached process line', async () => {
  const store = setup();
  await waitFor(() => expect(rowPids().length).toBe(5));
  expect(screen.getByTestId('tree-ancestry')).toBeDisabled();
  act(() => { store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '2000' })); });
  expect(screen.getByTestId('tree-ancestry')).not.toBeDisabled();
  fireEvent.click(screen.getByTestId('tree-ancestry'));
  expect(rowPids()).toEqual([1000, 2000, 2001]);
  expect(row(2000)).toHaveClass('attached');
  // Detaching turns the restriction off again rather than leaving an empty tree.
  act(() => { store.dispatch(sessionActions.detached()); });
  expect(rowPids().length).toBe(5);
});

test('a device that reports no parent pids gets a flat list and a note', async () => {
  setup();
  procs = [{ pid: 1, name: 'a', parameters: {} }, { pid: 2, name: 'b', parameters: {} }];
  fireEvent.click(screen.getByTestId('tree-refresh'));
  await waitFor(() => expect(rowPids()).toEqual([1, 2]));
  expect(screen.getByText(/does not report parent processes/)).toBeInTheDocument();
});

test('an enumeration failure is shown in the panel, not thrown', async () => {
  setup();
  await waitFor(() => expect(rowPids().length).toBe(5));
  (window as any).fermion.enumerateProcesses = async () => { throw new Error('device lost'); };
  fireEvent.click(screen.getByTestId('tree-refresh'));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('device lost'));
});
