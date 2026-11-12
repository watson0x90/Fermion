import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session, { sessionActions } from '../../store/sessionSlice';
import output from '../../store/outputSlice';
import ui, { uiActions } from '../../store/uiSlice';
import { InspectorPanel } from './InspectorPanel';

/* eslint-disable @typescript-eslint/no-explicit-any */
const list = (items: any[], extra = {}) => ({ items, total: items.length, truncated: false, ...extra });
const MODS = [
  { name: 'node.exe', base: '0x7ff62c710000', size: 92749824, path: 'C:\\node.exe' },
  { name: 'ntdll.dll', base: '0x7fff960d0000', size: 2539520, path: 'C:\\Windows\\ntdll.dll' },
];
const THREADS = [
  { id: 5156, name: 'MainThread', state: 'running', pc: '0x7fff962393d4', where: 'ntdll.dll+0x1693d4', registers: { pc: '0x7fff962393d4', sp: '0x10000', rax: '0x1' } },
  { id: 77, name: '', state: 'waiting', pc: '0x500', where: '0x500', registers: {} },
];
const HEX256 = '4d5a9000' + '00'.repeat(252);

let inspect: any;
function setup({ attached = true, active = true } = {}) {
  inspect = {
    modules: vi.fn(async () => list(MODS)),
    exports: vi.fn(async (m: string) => list([{ type: 'function', name: m + '_CreateFileW', address: '0x7fff960d1000' }, { type: 'variable', name: 'g_data', address: '0x7fff960d2000' }])),
    imports: vi.fn(async () => list([{ type: 'function', name: 'NtClose', module: 'ntdll.dll', address: '0x7fff960d3000' }])),
    threads: vi.fn(async () => list(THREADS)),
    backtrace: vi.fn(async () => list([{ address: '0x7fff933f294f', where: 'KERNELBASE.dll+0xc294f', symbol: 'KERNELBASE.dll!Sleep' }, { address: '0x500', where: '0x500', symbol: '' }])),
    ranges: vi.fn(async (p: string) => list([{ base: '0x1000', size: 4096, protection: p, file: 'C:\\Windows\\a.dll' }, { base: '0x9000', size: 8192, protection: p, file: '' }])),
    read: vi.fn(async (address: string, size: number) => ({ address, size, requested: size, hex: HEX256 })),
    scan: vi.fn(async () => ({ ...list([{ address: '0x1010', size: 2, where: 'a.dll+0x10' }]), stopped: '', rangesScanned: 2, rangesTotal: 2 })),
  };
  (window as any).fermion = { inspect };
  const store = configureStore({ reducer: { session, output, ui } });
  if (attached) store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '4821' }));
  if (active) store.dispatch(uiActions.setActiveTab('inspector'));
  render(<Provider store={store}><InspectorPanel /></Provider>);
  return store;
}
const open = (sub: string) => fireEvent.click(screen.getByTestId('insp-' + sub));

test('not attached: offers the three views but explains that a process is needed; nothing is queried', async () => {
  setup({ attached: false });
  for (const label of ['Modules', 'Memory', 'Threads']) expect(screen.getByRole('tab', { name: label })).toBeInTheDocument();
  expect(screen.getByTestId('inspector-panel')).toHaveTextContent(/Attach to a process/);
  await new Promise((r) => setTimeout(r, 20));
  expect(inspect.modules).not.toHaveBeenCalled();
});

test('nothing is queried while the Inspector tab itself is hidden', async () => {
  const store = setup({ active: false });
  await new Promise((r) => setTimeout(r, 20));
  expect(inspect.modules).not.toHaveBeenCalled();
  act(() => { store.dispatch(uiActions.setActiveTab('inspector')); });
  await waitFor(() => expect(inspect.modules).toHaveBeenCalledTimes(1));
});

test('Modules: lists name, base and size; only the visible view is loaded', async () => {
  setup();
  const row = await screen.findByTestId('mod-row-ntdll.dll');
  expect(within(row).getByText('0x7fff960d0000')).toBeInTheDocument();
  expect(within(row).getByText('2.4 MB')).toBeInTheDocument();
  expect(screen.getByTestId('mod-count')).toHaveTextContent('2 modules');
  expect(inspect.threads).not.toHaveBeenCalled();
  expect(inspect.ranges).not.toHaveBeenCalled();
});

test('Modules: filter, then select a module to see exports, switch to imports, filter symbols', async () => {
  setup();
  await screen.findByTestId('mod-row-ntdll.dll');
  fireEvent.change(screen.getByTestId('mod-filter'), { target: { value: 'ntdll' } });
  expect(screen.queryByTestId('mod-row-node.exe')).toBeNull();
  expect(screen.getByTestId('mod-count')).toHaveTextContent('1 of 2 modules');

  fireEvent.click(screen.getByTestId('mod-row-ntdll.dll'));
  await waitFor(() => expect(screen.getAllByTestId('sym-row').length).toBe(2));
  expect(inspect.exports).toHaveBeenCalledWith('ntdll.dll');
  expect(screen.getByTestId('mod-detail')).toHaveTextContent('ntdll.dll_CreateFileW');

  fireEvent.change(screen.getByTestId('sym-filter'), { target: { value: 'g_' } });
  expect(screen.getAllByTestId('sym-row').length).toBe(1);

  fireEvent.click(screen.getByTestId('sym-kind-imports'));
  await waitFor(() => expect(inspect.imports).toHaveBeenCalledWith('ntdll.dll'));
  fireEvent.change(screen.getByTestId('sym-filter'), { target: { value: '' } });
  await waitFor(() => expect(screen.getByTestId('mod-detail')).toHaveTextContent('NtClose'));
});

test('Modules: a truncated symbol list says how many are shown', async () => {
  setup();
  inspect.exports.mockResolvedValueOnce({ items: [{ type: 'function', name: 'a', address: '0x1' }], total: 50000, truncated: true });
  fireEvent.click(await screen.findByTestId('mod-row-node.exe'));
  await waitFor(() => expect(screen.getByTestId('mod-detail')).toHaveTextContent(/first 1 of 50,000 exports/));
});

test('Modules: an export address opens in the Memory tab, read from the start of its row and marked', async () => {
  setup();
  fireEvent.click(await screen.findByTestId('mod-row-ntdll.dll'));
  inspect.read.mockImplementation(async (address: string, size: number) => ({ address, size, requested: size, hex: HEX256 }));
  fireEvent.click((await screen.findAllByTestId('sym-addr'))[0]);
  expect(screen.getByTestId('insp-memory')).toHaveAttribute('aria-selected', 'true');
  await waitFor(() => expect(inspect.read).toHaveBeenCalledWith('0x7fff960d1000', 256));
  await waitFor(() => expect(screen.getAllByTestId('hex-row').length).toBe(16));
  expect((screen.getByTestId('mem-addr') as HTMLInputElement).value).toBe('0x7fff960d1000');
  expect(screen.getAllByTestId('hex-row')[0].querySelectorAll('.hl').length).toBe(1);
});

test('Memory: ranges list; choosing a range reads it into the hex view; paging moves by 256 bytes', async () => {
  setup();
  open('memory');
  await waitFor(() => expect(screen.getAllByTestId('range-row').length).toBe(2));
  expect(inspect.ranges).toHaveBeenCalledWith('r--');
  expect(screen.getAllByTestId('range-row')[0]).toHaveTextContent('a.dll');
  expect(screen.queryAllByTestId('hex-row').length).toBe(0);

  fireEvent.click(screen.getAllByTestId('range-row')[0]);
  await waitFor(() => expect(inspect.read).toHaveBeenCalledWith('0x1000', 256));
  await waitFor(() => expect(screen.getAllByTestId('hex-row').length).toBe(16));
  expect(screen.getAllByTestId('hex-row')[0]).toHaveTextContent('0x1000');
  expect(screen.getAllByTestId('hex-row')[0]).toHaveTextContent('MZ');

  fireEvent.click(screen.getByTestId('mem-next'));
  await waitFor(() => expect(inspect.read).toHaveBeenLastCalledWith('0x1100', 256));
  fireEvent.click(screen.getByTestId('mem-prev'));
  await waitFor(() => expect(inspect.read).toHaveBeenLastCalledWith('0x1000', 256));
});

test('Memory: changing protection re-lists ranges', async () => {
  setup();
  open('memory');
  await waitFor(() => expect(inspect.ranges).toHaveBeenCalledWith('r--'));
  fireEvent.change(screen.getByTestId('range-prot'), { target: { value: 'r-x' } });
  await waitFor(() => expect(inspect.ranges).toHaveBeenCalledWith('r-x'));
});

test('Memory: Go accepts hex with or without 0x; a bad address is refused without calling the target', async () => {
  setup();
  open('memory');
  fireEvent.change(screen.getByTestId('mem-addr'), { target: { value: 'not-an-address' } });
  fireEvent.click(screen.getByTestId('mem-go'));
  expect(screen.getByRole('alert')).toHaveTextContent(/hex address/);
  expect(inspect.read).not.toHaveBeenCalled();

  fireEvent.change(screen.getByTestId('mem-addr'), { target: { value: '7FF123' } });
  fireEvent.keyDown(screen.getByTestId('mem-addr'), { key: 'Enter' });
  await waitFor(() => expect(inspect.read).toHaveBeenCalledWith('0x7ff120', 256)); // start of its row
});

test('Memory: unreadable memory shows the error; a short read says how much was readable', async () => {
  setup();
  open('memory');
  inspect.read.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:invoke': Error: Cannot read memory at 0x10: access violation"));
  fireEvent.change(screen.getByTestId('mem-addr'), { target: { value: '0x10' } });
  fireEvent.click(screen.getByTestId('mem-go'));
  await waitFor(() => expect(screen.getByTestId('hex-error')).toHaveTextContent('Cannot read memory at 0x10: access violation'));
  expect(screen.getByTestId('hex-error').textContent).not.toMatch(/remote method/);

  inspect.read.mockResolvedValueOnce({ address: '0x2000', size: 64, requested: 256, hex: '00'.repeat(64) });
  fireEvent.change(screen.getByTestId('mem-addr'), { target: { value: '0x2000' } });
  fireEvent.click(screen.getByTestId('mem-go'));
  await waitFor(() => expect(screen.getByTestId('hexview')).toHaveTextContent(/Only 64 of 256 bytes are readable/));
});

test('Memory scan: hex pattern is normalized, results listed, and a result opens marked in the hex view', async () => {
  setup();
  open('memory');
  fireEvent.click(screen.getByTestId('mem-mode-scan'));
  fireEvent.change(screen.getByTestId('scan-pattern'), { target: { value: '4D5A??00' } });
  fireEvent.click(screen.getByTestId('scan-run'));
  await waitFor(() => expect(inspect.scan).toHaveBeenCalledWith('4d 5a ?? 00', 'r--'));
  await waitFor(() => expect(screen.getByTestId('scan-status')).toHaveTextContent('1 match in 2 of 2 ranges'));
  fireEvent.click(screen.getByTestId('scan-row'));
  await waitFor(() => expect(inspect.read).toHaveBeenCalledWith('0x1010', 256));
  await waitFor(() => expect(screen.getAllByTestId('hex-row')[0].querySelectorAll('.hl').length).toBe(2)); // the 2 matched bytes
});

test('Memory scan: text mode scans for the UTF-8 bytes; an invalid hex pattern is refused locally', async () => {
  setup();
  open('memory');
  fireEvent.click(screen.getByTestId('mem-mode-scan'));
  fireEvent.change(screen.getByTestId('scan-pattern'), { target: { value: 'xyz' } });
  fireEvent.click(screen.getByTestId('scan-run'));
  expect(screen.getByRole('alert')).toHaveTextContent(/hex bytes/);
  expect(inspect.scan).not.toHaveBeenCalled();

  fireEvent.change(screen.getByTestId('scan-as'), { target: { value: 'text' } });
  fireEvent.change(screen.getByTestId('scan-pattern'), { target: { value: 'MZ' } });
  fireEvent.keyDown(screen.getByTestId('scan-pattern'), { key: 'Enter' });
  await waitFor(() => expect(inspect.scan).toHaveBeenCalledWith('4d 5a', 'r--'));
});

test('Memory scan: a stopped scan says why', async () => {
  setup();
  open('memory');
  fireEvent.click(screen.getByTestId('mem-mode-scan'));
  inspect.scan.mockResolvedValueOnce({ items: [], total: 0, truncated: true, stopped: 'time', rangesScanned: 3, rangesTotal: 400 });
  fireEvent.change(screen.getByTestId('scan-pattern'), { target: { value: '00 00' } });
  fireEvent.click(screen.getByTestId('scan-run'));
  await waitFor(() => expect(screen.getByTestId('scan-status')).toHaveTextContent(/0 matches in 3 of 400 ranges — stopped at the time limit/));
});

test('Threads: lists tid, state and where; selecting one shows registers and a backtrace', async () => {
  setup();
  open('threads');
  const row = await screen.findByTestId('thr-row-5156');
  expect(row).toHaveTextContent('running');
  expect(row).toHaveTextContent('ntdll.dll+0x1693d4');
  expect(inspect.backtrace).not.toHaveBeenCalled();

  fireEvent.click(row);
  await waitFor(() => expect(inspect.backtrace).toHaveBeenCalledWith(5156));
  expect(screen.getByTestId('reg-rax')).toHaveTextContent('0x1');
  await waitFor(() => expect(screen.getAllByTestId('bt-row').length).toBe(2));
  expect(screen.getAllByTestId('bt-row')[0]).toHaveTextContent('KERNELBASE.dll!Sleep');
  expect(screen.getAllByTestId('bt-row')[1]).toHaveTextContent('0x500'); // no symbol: falls back to where
});

test('Threads: a register value opens in the Memory tab; a thread without context says so', async () => {
  setup();
  open('threads');
  fireEvent.click(await screen.findByTestId('thr-row-77'));
  expect(screen.getByTestId('thr-registers')).toHaveTextContent(/No register context/);
  fireEvent.click(screen.getByTestId('thr-row-5156'));
  fireEvent.click(screen.getByTestId('reg-sp'));
  expect(screen.getByTestId('insp-memory')).toHaveAttribute('aria-selected', 'true');
  await waitFor(() => expect(inspect.read).toHaveBeenCalledWith('0x10000', 256));
});

test('a listing failure is shown in the view, with the IPC wrapper stripped', async () => {
  setup();
  inspect.threads.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:invoke': Error: script is destroyed"));
  open('threads');
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Could not list threads: script is destroyed'));
});

test('a new session starts every view from scratch (no stale modules or hex view)', async () => {
  const store = setup();
  fireEvent.click(await screen.findByTestId('mod-row-ntdll.dll'));
  fireEvent.click((await screen.findAllByTestId('sym-addr'))[0]);
  await waitFor(() => expect(screen.getAllByTestId('hex-row').length).toBe(16));

  act(() => { store.dispatch(sessionActions.detached()); });
  expect(screen.queryByTestId('hex-row')).toBeNull();
  inspect.read.mockClear();
  act(() => { store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '9999' })); });
  open('memory');
  await waitFor(() => expect(inspect.ranges).toHaveBeenCalled());
  expect(screen.queryByTestId('hex-row')).toBeNull();
  expect(inspect.read).not.toHaveBeenCalled(); // the old address is not re-read in the new process
  expect((screen.getByTestId('mem-addr') as HTMLInputElement).value).toBe('');
});

test('Modules: selecting another module clears the previous module symbols while the new ones load', async () => {
  setup();
  fireEvent.click(await screen.findByTestId('mod-row-ntdll.dll'));
  await waitFor(() => expect(screen.getAllByTestId('sym-row').length).toBe(2));
  let finish: (v: unknown) => void = () => {};
  inspect.exports.mockImplementationOnce(() => new Promise((r) => { finish = r; }));
  fireEvent.click(screen.getByTestId('mod-row-node.exe'));
  // node.exe header must not sit above ntdll.dll's (clickable) exports.
  await waitFor(() => expect(screen.queryAllByTestId('sym-row').length).toBe(0));
  await act(async () => { finish(list([{ type: 'function', name: 'node_main', address: '0x7ff62c711000' }])); });
  await waitFor(() => expect(screen.getByTestId('mod-detail')).toHaveTextContent('node_main'));
});

test('Memory scan: a pattern with fewer than two concrete bytes, or one character of text, is refused locally', async () => {
  setup();
  open('memory');
  fireEvent.click(screen.getByTestId('mem-mode-scan'));
  fireEvent.change(screen.getByTestId('scan-pattern'), { target: { value: '00' } });
  fireEvent.click(screen.getByTestId('scan-run'));
  expect(screen.getByRole('alert')).toHaveTextContent(/at least two/);
  fireEvent.change(screen.getByTestId('scan-as'), { target: { value: 'text' } });
  fireEvent.change(screen.getByTestId('scan-pattern'), { target: { value: 'M' } });
  fireEvent.click(screen.getByTestId('scan-run'));
  expect(screen.getByRole('alert')).toHaveTextContent(/at least two/);
  expect(inspect.scan).not.toHaveBeenCalled();
});

test('Memory: paging at the top of the address space stays row-aligned', async () => {
  setup();
  open('memory');
  fireEvent.change(screen.getByTestId('mem-addr'), { target: { value: '0xffffffffffffff80' } });
  fireEvent.click(screen.getByTestId('mem-go'));
  await waitFor(() => expect(inspect.read).toHaveBeenLastCalledWith('0xffffffffffffff80', 256));
  fireEvent.click(screen.getByTestId('mem-next'));
  await waitFor(() => expect(inspect.read).toHaveBeenLastCalledWith('0xfffffffffffffff0', 256));
});

test('Memory: Go on the address already shown reads it again (memory changes)', async () => {
  setup();
  open('memory');
  fireEvent.change(screen.getByTestId('mem-addr'), { target: { value: '0x2000' } });
  fireEvent.click(screen.getByTestId('mem-go'));
  await waitFor(() => expect(inspect.read).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByTestId('mem-go'));
  await waitFor(() => expect(inspect.read).toHaveBeenCalledTimes(2));
});

test('re-attaching to the same pid does not replay the previous session address in Memory', async () => {
  const store = setup();
  fireEvent.click(await screen.findByTestId('mod-row-ntdll.dll'));
  fireEvent.click((await screen.findAllByTestId('sym-addr'))[0]);
  await waitFor(() => expect(inspect.read).toHaveBeenCalled());
  act(() => { store.dispatch(sessionActions.detached()); });
  inspect.read.mockClear();
  act(() => { store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '4821' })); }); // same pid again
  open('memory');
  await waitFor(() => expect(inspect.ranges).toHaveBeenCalled());
  await new Promise((r) => setTimeout(r, 20));
  expect(inspect.read).not.toHaveBeenCalled();
});

test('Threads: Auto re-reads the list every couple of seconds while the view is open, and stops when turned off', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    setup();
    open('threads');
    await waitFor(() => expect(inspect.threads).toHaveBeenCalledTimes(1));
    await act(async () => { vi.advanceTimersByTime(6000); });
    expect(inspect.threads).toHaveBeenCalledTimes(1); // not automatic by default

    fireEvent.click(screen.getByTestId('thr-auto'));
    expect(screen.getByTestId('thr-auto')).toHaveAttribute('aria-pressed', 'true');
    await act(async () => { vi.advanceTimersByTime(2100); });
    await waitFor(() => expect(inspect.threads.mock.calls.length).toBeGreaterThanOrEqual(2));
    await act(async () => { vi.advanceTimersByTime(2100); });
    await waitFor(() => expect(inspect.threads.mock.calls.length).toBeGreaterThanOrEqual(3)); // and it keeps going

    // Leaving the view pauses it; coming back resumes.
    open('modules');
    const n = inspect.threads.mock.calls.length;
    await act(async () => { vi.advanceTimersByTime(6000); });
    expect(inspect.threads).toHaveBeenCalledTimes(n);

    open('threads');
    // Coming back re-reads once straight away; let that land before counting.
    await waitFor(() => expect(inspect.threads.mock.calls.length).toBeGreaterThan(n));
    fireEvent.click(screen.getByTestId('thr-auto')); // Auto off
    await act(async () => { vi.advanceTimersByTime(50); });
    const m = inspect.threads.mock.calls.length;
    await act(async () => { vi.advanceTimersByTime(6000); });
    expect(inspect.threads).toHaveBeenCalledTimes(m);
  } finally { vi.useRealTimers(); }
});

test('Threads: a slow listing is not piled up on by Auto', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    setup();
    open('threads');
    await waitFor(() => expect(inspect.threads).toHaveBeenCalledTimes(1));
    inspect.threads.mockImplementation(() => new Promise(() => {})); // never answers
    fireEvent.click(screen.getByTestId('thr-auto'));
    await act(async () => { vi.advanceTimersByTime(2100); });
    await waitFor(() => expect(inspect.threads).toHaveBeenCalledTimes(2));
    await act(async () => { vi.advanceTimersByTime(10000); });
    expect(inspect.threads).toHaveBeenCalledTimes(2); // still waiting on the first
  } finally { vi.useRealTimers(); }
});

test('Memory: Auto keeps re-reading the bytes on screen', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    setup();
    open('memory');
    fireEvent.change(screen.getByTestId('mem-addr'), { target: { value: '0x2000' } });
    fireEvent.click(screen.getByTestId('mem-go'));
    await waitFor(() => expect(inspect.read).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByTestId('mem-auto'));
    await act(async () => { vi.advanceTimersByTime(2100); });
    await waitFor(() => expect(inspect.read).toHaveBeenCalledTimes(2));
    expect(inspect.read).toHaveBeenLastCalledWith('0x2000', 256);
  } finally { vi.useRealTimers(); }
});
