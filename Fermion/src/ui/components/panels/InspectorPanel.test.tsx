import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session, { sessionActions } from '../../store/sessionSlice';
import output from '../../store/outputSlice';
import ui, { uiActions } from '../../store/uiSlice';
import bookmarks, { bookmarksActions } from '../../store/bookmarksSlice';
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
let exportFile: any;
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
    follow: vi.fn(async (id: number, scope: any) => ({ following: true, threadId: id, maxSeconds: 15, scope, excluded: scope?.mode === 'all' ? 0 : 40 })),
    unfollow: vi.fn(async () => ({ following: false, threadId: 5156, calls: 1234, total: 2, truncated: false, endedBy: 'stop', scope: { mode: 'all', module: '' }, modules: [{ name: 'ntdll.dll', calls: 1000, functions: 1 }, { name: '', calls: 234, functions: 1 }], items: [{ address: '0x7fff96125a70', name: 'ntdll.dll!RtlSizeHeap', module: 'ntdll.dll', count: 1000 }, { address: '0x500', name: '0x500', module: '', count: 234 }] })),
  };
  exportFile = vi.fn(async () => 'C:/calls.csv');
  (window as any).fermion = { inspect, exportFile };
  const store = configureStore({ reducer: { session, output, ui, bookmarks } });
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

test('Threads: Follow counts the calls a thread makes; Stop shows them, most-called first', async () => {
  setup();
  open('threads');
  fireEvent.click(await screen.findByTestId('thr-row-5156'));
  const follow = await screen.findByTestId('thr-follow');
  expect(follow).toHaveTextContent('Follow');
  fireEvent.click(follow);
  await waitFor(() => expect(inspect.follow).toHaveBeenCalledWith(5156, { mode: 'all', module: '' }));
  await waitFor(() => expect(screen.getByTestId('thr-follow')).toHaveTextContent('Stop'));
  expect(screen.getByTestId('thr-follow-status')).toHaveTextContent(/Following thread 5156/);
  // Another thread cannot be followed meanwhile.
  fireEvent.click(screen.getByTestId('thr-row-77'));
  expect(screen.getByTestId('thr-follow')).toHaveTextContent('Stop');

  fireEvent.click(screen.getByTestId('thr-follow'));
  await waitFor(() => expect(inspect.unfollow).toHaveBeenCalledTimes(1));
  const rows = await screen.findAllByTestId('follow-row');
  expect(rows.length).toBe(2);
  expect(rows[0]).toHaveTextContent('ntdll.dll!RtlSizeHeap');
  expect(rows[0]).toHaveTextContent('1,000');
  expect(screen.getByTestId('thr-follow-status')).toHaveTextContent('1,234 calls to 2 functions');
  expect(screen.getByTestId('thr-follow')).toHaveTextContent('Follow');
});

test('Threads: a follow that ended at the time limit, or was cut short, says so', async () => {
  setup();
  open('threads');
  fireEvent.click(await screen.findByTestId('thr-row-5156'));
  inspect.unfollow.mockResolvedValueOnce({ following: false, threadId: 5156, calls: 90000, total: 6000, truncated: true, endedBy: 'limit', items: [{ address: '0x1', name: 'a!b', count: 9 }] });
  fireEvent.click(await screen.findByTestId('thr-follow'));
  await waitFor(() => expect(screen.getByTestId('thr-follow')).toHaveTextContent('Stop'));
  fireEvent.click(screen.getByTestId('thr-follow'));
  await waitFor(() => expect(screen.getByTestId('thr-follow-status')).toHaveTextContent(/stopped at the 15 second limit/));
  expect(screen.getByTestId('thr-follow-status')).toHaveTextContent(/showing the 1 most-called/);
});

test('Threads: a follow that cannot start is reported and leaves Follow available', async () => {
  setup();
  open('threads');
  fireEvent.click(await screen.findByTestId('thr-row-5156'));
  inspect.follow.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:invoke': Error: That is Frida's own thread; it cannot be followed."));
  fireEvent.click(await screen.findByTestId('thr-follow'));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent("That is Frida's own thread; it cannot be followed."));
  expect(screen.getByTestId('thr-follow')).toHaveTextContent('Follow');
  expect(inspect.unfollow).not.toHaveBeenCalled();
});

test('Threads: clicking a followed function opens it in Memory', async () => {
  setup();
  open('threads');
  fireEvent.click(await screen.findByTestId('thr-row-5156'));
  fireEvent.click(await screen.findByTestId('thr-follow'));
  await waitFor(() => expect(screen.getByTestId('thr-follow')).toHaveTextContent('Stop'));
  fireEvent.click(screen.getByTestId('thr-follow'));
  const rows = await screen.findAllByTestId('follow-row');
  fireEvent.click(within(rows[0]).getByRole('button'));
  expect(screen.getByTestId('insp-memory')).toHaveAttribute('aria-selected', 'true');
  await waitFor(() => expect(inspect.read).toHaveBeenCalledWith('0x7fff96125a70', 256));
});

// ---- limiting what a follow covers ----
async function selectThread() {
  setup();
  open('threads');
  fireEvent.click(await screen.findByTestId('thr-row-5156'));
  return screen.findByTestId('thr-follow');
}
async function followAndStop() {
  const follow = await selectThread();
  fireEvent.click(follow);
  await waitFor(() => expect(screen.getByTestId('thr-follow')).toHaveTextContent('Stop'));
  fireEvent.click(screen.getByTestId('thr-follow'));
  await screen.findAllByTestId('follow-row');
}

test('Threads: a follow can skip system libraries; the choice is fixed while following and named in the result', async () => {
  const follow = await selectThread();
  const scope = screen.getByTestId('thr-follow-scope') as HTMLSelectElement;
  expect(scope.value).toBe('all');
  expect(screen.queryByTestId('thr-follow-module')).toBeNull();
  fireEvent.change(scope, { target: { value: 'app' } });
  inspect.unfollow.mockResolvedValueOnce({ following: false, threadId: 5156, calls: 10, total: 1, truncated: false, endedBy: 'stop', scope: { mode: 'app', module: '' }, modules: [], items: [{ address: '0x1', name: 'a!b', module: 'a', count: 10 }] });
  fireEvent.click(follow);
  await waitFor(() => expect(inspect.follow).toHaveBeenCalledWith(5156, { mode: 'app', module: '' }));
  await waitFor(() => expect(screen.getByTestId('thr-follow')).toHaveTextContent('Stop'));
  expect(screen.getByTestId('thr-follow-status')).toHaveTextContent(/system libraries not followed/);
  expect(screen.getByTestId('thr-follow-scope')).toBeDisabled();
  fireEvent.click(screen.getByTestId('thr-follow'));
  await waitFor(() => expect(screen.getByTestId('thr-follow-status')).toHaveTextContent('10 calls to 1 functions — system libraries not followed'));
  expect(screen.getByTestId('thr-follow-scope')).not.toBeDisabled();
});

test('Threads: following one module needs its name, offered from the loaded modules', async () => {
  const follow = await selectThread();
  const before = inspect.modules.mock.calls.length; // the Modules view loaded its own list
  fireEvent.change(screen.getByTestId('thr-follow-scope'), { target: { value: 'module' } });
  const name = await screen.findByTestId('thr-follow-module');
  expect(follow).toBeDisabled();
  await waitFor(() => expect(inspect.modules).toHaveBeenCalledTimes(before + 1)); // fetched for the suggestions
  await waitFor(() => expect(document.querySelectorAll('#thr-follow-modules option').length).toBe(2));
  expect([...document.querySelectorAll('#thr-follow-modules option')].map((o) => (o as HTMLOptionElement).value)).toEqual(['node.exe', 'ntdll.dll']);
  fireEvent.change(name, { target: { value: '  node.exe ' } });
  expect(follow).not.toBeDisabled();
  fireEvent.click(follow);
  await waitFor(() => expect(inspect.follow).toHaveBeenCalledWith(5156, { mode: 'module', module: 'node.exe' }));
  await waitFor(() => expect(screen.getByTestId('thr-follow-status')).toHaveTextContent(/only node\.exe followed/));
  expect(screen.getByTestId('thr-follow-module')).toBeDisabled();
});

test('Threads: a module that is not loaded is reported and nothing is followed', async () => {
  const follow = await selectThread();
  fireEvent.change(screen.getByTestId('thr-follow-scope'), { target: { value: 'module' } });
  fireEvent.change(await screen.findByTestId('thr-follow-module'), { target: { value: 'nope.dll' } });
  inspect.follow.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:invoke': Error: Module not found: nope.dll"));
  fireEvent.click(follow);
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Module not found: nope.dll'));
  expect(screen.getByTestId('thr-follow')).toHaveTextContent('Follow');
});

// ---- working with the result ----
test('Follow results: the filter narrows the functions by name, module or address', async () => {
  await followAndStop();
  expect(screen.getByTestId('follow-shown')).toHaveTextContent('2 functions');
  fireEvent.change(screen.getByTestId('follow-filter'), { target: { value: 'sizeheap' } });
  expect(screen.getAllByTestId('follow-row').length).toBe(1);
  expect(screen.getByTestId('follow-shown')).toHaveTextContent('1 of 2');
  fireEvent.change(screen.getByTestId('follow-filter'), { target: { value: 'zzz' } });
  expect(screen.queryAllByTestId('follow-row').length).toBe(0);
  expect(screen.getByTestId('follow-results')).toHaveTextContent('No function matches the filter.');
});

test('Follow results: grouped by module with totals; a group opens to show its functions', async () => {
  await followAndStop();
  const toggle = screen.getByTestId('follow-bymodule');
  expect(toggle).toHaveAttribute('aria-pressed', 'false');
  fireEvent.click(toggle);
  expect(toggle).toHaveAttribute('aria-pressed', 'true');
  const groups = screen.getAllByTestId('follow-group');
  expect(groups.length).toBe(2);
  expect(groups[0]).toHaveTextContent('ntdll.dll');
  expect(groups[0]).toHaveTextContent('1,000 calls');
  expect(groups[0]).toHaveTextContent('1 function');
  expect(groups[1]).toHaveTextContent('(no module)');
  expect(groups[1]).toHaveTextContent('234 calls');
  expect(screen.queryAllByTestId('follow-row').length).toBe(0); // closed to start with: an overview
  fireEvent.click(groups[0]);
  expect(groups[0]).toHaveAttribute('aria-expanded', 'true');
  expect(screen.getAllByTestId('follow-row').length).toBe(1);
  expect(screen.getByTestId('follow-row')).toHaveTextContent('ntdll.dll!RtlSizeHeap');
  fireEvent.click(groups[0]);
  expect(screen.queryAllByTestId('follow-row').length).toBe(0);
});

test('Follow results: filtering while grouped opens the groups that match and hides the rest', async () => {
  await followAndStop();
  fireEvent.click(screen.getByTestId('follow-bymodule'));
  fireEvent.change(screen.getByTestId('follow-filter'), { target: { value: '0x500' } });
  const groups = screen.getAllByTestId('follow-group');
  expect(groups.length).toBe(1);
  expect(groups[0]).toHaveTextContent('(no module)');
  expect(screen.getAllByTestId('follow-row').length).toBe(1);
});

test('Follow results: a module whose functions did not make the list says so when opened', async () => {
  const follow = await selectThread();
  inspect.unfollow.mockResolvedValueOnce({ following: false, threadId: 5156, calls: 50, total: 9, truncated: true, endedBy: 'stop', scope: { mode: 'all', module: '' },
    modules: [{ name: 'a.dll', calls: 40, functions: 1 }, { name: 'rare.dll', calls: 10, functions: 8 }], items: [{ address: '0x1', name: 'a.dll!f', module: 'a.dll', count: 40 }] });
  fireEvent.click(follow);
  await waitFor(() => expect(screen.getByTestId('thr-follow')).toHaveTextContent('Stop'));
  fireEvent.click(screen.getByTestId('thr-follow'));
  await screen.findAllByTestId('follow-row');
  fireEvent.click(screen.getByTestId('follow-bymodule'));
  const rare = screen.getAllByTestId('follow-group')[1];
  expect(rare).toHaveTextContent('8 functions');
  fireEvent.click(rare);
  expect(screen.getByTestId('follow-results')).toHaveTextContent('None of its functions are among the most-called listed.');
});

test('Follow results: Save writes the functions shown as CSV, without becoming the script file', async () => {
  await followAndStop();
  fireEvent.change(screen.getByTestId('follow-filter'), { target: { value: 'ntdll' } });
  fireEvent.click(screen.getByTestId('follow-save'));
  expect(exportFile).toHaveBeenCalledTimes(1);
  const [csv, opts] = exportFile.mock.calls[0];
  expect(csv).toBe('calls,module,function,address\r\n1000,ntdll.dll,ntdll.dll!RtlSizeHeap,0x7fff96125a70\r\n');
  expect(opts).toEqual(expect.objectContaining({ defaultPath: 'thread-5156-calls.csv' }));
});

test('Follow results: a new follow starts with the filter cleared', async () => {
  await followAndStop();
  fireEvent.change(screen.getByTestId('follow-filter'), { target: { value: 'zzz' } });
  fireEvent.click(screen.getByTestId('thr-follow'));
  await waitFor(() => expect(screen.getByTestId('thr-follow')).toHaveTextContent('Stop'));
  fireEvent.click(screen.getByTestId('thr-follow'));
  expect((await screen.findAllByTestId('follow-row')).length).toBe(2);
  expect((screen.getByTestId('follow-filter') as HTMLInputElement).value).toBe('');
});

// ---- Disassembly ----
const INSNS = (base: number, n: number) => Array.from({ length: n }, (_, i) => {
  const address = '0x' + (base + i * 4).toString(16);
  if (i === 2) return { address, size: 4, bytes: 'e8000000', text: 'call 0x7fff96125a70', kind: 'call', target: '0x7fff96125a70', targetName: 'ntdll.dll!RtlSizeHeap' };
  if (i === 3) return { address, size: 4, bytes: 'c3', text: 'ret', kind: 'ret', target: null, targetName: '' };
  return { address, size: 4, bytes: '4889d8', text: 'mov rax, rbx', kind: '', target: null, targetName: '' };
});
function withDisassembly() {
  inspect.disassemble = vi.fn(async (address: string, count: number) => {
    const base = parseInt(address, 16);
    return { address, next: '0x' + (base + count * 4).toString(16), stopped: '', where: 'node.exe+0x100', symbol: 'node.exe!main', protection: 'r-x', items: INSNS(base, Math.min(count, 6)) };
  });
}

test('Disassembly: Go lists the instructions at an address with bytes, and marks calls and returns', async () => {
  setup();
  withDisassembly();
  open('code');
  expect(screen.getByTestId('code-list')).toHaveTextContent('Enter an address');
  fireEvent.change(screen.getByTestId('code-addr'), { target: { value: '0x1000' } });
  fireEvent.click(screen.getByTestId('code-go'));
  const rows = await screen.findAllByTestId('code-row');
  expect(inspect.disassemble).toHaveBeenCalledWith('0x1000', 60);
  expect(rows.length).toBe(6);
  expect(rows[0]).toHaveTextContent('0x1000');
  expect(rows[0]).toHaveTextContent('4889d8');
  expect(rows[0]).toHaveTextContent('mov rax, rbx');
  expect(rows[2]).toHaveClass('k-call');
  expect(rows[3]).toHaveClass('k-ret');
  expect(screen.getByTestId('code-where')).toHaveTextContent('node.exe!main · r-x');
});

test('Disassembly: an address that is not hex is refused without asking the target', async () => {
  setup();
  withDisassembly();
  open('code');
  fireEvent.change(screen.getByTestId('code-addr'), { target: { value: 'main' } });
  fireEvent.keyDown(screen.getByTestId('code-addr'), { key: 'Enter' });
  expect(screen.getByRole('alert')).toHaveTextContent('Enter a hex address');
  expect(inspect.disassemble).not.toHaveBeenCalled();
});

test('Disassembly: a call target can be followed, and Back returns', async () => {
  setup();
  withDisassembly();
  open('code');
  expect(screen.getByTestId('code-back')).toBeDisabled();
  fireEvent.change(screen.getByTestId('code-addr'), { target: { value: '0x1000' } });
  fireEvent.click(screen.getByTestId('code-go'));
  const target = await screen.findByTestId('code-target');
  expect(target).toHaveTextContent('ntdll.dll!RtlSizeHeap');
  fireEvent.click(target);
  await waitFor(() => expect(inspect.disassemble).toHaveBeenLastCalledWith('0x7fff96125a70', 60));
  await waitFor(() => expect(screen.getAllByTestId('code-row')[0]).toHaveTextContent('0x7fff96125a70'));
  expect((screen.getByTestId('code-addr') as HTMLInputElement).value).toBe('0x7fff96125a70');
  fireEvent.click(screen.getByTestId('code-back'));
  await waitFor(() => expect(screen.getAllByTestId('code-row')[0]).toHaveTextContent('0x1000'));
  expect(screen.getByTestId('code-back')).toBeDisabled();
});

test('Disassembly: More continues where the listing ended; the end of a range is stated', async () => {
  setup();
  withDisassembly();
  open('code');
  fireEvent.change(screen.getByTestId('code-addr'), { target: { value: '0x1000' } });
  fireEvent.click(screen.getByTestId('code-go'));
  await screen.findAllByTestId('code-row');
  inspect.disassemble.mockResolvedValueOnce({ address: '0x10f0', next: '0x10f8', stopped: 'end', where: 'x', symbol: '', protection: 'r-x', items: INSNS(0x10f0, 2) });
  fireEvent.click(screen.getByTestId('code-more'));
  await waitFor(() => expect(screen.getAllByTestId('code-row').length).toBe(8));
  expect(inspect.disassemble).toHaveBeenLastCalledWith('0x10f0', 60);
  expect(screen.getByTestId('code-stopped')).toHaveTextContent('End of this memory range.');
  expect(screen.queryByTestId('code-more')).toBeNull();
});

test('Disassembly: memory that cannot be read is reported; non-executable memory is flagged', async () => {
  setup();
  withDisassembly();
  open('code');
  inspect.disassemble.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:invoke': Error: 0x10 is not in readable memory."));
  fireEvent.change(screen.getByTestId('code-addr'), { target: { value: '0x10' } });
  fireEvent.click(screen.getByTestId('code-go'));
  await waitFor(() => expect(screen.getByTestId('code-error')).toHaveTextContent('0x10 is not in readable memory.'));
  expect(screen.queryAllByTestId('code-row').length).toBe(0);
  inspect.disassemble.mockResolvedValueOnce({ address: '0x2000', next: '0x2008', stopped: 'undecodable', where: '0x2000', symbol: '', protection: 'rw-', items: INSNS(0x2000, 2) });
  fireEvent.change(screen.getByTestId('code-addr'), { target: { value: '0x2000' } });
  fireEvent.click(screen.getByTestId('code-go'));
  await waitFor(() => expect(screen.getByTestId('code-not-exec')).toBeInTheDocument());
  expect(screen.getByTestId('code-stopped')).toHaveTextContent('not an instruction');
});

test('an address request from elsewhere opens the Inspector on the view it names', async () => {
  const store = setup();
  withDisassembly();
  act(() => { store.dispatch(uiActions.setActiveTab('hooks' as any)); });
  act(() => { store.dispatch(uiActions.openAddress({ view: 'code', address: '0x1000' })); });
  expect(store.getState().ui.activeTab).toBe('inspector');
  await waitFor(() => expect(screen.getByTestId('insp-code')).toHaveAttribute('aria-selected', 'true'));
  await waitFor(() => expect(inspect.disassemble).toHaveBeenCalledWith('0x1000', 60));
  act(() => { store.dispatch(uiActions.openAddress({ view: 'memory', address: '0x7fff960d0000' })); });
  await waitFor(() => expect(screen.getByTestId('insp-memory')).toHaveAttribute('aria-selected', 'true'));
  await waitFor(() => expect(inspect.read).toHaveBeenCalledWith('0x7fff960d0000', 256));
});

// ---- Bookmarks ----
const BM = { id: 'b1', label: 'ntdll start', module: 'ntdll.dll', offset: 0x100, address: '0x1100', view: 'memory' as const, note: '' };

test('Bookmarks: an empty list explains how to add one', () => {
  setup();
  open('bookmarks');
  expect(screen.getByTestId('bm-list')).toHaveTextContent('No bookmarks yet.');
  expect(screen.getByTestId('bm-count')).toHaveTextContent('0 bookmarks');
});

test('Bookmarks: a bookmark in a module points at where that module is now, and opens there', async () => {
  const store = setup();
  act(() => { store.dispatch(bookmarksActions.added(BM)); });
  open('bookmarks');
  const row = await screen.findByTestId('bm-row');
  // ntdll.dll is at 0x7fff960d0000 in this session: + 0x100.
  await waitFor(() => expect(within(row).getByTestId('bm-where')).toHaveTextContent('ntdll.dll+0x100 · 0x7fff960d0100'));
  fireEvent.click(within(row).getByTestId('bm-open-code'));
  expect(store.getState().ui.addressRequest).toMatchObject({ view: 'code', address: '0x7fff960d0100' });
  await waitFor(() => expect(screen.getByTestId('insp-code')).toHaveAttribute('aria-selected', 'true'));
});

test('Bookmarks: a module that is not loaded in this process is said to be so, and cannot be opened', async () => {
  const store = setup();
  act(() => { store.dispatch(bookmarksActions.added({ ...BM, module: 'gone.dll' })); });
  open('bookmarks');
  const row = await screen.findByTestId('bm-row');
  await waitFor(() => expect(within(row).getByTestId('bm-where')).toHaveTextContent('gone.dll+0x100 · not loaded in this process'));
  expect(within(row).getByTestId('bm-open-memory')).toBeDisabled();
});

test('Bookmarks: an address outside any module opens as it is', async () => {
  const store = setup();
  act(() => { store.dispatch(bookmarksActions.added({ ...BM, module: '', offset: null, address: '0x9000' })); });
  open('bookmarks');
  fireEvent.click(within(await screen.findByTestId('bm-row')).getByTestId('bm-open-memory'));
  expect(store.getState().ui.addressRequest).toMatchObject({ view: 'memory', address: '0x9000' });
});

test('Bookmarks: the name and note can be edited in place; Remove deletes', async () => {
  const store = setup();
  act(() => { store.dispatch(bookmarksActions.added(BM)); });
  open('bookmarks');
  const row = await screen.findByTestId('bm-row');
  fireEvent.change(within(row).getByTestId('bm-label'), { target: { value: 'syscall stubs' } });
  fireEvent.change(within(row).getByTestId('bm-note'), { target: { value: 'check NtCreateFile' } });
  expect(store.getState().bookmarks.items[0]).toMatchObject({ label: 'syscall stubs', note: 'check NtCreateFile' });
  fireEvent.click(within(row).getByTestId('bm-remove'));
  expect(screen.queryByTestId('bm-row')).toBeNull();
});

test('Bookmarks are listed without a session too, but cannot be opened', () => {
  const store = setup({ attached: false });
  act(() => { store.dispatch(bookmarksActions.added(BM)); });
  open('bookmarks');
  const row = screen.getByTestId('bm-row');
  expect(within(row).getByTestId('bm-label')).toHaveValue('ntdll start');
  expect(within(row).getByTestId('bm-open-memory')).toBeDisabled();
  expect(within(row).getByTestId('bm-where')).toHaveTextContent(/^ntdll\.dll\+0x100$/);
});

test('a request to show the bookmarks opens that view', async () => {
  const store = setup();
  act(() => { store.dispatch(uiActions.showBookmarks()); });
  await waitFor(() => expect(screen.getByTestId('insp-bookmarks')).toHaveAttribute('aria-selected', 'true'));
});

// ---- writing memory ----
async function openMemoryAt1000() {
  open('memory');
  await waitFor(() => expect(screen.getAllByTestId('range-row').length).toBe(2));
  fireEvent.click(screen.getAllByTestId('range-row')[0]);
  await waitFor(() => expect(screen.getAllByTestId('hex-row').length).toBe(16));
}
function withWrite() {
  inspect.write = vi.fn(async (address: string, bytes: string) => ({ address, size: bytes.length / 2, original: '4d5a9000'.slice(0, bytes.length), written: bytes, protection: 'rw-' }));
}

test('without Edit nothing in the Memory tab can write: bytes are not clickable and there is no write bar', async () => {
  setup();
  withWrite();
  await openMemoryAt1000();
  expect(screen.queryByTestId('mem-editbar')).toBeNull();
  expect(screen.queryAllByTestId('hex-byte').length).toBe(0);
  expect(screen.getByTestId('mem-edit')).toHaveAttribute('aria-pressed', 'false');
});

test('Edit: pick a byte, type bytes, see what they replace, and Write sends exactly that', async () => {
  setup();
  withWrite();
  await openMemoryAt1000();
  fireEvent.click(screen.getByTestId('mem-edit'));
  expect(screen.getByTestId('mem-editbar')).toHaveTextContent('Click a byte in the view');
  expect(screen.queryByTestId('mem-write')).toBeNull();
  fireEvent.click(screen.getAllByTestId('hex-byte')[1]); // 0x1001
  expect(screen.getByTestId('mem-edit-at')).toHaveTextContent('0x1001');
  expect(screen.getByTestId('mem-write')).toBeDisabled(); // nothing typed yet
  fireEvent.change(screen.getByTestId('mem-edit-input'), { target: { value: 'de ad' } });
  expect(screen.getByTestId('mem-edit-preview')).toHaveTextContent('5a 90 → de ad');
  expect(screen.getByTestId('mem-write')).toHaveTextContent('Write 2 bytes');
  expect(inspect.write).not.toHaveBeenCalled(); // typing writes nothing
  const reads = inspect.read.mock.calls.length;
  fireEvent.click(screen.getByTestId('mem-write'));
  await waitFor(() => expect(inspect.write).toHaveBeenCalledWith('0x1001', 'dead'));
  expect(inspect.write).toHaveBeenCalledTimes(1);
  await waitFor(() => expect(inspect.read.mock.calls.length).toBeGreaterThan(reads)); // the view is read again
  await waitFor(() => expect(screen.getByTestId('mem-mode-writes')).toHaveTextContent('Writes (1)'));
  expect((screen.getByTestId('mem-edit-input') as HTMLInputElement).value).toBe('');
});

test('Edit: input that is not bytes cannot be written; text is written as its bytes', async () => {
  setup();
  withWrite();
  await openMemoryAt1000();
  fireEvent.click(screen.getByTestId('mem-edit'));
  fireEvent.click(screen.getAllByTestId('hex-byte')[0]);
  fireEvent.change(screen.getByTestId('mem-edit-input'), { target: { value: '9' } });
  expect(screen.getByTestId('mem-edit-error')).toHaveTextContent(/incomplete/);
  expect(screen.getByTestId('mem-write')).toBeDisabled();
  fireEvent.change(screen.getByTestId('mem-edit-as'), { target: { value: 'text' } });
  fireEvent.change(screen.getByTestId('mem-edit-input'), { target: { value: 'Hi' } });
  fireEvent.click(screen.getByTestId('mem-write'));
  await waitFor(() => expect(inspect.write).toHaveBeenCalledWith('0x1000', '4869'));
});

test('a write that fails is reported and not listed', async () => {
  setup();
  inspect.write = vi.fn(async () => { throw new Error("Error invoking remote method 'fermion:invoke': Error: Memory at 0x1000 is not in mapped memory"); });
  await openMemoryAt1000();
  fireEvent.click(screen.getByTestId('mem-edit'));
  fireEvent.click(screen.getAllByTestId('hex-byte')[0]);
  fireEvent.change(screen.getByTestId('mem-edit-input'), { target: { value: '00' } });
  fireEvent.click(screen.getByTestId('mem-write'));
  await waitFor(() => expect(screen.getByTestId('mem-edit-error')).toHaveTextContent('Memory at 0x1000 is not in mapped memory'));
  expect(screen.getByTestId('mem-mode-writes')).toHaveTextContent(/^Writes$/);
});

test('Writes lists what was written; Revert writes the earlier bytes back and removes the entry', async () => {
  setup();
  withWrite();
  await openMemoryAt1000();
  fireEvent.click(screen.getByTestId('mem-edit'));
  fireEvent.click(screen.getAllByTestId('hex-byte')[0]);
  fireEvent.change(screen.getByTestId('mem-edit-input'), { target: { value: '9090' } });
  fireEvent.click(screen.getByTestId('mem-write'));
  await waitFor(() => expect(screen.getByTestId('mem-mode-writes')).toHaveTextContent('Writes (1)'));
  fireEvent.click(screen.getByTestId('mem-mode-writes'));
  const row = screen.getByTestId('write-row');
  expect(row).toHaveTextContent('0x1000');
  expect(row).toHaveTextContent('4d 5a → 90 90');
  fireEvent.click(screen.getByTestId('write-revert'));
  await waitFor(() => expect(inspect.write).toHaveBeenLastCalledWith('0x1000', '4d5a'));
  await waitFor(() => expect(screen.queryByTestId('write-row')).toBeNull());
});

test('a write under a later, overlapping write is not reverted first', async () => {
  setup();
  withWrite();
  await openMemoryAt1000();
  fireEvent.click(screen.getByTestId('mem-edit'));
  for (const [at, bytes] of [[0, '9090'], [1, 'cc']] as const) {
    fireEvent.click(screen.getAllByTestId('hex-byte')[at]);
    fireEvent.change(screen.getByTestId('mem-edit-input'), { target: { value: bytes } });
    fireEvent.click(screen.getByTestId('mem-write'));
    await waitFor(() => expect(inspect.write).toHaveBeenCalledTimes(at + 1));
  }
  await waitFor(() => expect(screen.getByTestId('mem-mode-writes')).toHaveTextContent('Writes (2)'));
  fireEvent.click(screen.getByTestId('mem-mode-writes'));
  fireEvent.click(screen.getAllByTestId('write-revert')[0]); // the older one
  expect(screen.getByTestId('mem-revert-error')).toHaveTextContent('The write at 0x1001 was made later over the same bytes. Revert that one first.');
  expect(inspect.write).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getAllByTestId('write-revert')[1]);
  await waitFor(() => expect(screen.getAllByTestId('write-row').length).toBe(1));
  fireEvent.click(screen.getByTestId('write-revert'));
  await waitFor(() => expect(screen.queryByTestId('write-row')).toBeNull());
});

test('writes made in another process are not offered for revert', async () => {
  const store = setup();
  withWrite();
  await openMemoryAt1000();
  fireEvent.click(screen.getByTestId('mem-edit'));
  fireEvent.click(screen.getAllByTestId('hex-byte')[0]);
  fireEvent.change(screen.getByTestId('mem-edit-input'), { target: { value: '90' } });
  fireEvent.click(screen.getByTestId('mem-write'));
  await waitFor(() => expect(screen.getByTestId('mem-mode-writes')).toHaveTextContent('Writes (1)'));
  act(() => { store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '9999' })); });
  expect(screen.getByTestId('mem-mode-writes')).toHaveTextContent(/^Writes$/);
});

// ---- coverage ----
const COVER = {
  recorded: true, threads: 12, all: true, seconds: 4.2, blocks: 3138, bytes: 41220, unmapped: 7, overflow: false, endedBy: 'stop',
  scope: { mode: 'app', module: '' }, moduleCount: 2, drcovBytes: 25300,
  modules: [{ name: 'node.exe', path: 'C:\\node.exe', blocks: 3000, bytes: 40000 }, { name: 'uv.dll', path: 'C:\\uv.dll', blocks: 138, bytes: 1220 }],
};
function withCover(over: any = {}) {
  inspect.coverStart = vi.fn(async (threads: any, scope: any) => ({ recording: true, threads: threads === 'all' ? 12 : 1, all: threads === 'all', maxSeconds: 600, maxBlocks: 2000000, scope, excluded: 40 }));
  inspect.coverStop = vi.fn(async () => COVER);
  inspect.coverSave = vi.fn(async (format: string) => ({ path: format === 'text' ? 'C:\\out\\node-coverage.md' : 'C:\\out\\node-coverage.drcov', format }));
  Object.assign(inspect, over);
}

test('Coverage: Record starts on all threads outside system libraries by default; Stop shows what ran', async () => {
  setup();
  withCover();
  open('coverage');
  expect(screen.getByTestId('cover-empty')).toHaveTextContent('Record which code runs');
  fireEvent.click(screen.getByTestId('cover-toggle'));
  await waitFor(() => expect(inspect.coverStart).toHaveBeenCalledWith('all', { mode: 'app', module: '' }));
  await waitFor(() => expect(screen.getByTestId('cover-status')).toHaveTextContent('Recording on 12 threads. Use the program now, then press Stop.'));
  expect(screen.getByTestId('cover-status')).toHaveTextContent('after 10 minutes or 2,000,000 blocks');
  expect(screen.getByTestId('cover-toggle')).toHaveTextContent('Stop');
  expect(screen.getByTestId('cover-who')).toBeDisabled();
  fireEvent.click(screen.getByTestId('cover-toggle'));
  await waitFor(() => expect(screen.getByTestId('cover-line')).toHaveTextContent('3,138 basic blocks (40.3 KB of code) in 2 modules, on 12 threads over 4.2 s.'));
  expect(screen.getByTestId('cover-line')).toHaveTextContent('7 more blocks ran outside every module');
  const rows = screen.getAllByTestId('cover-row');
  expect(rows.length).toBe(2);
  expect(rows[0]).toHaveTextContent('node.exe');
  expect(rows[0]).toHaveTextContent('3,000');
  expect(screen.getByTestId('cover-toggle')).toHaveTextContent('Record');
});

test('Coverage: one thread and one module can be chosen; a module scope waits for a name', async () => {
  setup();
  withCover();
  open('coverage');
  await waitFor(() => expect(screen.getByTestId('cover-who').querySelectorAll('option').length).toBe(3)); // all + two threads
  fireEvent.change(screen.getByTestId('cover-who'), { target: { value: '5156' } });
  fireEvent.change(screen.getByTestId('cover-scope'), { target: { value: 'module' } });
  expect(screen.getByTestId('cover-toggle')).toBeDisabled();
  fireEvent.change(screen.getByTestId('cover-module'), { target: { value: ' ntdll.dll ' } });
  fireEvent.click(screen.getByTestId('cover-toggle'));
  await waitFor(() => expect(inspect.coverStart).toHaveBeenCalledWith(5156, { mode: 'module', module: 'ntdll.dll' }));
});

test('Coverage: the two Save buttons ask main for that format and show where it went; Cancel shows nothing', async () => {
  setup();
  withCover();
  open('coverage');
  fireEvent.click(screen.getByTestId('cover-toggle'));
  await waitFor(() => expect(screen.getByTestId('cover-toggle')).toHaveTextContent('Stop'));
  fireEvent.click(screen.getByTestId('cover-toggle'));
  await waitFor(() => expect(screen.getByTestId('cover-save-drcov')).toBeInTheDocument());
  fireEvent.click(screen.getByTestId('cover-save-drcov'));
  await waitFor(() => expect(screen.getByTestId('cover-saved')).toHaveTextContent('Saved to C:\\out\\node-coverage.drcov'));
  expect(inspect.coverSave).toHaveBeenLastCalledWith('drcov');
  fireEvent.click(screen.getByTestId('cover-save-text'));
  await waitFor(() => expect(screen.getByTestId('cover-saved')).toHaveTextContent('node-coverage.md'));
  expect(inspect.coverSave).toHaveBeenLastCalledWith('text');
  inspect.coverSave = vi.fn(async () => ({ path: null, format: 'drcov' }));
  fireEvent.click(screen.getByTestId('cover-save-drcov'));
  await waitFor(() => expect(inspect.coverSave).toHaveBeenCalled());
  expect(screen.getByTestId('cover-saved')).toHaveTextContent('node-coverage.md'); // unchanged
});

test('Coverage: a recording that cannot start, or a save that fails, is reported', async () => {
  setup();
  withCover({ coverStart: vi.fn(async () => { throw new Error("Error invoking remote method 'fermion:invoke': Error: Module not found: nope.dll"); }) });
  open('coverage');
  fireEvent.click(screen.getByTestId('cover-toggle'));
  await waitFor(() => expect(screen.getByTestId('cover-error')).toHaveTextContent('Module not found: nope.dll'));
  expect(screen.getByTestId('cover-toggle')).toHaveTextContent('Record');
  expect(screen.queryByTestId('cover-status')).toBeNull();
});

test('Coverage: nothing recorded says so and offers nothing to save', async () => {
  setup();
  withCover({ coverStop: vi.fn(async () => ({ recorded: false })) });
  open('coverage');
  fireEvent.click(screen.getByTestId('cover-toggle'));
  await waitFor(() => expect(screen.getByTestId('cover-toggle')).toHaveTextContent('Stop'));
  fireEvent.click(screen.getByTestId('cover-toggle'));
  await waitFor(() => expect(screen.getByTestId('cover-error')).toHaveTextContent('Nothing was recorded.'));
  expect(screen.queryByTestId('cover-save-drcov')).toBeNull();
});

// ---- memory watch ----
const PLACE = {
  op: 'write', from: '0x7fff96101234', where: 'ntdll.dll+0x31234', symbol: 'ntdll.dll!memcpy', hits: 5, near: 0, last: '0x500014', threads: [5156, 77],
  frames: [{ address: '0x7ff62c711000', where: 'node.exe+0x1000', symbol: 'node.exe!save_settings' }, { address: '0x500', where: '0x500', symbol: '' }],
};
const NEARBY = { op: 'read', from: '0x7ff62c712000', where: 'node.exe+0x2000', symbol: '', hits: 0, near: 9, last: '0x500800', threads: [77], frames: [] };
const WATCHED = { watching: true, endedBy: '', address: '0x500010', size: 8, seconds: 1.5, hits: 5, near: 9, places: 2, truncated: false, error: '', items: [PLACE, NEARBY] };
function withWatch(over: any = {}) {
  inspect.watchStart = vi.fn(async (address: string, size: number) => ({ watching: true, address, size, pages: 1, pageSize: 4096, maxSeconds: 600, protection: 'rw-' }));
  inspect.watchHits = vi.fn(async () => WATCHED);
  inspect.watchStop = vi.fn(async () => ({ ...WATCHED, watching: false, endedBy: 'stop', seconds: 2 }));
  Object.assign(inspect, over);
}

test('Watch: an address and a size start a watch; who touched the bytes is listed while it runs', async () => {
  setup();
  withWatch();
  open('watch');
  expect(screen.getByTestId('watch-empty')).toHaveTextContent('which code reads or writes');
  expect(screen.getByTestId('watch-toggle')).toBeDisabled(); // no address yet
  fireEvent.change(screen.getByTestId('watch-address'), { target: { value: ' 0x500010 ' } });
  expect(screen.getByTestId('watch-size')).toHaveValue('8');
  fireEvent.click(screen.getByTestId('watch-toggle'));
  await waitFor(() => expect(inspect.watchStart).toHaveBeenCalledWith('0x500010', 8));
  await waitFor(() => expect(screen.getByTestId('watch-status')).toHaveTextContent('Watching 8 bytes at 0x500010'));
  expect(screen.getByTestId('watch-status')).toHaveTextContent('sampled');
  expect(screen.getByTestId('watch-address')).toBeDisabled();
  const row = await screen.findByTestId('watch-row');
  expect(row).toHaveTextContent('write');
  expect(row).toHaveTextContent('ntdll.dll!memcpy');
  expect(row).toHaveTextContent('5');
  expect(screen.getAllByTestId('watch-row').length).toBe(1); // the place that only touched other bytes is not listed
  expect(screen.getByTestId('watch-line')).toHaveTextContent('5 accesses from 1 place');
  fireEvent.click(screen.getByTestId('watch-toggle'));
  await waitFor(() => expect(inspect.watchStop).toHaveBeenCalled());
  await waitFor(() => expect(screen.getByTestId('watch-toggle')).toHaveTextContent('Watch'));
  expect(screen.getByTestId('watch-line')).toHaveTextContent('5 accesses from 1 place in 2 s');
  expect(screen.getByTestId('watch-address')).not.toBeDisabled();
});

test('Watch: a place opens its call stack; accesses to the rest of the page can be shown', async () => {
  setup();
  withWatch();
  open('watch');
  fireEvent.change(screen.getByTestId('watch-address'), { target: { value: '0x500010' } });
  fireEvent.click(screen.getByTestId('watch-toggle'));
  fireEvent.click(await screen.findByTestId('watch-row'));
  const stack = screen.getByTestId('watch-stack');
  expect(within(stack).getAllByTestId('watch-frame').map((f) => f.textContent)).toEqual(['node.exe!save_settings0x7ff62c711000', '0x5000x500']);
  expect(screen.getByTestId('watch-near')).toHaveTextContent('9 accesses to other bytes on the same page');
  fireEvent.click(screen.getByTestId('watch-near-toggle'));
  expect(screen.getAllByTestId('watch-row').length).toBe(2);
  expect(screen.getAllByTestId('watch-row')[1]).toHaveTextContent('node.exe+0x2000');
});

test('Watch: the size must be 1..4096; a refusal from the target is shown; a watch that ends by itself is collected', async () => {
  setup();
  withWatch({ watchStart: vi.fn(async () => { throw new Error("Error invoking remote method 'fermion:invoke': Error: 0x500010 is code. A watch is for data; hook the code instead.") }) });
  open('watch');
  fireEvent.change(screen.getByTestId('watch-address'), { target: { value: '0x500010' } });
  for (const bad of ['0', '4097', 'x', '']) {
    fireEvent.change(screen.getByTestId('watch-size'), { target: { value: bad } });
    expect(screen.getByTestId('watch-toggle')).toBeDisabled();
  }
  fireEvent.change(screen.getByTestId('watch-size'), { target: { value: '16' } });
  fireEvent.click(screen.getByTestId('watch-toggle'));
  await waitFor(() => expect(screen.getByTestId('watch-error')).toHaveTextContent('0x500010 is code. A watch is for data; hook the code instead.'));
  expect(screen.getByTestId('watch-toggle')).toHaveTextContent('Watch');

  withWatch({ watchHits: vi.fn(async () => ({ ...WATCHED, watching: false, endedBy: 'lost', error: 'unable to protect' })) });
  fireEvent.click(screen.getByTestId('watch-toggle'));
  await waitFor(() => expect(screen.getByTestId('watch-ended')).toHaveTextContent('can no longer be trapped'), { timeout: 3000 });
  expect(screen.getByTestId('watch-toggle')).toHaveTextContent('Watch');
  expect(screen.getAllByTestId('watch-row').length).toBe(1); // what was seen stays
});

test('Watch: an address sent from the address menu fills the field and opens the view, without starting', async () => {
  const store = setup();
  withWatch();
  act(() => { store.dispatch(uiActions.openAddress({ view: 'watch', address: '0x7fff960d2000' })); });
  await waitFor(() => expect(screen.getByTestId('insp-watch')).toHaveAttribute('aria-selected', 'true'));
  expect(screen.getByTestId('watch-address')).toHaveValue('0x7fff960d2000');
  expect(inspect.watchStart).not.toHaveBeenCalled();
});
