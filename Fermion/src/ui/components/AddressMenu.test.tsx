import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session, { sessionActions } from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui from '../store/uiSlice';
import hooksReducer from '../store/hooksSlice';
import bookmarksReducer from '../store/bookmarksSlice';
import { addrMenu, openAddressMenu, closeAddressMenu } from '../addressMenu';
import { setTerminalSink } from '../bridge';
import { AddressMenu } from './AddressMenu';

/* eslint-disable @typescript-eslint/no-explicit-any */
let hooks: any;
let clip: string[];
function setup({ attached = true } = {}) {
  hooks = {
    search: vi.fn(async (_kind: string, address: string) => ({ items: [{ name: 'kernel32.dll!CreateFileW', module: 'kernel32.dll', offset: 16, address }], total: 1, truncated: false })),
    add: vi.fn(async (spec: any) => ({ id: spec.id, address: spec.address, enabled: true, calls: 0 })),
  };
  (window as any).fermion = { hooks };
  clip = [];
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: (t: string) => { clip.push(t); return Promise.resolve(); } } });
  const store = configureStore({ reducer: { session, output, ui, hooks: hooksReducer, bookmarks: bookmarksReducer } });
  if (attached) store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '4821' }));
  render(
    <Provider store={store}>
      <span data-testid="an-address" {...addrMenu('0x7FF010')}>0x7FF010</span>
      <span data-testid="not-an-address" {...addrMenu('hello')}>hello</span>
      <AddressMenu />
    </Provider>,
  );
  return store;
}
const openMenu = () => fireEvent.contextMenu(screen.getByTestId('an-address'), { clientX: 40, clientY: 50 });

test('right-clicking an address opens the menu for it; anything else is left alone', () => {
  setup();
  expect(screen.queryByTestId('addr-menu')).toBeNull();
  fireEvent.contextMenu(screen.getByTestId('not-an-address'));
  expect(screen.queryByTestId('addr-menu')).toBeNull();
  openMenu();
  const menu = screen.getByTestId('addr-menu');
  expect(menu).toHaveAttribute('role', 'menu');
  expect(menu).toHaveTextContent('0x7ff010');
  expect(screen.getAllByRole('menuitem').map((b) => b.textContent)).toEqual(['Copy address', 'Open in Memory', 'Open in Disassembly', 'Hook this address', 'Find references', 'Watch reads and writes', 'Find heap block', 'Name this address…', 'Bookmark']);
});

test('Copy address puts it on the clipboard and closes the menu', () => {
  setup();
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-copy'));
  expect(clip).toEqual(['0x7ff010']);
  expect(screen.queryByTestId('addr-menu')).toBeNull();
});

test('Open in Memory / Open in Disassembly ask the Inspector for that view', () => {
  const store = setup();
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-code'));
  expect(store.getState().ui.activeTab).toBe('inspector');
  expect(store.getState().ui.addressRequest).toEqual({ view: 'code', address: '0x7ff010', n: 1 });
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-memory'));
  expect(store.getState().ui.addressRequest).toEqual({ view: 'memory', address: '0x7ff010', n: 2 });
});

test('Hook this address places a hook there and opens the Hooks tab on it', async () => {
  const store = setup();
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-hook'));
  await waitFor(() => expect(store.getState().ui.activeTab).toBe('hooks'));
  expect(hooks.search).toHaveBeenCalledWith('exports', '0x7ff010');
  const [hook] = store.getState().hooks.hooks;
  expect(hook).toMatchObject({ name: 'kernel32.dll!CreateFileW', module: 'kernel32.dll', offset: 16, status: 'on' });
  expect(store.getState().hooks.selected).toBe(hook.id);
  // Asking again for the same place selects the hook that is there.
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-hook'));
  await waitFor(() => expect(hooks.search).toHaveBeenCalledTimes(2));
  expect(store.getState().hooks.hooks.length).toBe(1);
  expect(hooks.add).toHaveBeenCalledTimes(1);
});

test('a hook that cannot be described is reported in Output', async () => {
  const store = setup();
  const lines: string[] = [];
  setTerminalSink({ write: (k: string, t: string) => lines.push(k + ' ' + t) });
  hooks.search.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:invoke': Error: Not attached to a process"));
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-hook'));
  await waitFor(() => expect(lines).toEqual(['ERR [!] Could not hook 0x7ff010: Not attached to a process']));
  expect(store.getState().hooks.hooks).toEqual([]);
});

test('without a session only Copy is available', () => {
  setup({ attached: false });
  openMenu();
  expect(screen.getByTestId('addr-menu-copy')).not.toBeDisabled();
  for (const id of ['addr-menu-memory', 'addr-menu-code', 'addr-menu-hook', 'addr-menu-bookmark']) expect(screen.getByTestId(id)).toBeDisabled();
});

test('the menu closes on Escape, on a click elsewhere, and when asked to', () => {
  setup();
  openMenu();
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(screen.queryByTestId('addr-menu')).toBeNull();
  openMenu();
  fireEvent.mouseDown(document.body);
  expect(screen.queryByTestId('addr-menu')).toBeNull();
  act(() => { openAddressMenu('0x10', 5, 5); });
  expect(screen.getByTestId('addr-menu')).toHaveTextContent('0x10');
  act(() => { closeAddressMenu(); });
  expect(screen.queryByTestId('addr-menu')).toBeNull();
});

test('the keyboard is put in the menu, and the arrow keys move through it', () => {
  setup();
  openMenu();
  expect(document.activeElement).toBe(screen.getByTestId('addr-menu-copy'));
  fireEvent.keyDown(screen.getByTestId('addr-menu'), { key: 'ArrowDown' });
  expect(document.activeElement).toBe(screen.getByTestId('addr-menu-memory'));
  fireEvent.keyDown(screen.getByTestId('addr-menu'), { key: 'ArrowUp' });
  fireEvent.keyDown(screen.getByTestId('addr-menu'), { key: 'ArrowUp' });
  expect(document.activeElement).toBe(screen.getByTestId('addr-menu-bookmark'));
});

test('openAddressMenu refuses text that is not an address', () => {
  setup();
  let opened = true;
  act(() => { opened = openAddressMenu('<b>x</b>', 1, 1); });
  expect(opened).toBe(false);
  expect(screen.queryByTestId('addr-menu')).toBeNull();
});

test('Bookmark saves the place by module and offset, named after it, and shows the Bookmarks view', async () => {
  const store = setup();
  const lines: string[] = [];
  setTerminalSink({ write: (k: string, t: string) => lines.push(k + ' ' + t) });
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-bookmark'));
  await waitFor(() => expect(store.getState().bookmarks.items.length).toBe(1));
  expect(store.getState().bookmarks.items[0]).toMatchObject({ label: 'kernel32.dll!CreateFileW', module: 'kernel32.dll', offset: 16, address: '0x7ff010', view: 'memory', note: '' });
  expect(store.getState().ui.activeTab).toBe('inspector');
  expect(store.getState().ui.bookmarksRequest).toBe(1);
  expect(lines).toContain('STATUS [+] Bookmarked kernel32.dll!CreateFileW');
  // The same place again is not added twice.
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-bookmark'));
  await waitFor(() => expect(lines).toContain('STATUS [+] kernel32.dll!CreateFileW is already bookmarked'));
  expect(store.getState().bookmarks.items.length).toBe(1);
});

test('Watch reads and writes hands the address to the Watch view of the Inspector', () => {
  const store = setup();
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-watch'));
  expect(store.getState().ui.activeTab).toBe('inspector');
  expect(store.getState().ui.addressRequest).toEqual({ view: 'watch', address: '0x7ff010', n: 1 });
  expect(screen.queryByTestId('addr-menu')).toBeNull();
});

test('Find heap block hands the address to the Heap view of the Inspector', () => {
  const store = setup();
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-heap'));
  expect(store.getState().ui.addressRequest).toEqual({ view: 'heap', address: '0x7ff010', n: 1 });
});

test('Name this address asks for a name and saves it as a bookmark with that label', async () => {
  const store = setup();
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-name'));
  const input = await screen.findByTestId('addr-menu-name-input');
  expect(input).toHaveValue('');
  expect(screen.getByTestId('addr-menu')).toBeInTheDocument(); // the menu stays open for the name
  fireEvent.change(input, { target: { value: '  parse_packet ' } });
  fireEvent.keyDown(input, { key: 'Enter' });
  await waitFor(() => expect(store.getState().bookmarks.items.length).toBe(1));
  expect(store.getState().bookmarks.items[0]).toMatchObject({ label: 'parse_packet', module: 'kernel32.dll', offset: 16, address: '0x7ff010', view: 'code' });
  expect(screen.queryByTestId('addr-menu')).toBeNull();
});

test('naming an address that already has a name changes that name; an empty name changes nothing', async () => {
  const store = setup();
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-name'));
  fireEvent.change(await screen.findByTestId('addr-menu-name-input'), { target: { value: 'first' } });
  fireEvent.keyDown(screen.getByTestId('addr-menu-name-input'), { key: 'Enter' });
  await waitFor(() => expect(store.getState().bookmarks.items.length).toBe(1));
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-name'));
  const again = await screen.findByTestId('addr-menu-name-input');
  expect(again).toHaveValue('first'); // the name it has is offered for editing
  fireEvent.change(again, { target: { value: 'second' } });
  fireEvent.click(screen.getByTestId('addr-menu-name-save'));
  await waitFor(() => expect(store.getState().bookmarks.items[0].label).toBe('second'));
  expect(store.getState().bookmarks.items.length).toBe(1);
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-name'));
  fireEvent.change(await screen.findByTestId('addr-menu-name-input'), { target: { value: '   ' } });
  fireEvent.keyDown(screen.getByTestId('addr-menu-name-input'), { key: 'Enter' });
  await new Promise((r) => setTimeout(r, 20));
  expect(store.getState().bookmarks.items[0].label).toBe('second');
});

test('Find references hands the address to the References view of the Inspector', () => {
  const store = setup();
  openMenu();
  fireEvent.click(screen.getByTestId('addr-menu-refs'));
  expect(store.getState().ui.addressRequest).toEqual({ view: 'refs', address: '0x7ff010', n: 1 });
});
