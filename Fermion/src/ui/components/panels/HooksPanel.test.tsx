import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session, { sessionActions } from '../../store/sessionSlice';
import output from '../../store/outputSlice';
import ui from '../../store/uiSlice';
import hooksReducer, { hooksActions } from '../../store/hooksSlice';
import { DEFAULT_HANDLER, Hit } from '../../hooking/model';
import { HooksPanel } from './HooksPanel';

/* eslint-disable @typescript-eslint/no-explicit-any */
const FOUND = [
  { name: 'kernel32.dll!CreateFileW', module: 'kernel32.dll', offset: 0x10, address: '0x7ff010' },
  { name: 'kernel32.dll!CreateFileA', module: 'kernel32.dll', offset: 0x20, address: '0x7ff020' },
  { name: '0x9000', module: '', offset: null, address: '0x9000' },
];

let hooks: any;
function setup({ attached = true } = {}) {
  hooks = {
    search: vi.fn(async () => ({ items: FOUND, total: 3, truncated: false })),
    add: vi.fn(async (spec: any) => ({ id: spec.id, address: spec.address, enabled: spec.enabled, calls: 0 })),
    update: vi.fn(async (id: string) => ({ id, enabled: true, calls: 0 })),
    enable: vi.fn(async (id: string, on: boolean) => ({ id, enabled: on, calls: 0 })),
    remove: vi.fn(async () => true),
    symbolicate: vi.fn(async () => [
      { address: '0x400100', name: 'target.exe!main', where: 'target.exe+0x100' },
      { address: '0x2b13aa8f64d', name: '', where: '0x2b13aa8f64d' },
    ]),
  };
  (window as any).fermion = { hooks };
  const store = configureStore({ reducer: { session, output, ui, hooks: hooksReducer } });
  if (attached) store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '4821' }));
  render(<Provider store={store}><HooksPanel /></Provider>);
  return store;
}
async function find(query = 'CreateFile') {
  fireEvent.change(screen.getByTestId('hook-query'), { target: { value: query } });
  fireEvent.click(screen.getByTestId('hook-search'));
  return screen.findAllByTestId('hook-result');
}
async function hookFirst(store: ReturnType<typeof setup>) {
  const rows = await find();
  fireEvent.click(within(rows[0]).getByTestId('hook-add'));
  await waitFor(() => expect(store.getState().hooks.hooks[0]?.status).toBe('on'));
  return store.getState().hooks.hooks[0];
}
const hit = (id: string, text: string, extra: Partial<Hit> = {}) => ({ seq: 1, id, t: 1250, tid: 42, depth: 0, phase: 'enter' as const, text, error: false, bt: null, ...extra });

test('not attached: search is unavailable and says why; nothing is asked of the target', () => {
  setup({ attached: false });
  expect(screen.getByTestId('hook-query')).toBeDisabled();
  expect(screen.getByTestId('hook-search')).toBeDisabled();
  expect(screen.getByTestId('hook-detached')).toHaveTextContent('Attach to a process to find functions.');
  expect(screen.getByTestId('hook-empty')).toBeInTheDocument();
  expect(hooks.search).not.toHaveBeenCalled();
});

test('search: the kind and query go to the target; results list name and address', async () => {
  setup();
  fireEvent.change(screen.getByTestId('hook-kind'), { target: { value: 'symbols' } });
  const rows = await find('  kernel32!Create*  ');
  expect(hooks.search).toHaveBeenCalledWith('symbols', 'kernel32!Create*');
  expect(rows.length).toBe(3);
  expect(rows[0]).toHaveTextContent('kernel32.dll!CreateFileW');
  expect(rows[0]).toHaveTextContent('0x7ff010');
  expect(screen.getByTestId('hook-search-status')).toHaveTextContent('3 functions');
});

test('search: Enter runs it; an empty query does not; a truncated or empty result says so', async () => {
  setup();
  expect(screen.getByTestId('hook-search')).toBeDisabled();
  fireEvent.keyDown(screen.getByTestId('hook-query'), { key: 'Enter' });
  expect(hooks.search).not.toHaveBeenCalled();
  hooks.search.mockResolvedValueOnce({ items: FOUND.slice(0, 2), total: 900, truncated: true });
  fireEvent.change(screen.getByTestId('hook-query'), { target: { value: 'a' } });
  fireEvent.keyDown(screen.getByTestId('hook-query'), { key: 'Enter' });
  await waitFor(() => expect(screen.getByTestId('hook-search-status')).toHaveTextContent('900 functions — showing the first 2'));
  hooks.search.mockResolvedValueOnce({ items: [], total: 0, truncated: false });
  fireEvent.click(screen.getByTestId('hook-search'));
  await waitFor(() => expect(screen.getByTestId('hook-search-status')).toHaveTextContent('No function matches.'));
});

test('search: a failure is reported', async () => {
  setup();
  hooks.search.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:invoke': Error: Module not found: nope.dll"));
  fireEvent.change(screen.getByTestId('hook-query'), { target: { value: 'nope.dll!0x10' } });
  fireEvent.click(screen.getByTestId('hook-search'));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Module not found: nope.dll'));
  expect(screen.queryByTestId('hook-results')).toBeNull();
});

test('Hook places a hook with the default handler at module + offset, selects it and marks the result', async () => {
  const store = setup();
  const h = await hookFirst(store);
  expect(hooks.add).toHaveBeenCalledWith({ id: h.id, module: 'kernel32.dll', offset: 0x10, address: '0x7ff010', code: DEFAULT_HANDLER, enabled: true, backtrace: true });
  const row = screen.getByTestId('hook-row-' + h.id);
  expect(row).toHaveAttribute('aria-selected', 'true');
  expect(within(row).getByTestId('hook-status')).toHaveTextContent('hooked');
  expect(within(screen.getAllByTestId('hook-result')[0]).getByTestId('hook-add')).toHaveTextContent('Hooked');
  expect(within(screen.getAllByTestId('hook-result')[0]).getByTestId('hook-add')).toBeDisabled();
});

test('Add all hooks every result that is not hooked yet', async () => {
  const store = setup();
  await hookFirst(store);
  expect(screen.getByTestId('hook-add-all')).toHaveTextContent('Add all 2');
  fireEvent.click(screen.getByTestId('hook-add-all'));
  await waitFor(() => expect(hooks.add).toHaveBeenCalledTimes(3));
  await waitFor(() => expect(store.getState().hooks.hooks.map((h) => h.status)).toEqual(['on', 'on', 'on']));
  expect(screen.queryByTestId('hook-add-all')).toBeNull();
  // The one outside any module is placed by address.
  expect(hooks.add.mock.calls[2][0]).toMatchObject({ module: '', offset: null, address: '0x9000' });
});

test('a hook that cannot be placed says why and stays in the list', async () => {
  const store = setup();
  hooks.add.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:invoke': Error: Could not hook 0x7ff010: unable to intercept function"));
  const rows = await find();
  fireEvent.click(within(rows[0]).getByTestId('hook-add'));
  await waitFor(() => expect(screen.getByTestId('hook-error')).toHaveTextContent('This hook is not placed: Could not hook 0x7ff010: unable to intercept function'));
  expect(screen.getByTestId('hook-status')).toHaveTextContent('not placed');
  expect(store.getState().hooks.hooks.length).toBe(1);
});

test('the switch turns a hook off and on in the target', async () => {
  const store = setup();
  const h = await hookFirst(store);
  const toggle = screen.getByTestId('hook-toggle') as HTMLInputElement;
  expect(toggle.checked).toBe(true);
  fireEvent.click(toggle);
  await waitFor(() => expect(hooks.enable).toHaveBeenCalledWith(h.id, false));
  await waitFor(() => expect(screen.getByTestId('hook-status')).toHaveTextContent('off'));
  fireEvent.click(screen.getByTestId('hook-toggle'));
  await waitFor(() => expect(hooks.enable).toHaveBeenCalledWith(h.id, true));
  await waitFor(() => expect(screen.getByTestId('hook-status')).toHaveTextContent('hooked'));
});

test('Remove takes the hook out of the target and the list', async () => {
  const store = setup();
  const h = await hookFirst(store);
  fireEvent.click(screen.getByTestId('hook-remove'));
  await waitFor(() => expect(hooks.remove).toHaveBeenCalledWith(h.id));
  expect(screen.queryByTestId('hook-row-' + h.id)).toBeNull();
  expect(screen.queryByTestId('hook-detail')).toBeNull();
});

test('Handler: edit, Apply sends the new code; the Handler tab marks unapplied changes', async () => {
  const store = setup();
  const h = await hookFirst(store);
  fireEvent.click(screen.getByTestId('hook-tab-handler'));
  const code = screen.getByTestId('hook-code') as HTMLTextAreaElement;
  expect(code.value).toBe(DEFAULT_HANDLER);
  expect(screen.getByTestId('hook-apply')).toBeDisabled();
  fireEvent.change(code, { target: { value: '({ onEnter(log, args) { log(args[0].readUtf16String()); } })' } });
  expect(screen.getByTestId('hook-tab-handler')).toHaveTextContent('Handler •');
  fireEvent.click(screen.getByTestId('hook-backtrace'));
  fireEvent.click(screen.getByTestId('hook-apply'));
  await waitFor(() => expect(hooks.update).toHaveBeenCalledWith(h.id, { code: '({ onEnter(log, args) { log(args[0].readUtf16String()); } })', backtrace: false }));
  await waitFor(() => expect(screen.getByTestId('hook-tab-handler')).toHaveTextContent(/^Handler$/));
  expect(store.getState().hooks.hooks[0]).toMatchObject({ backtrace: false, code: '({ onEnter(log, args) { log(args[0].readUtf16String()); } })' });
});

test('Handler: code the target rejects is reported, kept in the editor, and the hook keeps its old handler', async () => {
  const store = setup();
  await hookFirst(store);
  fireEvent.click(screen.getByTestId('hook-tab-handler'));
  hooks.update.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:invoke': Error: The handler does not compile: unexpected token"));
  fireEvent.change(screen.getByTestId('hook-code'), { target: { value: '({ onEnter(' } });
  fireEvent.keyDown(screen.getByTestId('hook-code'), { key: 'Enter', ctrlKey: true });
  await waitFor(() => expect(screen.getByTestId('hook-code-error')).toHaveTextContent('The handler does not compile: unexpected token'));
  expect((screen.getByTestId('hook-code') as HTMLTextAreaElement).value).toBe('({ onEnter(');
  expect(store.getState().hooks.hooks[0].code).toBe(DEFAULT_HANDLER);
  fireEvent.click(screen.getByTestId('hook-revert'));
  expect((screen.getByTestId('hook-code') as HTMLTextAreaElement).value).toBe(DEFAULT_HANDLER);
  expect(screen.queryByTestId('hook-code-error')).toBeNull();
});

test('Calls: what a hook logs is listed with time, thread and direction; the call count updates', async () => {
  const store = setup();
  const h = await hookFirst(store);
  act(() => {
    store.dispatch(hooksActions.batchReceived({ hits: [hit(h.id, '(0x1, 0x2)'), hit(h.id, '=> 0x0', { phase: 'leave' }), hit(h.id, 'onEnter threw: boom', { error: true })], dropped: 0, counts: { [h.id]: 1234 } }));
  });
  const rows = screen.getAllByTestId('hook-hit');
  expect(rows.length).toBe(3);
  expect(rows[0]).toHaveTextContent('+1.250s');
  expect(rows[0]).toHaveTextContent('42');
  expect(rows[0]).toHaveTextContent('→(0x1, 0x2)');
  expect(rows[1]).toHaveTextContent('←=> 0x0');
  expect(rows[2]).toHaveClass('err');
  expect(screen.getByTestId('hook-calls')).toHaveTextContent('1,234');
  expect(screen.getByTestId('hook-hit-count')).toHaveTextContent('3 lines');
});

test('Calls: target text is shown as text, never as markup', async () => {
  const store = setup();
  const h = await hookFirst(store);
  act(() => { store.dispatch(hooksActions.batchReceived({ hits: [hit(h.id, '<img src=x onerror=alert(1)>')], dropped: 0, counts: {} })); });
  expect(screen.getByTestId('hook-hit')).toHaveTextContent('<img src=x onerror=alert(1)>');
  expect(screen.getByTestId('hook-hits').querySelector('img')).toBeNull();
});

test('Calls: a line with callers opens to show them, named by the target', async () => {
  const store = setup();
  const h = await hookFirst(store);
  act(() => { store.dispatch(hooksActions.batchReceived({ hits: [hit(h.id, 'with', { bt: ['0x400100', '0x2b13aa8f64d'] }), hit(h.id, 'without')], dropped: 0, counts: {} })); });
  const [withBt, without] = screen.getAllByTestId('hook-hit');
  expect(within(without).getByRole('button')).toBeDisabled();
  fireEvent.click(within(withBt).getByRole('button'));
  await waitFor(() => expect(hooks.symbolicate).toHaveBeenCalledWith(['0x400100', '0x2b13aa8f64d']));
  const frames = await screen.findAllByTestId('hook-frame');
  expect(frames.length).toBe(1);
  expect(frames[0]).toHaveTextContent('target.exe!main');
  // An address that belongs to no module is counted, not listed (hover shows it).
  expect(screen.getByTestId('hook-frames-other')).toHaveTextContent('1 more outside any module');
  expect(screen.getByTestId('hook-frames-other')).toHaveAttribute('title', '0x2b13aa8f64d');
  // Closing and reopening does not ask again.
  fireEvent.click(within(withBt).getByRole('button'));
  expect(screen.queryByTestId('hook-frames')).toBeNull();
  fireEvent.click(within(withBt).getByRole('button'));
  expect(await screen.findAllByTestId('hook-frame')).toHaveLength(1);
  expect(hooks.symbolicate).toHaveBeenCalledTimes(1);
});

test('Calls: only the selected hook is listed unless All hooks is on; dropped lines are counted; Clear empties', async () => {
  const store = setup();
  await hookFirst(store);
  fireEvent.click(screen.getByTestId('hook-add-all'));
  await waitFor(() => expect(store.getState().hooks.hooks.length).toBe(3));
  const [a, b] = store.getState().hooks.hooks;
  act(() => { store.dispatch(hooksActions.batchReceived({ hits: [hit(a.id, 'from a'), hit(b.id, 'from b')], dropped: 800, counts: {} })); });
  expect(screen.getAllByTestId('hook-hit').length).toBe(1);
  expect(screen.getByTestId('hook-hit-count')).toHaveTextContent('1 line · 800 dropped');
  fireEvent.click(screen.getByTestId('hook-hits-all'));
  const rows = screen.getAllByTestId('hook-hit');
  expect(rows.length).toBe(2);
  expect(rows[1]).toHaveTextContent('kernel32.dll!CreateFileA from b');
  fireEvent.click(screen.getByTestId('hook-hits-clear'));
  expect(screen.queryAllByTestId('hook-hit').length).toBe(0);
  expect(store.getState().hooks.dropped).toBe(0);
});

test('the Output switch controls whether hook lines are also printed there', async () => {
  const store = setup();
  await hookFirst(store);
  const echo = screen.getByTestId('hook-echo');
  expect(echo).toHaveAttribute('aria-pressed', 'true');
  fireEvent.click(echo);
  expect(store.getState().hooks.echo).toBe(false);
  expect(screen.getByTestId('hook-echo')).toHaveAttribute('aria-pressed', 'false');
});

test('hooks are kept when the session ends and placed again on the next attach', async () => {
  const store = setup();
  const h = await hookFirst(store);
  act(() => { store.dispatch(sessionActions.detached()); store.dispatch(hooksActions.sessionEnded()); });
  expect(screen.getByTestId('hook-status')).toHaveTextContent('placed on attach');
  expect(screen.getByTestId('hook-detached')).toHaveTextContent('Your hooks are kept and are placed again when you attach.');
  hooks.add.mockClear();
  act(() => { store.dispatch(sessionActions.attached('999')); });
  await waitFor(() => expect(hooks.add).toHaveBeenCalledTimes(1));
  expect(hooks.add.mock.calls[0][0]).toMatchObject({ id: h.id, module: 'kernel32.dll', offset: 0x10 });
  await waitFor(() => expect(screen.getByTestId('hook-status')).toHaveTextContent('hooked'));
});

test('while detached, a hook can still be edited, switched off and removed without touching the target', async () => {
  const store = setup();
  await hookFirst(store);
  act(() => { store.dispatch(sessionActions.detached()); store.dispatch(hooksActions.sessionEnded()); });
  for (const fn of [hooks.add, hooks.update, hooks.enable, hooks.remove]) fn.mockClear();
  fireEvent.click(screen.getByTestId('hook-toggle'));
  await waitFor(() => expect(screen.getByTestId('hook-status')).toHaveTextContent('off'));
  fireEvent.click(screen.getByTestId('hook-tab-handler'));
  fireEvent.change(screen.getByTestId('hook-code'), { target: { value: '({ onEnter(log) { log(1); } })' } });
  fireEvent.click(screen.getByTestId('hook-apply'));
  await waitFor(() => expect(store.getState().hooks.hooks[0].code).toBe('({ onEnter(log) { log(1); } })'));
  fireEvent.click(screen.getByTestId('hook-remove'));
  expect(store.getState().hooks.hooks.length).toBe(0);
  for (const fn of [hooks.add, hooks.update, hooks.enable, hooks.remove]) expect(fn).not.toHaveBeenCalled();
});
