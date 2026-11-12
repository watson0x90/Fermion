import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session from './store/sessionSlice';
import output from './store/outputSlice';
import ui from './store/uiSlice';
import hooks, { hooksActions } from './store/hooksSlice';
import bookmarks, { bookmarksActions } from './store/bookmarksSlice';
import { hookFromTarget } from './hooking/model';
import { setTerminalSink } from './bridge';
import { initWorkspace, snapshot, SAVE_DELAY_MS } from './workspace';

const SAVED_HOOK = { id: 'h1', name: 'k32!CreateFileW', module: 'k32', offset: 16, address: '0x10', code: '({ onEnter() {} })', enabled: true, backtrace: false };
const SAVED_MARK = { id: 'b1', label: 'entry', module: 'app.exe', offset: 256, address: '0x400100', view: 'code' as const, note: 'n' };

const makeStore = () => configureStore({ reducer: { session, output, ui, hooks, bookmarks } });
function fakeApi(saved: unknown = { hooks: [], bookmarks: [] }) {
  const saves: unknown[] = [];
  return { saves, workspace: { load: vi.fn(async () => saved), save: vi.fn(async (d: unknown) => { saves.push(d); return {}; }) } };
}
let lines: string[];
beforeEach(() => { lines = []; setTerminalSink({ write: (k: string, t: string) => lines.push(k + ' ' + t) }); vi.useFakeTimers(); });
afterEach(() => { vi.useRealTimers(); setTerminalSink(null); });

test('what was saved is loaded: hooks wait to be placed, switched-off ones stay off', async () => {
  const store = makeStore();
  await initWorkspace(store, fakeApi({ hooks: [SAVED_HOOK, { ...SAVED_HOOK, id: 'h2', enabled: false }], bookmarks: [SAVED_MARK] }));
  expect(store.getState().hooks.hooks).toEqual([
    { ...SAVED_HOOK, status: 'waiting', error: '', calls: 0 },
    { ...SAVED_HOOK, id: 'h2', enabled: false, status: 'off', error: '', calls: 0 },
  ]);
  expect(store.getState().bookmarks.items).toEqual([SAVED_MARK]);
});

test('loading does not count as a change: nothing is written back', async () => {
  const store = makeStore();
  const api = fakeApi({ hooks: [SAVED_HOOK], bookmarks: [SAVED_MARK] });
  await initWorkspace(store, api);
  await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS * 3);
  expect(api.workspace.save).not.toHaveBeenCalled();
});

test('a change is saved a moment later, once, with only what belongs on disk', async () => {
  const store = makeStore();
  const api = fakeApi();
  await initWorkspace(store, api);
  store.dispatch(hooksActions.added(hookFromTarget({ name: 'k!f', module: 'k', offset: 1, address: '0x1' }, 'h9')));
  store.dispatch(hooksActions.patched({ id: 'h9', code: '({ onEnter(log) { log(1); } })' }));
  store.dispatch(bookmarksActions.added(SAVED_MARK));
  expect(api.workspace.save).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS + 10);
  expect(api.workspace.save).toHaveBeenCalledTimes(1);
  expect(api.saves[0]).toEqual({
    hooks: [{ id: 'h9', name: 'k!f', module: 'k', offset: 1, address: '0x1', code: '({ onEnter(log) { log(1); } })', enabled: true, backtrace: true }],
    bookmarks: [SAVED_MARK],
  });
});

test('session state changing (a hook placed, calls counted, hits arriving) is not a reason to save', async () => {
  const store = makeStore();
  const api = fakeApi({ hooks: [SAVED_HOOK], bookmarks: [] });
  await initWorkspace(store, api);
  store.dispatch(hooksActions.patched({ id: 'h1', status: 'on' }));
  store.dispatch(hooksActions.batchReceived({ hits: [], dropped: 0, counts: { h1: 500 } }));
  store.dispatch(hooksActions.sessionEnded());
  await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS * 3);
  expect(api.workspace.save).not.toHaveBeenCalled();
});

test('the returned flush writes a pending change at once', async () => {
  const store = makeStore();
  const api = fakeApi();
  const flush = await initWorkspace(store, api);
  store.dispatch(bookmarksActions.added(SAVED_MARK));
  await flush();
  expect(api.workspace.save).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS * 3);
  expect(api.workspace.save).toHaveBeenCalledTimes(1); // not saved a second time
});

test('a save that fails is reported once, and tried again on the next change', async () => {
  const store = makeStore();
  const api = fakeApi();
  api.workspace.save.mockRejectedValue(new Error("Error invoking remote method 'fermion:workspaceSave': Error: disk full"));
  await initWorkspace(store, api);
  store.dispatch(bookmarksActions.added(SAVED_MARK));
  await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS + 10);
  store.dispatch(bookmarksActions.changed({ id: 'b1', note: 'again' }));
  await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS + 10);
  expect(api.workspace.save).toHaveBeenCalledTimes(2);
  expect(lines.filter((l) => l.includes('Could not save'))).toEqual(['ERR [!] Could not save hooks and bookmarks: disk full']);
});

test('a load that fails is reported and the app starts empty; later changes are still saved', async () => {
  const store = makeStore();
  const api = fakeApi();
  api.workspace.load.mockRejectedValueOnce(new Error('unreadable'));
  await initWorkspace(store, api);
  expect(lines).toEqual(['ERR [!] Could not load saved hooks and bookmarks: unreadable']);
  store.dispatch(bookmarksActions.added(SAVED_MARK));
  await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS + 10);
  expect(api.workspace.save).toHaveBeenCalledTimes(1);
});

test('hooks added while the saved ones were still loading are kept, not replaced', async () => {
  const store = makeStore();
  let finish: (v: unknown) => void = () => {};
  const api = fakeApi();
  api.workspace.load.mockImplementationOnce(() => new Promise((r) => { finish = r; }));
  const ready = initWorkspace(store, api);
  store.dispatch(hooksActions.added(hookFromTarget({ name: 'mine', module: 'm', offset: 1, address: '0x1' }, 'mine')));
  finish({ hooks: [SAVED_HOOK], bookmarks: [] });
  await ready;
  expect(store.getState().hooks.hooks.map((h) => h.id)).toEqual(['mine']);
});

test('without the bridge nothing happens', async () => {
  const flush = await initWorkspace(makeStore(), {});
  await flush();
});

test('snapshot leaves session state out', () => {
  const store = makeStore();
  store.dispatch(hooksActions.added(hookFromTarget({ name: 'k!f', module: 'k', offset: 1, address: '0x1' }, 'h1')));
  const before = snapshot(store.getState());
  store.dispatch(hooksActions.patched({ id: 'h1', status: 'error', error: 'x', calls: 9 }));
  expect(snapshot(store.getState())).toBe(before);
});
