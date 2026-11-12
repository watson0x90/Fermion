import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session from './store/sessionSlice';
import output from './store/outputSlice';
import ui from './store/uiSlice';
import hooks, { hooksActions } from './store/hooksSlice';
import bookmarks, { bookmarksActions } from './store/bookmarksSlice';
import { hookFromTarget } from './hooking/model';
import { setTerminalSink } from './bridge';
import sets from './store/setsSlice';
import { initWorkspace, snapshot, switchSet, changeSet, programName, SAVE_DELAY_MS } from './workspace';

const SAVED_HOOK = { id: 'h1', name: 'k32!CreateFileW', module: 'k32', offset: 16, address: '0x10', code: '({ onEnter() {} })', enabled: true, backtrace: false };
const SAVED_MARK = { id: 'b1', label: 'entry', module: 'app.exe', offset: 256, address: '0x400100', view: 'code' as const, note: 'n' };

const makeStore = () => configureStore({ reducer: { session, output, ui, hooks, bookmarks, sets } });
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
    set: '',
    others: [],
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

// ---- a set per program ----
const hookFor = (id: string) => hookFromTarget({ name: 'k!' + id, module: 'k', offset: 1, address: '0x1' }, id);

test('programName is the file name of a path, or the process name as given', () => {
  expect(programName('C:\\Windows\\notepad.exe')).toBe('notepad.exe');
  expect(programName(' /usr/bin/cat ')).toBe('cat');
  expect(programName('notepad.exe')).toBe('notepad.exe');
});

test('switching to a program with nothing saved starts it empty and keeps the set that was in use', () => {
  const store = makeStore();
  store.dispatch(hooksActions.added(hookFor('h1')));
  store.dispatch(bookmarksActions.added(SAVED_MARK));
  expect(store.dispatch(switchSet('notepad.exe'))).toEqual([]);
  expect(store.getState().hooks.hooks).toEqual([]);
  expect(store.getState().bookmarks.items).toEqual([]);
  expect(store.getState().sets.active).toBe('notepad.exe');
  expect(store.getState().sets.others.map((o) => [o.name, o.hooks.map((h) => h.id), o.bookmarks.length])).toEqual([['', ['h1'], 1]]);
  expect(Object.keys(store.getState().sets.others[0].hooks[0])).toEqual(['id', 'name', 'module', 'offset', 'address', 'code', 'enabled', 'backtrace']);
  expect(lines).toEqual(['STATUS [+] Hooks and bookmarks: using the set for notepad.exe (0 hooks, 0 bookmarks). The set for General is kept.']);
});

test('switching back brings a set in again, waiting to be placed; the name is matched without case', () => {
  const store = makeStore();
  store.dispatch(switchSet('Notepad.exe'));
  store.dispatch(hooksActions.added(hookFor('n1')));
  store.dispatch(hooksActions.patched({ id: 'n1', status: 'on', calls: 5 }));
  store.dispatch(switchSet('calc.exe'));
  store.dispatch(hooksActions.added(hookFor('c1')));
  const hooks = store.dispatch(switchSet('NOTEPAD.EXE'));
  expect(hooks).toEqual([{ ...hookFor('n1'), status: 'waiting', error: '', calls: 0 }]);
  expect(store.getState().sets.active).toBe('Notepad.exe'); // as it was first named
  expect(store.getState().sets.others.map((o) => o.name)).toEqual(['calc.exe']);
  expect(lines[lines.length - 1]).toBe('STATUS [+] Hooks and bookmarks: using the set for NOTEPAD.EXE (1 hook, 0 bookmarks). The set for calc.exe is kept.');
});

test('switching to the set already in use changes nothing; an empty set that is left is not kept', () => {
  const store = makeStore();
  store.dispatch(switchSet('a.exe'));
  store.dispatch(hooksActions.added(hookFor('a1')));
  lines.length = 0;
  expect(store.dispatch(switchSet('A.EXE'))).toEqual(store.getState().hooks.hooks);
  expect(lines).toEqual([]);
  store.dispatch(switchSet('b.exe'));
  store.dispatch(switchSet('c.exe')); // b.exe had nothing in it
  expect(store.getState().sets.others.map((o) => o.name)).toEqual(['a.exe']);
});

test('hits of the set that was left are cleared', () => {
  const store = makeStore();
  store.dispatch(hooksActions.added(hookFor('h1')));
  store.dispatch(hooksActions.batchReceived({ hits: [{ seq: 1, id: 'h1', t: 0, tid: 1, depth: 0, phase: 'enter', text: 'x' }] as never, dropped: 0, counts: { h1: 1 } }));
  store.dispatch(switchSet('x.exe'));
  expect(store.getState().hooks.hits).toEqual([]);
});

test('without the sets slice a switch does nothing and says so by returning null', () => {
  const store = configureStore({ reducer: { session, output, ui, hooks, bookmarks } });
  store.dispatch(hooksActions.added(hookFor('h1')));
  expect(store.dispatch(switchSet('x.exe') as never)).toBeNull();
  expect(store.getState().hooks.hooks.length).toBe(1);
});

test('the set in use and the other sets are saved, and come back', async () => {
  const store = makeStore();
  const api = fakeApi();
  await initWorkspace(store, api);
  store.dispatch(hooksActions.added(hookFor('g1')));
  store.dispatch(switchSet('notepad.exe'));
  store.dispatch(bookmarksActions.added(SAVED_MARK));
  await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS + 10);
  const saved = api.saves[api.saves.length - 1] as { set: string; hooks: unknown[]; bookmarks: unknown[]; others: { name: string; hooks: { id: string }[] }[] };
  expect([saved.set, saved.hooks, saved.bookmarks]).toEqual(['notepad.exe', [], [SAVED_MARK]]);
  expect(saved.others.map((o) => [o.name, o.hooks.map((h) => h.id)])).toEqual([['', ['g1']]]);

  const again = makeStore();
  await initWorkspace(again, fakeApi(saved));
  expect(again.getState().sets.active).toBe('notepad.exe');
  expect(again.getState().bookmarks.items).toEqual([SAVED_MARK]);
  expect(again.getState().sets.others.map((o) => o.name)).toEqual(['']);
});

test('picking a set in a session takes the old hooks out of the process and places the new ones', async () => {
  vi.useRealTimers();
  const store = makeStore();
  const calls: unknown[][] = [];
  (window as unknown as { fermion?: unknown }).fermion = { hooks: {
    remove: async (id: string) => { calls.push(['remove', id]); },
    add: async (spec: { id: string; address: string }) => { calls.push(['add', spec.id]); return { id: spec.id, address: spec.address, enabled: true }; },
  } };
  try {
    store.dispatch(switchSet('other.exe'));
    store.dispatch(hooksActions.added(hookFor('o1')));
    store.dispatch(switchSet('app.exe'));
    store.dispatch(hooksActions.added(hookFor('a1')));
    store.dispatch(hooksActions.added(hookFor('a2')));
    store.dispatch(hooksActions.patched({ id: 'a1', status: 'on' })); // a2 was never placed
    await changeSet(store.dispatch, 'other.exe', store.getState().hooks.hooks, true);
    expect(calls).toEqual([['remove', 'a1'], ['add', 'o1']]);
    expect(store.getState().hooks.hooks.map((h) => [h.id, h.status])).toEqual([['o1', 'on']]);
    calls.length = 0;
    await changeSet(store.dispatch, 'app.exe', store.getState().hooks.hooks, false); // not attached: nothing to do in a process
    expect(calls).toEqual([]);
    expect(store.getState().hooks.hooks.map((h) => h.status)).toEqual(['waiting', 'waiting']);
  } finally { delete (window as unknown as { fermion?: unknown }).fermion; }
});
