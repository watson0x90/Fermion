import { configureStore } from '@reduxjs/toolkit';
import session from './store/sessionSlice';
import output from './store/outputSlice';
import ui, { uiActions } from './store/uiSlice';
import { setTerminalSink } from './bridge';
import { isTypeScript } from './fileOps';
import { attachAndLoad, reloadFromEditor, scriptOptions } from './sessionOps';

/* eslint-disable @typescript-eslint/no-explicit-any */
const makeStore = () => configureStore({ reducer: { session, output, ui } });
let calls: unknown[][];
let lines: string[];

beforeEach(() => {
  calls = [];
  lines = [];
  setTerminalSink({ write: (k: string, t: string) => lines.push(k + ' ' + t) });
  (window as any).MonacoCodeEditor = { getValue: () => 'SCRIPT' };
  (window as any).fermion = {
    attach: async (pid: number) => { calls.push(['attach', pid]); },
    getState: async () => ({ deviceId: 'local', isAttached: true, hasScript: false, currentPid: '7' }),
    loadScript: async (...a: unknown[]) => { calls.push(['loadScript', ...a]); return { compiled: a.length > 1, typescript: a.length > 1 }; },
    reloadScript: async (...a: unknown[]) => { calls.push(['reloadScript', ...a]); return { compiled: a.length > 1, typescript: a.length > 1 }; },
  };
});
afterEach(() => { setTerminalSink(null); delete (window as any).fermion; delete (window as any).MonacoCodeEditor; });

test('isTypeScript goes by the file name: .ts, in any case, and nothing else', () => {
  expect(isTypeScript('C:\\scripts\\hook.ts')).toBe(true);
  expect(isTypeScript('/home/me/Hook.TS')).toBe(true);
  for (const no of ['a.js', 'a.tsx', 'a.ts.bak', 'ts', '', null, undefined]) expect(isTypeScript(no)).toBe(false);
});

test('a script saved as .ts is loaded and reloaded as TypeScript, and Output says so', async () => {
  const store = makeStore();
  store.dispatch(uiActions.fileOpened('C:\\scripts\\hook.ts'));
  expect(scriptOptions(store.dispatch)).toEqual({ typescript: true });
  expect(await attachAndLoad(store.dispatch, 7, 'app.exe')).toBe(true);
  expect(await reloadFromEditor(store.dispatch)).toBe(true);
  expect(calls).toEqual([['attach', 7], ['loadScript', 'SCRIPT', { typescript: true }], ['reloadScript', 'SCRIPT', { typescript: true }]]);
  expect(lines.filter((l) => l.includes('TypeScript'))).toEqual(['STATUS [+] TypeScript compiled, types checked', 'STATUS [+] TypeScript compiled, types checked']);
});

test('any other script is loaded exactly as before, with no options', async () => {
  const store = makeStore();
  expect(scriptOptions(store.dispatch)).toBeUndefined(); // never saved
  store.dispatch(uiActions.fileOpened('C:\\scripts\\hook.js'));
  await attachAndLoad(store.dispatch, 7, 'app.exe');
  await reloadFromEditor(store.dispatch);
  expect(calls).toEqual([['attach', 7], ['loadScript', 'SCRIPT'], ['reloadScript', 'SCRIPT']]);
  expect(lines.some((l) => l.includes('TypeScript'))).toBe(false);
});

test('scriptOptions tolerates a dispatch that is not a store', () => {
  expect(scriptOptions(() => undefined)).toBeUndefined();
  expect(scriptOptions(() => { throw new Error('no thunks'); })).toBeUndefined();
});
