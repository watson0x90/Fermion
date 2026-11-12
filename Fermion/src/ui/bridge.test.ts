import { configureStore } from '@reduxjs/toolkit';
import session, { sessionActions } from './store/sessionSlice';
import output from './store/outputSlice';
import ui from './store/uiSlice';
import hooks, { hooksActions } from './store/hooksSlice';
import { hookFromTarget } from './hooking/model';
import {
  initBridge, setTerminalSink, setTraceSink, routeMessage,
  setOutputMirror, writeTerminal, clearTerminal, terminalEntries, loadTerminal,
} from './bridge';

function makeStore() {
  return configureStore({ reducer: { session, output, ui } });
}

function fakeFermion() {
  const handlers: Record<string, (...a: unknown[]) => void> = {};
  return {
    onMessage: (cb: (...a: unknown[]) => void) => { handlers.message = cb; },
    onLog: (cb: (...a: unknown[]) => void) => { handlers.log = cb; },
    onDetached: (cb: (...a: unknown[]) => void) => { handlers.detached = cb; },
    getState: async () => ({ deviceId: 'local', isAttached: true, hasScript: false, currentPid: '99' }),
    emit: (ev: string, ...a: unknown[]) => handlers[ev](...a),
  };
}

test('routeMessage: SEND/MSG to trace only in trace mode', () => {
  expect(routeMessage('SEND', true)).toBe('trace');
  expect(routeMessage('MSG', true)).toBe('trace');
  expect(routeMessage('SEND', false)).toBe('terminal');
  expect(routeMessage('LOG', true)).toBe('terminal');
});

test('initBridge: message -> terminal sink + counted; detached clears session', () => {
  const store = makeStore();
  const f = fakeFermion();
  const writes: unknown[][] = [];
  setTerminalSink({ write: (k: string, t: string) => writes.push([k, t]) });
  setTraceSink(null);
  initBridge(store, f);
  f.emit('message', { type: 'send', payload: { x: 1 } });
  expect(writes.length).toBe(1);
  expect(store.getState().output.count).toBe(1);
  f.emit('detached', 'process-terminated');
  expect(store.getState().session.isAttached).toBe(false);
});

test('writeTerminal also feeds the output mirror; clear/entries/load reach the sink', () => {
  const writes: unknown[][] = [];
  const mirrored: unknown[][] = [];
  let cleared = 0;
  let loaded: unknown = null;
  setTerminalSink({
    write: (k: string, t: string) => writes.push([k, t]),
    clear: () => { cleared++; },
    entries: () => [{ kind: 'LOG', text: 'old' }],
    load: (e: unknown) => { loaded = e; },
  });
  let mirrorCleared = 0;
  setOutputMirror({ line: (k, t) => mirrored.push([k, t]), clear: () => { mirrorCleared++; } });
  writeTerminal('LOG', 'hello');
  expect(writes).toEqual([['LOG', 'hello']]);
  expect(mirrored).toEqual([['LOG', 'hello']]);

  // A clear reaches the mirror too, so the detached window never shows output
  // the main window has dropped.
  clearTerminal();
  expect(cleared).toBe(1);
  expect(mirrorCleared).toBe(1);

  setOutputMirror(null);
  writeTerminal('LOG', 'again');
  expect(mirrored.length).toBe(1);
  clearTerminal();
  expect(cleared).toBe(2);
  expect(mirrorCleared).toBe(1);
  expect(terminalEntries()).toEqual([{ kind: 'LOG', text: 'old' }]);
  loadTerminal([{ kind: 'ERR', text: 'x' }]);
  expect(loaded).toEqual([{ kind: 'ERR', text: 'x' }]);
});

test('bridge events reach the mirror too (the detached window sees live Frida output)', () => {
  const store = makeStore();
  const f = fakeFermion();
  const mirrored: unknown[][] = [];
  setTerminalSink({ write: () => {} });
  setTraceSink(null);
  setOutputMirror({ line: (k, t) => mirrored.push([k, t]), clear: () => {} });
  initBridge(store, f);
  f.emit('log', 'warning', 'careful');
  f.emit('detached', 'gone');
  setOutputMirror(null);
  expect(mirrored).toEqual([['WARN', 'careful'], ['STATUS', '[+] Exit Reason: gone']]);
});

test('initBridge: message in trace mode -> trace sink, not terminal', () => {
  const store = makeStore();
  store.dispatch({ type: 'session/setTraceMode', payload: true });
  const f = fakeFermion();
  const writes: unknown[][] = [];
  const traced: unknown[] = [];
  setTerminalSink({ write: (k: string, t: string) => writes.push([k, t]) });
  setTraceSink((p) => traced.push(p));
  initBridge(store, f);
  f.emit('message', { type: 'send', payload: 'DOT' });
  expect(writes.length).toBe(0);
  expect(traced).toEqual(['DOT']);
});

// ---- hook hits ----
function hookStore() {
  const store = configureStore({ reducer: { session, output, ui, hooks } });
  store.dispatch(hooksActions.added(hookFromTarget({ name: 'k32!CreateFileW', module: 'k32', offset: 16, address: '0x10' }, 'h1')));
  return store;
}
const BATCH = { fermionHooks: 'hits', dropped: 0, counts: { h1: 2 }, hits: [
  { seq: 1, id: 'h1', t: 10, tid: 4, depth: 0, phase: 'enter', text: '(0x1)' },
  { seq: 2, id: 'h1', t: 11, tid: 4, depth: 0, phase: 'leave', text: '=> 0x0' },
] };

test('a batch of hook hits goes to the Hooks store and, as readable lines, to Output', () => {
  const store = hookStore();
  const f = fakeFermion();
  const writes: unknown[][] = [];
  setTerminalSink({ write: (k: string, t: string) => writes.push([k, t]) });
  initBridge(store, f);
  f.emit('message', { type: 'send', payload: BATCH });
  expect(store.getState().hooks.hits.map((h) => h.text)).toEqual(['(0x1)', '=> 0x0']);
  expect(store.getState().hooks.hooks[0].calls).toBe(2);
  expect(writes).toEqual([['MSG', '[hook] k32!CreateFileW -> (0x1)'], ['MSG', '[hook] k32!CreateFileW <- => 0x0']]);
  expect(store.getState().output.count).toBe(2);
});

test('hook hits are not printed in Output when that is switched off, and errors print as errors', () => {
  const store = hookStore();
  const f = fakeFermion();
  const writes: unknown[][] = [];
  setTerminalSink({ write: (k: string, t: string) => writes.push([k, t]) });
  initBridge(store, f);
  f.emit('message', { type: 'send', payload: { ...BATCH, hits: [{ ...BATCH.hits[0], error: true, text: 'onEnter threw: boom' }] } });
  expect(writes).toEqual([['ERR', '[hook] k32!CreateFileW -> onEnter threw: boom']]);
  store.dispatch(hooksActions.echoSet(false));
  f.emit('message', { type: 'send', payload: BATCH });
  expect(writes.length).toBe(1);
  expect(store.getState().hooks.hits.length).toBe(3);
});

test('hook hits are never taken for graph trace data, and hits for unknown hooks print nothing', () => {
  const store = hookStore();
  const f = fakeFermion();
  const writes: unknown[][] = [];
  const traced: unknown[] = [];
  setTerminalSink({ write: (k: string, t: string) => writes.push([k, t]) });
  setTraceSink((p) => traced.push(p));
  initBridge(store, f);
  store.dispatch(sessionActions.setTraceMode(true));
  f.emit('message', { type: 'send', payload: { ...BATCH, hits: [{ ...BATCH.hits[0], id: 'ghost' }] } });
  expect(traced).toEqual([]);
  expect(writes).toEqual([]);
  setTraceSink(null);
});

test('when the session detaches, the hooks are marked as waiting', () => {
  const store = hookStore();
  const f = fakeFermion();
  setTerminalSink({ write: () => {} });
  initBridge(store, f);
  store.dispatch(hooksActions.patched({ id: 'h1', status: 'on' }));
  f.emit('detached', 'process-terminated');
  expect(store.getState().hooks.hooks[0].status).toBe('waiting');
});

test('a store without the Hooks slice still prints such a message instead of failing', () => {
  const store = makeStore();
  const f = fakeFermion();
  const writes: unknown[][] = [];
  setTerminalSink({ write: (k: string, t: string) => writes.push([k, t]) });
  initBridge(store, f);
  expect(() => f.emit('message', { type: 'send', payload: BATCH })).not.toThrow();
  expect(writes.length).toBe(1);
});

test('a process that replaced itself is followed without asking: script in, catching on, then resumed', async () => {
  const store = makeStore();
  const f = fakeFermion() as ReturnType<typeof fakeFermion> & { onChild: (cb: (...a: unknown[]) => void) => void };
  let onChild: (...a: unknown[]) => void = () => {};
  f.onChild = (cb) => { onChild = cb; };
  const calls: unknown[][] = [];
  const w = window as unknown as { fermion?: unknown; MonacoCodeEditor?: unknown };
  w.MonacoCodeEditor = { getValue: () => 'SCRIPT' };
  w.fermion = {
    resolveChild: async (pid: number, action: string) => { calls.push(['resolveChild', pid, action]); return { pid, action }; },
    loadScript: async (src: string) => { calls.push(['loadScript', src]); return { compiled: false }; },
    setChildGating: async (on: boolean) => { calls.push(['setChildGating', on]); return on; },
    resume: async (pid: number) => { calls.push(['resume', pid]); },
    getState: async () => ({ deviceId: 'local', isAttached: true, hasScript: false, currentPid: '300' }),
  };
  const writes: unknown[][] = [];
  setTerminalSink({ write: (k: string, t: string) => writes.push([k, t]) });
  try {
    initBridge(store, f);
    onChild({ pid: 300, parentPid: 300, path: '/usr/bin/tool', argv: ['/usr/bin/tool', '-v'], replaced: true });
    await vi.waitFor(() => expect(calls[calls.length - 1]).toEqual(['resume', 300]));
    expect(calls).toEqual([['resolveChild', 300, 'attach'], ['loadScript', 'SCRIPT'], ['setChildGating', true], ['resume', 300]]);
    expect(store.getState().session.children).toEqual([]); // nothing to choose
    expect(store.getState().session.target).toEqual({ kind: 'attach', pid: 300, name: 'tool' });
    expect(store.getState().session.ended).toBeNull();
    expect(writes).toEqual([
      ['STATUS', '[+] Process 300 started a new program: tool -v. Following it.'],
      ['STATUS', '[+] Now on tool -v (pid 300)'],
    ]);
  } finally { delete w.fermion; delete w.MonacoCodeEditor; }
});

test('a caught child process is put in the store and announced in Output; a malformed announcement is ignored', () => {
  const store = makeStore();
  const f = fakeFermion() as ReturnType<typeof fakeFermion> & { onChild: (cb: (...a: unknown[]) => void) => void };
  let onChild: (...a: unknown[]) => void = () => {};
  f.onChild = (cb) => { onChild = cb; };
  const writes: unknown[][] = [];
  setTerminalSink({ write: (k: string, t: string) => writes.push([k, t]) });
  initBridge(store, f);
  onChild({ pid: 200, parentPid: 99, path: 'C:/app/helper.exe', argv: ['C:/app/helper.exe', '-x'] });
  onChild({ pid: 'nope' });
  expect(store.getState().session.children).toEqual([{ pid: 200, parentPid: 99, path: 'C:/app/helper.exe', argv: ['C:/app/helper.exe', '-x'] }]);
  expect(writes).toEqual([['STATUS', '[+] Caught child process 200: helper.exe -x (suspended; choose in the Session sidebar)']]);
});
