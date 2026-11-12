import { configureStore } from '@reduxjs/toolkit';
import session from './store/sessionSlice';
import output from './store/outputSlice';
import ui from './store/uiSlice';
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
