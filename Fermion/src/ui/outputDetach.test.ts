import { configureStore } from '@reduxjs/toolkit';
import session from './store/sessionSlice';
import output from './store/outputSlice';
import ui, { uiActions } from './store/uiSlice';
import { setTerminalSink, writeTerminal, clearTerminal, setOutputMirror } from './bridge';
import { initOutputHost, initOutputClient } from './outputDetach';

/* eslint-disable @typescript-eslint/no-explicit-any */
function makeStore() {
  return configureStore({ reducer: { session, output, ui } });
}

// A fake window.fermion.output: records what this window sends and lets the
// test deliver relay/state events to it.
function fakeOutputApi() {
  const sent: any[] = [];
  let relay: (m: any) => void = () => {};
  let state: (d: boolean) => void = () => {};
  return {
    api: {
      output: {
        send: (m: any) => sent.push(m),
        onRelay: (cb: any) => { relay = cb; return () => {}; },
        onState: (cb: any) => { state = cb; return () => {}; },
      },
    },
    sent,
    deliver: (m: any) => relay(m),
    setState: (d: boolean) => state(d),
  };
}

function fakeSink() {
  const lines: { kind: string; text: string }[] = [];
  return {
    lines,
    sink: {
      write: (kind: string, text: string) => { lines.push({ kind, text }); },
      clear: () => { lines.length = 0; },
      entries: () => lines.slice(),
      load: (e: { kind: string; text: string }[]) => { lines.length = 0; lines.push(...e); },
    },
  };
}

afterEach(() => { setOutputMirror(null); setTerminalSink(null); });

test('host: state events flip ui.outputDetached', () => {
  const store = makeStore();
  const f = fakeOutputApi();
  initOutputHost(store, f.api);
  f.setState(true);
  expect(store.getState().ui.outputDetached).toBe(true);
  f.setState(false);
  expect(store.getState().ui.outputDetached).toBe(false);
});

test('host: ready -> one snapshot of history + toolbar state, then every later line is mirrored', () => {
  const store = makeStore();
  const f = fakeOutputApi();
  const t = fakeSink();
  setTerminalSink(t.sink);
  initOutputHost(store, f.api);
  writeTerminal('LOG', 'before-detach'); // history: not mirrored yet
  expect(f.sent).toEqual([]);

  f.setState(true);
  f.deliver({ t: 'ready' });
  expect(f.sent).toEqual([{
    t: 'snapshot',
    entries: [{ kind: 'LOG', text: 'before-detach' }],
    filters: store.getState().output.filters,
    follow: true,
    theme: store.getState().ui.theme,
  }]);

  writeTerminal('ERR', 'after-detach');
  expect(f.sent[1]).toEqual({ t: 'line', kind: 'ERR', text: 'after-detach' });
  // The docked terminal keeps the full history for when it comes back.
  expect(t.lines.map((l) => l.text)).toEqual(['before-detach', 'after-detach']);
});

test('host: docking stops the mirror', () => {
  const store = makeStore();
  const f = fakeOutputApi();
  setTerminalSink(fakeSink().sink);
  initOutputHost(store, f.api);
  f.setState(true);
  f.deliver({ t: 'ready' });
  f.setState(false);
  f.sent.length = 0;
  writeTerminal('LOG', 'docked-again');
  expect(f.sent).toEqual([]);
});

test('host: toolbar changes made in the detached window are applied to the main store + terminal', () => {
  const store = makeStore();
  const f = fakeOutputApi();
  const t = fakeSink();
  setTerminalSink(t.sink);
  initOutputHost(store, f.api);
  writeTerminal('LOG', 'x');
  store.dispatch({ type: 'output/counted' });

  f.deliver({ t: 'filter', kind: 'WARN', on: false });
  expect(store.getState().output.filters.WARN).toBe(false);
  f.deliver({ t: 'follow', on: false });
  expect(store.getState().output.follow).toBe(false);
  f.setState(true);
  f.deliver({ t: 'ready' });
  f.sent.length = 0;
  f.deliver({ t: 'clear' });
  expect(t.lines).toEqual([]);
  expect(store.getState().output.count).toBe(0);
  // The main window clears and tells the detached window to clear at the same
  // point in the line stream (the detached window does not clear on its own).
  expect(f.sent).toEqual([{ t: 'clear' }]);
  // Junk from the relay is ignored, not thrown on.
  expect(() => { f.deliver(null); f.deliver({ t: 'filter', kind: 'NOPE', on: false }); }).not.toThrow();
  expect('NOPE' in store.getState().output.filters).toBe(false);
});

test('host: a clear made in the main window (Alt-C) while detached also clears the detached window', () => {
  const store = makeStore();
  const f = fakeOutputApi();
  const t = fakeSink();
  setTerminalSink(t.sink);
  initOutputHost(store, f.api);
  writeTerminal('LOG', 'x');
  f.setState(true);
  f.deliver({ t: 'ready' });
  f.sent.length = 0;
  clearTerminal();
  expect(t.lines).toEqual([]);
  expect(f.sent).toEqual([{ t: 'clear' }]);
});

test('host: a theme change is pushed to the detached window, only while detached', () => {
  const store = makeStore();
  const f = fakeOutputApi();
  initOutputHost(store, f.api);
  store.dispatch(uiActions.setTheme('Monokai'));
  expect(f.sent).toEqual([]);
  f.setState(true);
  store.dispatch(uiActions.setTheme('Cobalt'));
  expect(f.sent).toEqual([{ t: 'theme', name: 'Cobalt' }]);
});

test('client: snapshot loads history + toolbar state + theme; lines append; theme follows', () => {
  const store = makeStore();
  const f = fakeOutputApi();
  const t = fakeSink();
  setTerminalSink(t.sink);
  initOutputClient(store, f.api);

  f.deliver({
    t: 'snapshot',
    entries: [{ kind: 'LOG', text: 'one' }, { kind: 'WARN', text: 'two' }],
    filters: { LOG: true, WARN: false, ERR: true, SEND: true, STATUS: true },
    follow: false,
    theme: 'Monokai',
  });
  expect(t.lines.map((l) => l.text)).toEqual(['one', 'two']);
  expect(store.getState().output.filters.WARN).toBe(false);
  expect(store.getState().output.follow).toBe(false);
  expect(store.getState().ui.theme).toBe('Monokai');

  f.deliver({ t: 'line', kind: 'ERR', text: 'three' });
  expect(t.lines.map((l) => l.text)).toEqual(['one', 'two', 'three']);
  // The client never echoes lines back.
  expect(f.sent).toEqual([]);

  f.deliver({ t: 'theme', name: 'Cobalt' });
  expect(store.getState().ui.theme).toBe('Cobalt');

  f.deliver({ t: 'clear' });
  expect(t.lines).toEqual([]);
  expect(() => { f.deliver(undefined); f.deliver({ t: 'snapshot' }); }).not.toThrow();
});
