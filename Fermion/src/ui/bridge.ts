// Wires the window.fermion preload bridge to the Redux store + the terminal.
// The IPC/security boundary (window.fermion) is unchanged from Phase 1; this is
// the UI-side glue that replaces the old imperative fstate mirror.
import { formatMessage } from '../output-model.js';
import { sessionActions } from './store/sessionSlice';
import { outputActions } from './store/outputSlice';

// Pure: a SEND/MSG payload goes to the trace graph only while trace mode is on.
export function routeMessage(kind: string, traceMode: boolean): 'trace' | 'terminal' {
  return (traceMode && (kind === 'SEND' || kind === 'MSG')) ? 'trace' : 'terminal';
}

export interface TerminalSink {
  write(kind: string, text: string): void;
}
let sink: TerminalSink | null = null;
export function setTerminalSink(s: TerminalSink | null) { sink = s; }
// Write a status/meta line to the terminal (e.g. the startup version banner).
export function writeTerminal(kind: string, text: string) { sink?.write(kind, text); }

let traceSink: ((payload: unknown) => void) | null = null;
export function setTraceSink(fn: ((payload: unknown) => void) | null) { traceSink = fn; }

/* eslint-disable @typescript-eslint/no-explicit-any */
type Fermion = any;
type AnyStore = any;
function api(injected?: Fermion): Fermion {
  return injected ?? (window as any).fermion;
}

// Subscribe the bridge events to the store + terminal. Called once at startup,
// before any attach, so no early output is lost.
export function initBridge(store: AnyStore, injected?: Fermion): void {
  const fermion = api(injected);
  if (!fermion) return;

  fermion.onMessage((m: any) => {
    const { kind, text } = formatMessage(m);
    if (routeMessage(kind, store.getState().session.traceMode) === 'trace') {
      traceSink?.(m.payload);
    } else {
      sink?.write(kind, text);
    }
    store.dispatch(outputActions.counted());
  });

  fermion.onLog((level: string, text: string) => {
    const r = formatMessage({ type: 'log', level, payload: text });
    sink?.write(r.kind, r.text);
    store.dispatch(outputActions.counted());
  });

  fermion.onDetached((reason: string) => {
    store.dispatch(sessionActions.detached());
    sink?.write('STATUS', `[+] Exit Reason: ${reason}`);
  });
}

// -= Thunks (plain async; take the store + script source; default api = window.fermion) =-

export async function attach(store: AnyStore, pid: number | string, scriptSrc: string, injected?: Fermion): Promise<void> {
  const fermion = api(injected);
  await fermion.attach(pid);
  store.dispatch(sessionActions.syncState(await fermion.getState()));
  await fermion.loadScript(scriptSrc);
  store.dispatch(sessionActions.scriptLoaded());
}

export async function spawn(store: AnyStore, path: string, args: string, scriptSrc: string, injected?: Fermion): Promise<void> {
  const fermion = api(injected);
  const { pid } = await fermion.spawn(path, args);
  store.dispatch(sessionActions.syncState(await fermion.getState()));
  await fermion.loadScript(scriptSrc);
  store.dispatch(sessionActions.scriptLoaded());
  await fermion.resume(pid);
}

export async function reload(store: AnyStore, scriptSrc: string, injected?: Fermion): Promise<void> {
  const fermion = api(injected);
  await fermion.reloadScript(scriptSrc);
  store.dispatch(sessionActions.scriptLoaded());
}

export async function detach(store: AnyStore, injected?: Fermion): Promise<void> {
  const fermion = api(injected);
  await fermion.detach();
  store.dispatch(sessionActions.detached());
}

export async function setDevice(store: AnyStore, spec: string, injected?: Fermion): Promise<void> {
  const fermion = api(injected);
  const id = await fermion.setDevice(spec);
  store.dispatch(sessionActions.setDevice(id));
}
