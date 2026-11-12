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

export interface OutputEntry { kind: string; text: string; }
export interface TerminalSink {
  write(kind: string, text: string): void;
  clear?(): void;
  entries?(): OutputEntry[];
  load?(entries: OutputEntry[]): void;
}
let sink: TerminalSink | null = null;
export function setTerminalSink(s: TerminalSink | null) { sink = s; }

// While the Output pane is detached, every line written here — and every clear —
// is also handed to the mirror, which relays it to the detached window (see
// outputDetach.ts). Going through one place keeps both windows in step.
export interface OutputMirror {
  line(kind: string, text: string): void;
  clear(): void;
}
let mirror: OutputMirror | null = null;
export function setOutputMirror(m: OutputMirror | null) { mirror = m; }

// Write a line to the terminal (Frida output, status/meta lines).
export function writeTerminal(kind: string, text: string) {
  sink?.write(kind, text);
  mirror?.line(kind, text);
}
export function clearTerminal() { sink?.clear?.(); mirror?.clear(); }
export function terminalEntries(): OutputEntry[] { return sink?.entries?.() ?? []; }
export function loadTerminal(entries: OutputEntry[]) { sink?.load?.(entries); }

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
      writeTerminal(kind, text);
    }
    store.dispatch(outputActions.counted());
  });

  fermion.onLog((level: string, text: string) => {
    const r = formatMessage({ type: 'log', level, payload: text });
    writeTerminal(r.kind, r.text);
    store.dispatch(outputActions.counted());
  });

  fermion.onDetached((reason: string) => {
    store.dispatch(sessionActions.detached());
    writeTerminal('STATUS', `[+] Exit Reason: ${reason}`);
  });
}
