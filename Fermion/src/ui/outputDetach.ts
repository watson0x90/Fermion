// Detached Output pane — the renderer-side glue for both windows.
//
// The main window stays the single source of output: it formats and routes
// Frida messages and keeps the full history in its own (hidden) terminal. The
// detached window is a mirror. When it reports `ready`, the main window sends
// one snapshot (history + toolbar state + theme) and from then on relays every
// new line and every clear. Toolbar changes made in the detached window are
// relayed back, so docking returns the pane exactly as the user left it.
import { uiActions } from './store/uiSlice';
import { outputActions, KINDS } from './store/outputSlice';
import {
  setOutputMirror, writeTerminal, clearTerminal, terminalEntries, loadTerminal, OutputEntry,
} from './bridge';

const BATCH_MS = 40;     // how long lines are collected before being relayed
const BATCH_MAX = 1000;  // lines per relay message

/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyStore = any;

function outputApi(injected?: any) {
  return (injected ?? (window as any).fermion)?.output;
}

// Main window: track detached state, serve the snapshot, mirror lines, and
// apply toolbar changes coming back from the detached window.
export function initOutputHost(store: AnyStore, injected?: any): void {
  const out = outputApi(injected);
  if (!out) return;

  // Lines for the detached window are collected and sent a few times a second
  // rather than one IPC message per line, which doubled the work under heavy
  // output. A batch is capped so no single message is huge.
  let pending: [string, string][] = [];
  let timer: ReturnType<typeof setTimeout> | null = null;
  const flush = () => {
    if (timer) { clearTimeout(timer); timer = null; }
    while (pending.length) out.send({ t: 'lines', items: pending.splice(0, BATCH_MAX) });
  };
  const schedule = () => { if (!timer) timer = setTimeout(flush, BATCH_MS); };
  const drop = () => { pending = []; if (timer) { clearTimeout(timer); timer = null; } };

  out.onState((detached: boolean) => {
    if (!detached) { setOutputMirror(null); drop(); }
    store.dispatch(uiActions.setOutputDetached(!!detached));
  });

  out.onRelay((msg: any) => {
    if (!msg || typeof msg !== 'object') return;
    switch (msg.t) {
      case 'ready': {
        const s = store.getState();
        out.send({
          t: 'snapshot',
          entries: terminalEntries(),
          filters: s.output.filters,
          follow: s.output.follow,
          theme: s.ui.theme,
        });
        // Anything still waiting to be sent is already in this snapshot.
        pending = [];
        setOutputMirror({
          line: (kind, text) => { pending.push([kind, text]); schedule(); },
          // Lines written before the clear go first, so the two windows drop
          // the same lines.
          clear: () => { flush(); out.send({ t: 'clear' }); },
        });
        break;
      }
      case 'filter':
        store.dispatch(outputActions.setFilter({ kind: String(msg.kind), on: !!msg.on }));
        break;
      case 'follow':
        store.dispatch(outputActions.setFollow(!!msg.on));
        break;
      case 'clear':
        // The detached window only asks; clearing here (which echoes a clear
        // back through the mirror) makes both windows drop the same lines.
        clearTerminal();
        store.dispatch(outputActions.clear());
        break;
      default:
    }
  });

  // Keep the detached window on the same theme as the main window.
  let lastTheme = store.getState().ui.theme;
  store.subscribe(() => {
    const s = store.getState();
    if (s.ui.theme === lastTheme) return;
    lastTheme = s.ui.theme;
    if (s.ui.outputDetached) out.send({ t: 'theme', name: lastTheme });
  });
}

// Detached window: render what the main window sends.
export function initOutputClient(store: AnyStore, injected?: any): void {
  const out = outputApi(injected);
  if (!out) return;

  out.onRelay((msg: any) => {
    if (!msg || typeof msg !== 'object') return;
    switch (msg.t) {
      case 'snapshot': {
        store.dispatch(outputActions.hydrate({ filters: msg.filters, follow: msg.follow }));
        if (typeof msg.theme === 'string') store.dispatch(uiActions.setTheme(msg.theme));
        const entries: OutputEntry[] = Array.isArray(msg.entries) ? msg.entries : [];
        loadTerminal(entries);
        break;
      }
      case 'line':
        writeTerminal(KINDS.includes(msg.kind) ? msg.kind : 'STATUS', String(msg.text));
        break;
      case 'lines':
        for (const item of Array.isArray(msg.items) ? msg.items : []) {
          if (!Array.isArray(item) || item.length < 2) continue;
          writeTerminal(KINDS.includes(item[0]) ? item[0] : 'STATUS', String(item[1]));
        }
        break;
      case 'theme':
        if (typeof msg.name === 'string') store.dispatch(uiActions.setTheme(msg.name));
        break;
      case 'clear':
        clearTerminal();
        store.dispatch(outputActions.clear());
        break;
      default:
    }
  });
}
