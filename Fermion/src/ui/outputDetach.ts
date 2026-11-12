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

  out.onState((detached: boolean) => {
    if (!detached) setOutputMirror(null);
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
        setOutputMirror({
          line: (kind, text) => out.send({ t: 'line', kind, text }),
          clear: () => out.send({ t: 'clear' }),
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
