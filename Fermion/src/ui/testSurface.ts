// Re-provides the Playwright test surface (window.__fermion / window.MonacoCodeEditor)
// for the React app. The isolated renderer has no ipcRenderer, so the suite
// drives the app through these supported hooks (terminal text, a state view, an
// attach trigger, and a synthetic-message injector) instead.
import { formatMessage } from '../output-model.js';
import { writeTerminal } from './bridge';
import { sessionActions } from './store/sessionSlice';

/* eslint-disable @typescript-eslint/no-explicit-any */
export function exposeTestSurface(store: any) {
  const w = window as any;
  w.__fermion = w.__fermion || {};

  // Inject a synthetic Frida message/log record straight to the terminal
  // (ui-test-console-log drives this).
  w.__fermion.handleScriptMessage = (m: any) => {
    const { kind, text } = formatMessage(m);
    writeTerminal(kind, text);
  };

  // A synchronous view of the session state (the bridge is async).
  w.__fermion.service = {
    get isAttached() { return store.getState().session.isAttached; },
    get hasScript() { return store.getState().session.hasScript; },
    get currentPid() { return store.getState().session.currentPid; },
    get deviceId() { return store.getState().session.deviceId; },
  };

  // Drive a real attach the way the Session panel does (ui-test-attach-console,
  // ui-test-trace-detach). Logs the same status line the app shows.
  w.__fermion.triggerAttach = async (pid: number | string) => {
    const f = w.fermion;
    writeTerminal('STATUS', '[?] Attempting process attach..');
    await f.attach(Number(pid));
    store.dispatch(sessionActions.syncState(await f.getState()));
    writeTerminal('STATUS', '[+] Injecting => PID: ' + pid);
    await f.loadScript(w.MonacoCodeEditor.getValue());
    store.dispatch(sessionActions.scriptLoaded());
  };
}
