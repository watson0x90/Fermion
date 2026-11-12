// Session operations shared by the Session sidebar and the Process tree, so
// "attach" means the same thing wherever it is triggered: attach, mirror the
// service state into the store, then load the editor's script.
import { sessionActions } from './store/sessionSlice';
import { writeTerminal } from './bridge';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;
const scriptSrc = (): string => (window as any).MonacoCodeEditor?.getValue?.() ?? '';

// Returns true when attached and the script is loaded. A failure (access
// denied, process gone, script error) is reported in Output rather than thrown.
export async function attachAndLoad(dispatch: (a: any) => unknown, pid: number): Promise<boolean> {
  const f = api();
  if (!f) return false;
  try {
    await f.attach(pid);
    dispatch(sessionActions.syncState(await f.getState()));
    await f.loadScript(scriptSrc());
    dispatch(sessionActions.scriptLoaded());
    return true;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    writeTerminal('ERR', `[!] Attach to PID ${pid} failed: ${msg}`);
    return false;
  }
}
