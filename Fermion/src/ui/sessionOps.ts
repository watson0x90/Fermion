// Session operations shared by the Session sidebar and the Process tree, so
// "attach" means the same thing wherever it is triggered: attach, mirror the
// service state into the store, then load the editor's script.
import { sessionActions } from './store/sessionSlice';
import { writeTerminal } from './bridge';
import { installAll } from './hooking/ops';
import { Hook } from './hooking/model';
import { cleanIpcError } from './inspector/format';
import { SessionTarget, SpawnConfig, Proc, parseEnv, pickReattach } from './session/launch';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;
const scriptSrc = (): string => (window as any).MonacoCodeEditor?.getValue?.() ?? '';

// Returns true when attached and the script is loaded. A failure (access
// denied, process gone, script error) is reported in Output rather than thrown.
export async function attachAndLoad(dispatch: (a: any) => unknown, pid: number, name = ''): Promise<boolean> {
  const f = api();
  if (!f) return false;
  try {
    await f.attach(pid);
    dispatch(sessionActions.sessionStarted({ kind: 'attach', pid, name }));
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

// Reload the editor's script into the attached process (Ctrl-T, the sidebar's
// Reload, and the Editor toolbar's Reload all come here). Returns true when
// the new script is loaded; a failure is reported in Output.
export async function reloadFromEditor(dispatch: (a: any) => unknown): Promise<boolean> {
  const f = api();
  if (!f) return false;
  try {
    await f.reloadScript(scriptSrc());
    dispatch(sessionActions.scriptLoaded());
    writeTerminal('STATUS', '[+] Script reloaded..');
    return true;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    writeTerminal('ERR', '[!] Error reloading script: ' + msg);
    return false;
  }
}

// Start a program under Frida: spawn it suspended, load the editor's script,
// place the Hooks tab's hooks, and then resume it — or, with `suspended`, leave
// it waiting so more can be set up before its first instruction runs. Returns
// true when the session is up; a failure is reported in Output.
export async function spawnAndLoad(dispatch: (a: any) => unknown, config: SpawnConfig, hooks: Hook[]): Promise<boolean> {
  const f = api();
  if (!f) return false;
  const { env, error } = parseEnv(config.env);
  if (error) { writeTerminal('ERR', '[!] Spawn: ' + error); return false; }
  const options: { env?: Record<string, string>; cwd?: string } = {};
  if (Object.keys(env).length) options.env = env;
  if (config.cwd.trim()) options.cwd = config.cwd.trim();
  let pid: number | null = null;
  try {
    const spawned = Object.keys(options).length ? await f.spawn(config.path, config.args, options) : await f.spawn(config.path, config.args);
    pid = spawned.pid;
    // Hooks first, while the store still shows no session: the Hooks tab then
    // finds them placed and does not place them a second time.
    await installAll(dispatch, hooks);
    dispatch(sessionActions.sessionStarted({ kind: 'spawn', ...config }));
    dispatch(sessionActions.syncState(await f.getState()));
    await f.loadScript(scriptSrc());
    dispatch(sessionActions.scriptLoaded());
    if (config.suspended) {
      dispatch(sessionActions.suspendedSet(pid));
      writeTerminal('STATUS', `[+] Spawned PID ${pid}, suspended. Press Resume to let it run.`);
    } else {
      await f.resume(pid);
      writeTerminal('STATUS', `[+] Spawned PID ${pid}`);
    }
    return true;
  } catch (e) {
    writeTerminal('ERR', '[!] Spawn failed: ' + cleanIpcError(e));
    // Never leave a process we started frozen behind a failed setup.
    if (pid !== null) { try { await f.resume(pid); } catch { /* it is gone, or was never suspended */ } }
    return false;
  }
}

export async function resumeSpawned(dispatch: (a: any) => unknown, pid: number): Promise<void> {
  try {
    await api().resume(pid);
    writeTerminal('STATUS', `[+] Resumed PID ${pid}`);
  } catch (e) {
    writeTerminal('ERR', '[!] Could not resume PID ' + pid + ': ' + cleanIpcError(e));
  } finally {
    dispatch(sessionActions.suspendedSet(null));
  }
}

// Start the last session's target again: spawn the same program the same way,
// or attach to the same program if it can be told which process that is.
// '' on success, else why not.
export async function reconnect(dispatch: (a: any) => unknown, target: SessionTarget, hooks: Hook[]): Promise<string> {
  if (target.kind === 'spawn') {
    return (await spawnAndLoad(dispatch, target, hooks)) ? '' : 'The program could not be started (see Output).';
  }
  let procs: Proc[];
  try {
    procs = await api().enumerateProcesses();
  } catch (e) {
    return 'Could not list processes: ' + cleanIpcError(e);
  }
  const { pid, message } = pickReattach(procs, target);
  if (pid === null) return message;
  return (await attachAndLoad(dispatch, pid, target.name)) ? '' : 'Could not attach (see Output).';
}
