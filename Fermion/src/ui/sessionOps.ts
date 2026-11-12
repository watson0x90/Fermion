// Session operations shared by the Session sidebar and the Process tree, so
// "attach" means the same thing wherever it is triggered: attach, mirror the
// service state into the store, then load the editor's script.
import { sessionActions } from './store/sessionSlice';
import { writeTerminal } from './bridge';
import { installAll } from './hooking/ops';
import { Hook } from './hooking/model';
import { cleanIpcError } from './inspector/format';
import { SessionTarget, SpawnConfig, Proc, ChildInfo, parseEnv, pickReattach, childName, childCommand } from './session/launch';
import { hooksActions } from './store/hooksSlice';
import { isTypeScript } from './fileOps';
import { switchSet, programName } from './workspace';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;
const scriptSrc = (): string => (window as any).MonacoCodeEditor?.getValue?.() ?? '';

// Load (or reload) the editor's script, and say so when it had to be compiled
// because it imports packages.
async function loadEditorScript(f: any, dispatch: (a: any) => unknown, reload = false): Promise<void> {
  const options = scriptOptions(dispatch);
  const load = reload ? f.reloadScript : f.loadScript;
  const r = options ? await load(scriptSrc(), options) : await load(scriptSrc());
  if (r && r.typescript) writeTerminal('STATUS', '[+] TypeScript compiled, types checked');
  else if (r && r.compiled) writeTerminal('STATUS', '[+] Script compiled with the packages it imports');
}

// What the editor's script is written in, for main: { typescript: true } for
// a file saved as .ts, nothing for JavaScript.
export function scriptOptions(dispatch: (a: any) => unknown): { typescript: true } | undefined {
  let path: unknown;
  try { path = dispatch((_d: unknown, getState: () => any) => getState()?.ui?.filePath); } catch { /* a store that takes no functions */ }
  return isTypeScript(typeof path === 'string' ? path : null) ? { typescript: true } : undefined;
}

// Hooks and bookmarks are kept per program: bring in the set of the program
// the session is starting on. Returns the hooks to place — that set's, or
// `fallback` where no sets are kept or the program has no name.
function targetHooks(dispatch: (a: any) => unknown, program: string, fallback: Hook[]): Hook[] {
  if (!program) return fallback;
  const hooks = dispatch(switchSet(program)) as unknown;
  return Array.isArray(hooks) ? hooks as Hook[] : fallback;
}

// Returns true when attached and the script is loaded. A failure (access
// denied, process gone, script error) is reported in Output rather than thrown.
// With `rethrow` the failure is also thrown, for callers that need the reason.
export async function attachAndLoad(dispatch: (a: any) => unknown, pid: number, name = '', rethrow = false): Promise<boolean> {
  const f = api();
  if (!f) return false;
  try {
    await f.attach(pid);
    if (!name) {
      // Attached by pid alone: find out which program it is, for its saved set.
      try { name = ((await f.enumerateProcesses()) as Proc[]).find((p) => p.pid === pid)?.name ?? ''; } catch { /* stays unnamed */ }
    }
    targetHooks(dispatch, name, []); // this program's hooks and bookmarks; the Hooks tab places them
    dispatch(sessionActions.sessionStarted({ kind: 'attach', pid, name }));
    dispatch(sessionActions.syncState(await f.getState()));
    await loadEditorScript(f, dispatch);
    dispatch(sessionActions.scriptLoaded());
    return true;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    writeTerminal('ERR', `[!] Attach to PID ${pid} failed: ${msg}`);
    if (rethrow) throw e;
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
    await loadEditorScript(f, dispatch, true);
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
    await installAll(dispatch, targetHooks(dispatch, programName(config.path), hooks));
    dispatch(sessionActions.sessionStarted({ kind: 'spawn', ...config }));
    dispatch(sessionActions.syncState(await f.getState()));
    await loadEditorScript(f, dispatch);
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

// Switch catching child processes on or off for the attached process. The
// preference is kept, so the next session starts with it too.
export async function setChildGating(dispatch: (a: any) => unknown, on: boolean, attached: boolean): Promise<void> {
  dispatch(sessionActions.childGatingSet(on));
  if (!attached) return;
  try {
    await api().setChildGating(on);
  } catch (e) {
    writeTerminal('ERR', '[!] Could not ' + (on ? 'start' : 'stop') + ' catching child processes: ' + cleanIpcError(e));
    if (on) dispatch(sessionActions.childGatingSet(false));
  }
}

// Let a caught child run without us.
export async function releaseChild(dispatch: (a: any) => unknown, child: ChildInfo): Promise<void> {
  dispatch(sessionActions.childResolved(child.pid));
  try {
    await api().resolveChild(child.pid, 'resume');
    writeTerminal('STATUS', `[+] Child process ${child.pid} was let run`);
  } catch (e) {
    writeTerminal('ERR', '[!] Could not resume child ' + child.pid + ': ' + cleanIpcError(e));
  }
}

// Move the session to a caught child: the script is loaded and the hooks are
// placed in it while it is still suspended, then it is resumed — or, with
// `suspended`, left waiting for Resume. The parent carries on uninstrumented.
export async function switchToChild(dispatch: (a: any) => unknown, child: ChildInfo, hooks: Hook[], opts: { suspended: boolean; keepCatching: boolean }): Promise<boolean> {
  const f = api();
  let moved = false;
  try {
    await f.resolveChild(child.pid, 'attach');
    moved = true;
    // The old session is gone (and main let its other caught children run).
    dispatch(sessionActions.childrenCleared());
    dispatch(hooksActions.sessionEnded());
    await installAll(dispatch, hooks.map((h) => ({ ...h, status: h.enabled ? 'waiting' as const : 'off' as const })));
    dispatch(sessionActions.sessionStarted({ kind: 'attach', pid: child.pid, name: childName(child) }));
    dispatch(sessionActions.syncState(await f.getState()));
    await loadEditorScript(f, dispatch);
    dispatch(sessionActions.scriptLoaded());
    if (opts.keepCatching) {
      try { await f.setChildGating(true); } catch (e) { writeTerminal('ERR', '[!] Child processes of the new process are not being caught: ' + cleanIpcError(e)); dispatch(sessionActions.childGatingSet(false)); }
    }
    if (opts.suspended) {
      dispatch(sessionActions.suspendedSet(child.pid));
      writeTerminal('STATUS', `[+] Now on child process ${child.pid}, suspended. Press Resume to let it run.`);
    } else {
      await f.resume(child.pid);
      writeTerminal('STATUS', child.replaced ? `[+] Now on ${childCommand(child)} (pid ${child.pid})` : `[+] Now on child process ${child.pid}`);
    }
    return true;
  } catch (e) {
    writeTerminal('ERR', (child.replaced ? '[!] Could not follow process ' + child.pid + ' into its new program: ' : '[!] Could not switch to child ' + child.pid + ': ') + cleanIpcError(e));
    dispatch(sessionActions.childResolved(child.pid));
    // Never leave it frozen: if the session did move, resume it there.
    if (moved) {
      try { await f.resume(child.pid); } catch { /* it is gone */ }
      try { dispatch(sessionActions.syncState(await f.getState())); } catch { /* keep what we have */ }
    }
    return false;
  }
}

// The attached process replaced its program (exec) while catching was on:
// main holds the new program at its first instruction. Nothing to choose:
// the session carries on in it, script and hooks in place before it runs.
export async function followReplacement(dispatch: (a: any) => unknown, child: ChildInfo, hooks: Hook[]): Promise<boolean> {
  writeTerminal('STATUS', `[+] Process ${child.pid} started a new program: ${childCommand(child)}. Following it.`);
  return switchToChild(dispatch, child, hooks, { suspended: false, keepCatching: true });
}
