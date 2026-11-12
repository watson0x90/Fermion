// What the Hooks tab does to the target: place, change, switch and remove
// hooks through window.fermion.hooks, keeping the store in step.
import { hooksActions } from '../store/hooksSlice';
import { cleanIpcError } from '../inspector/format';
import { Hook, Target, hookFromTarget } from './model';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion?.hooks;
type Dispatch = (action: any) => unknown;

// Is the hook known to the agent of the current session?
const placed = (hook: Hook) => hook.status === 'on' || hook.status === 'off';

// Place (or place again) a hook in the attached process. '' on success, else
// the reason, which is also kept on the hook.
export async function installHook(dispatch: Dispatch, hook: Hook): Promise<string> {
  try {
    const r = await api().add({
      id: hook.id, module: hook.module, offset: hook.offset, address: hook.address,
      code: hook.code, enabled: hook.enabled, backtrace: hook.backtrace,
    });
    dispatch(hooksActions.patched({
      id: hook.id, status: r?.enabled ? 'on' : 'off', error: '',
      address: typeof r?.address === 'string' ? r.address : hook.address,
    }));
    return '';
  } catch (e) {
    const error = cleanIpcError(e);
    dispatch(hooksActions.patched({ id: hook.id, status: 'error', error }));
    return error;
  }
}

// A new session: every hook is placed again where its module now is.
export async function installAll(dispatch: Dispatch, hooks: Hook[]): Promise<void> {
  for (const hook of hooks) await installHook(dispatch, hook);
}

export async function addTarget(dispatch: Dispatch, target: Target, attached: boolean): Promise<Hook> {
  const hook = hookFromTarget(target);
  dispatch(hooksActions.added(hook));
  if (attached) await installHook(dispatch, hook);
  return hook;
}

export async function setEnabled(dispatch: Dispatch, hook: Hook, on: boolean, attached: boolean): Promise<void> {
  const next = { ...hook, enabled: on };
  dispatch(hooksActions.patched({ id: hook.id, enabled: on, ...(attached ? {} : { status: on ? 'waiting' as const : 'off' as const }) }));
  if (!attached) return;
  if (!placed(hook)) { await installHook(dispatch, next); return; }
  try {
    const r = await api().enable(hook.id, on);
    dispatch(hooksActions.patched({ id: hook.id, status: r?.enabled ? 'on' : 'off', error: '' }));
  } catch (e) {
    dispatch(hooksActions.patched({ id: hook.id, status: 'error', error: cleanIpcError(e) }));
  }
}

// Use a new handler (and backtrace setting). '' on success. On failure the
// hook keeps running its previous handler and the reason is returned for the
// editor to show.
export async function applyHandler(dispatch: Dispatch, hook: Hook, code: string, backtrace: boolean, attached: boolean): Promise<string> {
  if (!attached) {
    dispatch(hooksActions.patched({ id: hook.id, code, backtrace }));
    return '';
  }
  if (!placed(hook)) {
    dispatch(hooksActions.patched({ id: hook.id, code, backtrace }));
    return installHook(dispatch, { ...hook, code, backtrace });
  }
  try {
    await api().update(hook.id, { code, backtrace });
    dispatch(hooksActions.patched({ id: hook.id, code, backtrace, error: '' }));
    return '';
  } catch (e) {
    return cleanIpcError(e);
  }
}

export async function removeHook(dispatch: Dispatch, hook: Hook, attached: boolean): Promise<void> {
  dispatch(hooksActions.removed(hook.id));
  if (attached && placed(hook)) {
    try { await api().remove(hook.id); } catch { /* the session went away: nothing left to remove */ }
  }
}
