// What the Hooks tab does to the target: place, change, switch and remove
// hooks through window.fermion.hooks, keeping the store in step.
import { hooksActions } from '../store/hooksSlice';
import { cleanIpcError } from '../inspector/format';
import { Hook, Target, hookFromTarget, sameTarget } from './model';
import { Preset } from './presets';

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

export interface PresetOutcome { added: string[]; present: string[]; missing: string[]; failed: string[]; }

// Add a preset's hooks to the attached process. Each function is looked up
// by its exact exported name in the modules the preset names, first hit
// wins; one that is not there (its module is not loaded, or this is not
// Windows) is reported as missing, and one already hooked is left alone.
export async function addPreset(dispatch: Dispatch, preset: Preset, existing: Hook[]): Promise<PresetOutcome> {
  const out: PresetOutcome = { added: [], present: [], missing: [], failed: [] };
  const known: Target[] = existing.slice();
  for (const entry of preset.hooks) {
    let target: Target | null = null;
    for (const module of entry.modules) {
      let items: Target[] = [];
      try { items = (await api().search('exports', module + '!' + entry.fn))?.items ?? []; } catch { /* treated as not found */ }
      // The search matches patterns and ignores case: keep the exact name only.
      target = items.find((t) => typeof t?.name === 'string' && t.name.slice(t.name.lastIndexOf('!') + 1) === entry.fn) ?? null;
      if (target) break;
    }
    if (!target) { out.missing.push(entry.fn); continue; }
    if (known.some((h) => sameTarget(h, target!))) { out.present.push(entry.fn); continue; }
    const hook: Hook = { ...hookFromTarget(target), code: entry.handler, backtrace: entry.callers !== false };
    known.push(hook);
    dispatch(hooksActions.added(hook));
    const error = await installHook(dispatch, hook);
    if (error) out.failed.push(entry.fn); else out.added.push(entry.fn);
  }
  return out;
}

// One sentence saying what adding a preset did.
export function presetSummary(label: string, o: PresetOutcome): string {
  const parts: string[] = [];
  const n = (count: number, what: string) => count + ' ' + what + (count === 1 ? '' : 's');
  if (o.added.length) parts.push(n(o.added.length, 'hook') + ' added');
  if (o.present.length) parts.push(o.present.length + ' already there');
  if (o.failed.length) parts.push(o.failed.length + ' could not be placed (' + o.failed.join(', ') + ')');
  if (o.missing.length) parts.push(o.missing.length + ' not found in this process (' + o.missing.join(', ') + ')');
  if (!o.added.length && !o.present.length && !o.failed.length) return label + ': none of its functions are in this process. The presets are for Windows programs, and a module that is not loaded yet is skipped.';
  return label + ': ' + parts.join('; ') + '.';
}
