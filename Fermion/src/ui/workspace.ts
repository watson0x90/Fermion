// Saved work: the Hooks tab's hooks and the address bookmarks are loaded when
// the app starts and written back (through main, which owns the file) a moment
// after they change. They are kept as one set per program: attaching to or
// spawning a program brings its set in, and the one that was in use is put
// away. Session state — what is hooked right now, call counts — is not saved.
import { hooksActions } from './store/hooksSlice';
import { bookmarksActions, Bookmark } from './store/bookmarksSlice';
import { setsActions, SavedHook, SavedSet, SetsState } from './store/setsSlice';
import { Hook } from './hooking/model';
import { installAll } from './hooking/ops';
import { writeTerminal } from './bridge';
import { cleanIpcError } from './inspector/format';

/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyStore = any;

export const SAVE_DELAY_MS = 400;

const savedHook = (h: Hook): SavedHook => ({ id: h.id, name: h.name, module: h.module, offset: h.offset, address: h.address, code: h.code, enabled: h.enabled, backtrace: h.backtrace });
const revive = (h: SavedHook): Hook => ({ ...h, status: h.enabled === false ? 'off' : 'waiting', error: '', calls: 0 }) as Hook;

interface Saveable { hooks?: { hooks: Hook[] }; bookmarks?: { items: Bookmark[] }; sets?: SetsState; }

// What goes to disk, as text: used to tell whether anything worth saving changed.
export function snapshot(state: Saveable): string {
  return JSON.stringify({
    hooks: (state.hooks?.hooks ?? []).map(savedHook),
    bookmarks: state.bookmarks?.items ?? [],
    set: state.sets?.active ?? '',
    others: state.sets?.others ?? [],
  });
}

// Program names are compared without case (Windows file names).
export const sameSet = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();
// The general set has no program.
export const setLabel = (name: string): string => name || 'General';
// The program a set is named after: the file name of a path, or a process name.
export const programName = (pathOrName: string): string => pathOrName.trim().split(/[\\/]/).pop() ?? '';

const count = (n: number, what: string) => n + ' ' + what + (n === 1 ? '' : 's');

// Bring in the set of `name`, putting the one in use away. Returns the hooks
// now in use (waiting to be placed), or null when the store keeps no sets.
// Nothing is touched in the target: see changeSet for a switch mid-session.
export const switchSet = (name: string, announce = true) => (dispatch: (a: any) => unknown, getState: () => any): Hook[] | null => {
  const state = getState() as Saveable;
  if (!state.sets || !state.hooks || !state.bookmarks) return null;
  if (sameSet(state.sets.active, name)) return state.hooks.hooks;
  const leaving: SavedSet = { name: state.sets.active, hooks: state.hooks.hooks.map(savedHook), bookmarks: state.bookmarks.items };
  const found = state.sets.others.find((o) => sameSet(o.name, name));
  const others = state.sets.others.filter((o) => !sameSet(o.name, name));
  if (leaving.hooks.length || leaving.bookmarks.length) others.push(leaving); // an empty set is not worth keeping
  const hooks = (found?.hooks ?? []).map(revive);
  const marks = found?.bookmarks ?? [];
  dispatch(setsActions.replaced({ active: found?.name ?? name, others }));
  dispatch(hooksActions.loaded(hooks));
  dispatch(hooksActions.hitsCleared());
  dispatch(bookmarksActions.loaded(marks));
  if (announce) {
    writeTerminal('STATUS', `[+] Hooks and bookmarks: using the set for ${setLabel(name)} (${count(hooks.length, 'hook')}, ${count(marks.length, 'bookmark')})`
      + (leaving.hooks.length || leaving.bookmarks.length ? `. The set for ${setLabel(leaving.name)} is kept.` : ''));
  }
  return hooks;
};

// The operator picks another set. In a session the hooks of the set being
// left are taken out of the process and the new set's hooks are placed.
export async function changeSet(dispatch: (a: any) => unknown, name: string, current: Hook[], attached: boolean): Promise<void> {
  if (attached) {
    const api = (window as any).fermion?.hooks;
    for (const hook of current) {
      if (hook.status !== 'on' && hook.status !== 'off') continue;
      try { await api.remove(hook.id); } catch { /* the session went away: nothing left to remove */ }
    }
  }
  const hooks = dispatch(switchSet(name, false)) as unknown;
  if (attached && Array.isArray(hooks)) await installAll(dispatch, hooks as Hook[]);
}

// Load what was saved, then keep it saved. Returns a function that writes any
// pending change at once (used when the window is closing, and by tests).
export async function initWorkspace(store: AnyStore, injected?: any): Promise<() => Promise<void>> {
  const api = (injected ?? (window as any).fermion)?.workspace;
  if (!api) return async () => {};

  try {
    const saved = await api.load();
    const hooks: Hook[] = (Array.isArray(saved?.hooks) ? saved.hooks : []).map(revive);
    // Anything the operator already did while this was loading stays.
    const untouched = !store.getState().hooks.hooks.length && !store.getState().bookmarks.items.length;
    if (hooks.length && !store.getState().hooks.hooks.length) store.dispatch(hooksActions.loaded(hooks));
    if (Array.isArray(saved?.bookmarks) && saved.bookmarks.length && !store.getState().bookmarks.items.length) {
      store.dispatch(bookmarksActions.loaded(saved.bookmarks));
    }
    if (store.getState().sets && untouched && (typeof saved?.set === 'string' || Array.isArray(saved?.others))) {
      store.dispatch(setsActions.replaced({
        active: typeof saved.set === 'string' ? saved.set : '',
        others: Array.isArray(saved.others) ? saved.others : [],
      }));
    }
  } catch (e) {
    writeTerminal('ERR', '[!] Could not load saved hooks and bookmarks: ' + cleanIpcError(e));
  }

  let last = snapshot(store.getState());
  let timer: ReturnType<typeof setTimeout> | null = null;
  let failed = false;
  const flush = async () => {
    if (timer) { clearTimeout(timer); timer = null; }
    const now = snapshot(store.getState());
    if (now === last) return;
    try {
      await api.save(JSON.parse(now));
      last = now;
      failed = false;
    } catch (e) {
      // Said once, not on every change, until a save works again.
      if (!failed) writeTerminal('ERR', '[!] Could not save hooks and bookmarks: ' + cleanIpcError(e));
      failed = true;
    }
  };
  store.subscribe(() => {
    if (timer || snapshot(store.getState()) === last) return;
    timer = setTimeout(() => { timer = null; flush(); }, SAVE_DELAY_MS);
  });
  window.addEventListener?.('beforeunload', () => { flush(); });
  return flush;
}
