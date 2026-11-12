// Saved work: the Hooks tab's hooks and the address bookmarks are loaded when
// the app starts and written back (through main, which owns the file) a moment
// after they change. Session state — what is hooked right now, call counts —
// is not saved.
import { hooksActions } from './store/hooksSlice';
import { bookmarksActions, Bookmark } from './store/bookmarksSlice';
import { Hook } from './hooking/model';
import { writeTerminal } from './bridge';
import { cleanIpcError } from './inspector/format';

/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyStore = any;

export const SAVE_DELAY_MS = 400;

const savedHook = (h: Hook) => ({ id: h.id, name: h.name, module: h.module, offset: h.offset, address: h.address, code: h.code, enabled: h.enabled, backtrace: h.backtrace });

// What goes to disk, as text: used to tell whether anything worth saving changed.
export function snapshot(state: { hooks?: { hooks: Hook[] }; bookmarks?: { items: Bookmark[] } }): string {
  return JSON.stringify({ hooks: (state.hooks?.hooks ?? []).map(savedHook), bookmarks: state.bookmarks?.items ?? [] });
}

// Load what was saved, then keep it saved. Returns a function that writes any
// pending change at once (used when the window is closing, and by tests).
export async function initWorkspace(store: AnyStore, injected?: any): Promise<() => Promise<void>> {
  const api = (injected ?? (window as any).fermion)?.workspace;
  if (!api) return async () => {};

  try {
    const saved = await api.load();
    const hooks: Hook[] = (Array.isArray(saved?.hooks) ? saved.hooks : []).map((h: any) => ({
      ...h, status: h.enabled === false ? 'off' : 'waiting', error: '', calls: 0,
    }));
    // Anything the operator already did while this was loading stays.
    if (hooks.length && !store.getState().hooks.hooks.length) store.dispatch(hooksActions.loaded(hooks));
    if (Array.isArray(saved?.bookmarks) && saved.bookmarks.length && !store.getState().bookmarks.items.length) {
      store.dispatch(bookmarksActions.loaded(saved.bookmarks));
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
