// Preferences: how the operator likes Fermion to look and to start out. They
// are kept in this window's local storage (like the colour theme), never sent
// to the main process or the target, and every value read back is checked:
// anything that is not a valid choice becomes the default.
export type ScopeDefault = 'all' | 'app';
export type WatchModeDefault = 'auto' | 'sampled';

export interface Prefs {
  editorFontSize: number;      // pixels, script editor (hook handlers follow, two sizes smaller)
  editorMinimap: boolean;
  editorWordWrap: boolean;
  outputFontSize: number;      // pixels
  coverScope: ScopeDefault;    // what Coverage records unless told otherwise
  followScope: ScopeDefault;   // what Follow goes into unless told otherwise
  watchMode: WatchModeDefault; // how a memory watch is kept unless told otherwise
  autoRefreshSeconds: number;  // the Auto button on Threads and Memory
  catchChildren: boolean;      // "Catch child processes" is on when Fermion starts
}

export const PREFS_KEY = 'fermion.prefs';

export const DEFAULT_PREFS: Prefs = {
  editorFontSize: 14,
  editorMinimap: true,
  editorWordWrap: false,
  outputFontSize: 13,
  coverScope: 'app',
  followScope: 'all',
  watchMode: 'auto',
  autoRefreshSeconds: 2,
  catchChildren: false,
};

export const FONT_MIN = 9;
export const FONT_MAX = 24;
export const REFRESH_MIN = 1;
export const REFRESH_MAX = 30;

function whole(value: unknown, min: number, max: number, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.round(value)));
}
const flag = (value: unknown, fallback: boolean) => (typeof value === 'boolean' ? value : fallback);
function oneOf<T extends string>(value: unknown, choices: readonly T[], fallback: T): T {
  return typeof value === 'string' && (choices as readonly string[]).includes(value) ? (value as T) : fallback;
}

// Any value -> valid preferences, holding only the known fields.
export function cleanPrefs(raw: unknown): Prefs {
  const r = (raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}) as Record<string, unknown>;
  const d = DEFAULT_PREFS;
  return {
    editorFontSize: whole(r.editorFontSize, FONT_MIN, FONT_MAX, d.editorFontSize),
    editorMinimap: flag(r.editorMinimap, d.editorMinimap),
    editorWordWrap: flag(r.editorWordWrap, d.editorWordWrap),
    outputFontSize: whole(r.outputFontSize, FONT_MIN, FONT_MAX, d.outputFontSize),
    coverScope: oneOf(r.coverScope, ['all', 'app'] as const, d.coverScope),
    followScope: oneOf(r.followScope, ['all', 'app'] as const, d.followScope),
    watchMode: oneOf(r.watchMode, ['auto', 'sampled'] as const, d.watchMode),
    autoRefreshSeconds: whole(r.autoRefreshSeconds, REFRESH_MIN, REFRESH_MAX, d.autoRefreshSeconds),
    catchChildren: flag(r.catchChildren, d.catchChildren),
  };
}

export function loadPrefs(): Prefs {
  try {
    const saved = localStorage.getItem(PREFS_KEY);
    if (saved) return cleanPrefs(JSON.parse(saved));
  } catch { /* storage unavailable or damaged: the defaults */ }
  return { ...DEFAULT_PREFS };
}

export function savePrefs(prefs: Prefs): void {
  try { localStorage.setItem(PREFS_KEY, JSON.stringify(cleanPrefs(prefs))); } catch { /* storage may be unavailable */ }
}

// The handler editor in the Hooks tab is a small pane: two sizes under the script editor.
export const handlerFontSize = (prefs: Prefs) => Math.max(FONT_MIN, prefs.editorFontSize - 2);

/* eslint-disable @typescript-eslint/no-explicit-any */
// What Monaco is told for the script editor, and for the handler editor.
export function editorOptions(prefs: Prefs) {
  return { fontSize: prefs.editorFontSize, minimap: { enabled: prefs.editorMinimap }, wordWrap: prefs.editorWordWrap ? 'on' : 'off' };
}
export function handlerOptions(prefs: Prefs) {
  return { fontSize: handlerFontSize(prefs), wordWrap: prefs.editorWordWrap ? 'on' : 'off' };
}

// Apply the preferences to what already exists: the editors and the terminal
// are created outside React and found on the window. Each is optional (an
// editor is created a moment after the app, and starts from loadPrefs()).
export function applyPrefs(prefs: Prefs): void {
  const w = window as any;
  try { w.MonacoCodeEditor?.updateOptions?.(editorOptions(prefs)); } catch { /* editor gone */ }
  try { w.MonacoHookEditor?.updateOptions?.(handlerOptions(prefs)); } catch { /* editor gone */ }
  try { w.__fermion?.terminal?.setFontSize?.(prefs.outputFontSize); } catch { /* terminal gone */ }
}
