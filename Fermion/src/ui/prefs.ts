// Preferences: how the operator likes Fermion to look and to start out. They
// are kept in this window's local storage (like the colour theme), never sent
// to the main process or the target, and every value read back is checked:
// anything that is not a valid choice becomes the default.
import { BUILT_IN_FONT, cleanFontName, fontStack } from './fonts';

export type ScopeDefault = 'all' | 'app';
export type WatchModeDefault = 'auto' | 'sampled';

export type Spacing = 'compact' | 'normal' | 'relaxed';
export type Whitespace = 'none' | 'selection' | 'all';
export type EditorCursor = 'line' | 'block' | 'underline';
export type OutputCursor = 'bar' | 'block' | 'underline';

export interface Prefs {
  dataFontFamily: string;      // addresses, hex and tables in the Inspector and elsewhere
  editorFontFamily: string;
  editorLineSpacing: Spacing;
  editorLineNumbers: boolean;
  editorTabSize: number;       // 2, 4 or 8
  editorWhitespace: Whitespace;
  editorCursor: EditorCursor;
  outputFontFamily: string;
  outputLineSpacing: Spacing;
  outputCursor: OutputCursor;
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
  dataFontFamily: BUILT_IN_FONT,
  editorFontFamily: BUILT_IN_FONT,
  editorLineSpacing: 'normal',
  editorLineNumbers: true,
  editorTabSize: 4,
  editorWhitespace: 'selection',
  editorCursor: 'line',
  outputFontFamily: BUILT_IN_FONT,
  outputLineSpacing: 'compact',
  outputCursor: 'bar',
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

// Which section of Settings each preference is shown in (and reset with).
export type Section = 'appearance' | 'editor' | 'output' | 'inspector' | 'session';
export const SECTION_OF: Record<keyof Prefs, Section> = {
  dataFontFamily: 'appearance',
  editorFontFamily: 'editor', editorFontSize: 'editor', editorLineSpacing: 'editor', editorLineNumbers: 'editor',
  editorMinimap: 'editor', editorWordWrap: 'editor', editorTabSize: 'editor', editorWhitespace: 'editor', editorCursor: 'editor',
  outputFontFamily: 'output', outputFontSize: 'output', outputLineSpacing: 'output', outputCursor: 'output',
  coverScope: 'inspector', followScope: 'inspector', watchMode: 'inspector', autoRefreshSeconds: 'inspector',
  catchChildren: 'session',
};

export const TAB_SIZES = [2, 4, 8] as const;
const SPACINGS = ['compact', 'normal', 'relaxed'] as const;
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
    dataFontFamily: cleanFontName(r.dataFontFamily, d.dataFontFamily),
    editorFontFamily: cleanFontName(r.editorFontFamily, d.editorFontFamily),
    editorLineSpacing: oneOf(r.editorLineSpacing, SPACINGS, d.editorLineSpacing),
    editorLineNumbers: flag(r.editorLineNumbers, d.editorLineNumbers),
    editorTabSize: (TAB_SIZES as readonly number[]).includes(r.editorTabSize as number) ? (r.editorTabSize as number) : d.editorTabSize,
    editorWhitespace: oneOf(r.editorWhitespace, ['none', 'selection', 'all'] as const, d.editorWhitespace),
    editorCursor: oneOf(r.editorCursor, ['line', 'block', 'underline'] as const, d.editorCursor),
    outputFontFamily: cleanFontName(r.outputFontFamily, d.outputFontFamily),
    outputLineSpacing: oneOf(r.outputLineSpacing, SPACINGS, d.outputLineSpacing),
    outputCursor: oneOf(r.outputCursor, ['bar', 'block', 'underline'] as const, d.outputCursor),
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

// Line spacing. The editor's is a multiple of the font size (0 lets the editor
// choose, which is what it did before there was a choice); Output's is a
// multiple of the line itself.
export const EDITOR_LINE: Record<Spacing, number> = { compact: 1.25, normal: 0, relaxed: 1.7 };
export const OUTPUT_LINE: Record<Spacing, number> = { compact: 1, normal: 1.15, relaxed: 1.3 };

/* eslint-disable @typescript-eslint/no-explicit-any */
// What Monaco is told for the script editor, and for the handler editor.
export function editorOptions(prefs: Prefs) {
  return {
    fontSize: prefs.editorFontSize,
    fontFamily: fontStack(prefs.editorFontFamily),
    lineHeight: EDITOR_LINE[prefs.editorLineSpacing],
    lineNumbers: prefs.editorLineNumbers ? 'on' : 'off',
    minimap: { enabled: prefs.editorMinimap },
    wordWrap: prefs.editorWordWrap ? 'on' : 'off',
    tabSize: prefs.editorTabSize,
    renderWhitespace: prefs.editorWhitespace,
    cursorStyle: prefs.editorCursor,
  };
}
export function handlerOptions(prefs: Prefs) {
  const o = editorOptions(prefs);
  return { fontSize: handlerFontSize(prefs), fontFamily: o.fontFamily, lineHeight: o.lineHeight, wordWrap: o.wordWrap, tabSize: o.tabSize, renderWhitespace: o.renderWhitespace, cursorStyle: o.cursorStyle };
}
// What the Output terminal is told.
export function outputLook(prefs: Prefs) {
  return { fontSize: prefs.outputFontSize, fontFamily: fontStack(prefs.outputFontFamily), lineHeight: OUTPUT_LINE[prefs.outputLineSpacing], cursorStyle: prefs.outputCursor };
}

// Apply the preferences to what already exists: the editors and the terminal
// are created outside React and found on the window. Each is optional (an
// editor is created a moment after the app, and starts from loadPrefs()).
export function applyPrefs(prefs: Prefs): void {
  const w = window as any;
  try { document.documentElement.style.setProperty('--mono', fontStack(prefs.dataFontFamily)); } catch { /* no document */ }
  for (const [editor, options] of [[w.MonacoCodeEditor, editorOptions(prefs)], [w.MonacoHookEditor, handlerOptions(prefs)]] as const) {
    try {
      editor?.updateOptions?.(options);
      editor?.getModel?.()?.updateOptions?.({ tabSize: prefs.editorTabSize }); // the tab width belongs to the text, not the editor
    } catch { /* editor gone */ }
  }
  try { w.monaco?.editor?.remeasureFonts?.(); } catch { /* no editor yet */ } // or the cursor drifts after a change of font
  try {
    const terminal = w.__fermion?.terminal;
    if (terminal?.setLook) terminal.setLook(outputLook(prefs));
    else terminal?.setFontSize?.(prefs.outputFontSize);
  } catch { /* terminal gone */ }
}
