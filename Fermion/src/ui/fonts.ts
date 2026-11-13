// Fixed-width fonts for the editor, Output and the Inspector's data. Only the
// built-in font is shipped; any other must already be installed on this
// computer. Nothing is downloaded, and the installed fonts cannot be listed, so
// a known set of common ones is tried and the operator may type another name.
export const BUILT_IN_FONT = 'IBM Plex Mono';
export const SYSTEM_FONT = 'System monospace';
export const FONT_NAME_MAX = 64;

// Common fixed-width families: Windows, macOS, Linux, then ones people install.
export const FONT_CANDIDATES: readonly string[] = [
  'Cascadia Mono', 'Cascadia Code', 'Consolas', 'Lucida Console', 'Courier New',
  'SF Mono', 'Menlo', 'Monaco',
  'DejaVu Sans Mono', 'Liberation Mono', 'Ubuntu Mono', 'Noto Sans Mono',
  'JetBrains Mono', 'Fira Code', 'Source Code Pro', 'Hack', 'Iosevka',
];

// A family name as typed or stored -> one that is safe to place in a CSS font
// stack: letters, digits, spaces and - _ . only. Anything else gives the fallback.
export function cleanFontName(value: unknown, fallback: string = BUILT_IN_FONT): string {
  if (typeof value !== 'string') return fallback;
  const name = value.replace(/[^\p{L}\p{N} ._-]/gu, '').replace(/\s+/g, ' ').trim().slice(0, FONT_NAME_MAX).trim();
  return name || fallback;
}

// The CSS font stack for a chosen family. The built-in font always follows, so
// a family that is not installed shows as the built-in one.
export function fontStack(name: string): string {
  if (name === SYSTEM_FONT) return 'ui-monospace, SFMono-Regular, Menlo, Consolas, "DejaVu Sans Mono", monospace';
  if (name === BUILT_IN_FONT) return '"IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
  return `"${cleanFontName(name)}", "IBM Plex Mono", ui-monospace, monospace`;
}

export type FontState = 'installed' | 'missing' | 'proportional' | 'unknown';

let ctx: CanvasRenderingContext2D | null | undefined;
function widthOf(font: string, text: string): number | null {
  if (ctx === undefined) {
    try { ctx = document.createElement('canvas').getContext('2d'); } catch { ctx = null; }
  }
  if (!ctx) return null;
  ctx.font = font;
  return ctx.measureText(text).width;
}

const SAMPLE = 'mmmmmmmmmmlliWW@0O';
const known = new Map<string, FontState>();

// Whether a family is installed here, found by drawing: text set in
// `"family", monospace` and in `"family", serif` has the same width only when
// the family itself was used for both. Then narrow and wide letters are
// compared, to tell a fixed-width font from one that is not.
// 'unknown' where nothing can be measured (no canvas).
export function fontState(name: string): FontState {
  if (name === BUILT_IN_FONT || name === SYSTEM_FONT) return 'installed';
  const hit = known.get(name);
  if (hit) return hit;
  const family = `"${cleanFontName(name)}"`;
  const mono = widthOf('72px monospace', SAMPLE);
  const serif = widthOf('72px serif', SAMPLE);
  const a = widthOf(`72px ${family}, monospace`, SAMPLE);
  const b = widthOf(`72px ${family}, serif`, SAMPLE);
  let state: FontState;
  if (mono == null || serif == null || a == null || b == null || mono === serif) state = 'unknown';
  else if (a !== b) state = 'missing';
  else {
    const narrow = widthOf(`72px ${family}, monospace`, 'iiiiiiii');
    const wide = widthOf(`72px ${family}, monospace`, 'MMMMMMMM');
    state = narrow != null && wide != null && Math.abs(narrow - wide) > 0.5 ? 'proportional' : 'installed';
  }
  known.set(name, state);
  return state;
}

// The candidates that are installed on this computer.
export function installedFonts(): string[] {
  return FONT_CANDIDATES.filter((name) => fontState(name) === 'installed');
}

// For tests: forget what was measured.
export function forgetFonts(): void { known.clear(); ctx = undefined; }
