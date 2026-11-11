// Theme engine: derive whole-app CSS-variable tokens from a Monaco theme's own
// colors so the chrome and the editor always agree, then apply them on :root and
// switch Monaco. Drives all shipped Fermion themes (16); default is Kuroir.

/* eslint-disable @typescript-eslint/no-explicit-any */

export interface MonacoTheme {
  base?: 'vs' | 'vs-dark' | 'hc-black' | string;
  colors?: Record<string, string>;
  rules?: unknown;
}

interface RGB { r: number; g: number; b: number; }

// ---- color helpers (pure) ----
export function parseHex(hex: string): RGB {
  let h = (hex || '').trim().replace('#', '');
  if (h.length === 3) h = h.split('').map((c) => c + c).join('');
  if (h.length >= 6) return { r: parseInt(h.slice(0, 2), 16), g: parseInt(h.slice(2, 4), 16), b: parseInt(h.slice(4, 6), 16) }; // ignores trailing alpha
  return { r: 0, g: 0, b: 0 };
}
export function toHex({ r, g, b }: RGB): string {
  const c = (n: number) => Math.max(0, Math.min(255, Math.round(n))).toString(16).padStart(2, '0');
  return `#${c(r)}${c(g)}${c(b)}`;
}
export function mix(a: string, b: string, t: number): string {
  const x = parseHex(a), y = parseHex(b);
  return toHex({ r: x.r + (y.r - x.r) * t, g: x.g + (y.g - x.g) * t, b: x.b + (y.b - x.b) * t });
}
const lighten = (c: string, t: number) => mix(c, '#ffffff', t);
const darken = (c: string, t: number) => mix(c, '#000000', t);

export function relLuminance(hex: string): number {
  const { r, g, b } = parseHex(hex);
  const f = (v: number) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4); };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}
export function contrastRatio(a: string, b: string): number {
  const la = relLuminance(a), lb = relLuminance(b);
  const hi = Math.max(la, lb), lo = Math.min(la, lb);
  return (hi + 0.05) / (lo + 0.05);
}
// Blend `fg` toward `surface` by at most `startMix`, pulling back toward `fg`
// until the result clears `minRatio` contrast against `surface`.
export function mixForContrast(fg: string, surface: string, startMix: number, minRatio: number): string {
  let t = startMix;
  for (let i = 0; i < 24 && t > 0; i++) {
    const c = mix(fg, surface, t);
    if (contrastRatio(c, surface) >= minRatio) return c;
    t = Math.max(0, t - 0.05);
  }
  return fg;
}

function saturation(hex: string): number {
  const { r, g, b } = parseHex(hex);
  const mx = Math.max(r, g, b) / 255, mn = Math.min(r, g, b) / 255;
  if (mx === 0) return 0;
  return (mx - mn) / mx;
}

// Semantic output-kind palettes (legible on light vs dark grounds).
const KIND_DARK = { log: '#56d364', warn: '#e3b341', err: '#f85149', msg: '#79c0ff', status: '#8b949e' };
const KIND_LIGHT = { log: '#2e7d32', warn: '#9a6b00', err: '#c23b2b', msg: '#1f6feb', status: '#5a5c56' };
const FERMION_GREEN_DARK = '#8ddb52';
const FERMION_GREEN_LIGHT = '#4f7d1f';

function pickAccent(colors: Record<string, string>, bg: string, isDark: boolean): string {
  const cursor = colors['editorCursor.foreground'];
  // Use the theme's cursor color only when it's a real hue (not near-gray/white).
  if (cursor && saturation(cursor) >= 0.35) {
    let a = cursor;
    // nudge toward legibility against the background
    if (contrastRatio(a, bg) < 2.2) a = isDark ? lighten(a, 0.25) : darken(a, 0.25);
    return a;
  }
  return isDark ? FERMION_GREEN_DARK : FERMION_GREEN_LIGHT;
}

// Derive the full token set from a Monaco theme. Pure.
export function deriveTokens(theme: MonacoTheme): Record<string, string> {
  const colors = theme.colors || {};
  const editorBg = colors['editor.background'] ? toHex(parseHex(colors['editor.background'])) : '#ffffff';
  const editorFg = colors['editor.foreground'] ? toHex(parseHex(colors['editor.foreground'])) : '#1a1a1a';
  const isDark = theme.base === 'vs-dark' || theme.base === 'hc-black' || relLuminance(editorBg) < 0.4;

  const bg = darken(editorBg, isDark ? 0.14 : 0.06);
  const chrome = mix(editorBg, bg, 0.5);
  const panel = lighten(editorBg, isDark ? 0.05 : 0.045);
  const elev = lighten(editorBg, isDark ? 0.09 : 0.09);
  const title = darken(chrome, isDark ? 0.08 : 0.03);
  // Secondary/tertiary text sits on --panel (the lightest chrome). Clamp both to
  // a contrast floor so low-contrast themes (e.g. Solarized) stay readable.
  const muted = mixForContrast(editorFg, panel, 0.42, 3.1);
  const faint = mixForContrast(editorFg, panel, 0.6, 2.5);
  const border = mix(editorFg, editorBg, isDark ? 0.8 : 0.82);
  const accent = pickAccent(colors, bg, isDark);
  // Button-label ink is the higher-contrast of near-black / white on the accent.
  const accentInk = contrastRatio('#12140e', accent) >= contrastRatio('#ffffff', accent) ? '#12140e' : '#ffffff';
  const kind = isDark ? KIND_DARK : KIND_LIGHT;

  return {
    '--bg': bg, '--chrome': chrome, '--panel': panel, '--elev': elev,
    '--fg': editorFg, '--muted': muted, '--faint': faint, '--border': border,
    '--accent': accent, '--accent-ink': accentInk, '--focus': accent,
    '--editor-bg': editorBg, '--term-bg': mix(editorBg, bg, 0.35), '--title-bg': title,
    '--logo-filter': isDark ? 'invert(1) brightness(1.35)' : 'none',
    '--log': kind.log, '--warn': kind.warn, '--err': kind.err, '--msg': kind.msg, '--status': kind.status,
    'color-scheme': isDark ? 'dark' : 'light',
  };
}

export function isDarkTheme(theme: MonacoTheme): boolean {
  const bg = theme.colors?.['editor.background'];
  return theme.base === 'vs-dark' || theme.base === 'hc-black' || (!!bg && relLuminance(bg) < 0.4);
}

// ---- runtime application ----
const STORAGE_KEY = 'fermion.theme';
const DEFAULT_THEME = 'Kuroir';

function themes(): Record<string, MonacoTheme> {
  return ((window as any).FermionThemes as Record<string, MonacoTheme>) || {};
}

export function themeNames(): string[] {
  const keys = Object.keys(themes());
  if (!keys.length) return [DEFAULT_THEME];
  return [DEFAULT_THEME, ...keys.filter((k) => k !== DEFAULT_THEME)];
}

// Display metadata for the Settings theme picker.
export function themeMeta(name: string): { label: string; swatch: string; dark: boolean } {
  const theme = themes()[name];
  const bg = theme?.colors?.['editor.background'];
  const label = name.replace(/([a-z])([A-Z])/g, '$1 $2'); // idleFingers -> idle Fingers
  return {
    label: label.charAt(0).toUpperCase() + label.slice(1),
    swatch: bg ? toHex(parseHex(bg)) : '#888888',
    dark: theme ? isDarkTheme(theme) : true,
  };
}

export function loadSavedTheme(): string {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && themes()[saved]) return saved;
  } catch { /* storage may be unavailable */ }
  return DEFAULT_THEME;
}

// Apply a theme app-wide: set CSS vars on :root, switch Monaco (defining the
// theme first), and persist the choice. Safe to call before Monaco exists.
export function applyTheme(name: string): void {
  const theme = themes()[name];
  if (!theme) return;
  const tokens = deriveTokens(theme);
  const root = document.documentElement;
  for (const [k, v] of Object.entries(tokens)) root.style.setProperty(k, v);

  const monaco = (window as any).monaco;
  if (monaco?.editor) {
    try { monaco.editor.defineTheme(name, theme); monaco.editor.setTheme(name); } catch { /* monaco not ready for this theme */ }
  }

  // Re-theme the xterm output to match (background/foreground + per-kind colors).
  const term = (window as any).__fermion?.terminal;
  if (term?.setTheme) {
    try {
      term.setTheme(
        {
          background: tokens['--term-bg'],
          foreground: tokens['--fg'],
          cursor: tokens['--term-bg'],
          selectionBackground: mix(tokens['--accent'], tokens['--term-bg'], 0.6),
        },
        { WARN: tokens['--warn'], ERR: tokens['--err'], SEND: tokens['--msg'], STATUS: tokens['--status'] },
      );
    } catch { /* terminal not ready */ }
  }

  try { localStorage.setItem(STORAGE_KEY, name); } catch { /* ignore */ }
}
