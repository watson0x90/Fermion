import { vi } from 'vitest';
import {
  parseHex, toHex, mix, relLuminance, contrastRatio,
  deriveTokens, isDarkTheme, applyTheme, loadSavedTheme, themeNames,
} from './themeEngine';
// Load the real theme set (classic script sets window.FermionThemes).
import '../../lang/monaco-theme.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

test('color helpers: parse/mix/luminance/contrast', () => {
  expect(toHex(parseHex('#E8E9E8'))).toBe('#e8e9e8');
  expect(toHex(parseHex('#fff'))).toBe('#ffffff');
  expect(parseHex('#11223344')).toEqual({ r: 0x11, g: 0x22, b: 0x33 }); // alpha ignored
  expect(mix('#000000', '#ffffff', 0.5)).toBe('#808080');
  expect(relLuminance('#ffffff')).toBeCloseTo(1, 1);
  expect(contrastRatio('#000000', '#ffffff')).toBeCloseTo(21, 0);
});

test('deriveTokens: Kuroir (light) maps editor colors and keeps logo upright', () => {
  const t = deriveTokens({ base: 'vs', colors: { 'editor.background': '#E8E9E8', 'editor.foreground': '#363636', 'editorCursor.foreground': '#202020' } });
  expect(t['--editor-bg']).toBe('#e8e9e8');
  expect(t['--fg']).toBe('#363636');
  expect(t['--logo-filter']).toBe('none');
  expect(t['color-scheme']).toBe('light');
  // chrome/bg are near the editor bg, not a foreign color
  expect(contrastRatio(t['--fg'], t['--bg'])).toBeGreaterThan(5);
});

test('deriveTokens: a vs-dark theme inverts the logo and goes dark', () => {
  const t = deriveTokens({ base: 'vs-dark', colors: { 'editor.background': '#272822', 'editor.foreground': '#f8f8f2' } });
  expect(t['--logo-filter']).toContain('invert(1)');
  expect(t['color-scheme']).toBe('dark');
  expect(relLuminance(t['--bg'])).toBeLessThan(0.2);
});

test('isDarkTheme reads base then falls back to luminance', () => {
  expect(isDarkTheme({ base: 'vs-dark', colors: {} })).toBe(true);
  expect(isDarkTheme({ base: 'vs', colors: { 'editor.background': '#111111' } })).toBe(true); // dark bg overrides
  expect(isDarkTheme({ base: 'vs', colors: { 'editor.background': '#ffffff' } })).toBe(false);
});

// Review Focus: EVERY shipped theme must stay legible (fg vs bg) after derivation.
test('all shipped themes derive legible foreground/background contrast', () => {
  const all = (window as any).FermionThemes as Record<string, any>;
  const names = Object.keys(all);
  expect(names.length).toBeGreaterThanOrEqual(16);
  for (const name of names) {
    const t = deriveTokens(all[name]);
    const ratio = contrastRatio(t['--fg'], t['--bg']);
    expect(ratio, `${name} fg/bg contrast`).toBeGreaterThanOrEqual(3.5);
    // accent must be legible against the chrome it sits on
    expect(contrastRatio(t['--accent'], t['--bg']), `${name} accent/bg`).toBeGreaterThanOrEqual(1.9);
    // secondary (muted) and tertiary (faint) text sit on --panel and must stay
    // legible even on low-contrast themes (review finding #1).
    expect(contrastRatio(t['--muted'], t['--panel']), `${name} muted/panel`).toBeGreaterThanOrEqual(2.8);
    expect(contrastRatio(t['--faint'], t['--panel']), `${name} faint/panel`).toBeGreaterThanOrEqual(2.2);
    // the primary-button ink must be the higher-contrast choice on the accent.
    const ink = t['--accent-ink'];
    const other = ink === '#ffffff' ? '#12140e' : '#ffffff';
    expect(contrastRatio(ink, t['--accent']), `${name} accent-ink best`).toBeGreaterThanOrEqual(contrastRatio(other, t['--accent']));
  }
});

test('themeNames lists Kuroir first', () => {
  expect(themeNames()[0]).toBe('Kuroir');
  expect(themeNames()).toContain('Monokai');
});

test('applyTheme sets CSS vars, switches Monaco + the terminal, and persists', () => {
  const defineTheme = vi.fn(); const setTheme = vi.fn();
  const termSetTheme = vi.fn();
  const setBackground = vi.fn();
  (window as any).monaco = { editor: { defineTheme, setTheme } };
  (window as any).__fermion = { terminal: { setTheme: termSetTheme } };
  (window as any).fermion = { win: { setBackground } };
  applyTheme('Monokai');
  // the native window background follows the theme (live-resize paint)
  expect(setBackground).toHaveBeenCalledWith(expect.stringMatching(/^#/));
  expect(document.documentElement.style.getPropertyValue('--editor-bg')).toBeTruthy();
  expect(defineTheme).toHaveBeenCalledWith('Monokai', expect.anything());
  expect(setTheme).toHaveBeenCalledWith('Monokai');
  // terminal re-themed with a background + per-kind colors
  expect(termSetTheme).toHaveBeenCalled();
  const [theme, kinds] = termSetTheme.mock.calls[0];
  expect(theme.background).toBeTruthy();
  expect(kinds.ERR).toBeTruthy();
  expect(loadSavedTheme()).toBe('Monokai');
});

test('loadSavedTheme falls back to Kuroir when nothing valid is stored', () => {
  localStorage.removeItem('fermion.theme');
  expect(loadSavedTheme()).toBe('Kuroir');
});

test('applyTheme shares the derived tokens with the dialog windows through localStorage', () => {
  (window as any).monaco = undefined;
  (window as any).__fermion = undefined;
  (window as any).fermion = undefined;
  applyTheme('Monokai');
  const stored = JSON.parse(localStorage.getItem('fermion.themeTokens') || 'null');
  expect(stored).toBeTruthy();
  expect(stored['--bg']).toBe(document.documentElement.style.getPropertyValue('--bg'));
  expect(stored['--logo-filter']).toContain('invert(1)');
  expect(stored['color-scheme']).toBe('dark');
  applyTheme('Kuroir');
  expect(JSON.parse(localStorage.getItem('fermion.themeTokens')!)['color-scheme']).toBe('light');
});
