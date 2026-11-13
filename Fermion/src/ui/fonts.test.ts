import { BUILT_IN_FONT, SYSTEM_FONT, cleanFontName, fontStack, fontState, installedFonts, forgetFonts } from './fonts';

// A canvas that "has" some fonts: a family that is installed gives its own
// width whatever follows it in the stack; any other falls through to the
// generic family, and monospace and serif differ.
function fakeCanvas(installed: Record<string, 'fixed' | 'proportional'>) {
  const ctx = {
    font: '',
    measureText(text: string) {
      const families = this.font.replace(/^\d+px /, '').split(',').map((f: string) => f.trim().replace(/"/g, ''));
      const used = families.find((f: string) => installed[f] || f === 'monospace' || f === 'serif') as string;
      if (used === 'monospace') return { width: text.length * 40 };
      if (used === 'serif') return { width: text.length * 31 };
      if (installed[used] === 'fixed') return { width: text.length * 43 };
      return { width: [...text].reduce((w, ch) => w + (ch === 'i' || ch === 'l' ? 20 : 60), 0) };
    },
  };
  return vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(ctx as unknown as CanvasRenderingContext2D);
}

beforeEach(() => forgetFonts());
afterEach(() => vi.restoreAllMocks());

test('a font name is made safe for a font stack: only letters, digits, spaces and - _ . are kept', () => {
  expect(cleanFontName('  JetBrains   Mono ')).toBe('JetBrains Mono');
  expect(cleanFontName('Evil"; } body { display: none')).toBe('Evil body display none');
  expect(cleanFontName('x'.repeat(200))).toHaveLength(64);
  expect(cleanFontName('Fira_Code-Retina v6.2')).toBe('Fira_Code-Retina v6.2');
  for (const junk of ['', '   ', '";{}', 7, null, undefined, ['Consolas']]) expect(cleanFontName(junk)).toBe(BUILT_IN_FONT);
  expect(cleanFontName('"', '')).toBe('');
});

test('the font stack always ends in the built-in font, so a missing family still shows fixed-width text', () => {
  expect(fontStack('Consolas')).toBe('"Consolas", "IBM Plex Mono", ui-monospace, monospace');
  expect(fontStack(BUILT_IN_FONT)).toMatch(/^"IBM Plex Mono", /);
  expect(fontStack(SYSTEM_FONT)).toMatch(/^ui-monospace, /);
  expect(fontStack('a"b;c')).toBe('"abc", "IBM Plex Mono", ui-monospace, monospace');
});

test('a family is found installed, missing or not fixed-width by measuring; the list offers only installed ones', () => {
  fakeCanvas({ Consolas: 'fixed', Menlo: 'fixed', Georgia: 'proportional' });
  expect(fontState('Consolas')).toBe('installed');
  expect(fontState('No Such Font')).toBe('missing');
  expect(fontState('Georgia')).toBe('proportional');
  expect(fontState(BUILT_IN_FONT)).toBe('installed');
  expect(fontState(SYSTEM_FONT)).toBe('installed');
  expect(installedFonts()).toEqual(['Consolas', 'Menlo']);
});

test('where nothing can be measured, no family is claimed to be installed or missing', () => {
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null);
  expect(fontState('Consolas')).toBe('unknown');
  expect(installedFonts()).toEqual([]);
});
