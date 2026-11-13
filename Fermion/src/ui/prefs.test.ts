import { DEFAULT_PREFS, cleanPrefs, loadPrefs, savePrefs, PREFS_KEY } from './prefs';

beforeEach(() => localStorage.clear());

test('the defaults are how Fermion behaved before there were preferences', () => {
  expect(DEFAULT_PREFS).toEqual({
    editorFontSize: 14, editorMinimap: true, editorWordWrap: false, outputFontSize: 13,
    coverScope: 'app', followScope: 'all', watchMode: 'auto', autoRefreshSeconds: 2, catchChildren: false,
  });
});

test('cleanPrefs keeps what is valid, clamps numbers, and replaces anything else with the default', () => {
  expect(cleanPrefs({ editorFontSize: 18, editorMinimap: false, coverScope: 'all', watchMode: 'sampled', autoRefreshSeconds: 5, catchChildren: true })).toEqual({
    ...DEFAULT_PREFS, editorFontSize: 18, editorMinimap: false, coverScope: 'all', watchMode: 'sampled', autoRefreshSeconds: 5, catchChildren: true,
  });
  expect(cleanPrefs({ editorFontSize: 400, outputFontSize: 1, autoRefreshSeconds: 0 })).toMatchObject({ editorFontSize: 24, outputFontSize: 9, autoRefreshSeconds: 1 });
  expect(cleanPrefs({ editorFontSize: 13.6 }).editorFontSize).toBe(14); // whole pixels
  // 'module' needs a module name, which a default cannot have.
  expect(cleanPrefs({ coverScope: 'module', followScope: 'module' })).toMatchObject({ coverScope: 'app', followScope: 'all' });
  expect(cleanPrefs({ editorFontSize: '18', editorMinimap: 'yes', coverScope: 7, watchMode: 'exact', catchChildren: 1, autoRefreshSeconds: NaN, extra: 'x' })).toEqual(DEFAULT_PREFS);
  for (const junk of [null, undefined, 'x', 5, [], [{ editorFontSize: 20 }]]) expect(cleanPrefs(junk)).toEqual(DEFAULT_PREFS);
});

test('preferences are saved in the window and read back; a damaged or missing store gives the defaults', () => {
  expect(loadPrefs()).toEqual(DEFAULT_PREFS);
  savePrefs({ ...DEFAULT_PREFS, outputFontSize: 16, catchChildren: true });
  expect(loadPrefs()).toEqual({ ...DEFAULT_PREFS, outputFontSize: 16, catchChildren: true });
  expect(JSON.parse(localStorage.getItem(PREFS_KEY) as string).outputFontSize).toBe(16);
  localStorage.setItem(PREFS_KEY, '{not json');
  expect(loadPrefs()).toEqual(DEFAULT_PREFS);
  localStorage.setItem(PREFS_KEY, JSON.stringify({ outputFontSize: 99999, followScope: 'app' }));
  expect(loadPrefs()).toEqual({ ...DEFAULT_PREFS, outputFontSize: 24, followScope: 'app' });
});
