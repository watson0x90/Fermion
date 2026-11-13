import { limitsOf, INSPECTOR_ZOOM, DEFAULT_PREFS, SECTION_OF, cleanPrefs, loadPrefs, savePrefs, PREFS_KEY, editorOptions, handlerOptions, outputLook, applyPrefs } from './prefs';

beforeEach(() => localStorage.clear());

test('the defaults are how Fermion behaved before there were preferences', () => {
  expect(DEFAULT_PREFS).toEqual({
    dataFontFamily: 'IBM Plex Mono', editorFontFamily: 'IBM Plex Mono', outputFontFamily: 'IBM Plex Mono',
    inspectorTextSize: 'normal',
    limitReplSeconds: 20, limitRecordMinutes: 10, limitCoverBlocks: 2000000, limitWatchHits: 200000, limitHeapLive: 200000, limitHeapFreed: 20000,
    editorLineSpacing: 'normal', editorLineNumbers: true, editorTabSize: 4, editorWhitespace: 'selection', editorCursor: 'line',
    outputLineSpacing: 'compact', outputCursor: 'bar',
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

test('fonts, spacing, tab width, whitespace and cursors: valid choices are kept, anything else becomes the default', () => {
  const good = { dataFontFamily: 'Consolas', editorFontFamily: 'JetBrains Mono', outputFontFamily: 'System monospace', editorLineSpacing: 'relaxed', editorLineNumbers: false,
    editorTabSize: 8, editorWhitespace: 'all', editorCursor: 'block', outputLineSpacing: 'normal', outputCursor: 'underline' };
  expect(cleanPrefs(good)).toEqual({ ...DEFAULT_PREFS, ...good });
  expect(cleanPrefs({ dataFontFamily: 7, editorFontFamily: '";}', outputFontFamily: '', editorLineSpacing: 'huge', editorLineNumbers: 'no', editorTabSize: 3,
    editorWhitespace: 'boundary', editorCursor: 'bar', outputLineSpacing: 2, outputCursor: 'line' })).toEqual(DEFAULT_PREFS);
  expect(cleanPrefs({ editorTabSize: '4' }).editorTabSize).toBe(4); // the default, not the string
  // A stored family can never break out of the font stack it is placed in.
  expect(cleanPrefs({ editorFontFamily: 'A"; } * { display: none } x' }).editorFontFamily).toBe('A display none x');
});

test('every preference belongs to a section of Settings', () => {
  expect(Object.keys(SECTION_OF).sort()).toEqual(Object.keys(DEFAULT_PREFS).sort());
});

test('the editor and Output are told the font, size, spacing and cursor; the handler editor is two sizes smaller', () => {
  const p = { ...DEFAULT_PREFS, editorFontFamily: 'Consolas', editorFontSize: 16, editorLineSpacing: 'relaxed' as const, editorLineNumbers: false, editorTabSize: 2,
    editorWhitespace: 'all' as const, editorCursor: 'block' as const, outputFontFamily: 'Menlo', outputFontSize: 15, outputLineSpacing: 'relaxed' as const, outputCursor: 'block' as const };
  expect(editorOptions(p)).toEqual({ fontSize: 16, fontFamily: '"Consolas", "IBM Plex Mono", ui-monospace, monospace', lineHeight: 1.7, lineNumbers: 'off',
    minimap: { enabled: true }, wordWrap: 'off', tabSize: 2, renderWhitespace: 'all', cursorStyle: 'block' });
  expect(handlerOptions(p)).toMatchObject({ fontSize: 14, fontFamily: '"Consolas", "IBM Plex Mono", ui-monospace, monospace', tabSize: 2 });
  expect(outputLook(p)).toEqual({ fontSize: 15, fontFamily: '"Menlo", "IBM Plex Mono", ui-monospace, monospace', lineHeight: 1.3, cursorStyle: 'block' });
  expect(editorOptions(DEFAULT_PREFS).lineHeight).toBe(0); // the editor's own spacing, as before
  expect(outputLook(DEFAULT_PREFS)).toMatchObject({ lineHeight: 1, cursorStyle: 'bar' });
});

test('applying preferences reaches the editors, their text, the terminal and the data font; fonts are measured again', () => {
  /* eslint-disable @typescript-eslint/no-explicit-any */
  const w = window as any;
  const model = { updateOptions: vi.fn() };
  const editor = { updateOptions: vi.fn(), getModel: () => model };
  const hook = { updateOptions: vi.fn(), getModel: () => null }; // no text open: nothing to set
  const terminal = { setLook: vi.fn(), setFontSize: vi.fn() };
  const remeasureFonts = vi.fn();
  Object.assign(w, { MonacoCodeEditor: editor, MonacoHookEditor: hook, monaco: { editor: { remeasureFonts } }, __fermion: { terminal } });
  try {
    const p = { ...DEFAULT_PREFS, dataFontFamily: 'Consolas', editorTabSize: 8, outputFontSize: 17 };
    applyPrefs(p);
    expect(editor.updateOptions).toHaveBeenCalledWith(editorOptions(p));
    expect(model.updateOptions).toHaveBeenCalledWith({ tabSize: 8 });
    expect(hook.updateOptions).toHaveBeenCalledWith(handlerOptions(p));
    expect(terminal.setLook).toHaveBeenCalledWith(outputLook(p));
    expect(terminal.setFontSize).not.toHaveBeenCalled();
    expect(remeasureFonts).toHaveBeenCalled();
    expect(document.documentElement.style.getPropertyValue('--mono')).toBe('"Consolas", "IBM Plex Mono", ui-monospace, monospace');
    // An older terminal (no setLook) still gets its size; a missing editor is not an error.
    w.__fermion = { terminal: { setFontSize: terminal.setFontSize } };
    w.MonacoCodeEditor = undefined;
    expect(() => applyPrefs(p)).not.toThrow();
    expect(terminal.setFontSize).toHaveBeenCalledWith(17);
  } finally {
    delete w.MonacoCodeEditor; delete w.MonacoHookEditor; delete w.monaco; delete w.__fermion;
    document.documentElement.style.removeProperty('--mono');
  }
});

test('limits and the Inspector text size: kept inside their ranges, and handed to the main process under its names', () => {
  expect(cleanPrefs({ limitReplSeconds: 90, limitRecordMinutes: 30, limitCoverBlocks: 500000, limitWatchHits: 50000, limitHeapLive: 50000, limitHeapFreed: 5000, inspectorTextSize: 'large' }))
    .toMatchObject({ limitReplSeconds: 90, limitRecordMinutes: 30, limitCoverBlocks: 500000, limitWatchHits: 50000, limitHeapLive: 50000, limitHeapFreed: 5000, inspectorTextSize: 'large' });
  expect(cleanPrefs({ limitReplSeconds: 1e9, limitRecordMinutes: 0, limitCoverBlocks: 5, limitWatchHits: 1e12, limitHeapLive: -1, limitHeapFreed: 1e12, inspectorTextSize: 'huge' }))
    .toMatchObject({ limitReplSeconds: 600, limitRecordMinutes: 1, limitCoverBlocks: 100000, limitWatchHits: 2000000, limitHeapLive: 10000, limitHeapFreed: 200000, inspectorTextSize: 'normal' });
  expect(cleanPrefs({ limitReplSeconds: '90', limitRecordMinutes: null })).toMatchObject({ limitReplSeconds: 20, limitRecordMinutes: 10 });
  expect(limitsOf({ ...DEFAULT_PREFS, limitReplSeconds: 45, limitHeapFreed: 5000 })).toEqual({ replTimeoutSeconds: 45, recordMinutes: 10, coverBlocks: 2000000, watchHits: 200000, heapLive: 200000, heapFreed: 5000 });
  applyPrefs({ ...DEFAULT_PREFS, inspectorTextSize: 'larger' });
  expect(document.documentElement.style.getPropertyValue('--insp-zoom')).toBe(String(INSPECTOR_ZOOM.larger));
  applyPrefs(DEFAULT_PREFS);
  expect(document.documentElement.style.getPropertyValue('--insp-zoom')).toBe('1');
});
