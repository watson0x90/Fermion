import sessionReducer, { sessionActions } from './sessionSlice';
import outputReducer, { outputActions } from './outputSlice';
import uiReducer, { uiActions } from './uiSlice';
import bookmarksReducer, { bookmarksActions, newBookmarkId, samePlace, Bookmark } from './bookmarksSlice';
import hooksReducer, { hooksActions } from './hooksSlice';
import { hookFromTarget } from '../hooking/model';

test('sessionSlice: attached sets isAttached + pid; detached clears + resets traceMode', () => {
  let s = sessionReducer(undefined, { type: '@@init' });
  expect(s.isAttached).toBe(false);
  s = sessionReducer(s, sessionActions.setTraceMode(true));
  s = sessionReducer(s, sessionActions.scriptLoaded());
  s = sessionReducer(s, sessionActions.attached('4821'));
  expect(s.isAttached).toBe(true);
  expect(s.currentPid).toBe('4821');
  expect(s.hasScript).toBe(true);
  s = sessionReducer(s, sessionActions.detached());
  expect(s.isAttached).toBe(false);
  expect(s.traceMode).toBe(false); // routing resets on detach
  expect(s.hasScript).toBe(false); // the old script is gone — Reload must disable
});

test('sessionSlice: scriptLoaded sets hasScript + resets traceMode; setDevice updates id', () => {
  let s = sessionReducer(undefined, sessionActions.setTraceMode(true));
  s = sessionReducer(s, sessionActions.scriptLoaded());
  expect(s.hasScript).toBe(true);
  expect(s.traceMode).toBe(false);
  s = sessionReducer(s, sessionActions.setDevice('usb@1'));
  expect(s.deviceId).toBe('usb@1');
});

test('outputSlice: toggleFilter flips a kind; counted increments; clear resets count', () => {
  let s = outputReducer(undefined, { type: '@@init' });
  expect(s.filters.LOG).toBe(true);
  s = outputReducer(s, outputActions.toggleFilter('LOG'));
  expect(s.filters.LOG).toBe(false);
  s = outputReducer(s, outputActions.counted());
  s = outputReducer(s, outputActions.counted());
  expect(s.count).toBe(2);
  s = outputReducer(s, outputActions.clear());
  expect(s.count).toBe(0);
});

test('outputSlice: setFilter sets one kind; hydrate adopts filters + follow from another window', () => {
  let s = outputReducer(undefined, { type: '@@init' });
  s = outputReducer(s, outputActions.setFilter({ kind: 'WARN', on: false }));
  expect(s.filters.WARN).toBe(false);
  s = outputReducer(s, outputActions.setFilter({ kind: 'WARN', on: false }));
  expect(s.filters.WARN).toBe(false); // idempotent, unlike toggle
  s = outputReducer(s, outputActions.setFilter({ kind: 'NOPE', on: false }));
  expect('NOPE' in s.filters).toBe(false); // unknown kinds are ignored
  s = outputReducer(s, outputActions.setFilter({ kind: 'toString', on: false }));
  expect(typeof s.filters.toString).toBe('function'); // inherited keys are not kinds
  s = outputReducer(s, outputActions.hydrate({ filters: { LOG: false, WARN: true, BOGUS: true }, follow: false }));
  expect(s.filters.LOG).toBe(false);
  expect(s.filters.WARN).toBe(true);
  expect(s.filters.ERR).toBe(true);         // kinds missing from the snapshot keep their value
  expect('BOGUS' in s.filters).toBe(false);
  expect(s.follow).toBe(false);
});

test('uiSlice: setOutputDetached tracks whether Output lives in its own window', () => {
  let s = uiReducer(undefined, { type: '@@init' });
  expect(s.outputDetached).toBe(false);
  s = uiReducer(s, uiActions.setOutputDetached(true));
  expect(s.outputDetached).toBe(true);
});

test('uiSlice: setActiveTab + setTheme + toggleRail/Settings', () => {
  let s = uiReducer(undefined, { type: '@@init' });
  expect(s.activeTab).toBe('editor');
  expect(s.theme).toBe('Kuroir'); // default = original Fermion
  s = uiReducer(s, uiActions.setActiveTab('graph'));
  expect(s.activeTab).toBe('graph');
  s = uiReducer(s, uiActions.setTheme('Monokai'));
  expect(s.theme).toBe('Monokai');
  s = uiReducer(s, uiActions.toggleRail());
  expect(s.railOpen).toBe(true);
  s = uiReducer(s, uiActions.toggleSettings(true));
  expect(s.settingsOpen).toBe(true);
});

test('uiSlice: openAddress switches to the Inspector and counts requests, so the same address can be asked for twice', () => {
  let s = uiReducer(undefined, uiActions.setActiveTab('repl'));
  expect(s.addressRequest).toBeNull();
  s = uiReducer(s, uiActions.openAddress({ view: 'code', address: '0x10' }));
  expect(s.activeTab).toBe('inspector');
  expect(s.addressRequest).toEqual({ view: 'code', address: '0x10', n: 1 });
  s = uiReducer(s, uiActions.openAddress({ view: 'code', address: '0x10' }));
  expect(s.addressRequest).toEqual({ view: 'code', address: '0x10', n: 2 });
});

test('sessionSlice: a session that ends keeps its target and the reason; a new one clears the reason', () => {
  let s = sessionReducer(undefined, sessionActions.sessionStarted({ kind: 'attach', pid: 7, name: 'a.exe' }));
  s = sessionReducer(s, sessionActions.attached('7'));
  s = sessionReducer(s, sessionActions.suspendedSet(7));
  s = sessionReducer(s, sessionActions.detached('process-terminated'));
  expect(s.ended).toBe('process-terminated');
  expect(s.target).toEqual({ kind: 'attach', pid: 7, name: 'a.exe' });
  expect(s.suspendedPid).toBeNull();
  // A second "detached" for a session that is already over does not overwrite the reason.
  s = sessionReducer(s, sessionActions.detached('user'));
  expect(s.ended).toBe('process-terminated');
  s = sessionReducer(s, sessionActions.sessionStarted({ kind: 'attach', pid: 8, name: 'a.exe' }));
  expect(s.ended).toBeNull();
  s = sessionReducer(s, sessionActions.endedDismissed());
  expect(s.ended).toBeNull();
});

test('sessionSlice: with no known target there is nothing to offer when a session ends', () => {
  let s = sessionReducer(undefined, sessionActions.attached('7'));
  s = sessionReducer(s, sessionActions.detached('process-terminated'));
  expect(s.ended).toBeNull();
});

const MARK: Bookmark = { id: 'b1', label: 'entry', module: 'app.exe', offset: 256, address: '0x400100', view: 'memory', note: '' };

test('bookmarksSlice: add, rename, annotate, change view, remove', () => {
  let s = bookmarksReducer(undefined, bookmarksActions.added(MARK));
  s = bookmarksReducer(s, bookmarksActions.changed({ id: 'b1', label: 'parser entry', note: 'start here', view: 'code' }));
  expect(s.items).toEqual([{ ...MARK, label: 'parser entry', note: 'start here', view: 'code' }]);
  s = bookmarksReducer(s, bookmarksActions.changed({ id: 'nope', label: 'x' }));
  expect(s.items.length).toBe(1);
  s = bookmarksReducer(s, bookmarksActions.removed('b1'));
  expect(s.items).toEqual([]);
});

test('bookmarksSlice: the same place is bookmarked once, whatever address it had; text is bounded', () => {
  let s = bookmarksReducer(undefined, bookmarksActions.added(MARK));
  s = bookmarksReducer(s, bookmarksActions.added({ ...MARK, id: 'b2', module: 'APP.EXE', address: '0x7ff0100' })); // same module + offset, another run
  expect(s.items.length).toBe(1);
  s = bookmarksReducer(s, bookmarksActions.added({ ...MARK, id: 'b3', offset: 512 }));
  expect(s.items.length).toBe(2);
  s = bookmarksReducer(s, bookmarksActions.changed({ id: 'b1', label: 'l'.repeat(900), note: 'n'.repeat(9000) }));
  expect(s.items[0].label.length).toBe(200);
  expect(s.items[0].note.length).toBe(2000);
  expect(samePlace({ module: '', offset: null, address: '0x9000' }, { module: '', offset: null, address: '0X9000' })).toBe(true);
  expect(newBookmarkId()).not.toBe(newBookmarkId());
  expect(newBookmarkId()).toMatch(/^[A-Za-z0-9_-]{1,64}$/);
});

test('bookmarksSlice / hooksSlice: loaded replaces the list with what was saved', () => {
  const b = bookmarksReducer(undefined, bookmarksActions.loaded([MARK, { ...MARK, id: 'b2', offset: 1 }]));
  expect(b.items.map((x) => x.id)).toEqual(['b1', 'b2']);
  const h = hooksReducer(undefined, hooksActions.loaded([hookFromTarget({ name: 'k!f', module: 'k', offset: 1, address: '0x1' }, 'h1'), hookFromTarget({ name: 'k!g', module: 'k', offset: 2, address: '0x2' }, 'h2')]));
  expect(h.hooks.map((x) => x.id)).toEqual(['h1', 'h2']);
  expect(h.selected).toBe('h1');
});

test('uiSlice: showBookmarks opens the Inspector and counts the request', () => {
  let s = uiReducer(undefined, uiActions.setActiveTab('hooks'));
  s = uiReducer(s, uiActions.showBookmarks());
  expect(s.activeTab).toBe('inspector');
  expect(s.bookmarksRequest).toBe(1);
});
