import sessionReducer, { sessionActions } from './sessionSlice';
import outputReducer, { outputActions } from './outputSlice';
import uiReducer, { uiActions } from './uiSlice';

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
