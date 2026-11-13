import { render, screen, fireEvent } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import session from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui, { uiActions } from '../store/uiSlice';
import '../../lang/monaco-theme.js'; // load the real theme set
import { Settings } from './Settings';

function renderSettings() {
  const store = configureStore({ reducer: { session, output, ui } });
  store.dispatch(uiActions.toggleSettings(true));
  render(<Provider store={store}><Settings /></Provider>);
  return store;
}

test('Settings lists themes and marks the current one; selecting dispatches setTheme', () => {
  const store = renderSettings();
  // Kuroir (default) is marked selected and labelled original Fermion.
  expect(screen.getByTestId('theme-Kuroir')).toHaveClass('sel');
  expect(screen.getByText(/original Fermion/)).toBeInTheDocument();
  fireEvent.click(screen.getByTestId('theme-Monokai'));
  expect(store.getState().ui.theme).toBe('Monokai');
});

test('clicking the scrim closes Settings', () => {
  const store = renderSettings();
  fireEvent.click(screen.getByTestId('settings-scrim'));
  expect(store.getState().ui.settingsOpen).toBe(false);
});

test('Settings renders nothing when closed', () => {
  const store = configureStore({ reducer: { session, output, ui } });
  const { container } = render(<Provider store={store}><Settings /></Provider>);
  expect(container).toBeEmptyDOMElement();
});

// ---- preferences ----
import prefs from '../store/prefsSlice';
import { DEFAULT_PREFS } from '../prefs';

function renderPrefs() {
  localStorage.clear();
  const store = configureStore({ reducer: { session, output, ui, prefs } });
  store.dispatch(uiActions.toggleSettings(true));
  render(<Provider store={store}><Settings /></Provider>);
  return store;
}

test('preferences show their current values and change the store as they are edited', () => {
  const store = renderPrefs();
  expect(screen.getByTestId('pref-editor-font')).toHaveValue(14);
  expect(screen.getByTestId('pref-editor-minimap')).toBeChecked();
  expect(screen.getByTestId('pref-cover-scope')).toHaveValue('app');
  expect(screen.getByTestId('pref-reset')).toBeDisabled(); // nothing differs from the defaults
  fireEvent.change(screen.getByTestId('pref-editor-font'), { target: { value: '18' } });
  fireEvent.click(screen.getByTestId('pref-editor-minimap'));
  fireEvent.click(screen.getByTestId('pref-editor-wrap'));
  fireEvent.change(screen.getByTestId('pref-output-font'), { target: { value: '16' } });
  fireEvent.change(screen.getByTestId('pref-cover-scope'), { target: { value: 'all' } });
  fireEvent.change(screen.getByTestId('pref-follow-scope'), { target: { value: 'app' } });
  fireEvent.change(screen.getByTestId('pref-watch-mode'), { target: { value: 'sampled' } });
  fireEvent.change(screen.getByTestId('pref-auto-refresh'), { target: { value: '5' } });
  fireEvent.click(screen.getByTestId('pref-catch-children'));
  expect(store.getState().prefs).toEqual({
    editorFontSize: 18, editorMinimap: false, editorWordWrap: true, outputFontSize: 16,
    coverScope: 'all', followScope: 'app', watchMode: 'sampled', autoRefreshSeconds: 5, catchChildren: true,
  });
  expect(screen.getByTestId('pref-editor-font')).toHaveValue(18);
});

test('a number out of range is brought into range; an empty field changes nothing; Reset restores the defaults', () => {
  const store = renderPrefs();
  fireEvent.change(screen.getByTestId('pref-editor-font'), { target: { value: '300' } });
  expect(store.getState().prefs.editorFontSize).toBe(24);
  fireEvent.change(screen.getByTestId('pref-auto-refresh'), { target: { value: '0' } });
  expect(store.getState().prefs.autoRefreshSeconds).toBe(1);
  fireEvent.change(screen.getByTestId('pref-output-font'), { target: { value: '' } });
  expect(store.getState().prefs.outputFontSize).toBe(13);
  expect(screen.getByTestId('pref-reset')).not.toBeDisabled();
  fireEvent.click(screen.getByTestId('pref-reset'));
  expect(store.getState().prefs).toEqual(DEFAULT_PREFS);
  expect(screen.getByTestId('pref-reset')).toBeDisabled();
});
