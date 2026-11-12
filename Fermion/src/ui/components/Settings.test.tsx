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
