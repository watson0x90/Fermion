import { render, screen, fireEvent } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import session from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui from '../store/uiSlice';
import { Rail } from './Rail';

function renderRail() {
  const store = configureStore({ reducer: { session, output, ui } });
  render(<Provider store={store}><Rail /></Provider>);
  return store;
}

test('rail jumps to a toolbox view', () => {
  const store = renderRail();
  fireEvent.click(screen.getByTestId('rail-graph'));
  expect(store.getState().ui.activeTab).toBe('graph');
  expect(screen.getByTestId('rail-graph')).toHaveClass('on');
});

test('expand toggle flips railOpen; Settings toggles settingsOpen', () => {
  const store = renderRail();
  expect(store.getState().ui.railOpen).toBe(false);
  fireEvent.click(screen.getByTestId('rail-toggle'));
  expect(store.getState().ui.railOpen).toBe(true);
  fireEvent.click(screen.getByTestId('open-settings'));
  expect(store.getState().ui.settingsOpen).toBe(true);
});

test('every rail button carries its label (shown when expanded)', () => {
  renderRail();
  for (const label of ['Session', 'Graph', 'Process tree', 'Inspector', 'Docs', 'About', 'Settings']) {
    expect(screen.getByText(label)).toBeInTheDocument();
  }
});
