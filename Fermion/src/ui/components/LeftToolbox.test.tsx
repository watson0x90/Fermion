import { render, screen, fireEvent } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import session from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui from '../store/uiSlice';
import { LeftToolbox } from './LeftToolbox';

function renderToolbox() {
  const store = configureStore({ reducer: { session, output, ui } });
  render(
    <Provider store={store}>
      <LeftToolbox />
    </Provider>,
  );
  return store;
}

// Regression (review #1/#2/#4): the toolbox must NOT unmount the Editor (or the
// Graph panel) when another tab is active, or window.MonacoCodeEditor dangles to
// a disposed editor and the user's script is lost. All panels stay mounted; only
// the active one is visible.
test('all toolbox panels stay mounted regardless of the active tab', () => {
  renderToolbox();
  // Default active tab is Editor, yet every panel slot is present in the DOM.
  for (const id of ['editor', 'repl', 'graph', 'tree', 'inspector']) {
    expect(screen.getByTestId(`panel-${id}`)).toBeInTheDocument();
  }
});

test('switching tabs toggles visibility but keeps every panel mounted', () => {
  const store = renderToolbox();
  const editorSlot = screen.getByTestId('panel-editor');
  fireEvent.click(screen.getByRole('tab', { name: 'Graph' }));
  expect(store.getState().ui.activeTab).toBe('graph');
  // The editor slot is still the same mounted node (not re-created).
  expect(screen.getByTestId('panel-editor')).toBe(editorSlot);
  // Inactive panels are hidden; the active one is visible.
  expect(screen.getByTestId('panel-editor')).not.toBeVisible();
  expect(screen.getByTestId('panel-graph')).toBeVisible();
});
