import { render, screen, fireEvent } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui from '../store/uiSlice';

// xterm can't mount in jsdom; the Output pane's controller is faked here.
vi.mock('../../terminal.js', () => ({
  createTerminal: () => ({
    write: vi.fn(), setFilter: vi.fn(), setFollow: vi.fn(), fit: vi.fn(),
    clear: vi.fn(), getText: () => '', searchNext: vi.fn(),
    copySelectionOrAll: () => '', dispose: vi.fn(),
  }),
}));

import { Layout } from './Layout';

function makeStore() {
  return configureStore({ reducer: { session, output, ui } });
}

test('Layout renders the 5 toolbox tabs, Output, and status bar; clicking a tab switches activeTab', () => {
  const store = makeStore();
  render(
    <Provider store={store}>
      <Layout />
    </Provider>,
  );
  for (const label of ['Editor', 'REPL', 'Graph', 'Process tree', 'Inspector']) {
    expect(screen.getByRole('tab', { name: label })).toBeInTheDocument();
  }
  expect(screen.getByTestId('output-pane')).toBeInTheDocument();
  expect(screen.getByTestId('status-bar')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('tab', { name: 'Graph' }));
  expect(store.getState().ui.activeTab).toBe('graph');
});
