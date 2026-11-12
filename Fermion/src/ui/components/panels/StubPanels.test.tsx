import { render, screen, fireEvent } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session from '../../store/sessionSlice';
import output from '../../store/outputSlice';
import ui from '../../store/uiSlice';

// xterm can't mount in jsdom; the Output pane's controller is faked.
vi.mock('../../../terminal.js', () => ({
  createTerminal: () => ({
    write: vi.fn(), setFilter: vi.fn(), setFollow: vi.fn(), fit: vi.fn(),
    clear: vi.fn(), getText: () => '', searchNext: vi.fn(),
    copySelectionOrAll: () => '', dispose: vi.fn(),
  }),
}));

import { Layout } from '../Layout';

function renderApp() {
  const store = configureStore({ reducer: { session, output, ui } });
  render(
    <Provider store={store}>
      <Layout />
    </Provider>,
  );
  return store;
}

test.each([
  ['REPL', 'repl-panel'],
  ['Inspector', 'inspector-panel'],
])('%s tab renders its Phase-3 stub panel', (tabLabel, testid) => {
  renderApp();
  fireEvent.click(screen.getByRole('tab', { name: tabLabel }));
  const panel = screen.getByTestId(testid);
  expect(panel).toBeInTheDocument();
  // The panel names itself (its final title), and says it is still to come.
  expect(panel).toHaveTextContent(tabLabel);
  expect(panel.textContent).toMatch(/Phase 3/);
});

test('Inspector stub lists the three target facets (Modules/Memory/Threads)', () => {
  renderApp();
  fireEvent.click(screen.getByRole('tab', { name: 'Inspector' }));
  for (const facet of ['Modules', 'Memory', 'Threads']) {
    expect(screen.getByText(facet)).toBeInTheDocument();
  }
});
