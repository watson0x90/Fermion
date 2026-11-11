import { render, screen } from '@testing-library/react';
import { Provider } from 'react-redux';
import { vi } from 'vitest';

// xterm can't mount in jsdom; fake the Output pane's controller.
vi.mock('../terminal.js', () => ({
  createTerminal: () => ({
    write: vi.fn(), setFilter: vi.fn(), setFollow: vi.fn(), fit: vi.fn(),
    clear: vi.fn(), getText: () => '', searchNext: vi.fn(),
    copySelectionOrAll: () => '', dispose: vi.fn(),
  }),
}));

import { store } from './store';
import { App } from './App';

test('App renders the root marker', () => {
  render(
    <Provider store={store}>
      <App />
    </Provider>,
  );
  expect(screen.getByTestId('app-root')).toBeInTheDocument();
});
