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

import { OutputWindow } from './OutputWindow';

/* eslint-disable @typescript-eslint/no-explicit-any */
test('the detached window shows a title bar + the Output pane, announces ready once mounted, and closing docks', () => {
  const send = vi.fn();
  const close = vi.fn(async () => true);
  (window as any).fermion = {
    output: { send, dock: vi.fn(), detach: vi.fn() },
    win: { close, minimize: vi.fn(), toggleMaximize: vi.fn(), isMaximized: vi.fn(async () => false) },
    onMaximizeChange: () => () => {},
  };
  const store = configureStore({ reducer: { session, output, ui } });
  render(<Provider store={store}><OutputWindow /></Provider>);

  expect(screen.getByTestId('output-window')).toBeInTheDocument();
  expect(screen.getByTestId('titlebar')).toBeInTheDocument();
  expect(screen.getByTestId('output-pane')).toBeInTheDocument();
  expect(screen.getByTestId('dock-output')).toBeInTheDocument();
  // No IDE chrome in this window.
  expect(screen.queryByTestId('status-bar')).toBeNull();
  expect(screen.queryByRole('tab')).toBeNull();
  // ready is what makes the main window send the snapshot.
  expect(send).toHaveBeenCalledWith({ t: 'ready' });
  expect(send).toHaveBeenCalledTimes(1);

  fireEvent.click(screen.getByTestId('win-close'));
  expect(close).toHaveBeenCalled();
});
