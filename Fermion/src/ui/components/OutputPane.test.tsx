import { render, screen, fireEvent, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui, { uiActions } from '../store/uiSlice';

const fakeCtrl = {
  write: vi.fn(),
  setFilter: vi.fn(),
  setFollow: vi.fn(),
  fit: vi.fn(),
  clear: vi.fn(),
  getText: () => 'text',
  searchNext: vi.fn(),
  copySelectionOrAll: () => 'sel',
  dispose: vi.fn(),
};
vi.mock('../../terminal.js', () => ({ createTerminal: () => fakeCtrl }));

import { OutputPane } from './OutputPane';

function makeStore() {
  return configureStore({ reducer: { session, output, ui } });
}

test('OutputPane: SEND chip shows as MSG, toggling filters the SEND kind, unmount disposes', () => {
  const store = makeStore();
  const { unmount } = render(
    <Provider store={store}>
      <OutputPane />
    </Provider>,
  );
  expect(screen.getByRole('button', { name: 'MSG' })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'SEND' })).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: 'MSG' }));
  expect(fakeCtrl.setFilter).toHaveBeenCalledWith('SEND', false);
  expect(store.getState().output.filters.SEND).toBe(false);

  unmount();
  expect(fakeCtrl.dispose).toHaveBeenCalled();
});

/* eslint-disable @typescript-eslint/no-explicit-any */
function fakeOutput() {
  const output = { detach: vi.fn(async () => true), dock: vi.fn(async () => true), send: vi.fn() };
  (window as any).fermion = { output };
  return output;
}

test('docked: the detach button asks the main process to pop Output out', () => {
  const out = fakeOutput();
  render(<Provider store={makeStore()}><OutputPane /></Provider>);
  const btn = screen.getByTestId('detach-output');
  expect(btn).not.toBeDisabled();
  fireEvent.click(btn);
  expect(out.detach).toHaveBeenCalled();
  expect(screen.queryByTestId('dock-output')).toBeNull();
});

test('docked: while Output is detached the pane is hidden but stays mounted (keeps history)', () => {
  fakeOutput();
  const store = makeStore();
  render(<Provider store={store}><OutputPane /></Provider>);
  expect(screen.getByTestId('output-pane')).not.toHaveAttribute('hidden');
  act(() => { store.dispatch(uiActions.setOutputDetached(true)); });
  expect(screen.getByTestId('output-pane')).toHaveAttribute('hidden');
  act(() => { store.dispatch(uiActions.setOutputDetached(false)); });
  expect(screen.getByTestId('output-pane')).not.toHaveAttribute('hidden');
});

test('standalone (detached window): dock button + toolbar changes are relayed to the main window', () => {
  const out = fakeOutput();
  fakeCtrl.clear.mockClear();
  render(<Provider store={makeStore()}><OutputPane standalone /></Provider>);
  expect(screen.queryByTestId('detach-output')).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: 'WARN' }));
  expect(out.send).toHaveBeenCalledWith({ t: 'filter', kind: 'WARN', on: false });
  fireEvent.click(screen.getByTitle('Follow tail'));
  expect(out.send).toHaveBeenCalledWith({ t: 'follow', on: false });
  // Clear is only requested here; the main window clears and echoes it back,
  // so both windows drop the same lines.
  fireEvent.click(screen.getByTestId('clear-output'));
  expect(fakeCtrl.clear).not.toHaveBeenCalled();
  expect(out.send).toHaveBeenCalledWith({ t: 'clear' });

  fireEvent.click(screen.getByTestId('dock-output'));
  expect(out.dock).toHaveBeenCalled();
});

test('docked: toolbar changes are not relayed anywhere', () => {
  const out = fakeOutput();
  render(<Provider store={makeStore()}><OutputPane /></Provider>);
  fireEvent.click(screen.getByRole('button', { name: 'WARN' }));
  fireEvent.click(screen.getByTestId('clear-output'));
  expect(out.send).not.toHaveBeenCalled();
});
