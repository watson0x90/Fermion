import { render, screen, fireEvent } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui from '../store/uiSlice';

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
