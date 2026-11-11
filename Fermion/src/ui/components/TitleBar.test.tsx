import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { TitleBar } from './TitleBar';

/* eslint-disable @typescript-eslint/no-explicit-any */

function setup(isMax = false) {
  const win = {
    minimize: vi.fn(async () => true),
    toggleMaximize: vi.fn(async () => !isMax),
    close: vi.fn(async () => true),
    isMaximized: vi.fn(async () => isMax),
  };
  let maxCb: ((m: boolean) => void) | null = null;
  (window as any).fermion = { win, onMaximizeChange: (cb: any) => { maxCb = cb; return () => {}; } };
  render(<TitleBar />);
  return { win, fire: (m: boolean) => maxCb && maxCb(m) };
}

test('window controls invoke the matching win.* IPC', () => {
  const { win } = setup();
  fireEvent.click(screen.getByTestId('win-min'));
  fireEvent.click(screen.getByTestId('win-max'));
  fireEvent.click(screen.getByTestId('win-close'));
  expect(win.minimize).toHaveBeenCalled();
  expect(win.toggleMaximize).toHaveBeenCalled();
  expect(win.close).toHaveBeenCalled();
});

test('maximize glyph follows the maximize-change event', async () => {
  const { fire } = setup(false);
  // Let the initial isMaximized() promise settle before firing an event, so it
  // can't resolve late and revert the change.
  await waitFor(() => expect(screen.getByTestId('win-max')).toHaveAttribute('title', 'Maximize'));
  await Promise.resolve();
  fire(true);
  await waitFor(() => expect(screen.getByTestId('win-max')).toHaveAttribute('title', 'Restore'));
});

test('the bar is the drag region and the controls are excluded', () => {
  setup();
  // controls live in a no-drag container distinct from the draggable bar
  expect(screen.getByTestId('titlebar')).toBeInTheDocument();
  expect(screen.getByTestId('win-close').closest('.winctl')).toBeTruthy();
});
