import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
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
  await act(async () => { await Promise.resolve(); });
  act(() => { fire(true); });
  await waitFor(() => expect(screen.getByTestId('win-max')).toHaveAttribute('title', 'Restore'));
});

test('the bar is the drag region, controls are excluded, and the wordmark is not image-draggable', () => {
  setup();
  // controls live in a no-drag container distinct from the draggable bar
  expect(screen.getByTestId('titlebar')).toBeInTheDocument();
  expect(screen.getByTestId('win-close').closest('.winctl')).toBeTruthy();
  // grabbing the logo must move the window, not start an HTML image-drag
  expect(screen.getByAltText('Fermion')).toHaveAttribute('draggable', 'false');
});

test('the subtitle names the window (main = Frida IDE; the detached window = Output)', () => {
  setup();
  expect(screen.getByText('Frida IDE')).toBeInTheDocument();
  render(<TitleBar subtitle="Output" />);
  expect(screen.getByText('Output')).toBeInTheDocument();
});
