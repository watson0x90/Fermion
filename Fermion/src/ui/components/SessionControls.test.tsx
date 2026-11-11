import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui from '../store/uiSlice';
import { SessionControls } from './SessionControls';

function makeStore() {
  return configureStore({ reducer: { session, output, ui } });
}

/* eslint-disable @typescript-eslint/no-explicit-any */
let calls: any[];
beforeEach(() => {
  calls = [];
  (window as any).MonacoCodeEditor = { getValue: () => 'SCRIPT' };
  (window as any).fermion = {
    enumerateDevices: async () => [{ id: 'local', name: 'Local' }],
    enumerateProcesses: async () => [{ pid: 4821, name: 'notepad.exe' }, { pid: 10, name: 'a' }],
    setDevice: async (id: string) => { calls.push(['setDevice', id]); return id; },
    attach: async (p: number) => { calls.push(['attach', p]); },
    getState: async () => ({ deviceId: 'local', isAttached: true, hasScript: false, currentPid: '4821' }),
    loadScript: async (s: string) => { calls.push(['loadScript', s]); },
  };
});

test('selecting a process + Attach drives attach + loadScript(editor value)', async () => {
  const store = makeStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  const procSel = screen.getByLabelText('process');
  fireEvent.focus(procSel); // loads processes
  await waitFor(() => expect(screen.getByText('notepad.exe · 4821')).toBeInTheDocument());
  fireEvent.change(procSel, { target: { value: '4821' } });
  fireEvent.click(screen.getByText('Attach'));
  await waitFor(() => expect(calls).toEqual([
    ['attach', 4821],
    ['loadScript', 'SCRIPT'],
  ]));
  expect(store.getState().session.isAttached).toBe(true);
});

test('device change calls setDevice and updates the store', async () => {
  const store = makeStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  await waitFor(() => expect(screen.getByText('local')).toBeInTheDocument());
  fireEvent.change(screen.getByLabelText('device'), { target: { value: 'local' } });
  await waitFor(() => expect(calls).toContainEqual(['setDevice', 'local']));
});
