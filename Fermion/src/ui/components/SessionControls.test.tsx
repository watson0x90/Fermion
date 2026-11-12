import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import session from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui from '../store/uiSlice';
import { setTerminalSink } from '../bridge';
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

// The old Device window could add a remote frida-server by address; the React
// sidebar lost that, leaving remote targets unreachable.
test('a remote frida-server can be added by host:port and becomes the selected device', async () => {
  const store = makeStore();
  let devices = [{ id: 'local', name: 'Local' }];
  (window as any).fermion.enumerateDevices = async () => devices;
  (window as any).fermion.setDevice = async (spec: string) => {
    calls.push(['setDevice', spec]);
    devices = [...devices, { id: 'socket@192.168.1.20:27042', name: '192.168.1.20:27042' }];
    return 'socket@192.168.1.20:27042';
  };
  render(<Provider store={store}><SessionControls /></Provider>);
  await waitFor(() => expect(screen.getByText('local')).toBeInTheDocument());

  expect(screen.getByTestId('remote-connect')).toBeDisabled(); // nothing typed
  fireEvent.change(screen.getByLabelText('remote device'), { target: { value: ' 192.168.1.20:27042 ' } });
  fireEvent.click(screen.getByTestId('remote-connect'));
  await waitFor(() => expect(calls).toContainEqual(['setDevice', 'socket@192.168.1.20:27042']));
  await waitFor(() => expect(store.getState().session.deviceId).toBe('socket@192.168.1.20:27042'));
  // It is listed and selected; the box is cleared for the next one.
  await waitFor(() => expect((screen.getByLabelText('device') as HTMLSelectElement).value).toBe('socket@192.168.1.20:27042'));
  expect((screen.getByLabelText('remote device') as HTMLInputElement).value).toBe('');
});

test('Enter in the remote box connects; a failure is reported in Output and the device is unchanged', async () => {
  const lines: string[] = [];
  setTerminalSink({ write: (k: string, t: string) => { lines.push(k + ' ' + t); } });
  const store = makeStore();
  (window as any).fermion.setDevice = async () => { throw new Error('unable to connect to remote frida-server'); };
  render(<Provider store={store}><SessionControls /></Provider>);
  const box = screen.getByLabelText('remote device');
  fireEvent.change(box, { target: { value: '10.0.0.9' } });
  fireEvent.keyDown(box, { key: 'Enter' });
  await waitFor(() => expect(lines.some((l) => l.startsWith('ERR') && l.includes('unable to connect'))).toBe(true));
  expect(store.getState().session.deviceId).toBe('local');
  expect((box as HTMLInputElement).value).toBe('10.0.0.9'); // kept, so it can be corrected
  setTerminalSink(null);
});

test('the device picker shows the device the session is on', async () => {
  const store = makeStore();
  (window as any).fermion.enumerateDevices = async () => [{ id: 'local', name: 'Local' }, { id: 'usb1', name: 'Pixel' }];
  render(<Provider store={store}><SessionControls /></Provider>);
  await waitFor(() => expect(screen.getByText('usb1')).toBeInTheDocument());
  fireEvent.change(screen.getByLabelText('device'), { target: { value: 'usb1' } });
  await waitFor(() => expect(store.getState().session.deviceId).toBe('usb1'));
  expect((screen.getByLabelText('device') as HTMLSelectElement).value).toBe('usb1');
});
