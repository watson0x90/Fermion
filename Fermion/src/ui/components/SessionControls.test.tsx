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

// ---- launch options, suspended start, session end + reconnect ----
import { act, within } from '@testing-library/react';
import { sessionActions } from '../store/sessionSlice';
import hooksReducer, { hooksActions } from '../store/hooksSlice';
import { hookFromTarget } from '../hooking/model';

function fullStore() {
  return configureStore({ reducer: { session, output, ui, hooks: hooksReducer } });
}
function withSpawn() {
  const f = (window as any).fermion;
  f.spawn = async (...a: any[]) => { calls.push(['spawn', ...a]); return { pid: 777 }; };
  f.resume = async (p: number) => { calls.push(['resume', p]); };
  f.detach = async () => { calls.push(['detach']); };
  f.hooks = { add: async (spec: any) => { calls.push(['hookAdd', spec.id]); return { id: spec.id, address: spec.address, enabled: true, calls: 0 }; } };
  f.getState = async () => ({ deviceId: 'local', isAttached: true, hasScript: false, currentPid: '777' });
  return f;
}
const lines: string[] = [];
beforeEach(() => { lines.length = 0; setTerminalSink({ write: (k: string, t: string) => lines.push(k + ' ' + t) }); });

test('Spawn with no options spawns, loads the script, then resumes', async () => {
  withSpawn();
  const store = fullStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  expect(screen.getByTestId('spawn')).toBeDisabled();
  fireEvent.change(screen.getByLabelText('spawn path'), { target: { value: 'C:/app.exe' } });
  fireEvent.change(screen.getByLabelText('spawn args'), { target: { value: '--in "a b.txt"' } });
  fireEvent.click(screen.getByTestId('spawn'));
  await waitFor(() => expect(calls).toEqual([['spawn', 'C:/app.exe', '--in "a b.txt"'], ['loadScript', 'SCRIPT'], ['resume', 777]]));
  expect(store.getState().session.target).toEqual({ kind: 'spawn', path: 'C:/app.exe', args: '--in "a b.txt"', env: '', cwd: '', suspended: false });
  expect(store.getState().session.suspendedPid).toBeNull();
});

test('Spawn options: environment and working directory are sent; the toggle counts what is set', async () => {
  withSpawn();
  const store = fullStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  expect(screen.queryByLabelText('environment')).toBeNull();
  fireEvent.click(screen.getByTestId('spawn-options-toggle'));
  fireEvent.change(screen.getByLabelText('spawn path'), { target: { value: 'C:/app.exe' } });
  fireEvent.change(screen.getByLabelText('environment'), { target: { value: 'DEBUG=1\n# note\nMODE=test' } });
  fireEvent.change(screen.getByLabelText('working directory'), { target: { value: ' C:\\work ' } });
  expect(screen.getByTestId('spawn-options-toggle')).toHaveTextContent('Options (3 set)');
  fireEvent.click(screen.getByTestId('spawn'));
  await waitFor(() => expect(calls[0]).toEqual(['spawn', 'C:/app.exe', '', { env: { DEBUG: '1', MODE: 'test' }, cwd: 'C:\\work' }]));
});

test('Spawn options: an environment line that is not NAME=value blocks the spawn and says which line', async () => {
  withSpawn();
  render(<Provider store={fullStore()}><SessionControls /></Provider>);
  fireEvent.click(screen.getByTestId('spawn-options-toggle'));
  fireEvent.change(screen.getByLabelText('spawn path'), { target: { value: 'C:/app.exe' } });
  fireEvent.change(screen.getByLabelText('environment'), { target: { value: 'DEBUG=1\nnot a variable' } });
  expect(screen.getByTestId('spawn-env-error')).toHaveTextContent('Line 2 is not NAME=value');
  expect(screen.getByTestId('spawn')).toBeDisabled();
  expect(calls).toEqual([]);
});

test('Start suspended: the program is left suspended until Resume is pressed', async () => {
  withSpawn();
  const store = fullStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  fireEvent.click(screen.getByTestId('spawn-options-toggle'));
  fireEvent.change(screen.getByLabelText('spawn path'), { target: { value: 'C:/app.exe' } });
  fireEvent.click(screen.getByTestId('spawn-suspended'));
  expect(screen.getByTestId('spawn')).toHaveTextContent('Spawn suspended');
  fireEvent.click(screen.getByTestId('spawn'));
  const note = await screen.findByTestId('session-suspended');
  expect(note).toHaveTextContent('Process 777 is suspended');
  expect(calls).toEqual([['spawn', 'C:/app.exe', ''], ['loadScript', 'SCRIPT']]);
  fireEvent.click(screen.getByTestId('resume'));
  await waitFor(() => expect(calls[calls.length - 1]).toEqual(['resume', 777]));
  await waitFor(() => expect(screen.queryByTestId('session-suspended')).toBeNull());
});

test('hooks are placed before a spawned program is resumed', async () => {
  withSpawn();
  const store = fullStore();
  store.dispatch(hooksActions.added(hookFromTarget({ name: 'k!f', module: 'k', offset: 16, address: '0x10' }, 'h1')));
  render(<Provider store={store}><SessionControls /></Provider>);
  fireEvent.change(screen.getByLabelText('spawn path'), { target: { value: 'C:/app.exe' } });
  fireEvent.click(screen.getByTestId('spawn'));
  await waitFor(() => expect(calls[calls.length - 1]).toEqual(['resume', 777]));
  const order = calls.map((c) => c[0]);
  expect(order.indexOf('hookAdd')).toBeGreaterThan(order.indexOf('spawn'));
  expect(order.indexOf('hookAdd')).toBeLessThan(order.indexOf('resume'));
  expect(store.getState().hooks.hooks[0].status).toBe('on');
});

test('a spawn that fails is reported, and a process that was started is not left frozen', async () => {
  const f = withSpawn();
  f.loadScript = async () => { throw new Error("Error invoking remote method 'fermion:invoke': Error: script error: boom"); };
  render(<Provider store={fullStore()}><SessionControls /></Provider>);
  fireEvent.change(screen.getByLabelText('spawn path'), { target: { value: 'C:/app.exe' } });
  fireEvent.click(screen.getByTestId('spawn'));
  await waitFor(() => expect(lines).toContain('ERR [!] Spawn failed: script error: boom'));
  expect(calls[calls.length - 1]).toEqual(['resume', 777]);
});

test('a program that cannot be started at all is reported, and there is nothing to resume', async () => {
  const f = withSpawn();
  f.spawn = async () => { throw new Error('unable to find executable'); };
  const store = fullStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  fireEvent.change(screen.getByLabelText('spawn path'), { target: { value: 'C:/nope.exe' } });
  fireEvent.click(screen.getByTestId('spawn'));
  await waitFor(() => expect(lines).toContain('ERR [!] Spawn failed: unable to find executable'));
  expect(calls).toEqual([]);
  expect(store.getState().session.isAttached).toBe(false);
  expect(store.getState().session.target).toBeNull();
});

test('when a session ends, the sidebar says why and offers to attach again', async () => {
  withSpawn();
  const store = fullStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  expect(screen.queryByTestId('session-ended')).toBeNull();
  const procSel = screen.getByLabelText('process');
  fireEvent.focus(procSel);
  await waitFor(() => expect(screen.getByText('notepad.exe · 4821')).toBeInTheDocument());
  fireEvent.change(procSel, { target: { value: '4821' } });
  fireEvent.click(screen.getByTestId('attach'));
  await waitFor(() => expect(store.getState().session.target).toEqual({ kind: 'attach', pid: 4821, name: 'notepad.exe' }));
  act(() => { store.dispatch(sessionActions.detached('process-terminated')); });
  const note = screen.getByTestId('session-ended');
  expect(note).toHaveTextContent('The process exited. Last session: notepad.exe (pid 4821).');
  expect(within(note).getByTestId('reconnect')).toHaveTextContent('Attach again');
  // The program was started again under a new pid: it is found by name.
  (window as any).fermion.enumerateProcesses = async () => [{ pid: 9001, name: 'notepad.exe' }, { pid: 10, name: 'a' }];
  calls.length = 0;
  fireEvent.click(screen.getByTestId('reconnect'));
  await waitFor(() => expect(calls).toEqual([['attach', 9001], ['loadScript', 'SCRIPT']]));
  await waitFor(() => expect(screen.queryByTestId('session-ended')).toBeNull());
});

test('attach again explains when the program is not running, or when several processes share its name', async () => {
  withSpawn();
  const store = fullStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  act(() => {
    store.dispatch(sessionActions.sessionStarted({ kind: 'attach', pid: 4821, name: 'notepad.exe' }));
    store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '4821' }));
    store.dispatch(sessionActions.detached('process-terminated'));
  });
  (window as any).fermion.enumerateProcesses = async () => [{ pid: 10, name: 'a' }];
  fireEvent.click(screen.getByTestId('reconnect'));
  await waitFor(() => expect(screen.getByTestId('reconnect-note')).toHaveTextContent('notepad.exe is not running.'));
  (window as any).fermion.enumerateProcesses = async () => [{ pid: 1, name: 'notepad.exe' }, { pid: 2, name: 'notepad.exe' }];
  fireEvent.click(screen.getByTestId('reconnect'));
  await waitFor(() => expect(screen.getByTestId('reconnect-note')).toHaveTextContent('2 processes are named notepad.exe: pick one in the Process list.'));
  expect(calls.filter((c) => c[0] === 'attach')).toEqual([]);
  fireEvent.click(screen.getByTestId('ended-dismiss'));
  expect(screen.queryByTestId('session-ended')).toBeNull();
});

test('a spawned session that ends offers to spawn the same program the same way', async () => {
  withSpawn();
  const store = fullStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  fireEvent.click(screen.getByTestId('spawn-options-toggle'));
  fireEvent.change(screen.getByLabelText('spawn path'), { target: { value: 'C:\\Tools\\app.exe' } });
  fireEvent.change(screen.getByLabelText('spawn args'), { target: { value: '-v' } });
  fireEvent.change(screen.getByLabelText('environment'), { target: { value: 'DEBUG=1' } });
  fireEvent.click(screen.getByTestId('spawn'));
  await waitFor(() => expect(calls[calls.length - 1]).toEqual(['resume', 777]));
  act(() => { store.dispatch(sessionActions.detached('process-terminated')); });
  expect(screen.getByTestId('session-ended')).toHaveTextContent('Last session: app.exe.');
  expect(screen.getByTestId('reconnect')).toHaveTextContent('Spawn again');
  calls.length = 0;
  fireEvent.click(screen.getByTestId('reconnect'));
  await waitFor(() => expect(calls[0]).toEqual(['spawn', 'C:\\Tools\\app.exe', '-v', { env: { DEBUG: '1' } }]));
});

test('Detach is remembered as the operator\'s own doing, and still offers to attach again', async () => {
  withSpawn();
  const store = fullStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  act(() => {
    store.dispatch(sessionActions.sessionStarted({ kind: 'attach', pid: 4821, name: 'notepad.exe' }));
    store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '4821' }));
  });
  fireEvent.click(screen.getByTestId('detach'));
  await waitFor(() => expect(screen.getByTestId('session-ended')).toHaveTextContent('You detached.'));
});

// ---- catching child processes ----
const CHILD = { pid: 200, parentPid: 4821, path: 'C:\\app\\helper.exe', argv: ['C:\\app\\helper.exe', '--type=renderer'] };
function withChildren() {
  const f = withSpawn();
  f.setChildGating = async (on: boolean) => { calls.push(['setChildGating', on]); return on; };
  f.resolveChild = async (pid: number, action: string) => { calls.push(['resolveChild', pid, action]); return { pid, action }; };
  f.getState = async () => ({ deviceId: 'local', isAttached: true, hasScript: false, currentPid: '200' });
  return f;
}
function attachedStore() {
  const store = fullStore();
  store.dispatch(sessionActions.sessionStarted({ kind: 'attach', pid: 4821, name: 'app.exe' }));
  store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '4821' }));
  return store;
}

test('Catch child processes switches catching on and off for the attached process', async () => {
  withChildren();
  const store = attachedStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  const box = screen.getByTestId('child-gating') as HTMLInputElement;
  expect(box.checked).toBe(false);
  fireEvent.click(box);
  await waitFor(() => expect(calls).toEqual([['setChildGating', true]]));
  expect(store.getState().session.childGating).toBe(true);
  fireEvent.click(screen.getByTestId('child-gating'));
  await waitFor(() => expect(calls).toEqual([['setChildGating', true], ['setChildGating', false]]));
});

test('the preference set before attaching is applied when a session starts', async () => {
  withChildren();
  const store = fullStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  fireEvent.click(screen.getByTestId('child-gating'));
  expect(calls).toEqual([]); // nothing to gate yet
  act(() => { store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '4821' })); });
  await waitFor(() => expect(calls).toEqual([['setChildGating', true]]));
});

test('catching that cannot be started is reported and the box is cleared', async () => {
  const f = withChildren();
  f.setChildGating = async () => { throw new Error("Error invoking remote method 'fermion:invoke': Error: not supported"); };
  const store = attachedStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  fireEvent.click(screen.getByTestId('child-gating'));
  await waitFor(() => expect(lines).toContain('ERR [!] Could not start catching child processes: not supported'));
  expect(store.getState().session.childGating).toBe(false);
});

test('a caught child is shown with its command line; Let it run resumes it', async () => {
  withChildren();
  const store = attachedStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  expect(screen.queryByTestId('child-caught')).toBeNull();
  act(() => { store.dispatch(sessionActions.childCaught(CHILD)); });
  const note = screen.getByTestId('child-caught');
  expect(note).toHaveTextContent('A child process is waiting.');
  expect(note).toHaveTextContent('helper.exe --type=renderer · pid 200');
  fireEvent.click(screen.getByTestId('child-release'));
  await waitFor(() => expect(calls).toEqual([['resolveChild', 200, 'resume']]));
  expect(screen.queryByTestId('child-caught')).toBeNull();
});

test('Switch to it moves the session: hooks and the script go in before the child is resumed', async () => {
  withChildren();
  const store = attachedStore();
  store.dispatch(hooksActions.added(hookFromTarget({ name: 'k!f', module: 'k', offset: 16, address: '0x10' }, 'h1')));
  store.dispatch(hooksActions.patched({ id: 'h1', status: 'on' })); // placed in the parent
  store.dispatch(sessionActions.childGatingSet(true));
  render(<Provider store={store}><SessionControls /></Provider>);
  await waitFor(() => expect(calls).toEqual([['setChildGating', true]]));
  calls.length = 0;
  act(() => { store.dispatch(sessionActions.childCaught(CHILD)); store.dispatch(sessionActions.childCaught({ ...CHILD, pid: 201 })); });
  fireEvent.click(screen.getAllByTestId('child-switch')[0]);
  await waitFor(() => expect(calls[calls.length - 1]).toEqual(['resume', 200]));
  expect(calls).toEqual([
    ['resolveChild', 200, 'attach'],
    ['hookAdd', 'h1'],           // placed again, in the child
    ['loadScript', 'SCRIPT'],
    ['setChildGating', true],    // its own children are caught too
    ['resume', 200],
  ]);
  expect(store.getState().session.target).toEqual({ kind: 'attach', pid: 200, name: 'helper.exe' });
  expect(store.getState().session.currentPid).toBe('200');
  expect(store.getState().session.children).toEqual([]); // the other one was let run by main
  expect(store.getState().session.ended).toBeNull();
  expect(lines).toContain('STATUS [+] Now on child process 200');
});

test('Keep it suspended leaves the child waiting for Resume after the switch', async () => {
  withChildren();
  const store = attachedStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  act(() => { store.dispatch(sessionActions.childCaught(CHILD)); });
  fireEvent.click(screen.getByTestId('child-suspended'));
  fireEvent.click(screen.getByTestId('child-switch'));
  await screen.findByTestId('session-suspended');
  expect(calls).toEqual([['resolveChild', 200, 'attach'], ['loadScript', 'SCRIPT']]);
  fireEvent.click(screen.getByTestId('resume'));
  await waitFor(() => expect(calls[calls.length - 1]).toEqual(['resume', 200]));
});

test('a switch that fails after the session moved does not leave the child frozen', async () => {
  const f = withChildren();
  f.loadScript = async () => { throw new Error('script error: boom'); };
  const store = attachedStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  act(() => { store.dispatch(sessionActions.childCaught(CHILD)); });
  fireEvent.click(screen.getByTestId('child-switch'));
  await waitFor(() => expect(lines).toContain('ERR [!] Could not switch to child 200: script error: boom'));
  expect(calls[calls.length - 1]).toEqual(['resume', 200]);
});

test('a switch main refuses leaves the session where it was', async () => {
  const f = withChildren();
  f.resolveChild = async () => { throw new Error('No caught child with pid 200'); };
  const store = attachedStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  act(() => { store.dispatch(sessionActions.childCaught(CHILD)); });
  fireEvent.click(screen.getByTestId('child-switch'));
  await waitFor(() => expect(lines).toContain('ERR [!] Could not switch to child 200: No caught child with pid 200'));
  expect(calls).toEqual([]);
  expect(store.getState().session.currentPid).toBe('4821');
  expect(screen.queryByTestId('child-caught')).toBeNull();
});

test('caught children disappear when the session ends', () => {
  withChildren();
  const store = attachedStore();
  render(<Provider store={store}><SessionControls /></Provider>);
  act(() => { store.dispatch(sessionActions.childCaught(CHILD)); });
  act(() => { store.dispatch(sessionActions.detached('process-terminated')); });
  expect(screen.queryByTestId('child-caught')).toBeNull();
  expect(store.getState().session.children).toEqual([]);
});
