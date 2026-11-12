import { parseEnv, envCount, pickReattach, endedText, targetLabel } from './launch';

test('parseEnv: NAME=value per line; blank lines and # comments are skipped; a value may contain =', () => {
  expect(parseEnv('DEBUG=1\n\n# a comment\r\n  PATH_EXTRA = C:\\x y \nQUERY=a=b=c\nEMPTY=')).toEqual({
    env: { DEBUG: '1', PATH_EXTRA: ' C:\\x y', QUERY: 'a=b=c', EMPTY: '' },
    error: '',
  });
  expect(parseEnv('')).toEqual({ env: {}, error: '' });
  expect(envCount('A=1\nB=2\n#C=3')).toBe(2);
});

test('parseEnv: a line that is not NAME=value is reported with its line number, and nothing is used', () => {
  expect(parseEnv('A=1\njust text')).toEqual({ env: {}, error: 'Line 2 is not NAME=value: just text' });
  expect(parseEnv('=value').error).toMatch(/^Line 1 is not NAME=value/);
  expect(envCount('A=1\nbroken')).toBe(0);
});

const PROCS = [{ pid: 10, name: 'a.exe' }, { pid: 20, name: 'b.exe' }, { pid: 21, name: 'b.exe' }, { pid: 30, name: 'c.exe' }];

test('pickReattach: the same pid under the same name is the same program', () => {
  expect(pickReattach(PROCS, { pid: 10, name: 'a.exe' })).toEqual({ pid: 10, message: '' });
  expect(pickReattach(PROCS, { pid: 21, name: 'b.exe' })).toEqual({ pid: 21, message: '' });
});

test('pickReattach: a pid now used by another program is not taken for it; the only process of that name is', () => {
  expect(pickReattach(PROCS, { pid: 10, name: 'c.exe' })).toEqual({ pid: 30, message: '' });
  expect(pickReattach(PROCS, { pid: 999, name: 'a.exe' })).toEqual({ pid: 10, message: '' });
});

test('pickReattach: nothing or several of that name is left to the operator', () => {
  expect(pickReattach(PROCS, { pid: 999, name: 'gone.exe' })).toEqual({ pid: null, message: 'gone.exe is not running.' });
  expect(pickReattach(PROCS, { pid: 999, name: 'b.exe' })).toEqual({ pid: null, message: '2 processes are named b.exe: pick one in the Process list.' });
  // Without a name only the pid can be matched.
  expect(pickReattach(PROCS, { pid: 30, name: '' })).toEqual({ pid: 30, message: '' });
  expect(pickReattach(PROCS, { pid: 999, name: '' })).toEqual({ pid: null, message: 'Process 999 is no longer running.' });
});

test('endedText: Frida detach reasons in plain words; an unknown one is shown as given', () => {
  expect(endedText('process-terminated')).toBe('The process exited.');
  expect(endedText('user')).toBe('You detached.');
  expect(endedText('connection-terminated')).toBe('The connection to the device was lost.');
  expect(endedText('something-new')).toBe('The session ended (something-new).');
});

test('targetLabel names what a session was on', () => {
  expect(targetLabel({ kind: 'attach', pid: 10, name: 'a.exe' })).toBe('a.exe (pid 10)');
  expect(targetLabel({ kind: 'attach', pid: 10, name: '' })).toBe('pid 10');
  expect(targetLabel({ kind: 'spawn', path: 'C:\\Tools\\app.exe', args: '', env: '', cwd: '', suspended: false })).toBe('app.exe');
  expect(targetLabel({ kind: 'spawn', path: '/usr/bin/app', args: '', env: '', cwd: '', suspended: false })).toBe('app');
});
