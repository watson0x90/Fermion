import { parseEnv, envCount, pickReattach, endedText, targetLabel, asChildInfo, childName, childCommand, isFork } from './launch';

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

test('asChildInfo keeps a well-formed announcement and drops anything else', () => {
  expect(asChildInfo({ pid: 200, parentPid: 100, path: 'C:\\app\\helper.exe', argv: ['C:\\app\\helper.exe', '--type=renderer'], envp: ['SECRET=1'] }))
    .toEqual({ pid: 200, parentPid: 100, path: 'C:\\app\\helper.exe', argv: ['C:\\app\\helper.exe', '--type=renderer'] });
  for (const bad of [null, 'x', {}, { pid: '200' }, { pid: -1 }, { pid: 1.5 }]) expect(asChildInfo(bad)).toBeNull();
  expect(asChildInfo({ pid: 5, parentPid: 'x', path: 7, argv: ['ok', 3, null, 'y'.repeat(5000)] })).toEqual({ pid: 5, parentPid: 0, path: '', argv: ['ok', 'y'.repeat(1024)] });
  expect(asChildInfo({ pid: 5, argv: Array(500).fill('a') })!.argv.length).toBe(64);
});

test('asChildInfo keeps the mark of a process that replaced itself, and only a true one', () => {
  expect(asChildInfo({ pid: 9, parentPid: 9, path: '/bin/cat', argv: ['/bin/cat'], replaced: true })).toEqual({ pid: 9, parentPid: 9, path: '/bin/cat', argv: ['/bin/cat'], replaced: true });
  expect(asChildInfo({ pid: 9, parentPid: 9, path: '/bin/cat', argv: [], replaced: 'yes' })).toEqual({ pid: 9, parentPid: 9, path: '/bin/cat', argv: [] });
});

test('a child with no program of its own is a fork: a copy of its parent', () => {
  const fork = { pid: 7, parentPid: 1, path: '', argv: [] };
  expect(isFork(fork)).toBe(true);
  expect(childCommand(fork)).toBe('copy of this process (fork)');
  expect(isFork({ pid: 7, parentPid: 1, path: '/bin/cat', argv: [] })).toBe(false);
  expect(isFork({ pid: 7, parentPid: 1, path: '', argv: ['cat'] })).toBe(false);
});

test('childName and childCommand describe a caught child', () => {
  const child = { pid: 200, parentPid: 100, path: 'C:\\app\\helper.exe', argv: ['C:\\app\\helper.exe', '--type=renderer', 'C:\\My Files\\a.txt'] };
  expect(childName(child)).toBe('helper.exe');
  expect(childCommand(child)).toBe('helper.exe --type=renderer "C:\\My Files\\a.txt"');
  expect(childName({ pid: 7, parentPid: 1, path: '', argv: ['/usr/bin/tool', '-v'] })).toBe('tool');
  expect(childName({ pid: 7, parentPid: 1, path: '', argv: [] })).toBe('pid 7');
  expect(childCommand({ ...child, argv: ['x', 'a'.repeat(500)] }, 40).length).toBe(40);
});
