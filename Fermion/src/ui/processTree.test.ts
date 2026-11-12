import { buildTree, flattenTree, ancestryOf, hasParentInfo, Proc } from './processTree';

const P = (pid: number, name: string, ppid?: number, extra: Record<string, unknown> = {}): Proc =>
  ({ pid, name, parameters: { ...(ppid === undefined ? {} : { ppid }), ...extra } });

// System(4) -> smss(300) ; explorer(1000) -> chrome(2000) -> chrome(2001), notepad(2100)
const SAMPLE: Proc[] = [
  P(2001, 'chrome.exe', 2000),
  P(4, 'System', 0),
  P(1000, 'explorer.exe', 900), // parent 900 has exited: becomes a root
  P(300, 'smss.exe', 4),
  P(2100, 'notepad.exe', 1000),
  P(2000, 'chrome.exe', 1000),
];

const shape = (rows: { pid: number; depth: number }[]) => rows.map((r) => `${'  '.repeat(r.depth)}${r.pid}`);

test('buildTree nests children under their parent, sorted by pid; orphans become roots', () => {
  const rows = flattenTree(buildTree(SAMPLE));
  expect(shape(rows)).toEqual(['4', '  300', '1000', '  2000', '    2001', '  2100']);
  expect(rows.find((r) => r.pid === 1000)!.hasChildren).toBe(true);
  expect(rows.find((r) => r.pid === 2100)!.hasChildren).toBe(false);
});

test('a process that names itself or a cycle as its parent cannot hang or vanish', () => {
  const procs = [P(0, 'Idle', 0), P(10, 'a', 11), P(11, 'b', 10), P(12, 'c', 11)];
  const rows = flattenTree(buildTree(procs));
  expect(rows.map((r) => r.pid).sort((a, b) => a - b)).toEqual([0, 10, 11, 12]); // every process shown once
  expect(rows.find((r) => r.pid === 0)!.depth).toBe(0);
});

test('duplicate pids in the listing are shown once', () => {
  const rows = flattenTree(buildTree([P(5, 'x'), P(5, 'x'), P(6, 'y', 5)]));
  expect(shape(rows)).toEqual(['5', '  6']);
});

test('no parent info at all: a flat list, and hasParentInfo says so', () => {
  const procs = [P(2, 'b'), P(1, 'a')];
  expect(hasParentInfo(procs)).toBe(false);
  expect(hasParentInfo(SAMPLE)).toBe(true);
  expect(shape(flattenTree(buildTree(procs)))).toEqual(['1', '2']);
});

test('collapsed nodes hide their descendants', () => {
  const rows = flattenTree(buildTree(SAMPLE), { collapsed: new Set([1000]) });
  expect(shape(rows)).toEqual(['4', '  300', '1000']);
  expect(rows.find((r) => r.pid === 1000)!.collapsed).toBe(true);
});

test('filter matches name (case-insensitive) or pid, and keeps the ancestors for context', () => {
  const byName = flattenTree(buildTree(SAMPLE), { filter: 'NOTEPAD' });
  expect(shape(byName)).toEqual(['1000', '  2100']);
  expect(byName.find((r) => r.pid === 2100)!.match).toBe(true);
  expect(byName.find((r) => r.pid === 1000)!.match).toBe(false); // context only

  const byPid = flattenTree(buildTree(SAMPLE), { filter: '2001' });
  expect(shape(byPid)).toEqual(['1000', '  2000', '    2001']);

  // A filter overrides collapse: a match inside a collapsed branch is still shown.
  const collapsed = flattenTree(buildTree(SAMPLE), { filter: 'notepad', collapsed: new Set([1000]) });
  expect(shape(collapsed)).toEqual(['1000', '  2100']);

  expect(flattenTree(buildTree(SAMPLE), { filter: 'zzz' })).toEqual([]);
});

test('ancestryOf: the chain from the root down to a pid, plus everything beneath it', () => {
  expect([...ancestryOf(SAMPLE, 2000)].sort((a, b) => a - b)).toEqual([1000, 2000, 2001]);
  expect([...ancestryOf(SAMPLE, 2001)].sort((a, b) => a - b)).toEqual([1000, 2000, 2001]);
  expect([...ancestryOf(SAMPLE, 9999)]).toEqual([]); // unknown pid
  // cycle-safe
  expect([...ancestryOf([P(10, 'a', 11), P(11, 'b', 10)], 10)].sort((a, b) => a - b)).toEqual([10, 11]);
});

test('only: restrict the tree to a set of pids (the attached process ancestry)', () => {
  const rows = flattenTree(buildTree(SAMPLE), { only: ancestryOf(SAMPLE, 2000) });
  expect(shape(rows)).toEqual(['1000', '  2000', '    2001']);
});

test('rows carry user and path when the device reports them', () => {
  const rows = flattenTree(buildTree([P(7, 'svc.exe', undefined, { user: 'SYSTEM', path: 'C:\\svc.exe' })]));
  expect(rows[0].user).toBe('SYSTEM');
  expect(rows[0].path).toBe('C:\\svc.exe');
});
