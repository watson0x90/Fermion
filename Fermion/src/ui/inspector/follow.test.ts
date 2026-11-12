import { filterFollow, groupFollow, followCsv, scopeText, moduleLabel, FollowItem } from './follow';

const ITEMS: FollowItem[] = [
  { address: '0x7ff01000', name: 'ntdll.dll!RtlAllocateHeap', module: 'ntdll.dll', count: 900 },
  { address: '0x400100', name: 'target.exe!parse', module: 'target.exe', count: 500 },
  { address: '0x7ff02000', name: 'ntdll.dll!RtlFreeHeap', module: 'ntdll.dll', count: 300 },
  { address: '0x9000', name: '0x9000', module: '', count: 20 },
];

test('filterFollow: matches the name, the module or the address, ignoring case; empty keeps everything', () => {
  expect(filterFollow(ITEMS, '')).toBe(ITEMS);
  expect(filterFollow(ITEMS, '   ')).toBe(ITEMS);
  expect(filterFollow(ITEMS, 'HEAP').map((i) => i.count)).toEqual([900, 300]);
  expect(filterFollow(ITEMS, 'target').map((i) => i.count)).toEqual([500]);
  expect(filterFollow(ITEMS, '0x9000').map((i) => i.count)).toEqual([20]);
  expect(filterFollow(ITEMS, 'nothing-like-this')).toEqual([]);
});

test('groupFollow: one group per module, most calls first, using the totals the agent counted', () => {
  // The agent counted more than the functions listed: totals come from it.
  const groups = groupFollow(ITEMS, [
    { name: 'ntdll.dll', calls: 5000, functions: 40 },
    { name: 'target.exe', calls: 500, functions: 1 },
    { name: 'kernel32.dll', calls: 60, functions: 3 },
    { name: '', calls: 20, functions: 1 },
  ]);
  expect(groups.map((g) => [g.name, g.calls, g.functions, g.items.length])).toEqual([
    ['ntdll.dll', 5000, 40, 2],
    ['target.exe', 500, 1, 1],
    ['kernel32.dll', 60, 3, 0], // counted, but none of its functions made the list
    ['', 20, 1, 1],
  ]);
  expect(groups[0].items.map((i) => i.count)).toEqual([900, 300]);
});

test('groupFollow: without agent totals (or for a filtered list) the totals are those of the rows given', () => {
  const groups = groupFollow(filterFollow(ITEMS, 'heap'), null);
  expect(groups).toEqual([{ name: 'ntdll.dll', calls: 1200, functions: 2, items: [ITEMS[0], ITEMS[2]] }]);
  expect(groupFollow([], null)).toEqual([]);
});

test('groupFollow: rows from an older agent with no module field are grouped under no module', () => {
  const old = [{ address: '0x1', name: 'a!b', count: 3 }] as unknown as FollowItem[];
  expect(groupFollow(old, undefined)).toEqual([{ name: '', calls: 3, functions: 1, items: old }]);
});

test('moduleLabel names code that belongs to no module', () => {
  expect(moduleLabel('ntdll.dll')).toBe('ntdll.dll');
  expect(moduleLabel('')).toBe('(no module)');
});

test('followCsv: a header and one line per function', () => {
  expect(followCsv(ITEMS.slice(0, 2))).toBe(
    'calls,module,function,address\r\n'
    + '900,ntdll.dll,ntdll.dll!RtlAllocateHeap,0x7ff01000\r\n'
    + '500,target.exe,target.exe!parse,0x400100\r\n',
  );
});

// Names come from the target. A spreadsheet must not run one as a formula,
// and commas, quotes and line breaks must not break the columns.
test('followCsv: quotes awkward names and defuses ones a spreadsheet would run as a formula', () => {
  const csv = followCsv([
    { address: '0x1', name: '=HYPERLINK("http://x","y")', module: '+evil', count: 1 },
    { address: '0x2', name: 'std::map<int, char>::find', module: 'a "b".dll', count: 2 },
    { address: '0x3', name: 'line\nbreak', module: '@m', count: 3 },
    { address: '0x4', name: '-neg', module: '\tx', count: 4 },
  ]);
  expect(csv.split('\r\n')).toEqual([
    'calls,module,function,address',
    `1,'+evil,"'=HYPERLINK(""http://x"",""y"")",0x1`,
    '2,"a ""b"".dll","std::map<int, char>::find",0x2',
    `3,'@m,"line\nbreak",0x3`,
    `4,'\tx,'-neg,0x4`,
    '',
  ]);
});

test('scopeText describes what a follow covered', () => {
  expect(scopeText({ mode: 'all', module: '' })).toBe('');
  expect(scopeText(null)).toBe('');
  expect(scopeText(undefined)).toBe('');
  expect(scopeText({ mode: 'app', module: '' })).toBe('system libraries not followed');
  expect(scopeText({ mode: 'module', module: 'target.exe' })).toBe('only target.exe followed');
});
