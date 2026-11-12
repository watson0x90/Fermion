import { parseHelpCommand, formatHelp, formatOverview, commonPrefix, HelpIndex, Inspection } from './help';

const INDEX: HelpIndex = {
  Process: { kind: 'namespace', sigs: [], doc: 'Information about the current process.' },
  'Process.id': { kind: 'property', sigs: ['id: number'], doc: 'PID of the current process.' },
  'Process.enumerateModules': { kind: 'function', sigs: ['enumerateModules(): Module[]'], doc: 'Enumerates modules loaded right now.\nSecond line of detail.\n\n@returns the modules' },
  'Process.findModuleByAddress': { kind: 'function', sigs: ['findModuleByAddress(address: NativePointerValue): Module | null', 'findModuleByAddress(name: string): Module | null'], doc: 'Looks up a module.' },
  NativePointer: { kind: 'class', sigs: ['new NativePointer(v: string | number)'], doc: 'Represents a native pointer value.' },
  'NativePointer.add': { kind: 'method', sigs: ['add(v: NativePointerValue | UInt64 | Int64 | number | string): NativePointer'], doc: 'Makes a new NativePointer by adding `v`.' },
  ptr: { kind: 'function', sigs: ['ptr(value: string | number): NativePointer'], doc: 'Short-hand for `new NativePointer(value)`.' },
  ModuleDetails: { kind: 'interface', sigs: [], doc: 'Not a runtime value.' },
};

test('parseHelpCommand: "help", "help <name>" and "?<name>"; ordinary code is not a help command', () => {
  expect(parseHelpCommand('help')).toEqual({ topic: '' });
  expect(parseHelpCommand('  help   Process.id  ')).toEqual({ topic: 'Process.id' });
  expect(parseHelpCommand('?Process')).toEqual({ topic: 'Process' });
  expect(parseHelpCommand('help(Process)')).toEqual({ topic: 'Process' }); // people try it as a function
  expect(parseHelpCommand('helper()')).toBeNull();
  expect(parseHelpCommand('var help = 1')).toBeNull();
  expect(parseHelpCommand('help 1 + 1')).toEqual({ topic: '1 + 1' }); // reported as "no help", not evaluated
});

test('formatHelp: a namespace lists its documentation and its live members with signatures and one-line docs', () => {
  const info: Inspection = {
    found: true, name: 'Process', type: 'object',
    members: [
      { name: 'enumerateModules', kind: 'function', arity: 0 },
      { name: 'id', kind: 'property', type: 'number' },
      { name: 'somethingNew', kind: 'function', arity: 2 }, // in this Frida, not in the definitions
    ],
  };
  const text = formatHelp('Process', info, INDEX);
  expect(text).toContain('Process — namespace');
  expect(text).toContain('Information about the current process.');
  expect(text).toMatch(/Properties\n {2}id: number\s+PID of the current process\./);
  expect(text).toMatch(/Functions\n {2}enumerateModules\(\): Module\[\]\s+Enumerates modules loaded right now\./);
  expect(text).not.toContain('Second line of detail'); // member rows carry only the first line
  expect(text).toMatch(/somethingNew\(…2 args\)/);     // undocumented: what the runtime reports
  expect(text).toContain('help Process.<name>');
});

test('formatHelp: a function shows every signature and the full documentation', () => {
  const text = formatHelp('Process.findModuleByAddress', { found: true, name: 'Process.findModuleByAddress', type: 'function', arity: 1, members: [] }, INDEX);
  expect(text).toContain('Process.findModuleByAddress — function');
  expect(text).toContain('findModuleByAddress(address: NativePointerValue): Module | null');
  expect(text).toContain('findModuleByAddress(name: string): Module | null');
  expect(text).toContain('Looks up a module.');
  const full = formatHelp('Process.enumerateModules', { found: true, name: 'Process.enumerateModules', type: 'function', arity: 0, members: [] }, INDEX);
  expect(full).toContain('Second line of detail.');
  expect(full).toContain('@returns the modules');
});

test('formatHelp: a property shows its type, documentation and current value', () => {
  const text = formatHelp('Process.id', { found: true, name: 'Process.id', type: 'number', value: '4821' }, INDEX);
  expect(text).toContain('Process.id — property');
  expect(text).toContain('id: number');
  expect(text).toContain('PID of the current process.');
  expect(text).toContain('Current value: 4821');
});

test('formatHelp: a class lists static members and what its instances offer', () => {
  const info: Inspection = {
    found: true, name: 'NativePointer', type: 'function', arity: 1,
    members: [],
    instanceMembers: [{ name: 'add', kind: 'function', arity: 1 }, { name: 'isNull', kind: 'function', arity: 0 }],
  };
  const text = formatHelp('NativePointer', info, INDEX);
  expect(text).toContain('NativePointer — class');
  expect(text).toContain('new NativePointer(v: string | number)');
  expect(text).toMatch(/Instances\n {2}add\(v: NativePointerValue/);
  expect(text).toMatch(/isNull\(\)/);
});

test('formatHelp: documented but not a value here (an instance method, an interface) still shows the documentation', () => {
  const text = formatHelp('NativePointer.add', { found: false, name: 'NativePointer.add' }, INDEX);
  expect(text).toContain('NativePointer.add — method');
  expect(text).toContain('Makes a new NativePointer by adding `v`.');
  expect(formatHelp('ModuleDetails', { found: false, name: 'ModuleDetails' }, INDEX)).toContain('ModuleDetails — interface');
});

test('formatHelp: something of the user\'s own gets a description from the live value alone', () => {
  const text = formatHelp('hooks', { found: true, name: 'hooks', type: 'object', members: [{ name: 'count', kind: 'property', type: 'number' }, { name: 'reset', kind: 'function', arity: 0 }] }, INDEX);
  expect(text).toContain('hooks — object');
  expect(text).toMatch(/count: number/);
  expect(text).toMatch(/reset\(\)/);
});

test('formatHelp: nothing known says so and points at Tab', () => {
  const text = formatHelp('nope', { found: false, name: 'nope' }, INDEX);
  expect(text).toContain('No help for “nope”');
  expect(text).toContain('Tab');
});

test('formatOverview: how the REPL works, and the documented APIs that exist in this target', () => {
  const text = formatOverview(['Process', 'ptr', 'NativePointer', 'myVar', 'ModuleDetails', 'Array'], INDEX);
  expect(text).toContain('help <name>');
  expect(text).toContain('Tab');
  expect(text).toMatch(/NativePointer, Process, ptr/);
  expect(text).not.toContain('myVar');
  expect(text).not.toContain('ModuleDetails'); // interfaces are not runtime values
});

test('commonPrefix: the longest prefix shared by every candidate', () => {
  expect(commonPrefix(['enumerateModules', 'enumerateThreads', 'enumerateRanges'])).toBe('enumerate');
  expect(commonPrefix(['id'])).toBe('id');
  expect(commonPrefix(['abc', 'xyz'])).toBe('');
  expect(commonPrefix([])).toBe('');
});
