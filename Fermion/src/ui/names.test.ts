import { buildNameIndex, parseWhere, nameText, NEAR } from './names';
import { Bookmark } from './store/bookmarksSlice';

const bm = (label: string, module: string, offset: number | null, address = '0x0'): Bookmark => ({ id: label + module + offset + address, label, module, offset, address, view: 'code', note: '' });

test('parseWhere reads "module+0xoffset" as the agent writes it, and nothing else', () => {
  expect(parseWhere('app.exe+0x1a2b')).toEqual({ module: 'app.exe', offset: 0x1a2b });
  expect(parseWhere('lib+plus.so+0x10')).toEqual({ module: 'lib+plus.so', offset: 0x10 }); // the last "+0x" is the offset
  for (const not of ['0x7ff600001000', 'app.exe', '', null, undefined, 'app.exe+12', 'app.exe+0x']) expect(parseWhere(not as string)).toBeNull();
});

test('an address the operator named shows that name; one just after it shows the name and how far in', () => {
  const names = buildNameIndex([bm('parse_packet', 'app.exe', 0x1000), bm('send_reply', 'App.EXE', 0x1400), bm('checksum', 'net.dll', 0x20)]);
  expect(names.find('app.exe+0x1000')).toEqual({ label: 'parse_packet', delta: 0 });
  expect(names.find('APP.exe+0x1040')).toEqual({ label: 'parse_packet', delta: 0x40 }); // module names compare as the system does
  expect(names.find('app.exe+0x1400')).toEqual({ label: 'send_reply', delta: 0 });
  expect(names.find('app.exe+0x13ff')).toEqual({ label: 'parse_packet', delta: 0x3ff }); // the nearest name before it
  expect(names.find('net.dll+0x25')).toEqual({ label: 'checksum', delta: 5 });
  expect(nameText({ label: 'parse_packet', delta: 0 })).toBe('parse_packet');
  expect(nameText({ label: 'parse_packet', delta: 0x40 })).toBe('parse_packet+0x40');
});

test('a name does not reach before its address, past the next 4 KB, or into another module', () => {
  const names = buildNameIndex([bm('parse_packet', 'app.exe', 0x1000)]);
  expect(names.find('app.exe+0xfff')).toBeNull();
  expect(names.find('app.exe+0x' + (0x1000 + NEAR - 1).toString(16))).not.toBeNull();
  expect(names.find('app.exe+0x' + (0x1000 + NEAR).toString(16))).toBeNull();
  expect(names.find('other.dll+0x1000')).toBeNull();
  expect(names.find('0x7ff600001000')).toBeNull();
  expect(names.find(null)).toBeNull();
});

test('a place outside every module is named by its address, exactly', () => {
  const names = buildNameIndex([bm('config block', '', null, '0x1D2F2C68000')]);
  expect(names.find('0x1d2f2c68000', '0x1d2f2c68000')).toEqual({ label: 'config block', delta: 0 });
  expect(names.find(null, '0x1D2F2C68000')).toEqual({ label: 'config block', delta: 0 });
  expect(names.find('0x1d2f2c68010', '0x1d2f2c68010')).toBeNull(); // no "nearby" without a module: the address may be reused
});

test('a bookmark whose label is only an address or a place names nothing; show() falls back to what the target said', () => {
  const names = buildNameIndex([bm('app.exe+0x1000', 'app.exe', 0x1000), bm('0x7ff600002000', 'app.exe', 0x2000), bm('  ', 'app.exe', 0x3000), bm('real name', 'app.exe', 0x4000)]);
  expect(names.find('app.exe+0x1000')).toBeNull();
  expect(names.find('app.exe+0x2000')).toBeNull();
  expect(names.find('app.exe+0x3000')).toBeNull();
  expect(names.size).toBe(1);
  expect(names.show('app.exe+0x4008', null, 'kernel32.dll!Sleep')).toBe('real name+0x8');
  expect(names.show('app.exe+0x1000', null, 'app.exe!main')).toBe('app.exe!main');
  expect(names.show('app.exe+0x1000', null, '')).toBe('app.exe+0x1000');
  expect(names.show(null, '0x500', '')).toBe('0x500');
});
