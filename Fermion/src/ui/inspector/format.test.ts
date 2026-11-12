import {
  fmtSize, hexRows, textToPattern, normalizePattern, parseAddress, addAddress, cleanIpcError, pageBase,
} from './format';

test('fmtSize: bytes, KB, MB, GB', () => {
  expect(fmtSize(0)).toBe('0 B');
  expect(fmtSize(4096)).toBe('4 KB');
  expect(fmtSize(1536)).toBe('1.5 KB');
  expect(fmtSize(2539520)).toBe('2.4 MB');
  expect(fmtSize(92749824)).toBe('88.5 MB');
  expect(fmtSize(3 * 1024 ** 3)).toBe('3 GB');
});

test('hexRows: 16 bytes per row with address, hex cells and printable ASCII', () => {
  const rows = hexRows('4d5a900003000000040000000000ffff' + '48656c6c6f0a', '0x7ff000');
  expect(rows.length).toBe(2);
  expect(rows[0].address).toBe('0x7ff000');
  expect(rows[0].bytes.slice(0, 3)).toEqual(['4d', '5a', '90']);
  expect(rows[0].bytes.length).toBe(16);
  expect(rows[0].ascii).toBe('MZ..............');
  expect(rows[1].address).toBe('0x7ff010');
  expect(rows[1].bytes).toEqual(['48', '65', '6c', '6c', '6f', '0a']); // short last row
  expect(rows[1].ascii).toBe('Hello.');
  expect(hexRows('', '0x0')).toEqual([]);
});

test('hexRows: a narrow pane can ask for 8 bytes per row', () => {
  const rows = hexRows('4d5a900003000000' + '0400000000000000' + 'ff', '0x1000', 8);
  expect(rows.map((r) => r.address)).toEqual(['0x1000', '0x1008', '0x1010']);
  expect(rows[0].bytes.length).toBe(8);
  expect(rows[0].ascii).toBe('MZ......');
  expect(rows[2].bytes).toEqual(['ff']);
});

test('hexRows: addresses above 2^53 stay exact', () => {
  const rows = hexRows('00'.repeat(32), '0x7fffffffffffff0');
  expect(rows[1].address).toBe('0x800000000000000');
});

test('textToPattern: text becomes its UTF-8 bytes as a scan pattern', () => {
  expect(textToPattern('MZ')).toBe('4d 5a');
  expect(textToPattern('é')).toBe('c3 a9');
  expect(textToPattern('')).toBe('');
});

test('normalizePattern: accepts spaced, unspaced, comma or 0x-prefixed hex with ?? wildcards', () => {
  expect(normalizePattern('4d 5a ?? 00')).toBe('4d 5a ?? 00');
  expect(normalizePattern('4D5A??00')).toBe('4d 5a ?? 00');
  expect(normalizePattern(' 0x4d, 0x5a ')).toBe('4d 5a');
  // Fewer than two concrete bytes would match a large part of the process.
  expect(normalizePattern('00')).toBeNull();
  expect(normalizePattern('4d ??')).toBeNull();
  expect(normalizePattern('4? 5?')).toBeNull();
  expect(normalizePattern('4d ?? 5a')).toBe('4d ?? 5a');
  expect(normalizePattern('4d 5')).toBeNull();     // half a byte
  expect(normalizePattern('xyz')).toBeNull();
  expect(normalizePattern('')).toBeNull();
  expect(normalizePattern('?? ??')).toBeNull();    // nothing concrete to find
});

test('parseAddress: 0x-prefixed or bare hex; rejects anything else', () => {
  expect(parseAddress('0x7FF000')).toBe('0x7ff000');
  expect(parseAddress('7ff000')).toBe('0x7ff000');
  expect(parseAddress('  0x10 ')).toBe('0x10');
  expect(parseAddress('0x')).toBeNull();
  expect(parseAddress('hello')).toBeNull();
  expect(parseAddress('0x' + 'f'.repeat(17))).toBeNull(); // wider than 64 bits
  expect(parseAddress('')).toBeNull();
});

test('addAddress / pageBase: 64-bit safe arithmetic, clamped to the address space', () => {
  expect(addAddress('0x1000', 256)).toBe('0x1100');
  expect(addAddress('0x1000', -256)).toBe('0xf00');
  expect(addAddress('0x10', -256)).toBe('0x0');
  expect(addAddress('0x7fffffffffffff00', 256)).toBe('0x8000000000000000');
  expect(addAddress('0xffffffffffffff00', 512)).toBe('0xffffffffffffffff');
  expect(pageBase('0x7ff123')).toBe('0x7ff120'); // start of its 16-byte row
});

test('cleanIpcError strips the Electron IPC wrapper from an error message', () => {
  expect(cleanIpcError(new Error("Error invoking remote method 'fermion:invoke': Error: Cannot read memory at 0x10: access violation")))
    .toBe('Cannot read memory at 0x10: access violation');
  expect(cleanIpcError(new Error('plain'))).toBe('plain');
  expect(cleanIpcError('str')).toBe('str');
});
