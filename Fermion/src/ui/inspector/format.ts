// Pure formatting/parsing helpers for the Inspector panel. Addresses are hex
// strings end to end ("0x7ff000"); arithmetic uses BigInt because 64-bit
// addresses do not fit a JS number.

const MAX_ADDR = (1n << 64n) - 1n;

export function fmtSize(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = bytes;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
  const s = u === 0 || Number.isInteger(v) ? String(Math.round(v)) : v.toFixed(1).replace(/\.0$/, '');
  return `${s} ${units[u]}`;
}

export function parseAddress(input: string): string | null {
  const m = /^(?:0x)?([0-9a-f]{1,16})$/i.exec((input ?? '').trim());
  return m ? '0x' + BigInt('0x' + m[1]).toString(16) : null;
}

export function addAddress(address: string, delta: number): string {
  let v = BigInt(address) + BigInt(delta);
  if (v < 0n) v = 0n;
  if (v > MAX_ADDR) v = MAX_ADDR;
  return '0x' + v.toString(16);
}

// The start of the 16-byte hex-view row that contains `address`.
export function pageBase(address: string): string {
  return '0x' + (BigInt(address) & ~0xfn).toString(16);
}

export interface HexRow { address: string; bytes: string[]; ascii: string; }

// Split a hex string (as returned by fermion.inspect.read) into rows of
// `perRow` bytes (16, or 8 when the pane is too narrow for 16).
export function hexRows(hex: string, base: string, perRow = 16): HexRow[] {
  const rows: HexRow[] = [];
  const start = BigInt(base);
  for (let off = 0; off * 2 < hex.length; off += perRow) {
    const chunk = hex.slice(off * 2, off * 2 + perRow * 2);
    const bytes = chunk.match(/.{2}/g) ?? [];
    const ascii = bytes.map((b) => { const c = parseInt(b, 16); return c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '.'; }).join('');
    rows.push({ address: '0x' + (start + BigInt(off)).toString(16), bytes, ascii });
  }
  return rows;
}

// Text -> scan pattern of its UTF-8 bytes ("MZ" -> "4d 5a").
export function textToPattern(text: string): string {
  return Array.from(new TextEncoder().encode(text), (b) => b.toString(16).padStart(2, '0')).join(' ');
}

// Normalize user-typed hex ("4D5A??00", "0x4d, 0x5a", "4d 5a ?? 00") to the
// spaced lower-case form Frida scans with; null when it is not a usable pattern.
export function normalizePattern(input: string): string | null {
  const compact = (input ?? '').toLowerCase().replace(/0x/g, '').replace(/[\s,]+/g, '');
  if (!compact || compact.length % 2 !== 0 || !/^[0-9a-f?]+$/.test(compact) || !/[0-9a-f]/.test(compact)) return null;
  return (compact.match(/.{2}/g) as string[]).join(' ');
}

// Electron wraps a main-process rejection as
// "Error invoking remote method 'x': Error: <message>"; show just <message>.
export function cleanIpcError(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  return msg.replace(/^Error invoking remote method '[^']*': (?:\w*Error: )?/, '');
}
