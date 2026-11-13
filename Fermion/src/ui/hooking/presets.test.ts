import { PRESETS } from './presets';


// A stand-in for Frida's NativePointer over a little fake memory: enough for
// a handler to read strings, integers and bytes the way it does in a target.
const mem = new Map<bigint, number>();
let nextFree = 0x10000n;
class P {
  v: bigint;
  constructor(v: bigint | number | string) { this.v = BigInt(v); }
  isNull() { return this.v === 0n; }
  add(n: number) { return new P(this.v + BigInt(n)); }
  toString() { return '0x' + this.v.toString(16); }
  toUInt32() { return Number(this.v & 0xffffffffn); }
  toInt32() { return Number(BigInt.asIntN(32, this.v)); }
  compare(o: P) { return this.v < o.v ? -1 : this.v > o.v ? 1 : 0; }
  readU8() { const b = mem.get(this.v); if (b === undefined) throw new Error('access violation'); return b; }
  readU16() { return this.readU8() | (this.add(1).readU8() << 8); }
  readU32() { return (this.readU16() | (this.add(2).readU16() << 16)) >>> 0; }
  readPointer() { return new P(BigInt(this.readU32()) | (BigInt(this.add(4).readU32()) << 32n)); }
  readByteArray(n: number) { const out = new Uint8Array(n); for (let i = 0; i < n; i++) out[i] = this.add(i).readU8(); return out.buffer; }
  readUtf16String(max = -1) { let s = ''; for (let i = 0; max < 0 || i < max; i++) { const c = this.add(i * 2).readU16(); if (c === 0 && max < 0) break; s += String.fromCharCode(c); } return s; }
  readAnsiString() { let s = ''; for (let i = 0; ; i++) { const c = this.add(i).readU8(); if (!c) break; s += String.fromCharCode(c); } return s; }
}
const NULL = new P(0);
const num = (n: number | bigint) => new P(n);
function bytes(list: number[]): P {
  const at = nextFree; nextFree += BigInt(list.length + 16);
  list.forEach((b, i) => mem.set(at + BigInt(i), b));
  return new P(at);
}
const wide = (s: string) => bytes([...s].flatMap((c) => [c.charCodeAt(0) & 0xff, c.charCodeAt(0) >> 8]).concat([0, 0]));
const ansi = (s: string) => bytes([...s].map((c) => c.charCodeAt(0)).concat([0]));
const u64 = (v: bigint) => Array.from({ length: 8 }, (_, i) => Number((v >> BigInt(i * 8)) & 0xffn));
const u32 = (v: number) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];

const find = (preset: string, fn: string) => PRESETS.find((p) => p.id === preset)!.hooks.find((h) => h.fn === fn)!;
// Run a handler the way the hooks agent does and return what it logged.
function run(preset: string, fn: string, args: P[], retval: P = num(0), pointerSize = 8): string[] {
  const out: string[] = [];
  const log = (...a: unknown[]) => out.push(a.join(' '));
  const h = new Function('ptr', 'Process', 'return (' + find(preset, fn).handler + '\n)')((v: string) => new P(v), { pointerSize });
  const self = {};
  const padded = [...args, ...Array(12).fill(NULL)];
  if (h.onEnter) h.onEnter.call(self, log, padded);
  if (h.onLeave) h.onLeave.call(self, log, retval);
  return out;
}

test('every preset has a name, a description and hooks; every handler compiles to onEnter/onLeave', () => {
  expect(PRESETS.map((p) => p.id)).toEqual(['files', 'registry', 'processes', 'network', 'ioctls', 'pipes', 'rpc']);
  const seen = new Set<string>();
  for (const preset of PRESETS) {
    expect(preset.label).toBeTruthy();
    expect(preset.about.length).toBeGreaterThan(20);
    expect(preset.hooks.length).toBeGreaterThan(0);
    for (const hook of preset.hooks) {
      expect(hook.modules.length).toBeGreaterThan(0);
      for (const m of hook.modules) expect(m).toMatch(/^[a-z0-9_]+\.dll$/);
      expect(hook.fn).toMatch(/^[A-Za-z_][A-Za-z0-9_]*$/);
      expect(seen.has(preset.id + '!' + hook.fn)).toBe(false);
      seen.add(preset.id + '!' + hook.fn);
      expect(hook.handler.length).toBeLessThan(65536);
      expect(hook.handler).not.toContain('`');
      const h = new Function('return (' + hook.handler + '\n)')();
      expect(typeof (h.onEnter ?? h.onLeave)).toBe('function');
    }
  }
});

test('files: CreateFileW shows the path, the access and how it is opened, and the result', () => {
  expect(run('files', 'CreateFileW', [wide('C:\\Temp\\a.txt'), num(0xc0000000), NULL, NULL, num(2)], num(0x1a4)))
    .toEqual(['CreateFileW("C:\\Temp\\a.txt", GENERIC_READ|GENERIC_WRITE, CREATE_ALWAYS) = handle 0x1a4']);
  expect(run('files', 'CreateFileW', [wide('x'), num(0), NULL, NULL, num(3)], num(0xffffffffffffffffn))[0]).toBe('CreateFileW("x", 0x0, OPEN_EXISTING) = INVALID_HANDLE_VALUE');
  expect(run('files', 'CreateFileW', [NULL, num(0x80000000), NULL, NULL, num(9)], num(4))[0]).toBe('CreateFileW(NULL, GENERIC_READ, 9) = handle 0x4');
  expect(run('files', 'MoveFileExW', [wide('a'), wide('b'), num(1)], num(1))).toEqual(['MoveFileExW("a" -> "b", flags 0x1) = ok']);
  expect(run('files', 'DeleteFileW', [wide('gone.txt')], num(0))).toEqual(['DeleteFileW("gone.txt") = failed']);
});

test('strings are shown as written: backslashes stay single, a control character is shown as its code', () => {
  expect(run('files', 'DeleteFileW', [wide('C:\\a\\b "q".txt')], num(1))).toEqual(['DeleteFileW("C:\\a\\b "q".txt") = ok']);
  expect(run('files', 'DeleteFileW', [wide('line1\nline2\ttab')], num(1))).toEqual(['DeleteFileW("line1<10>line2<9>tab") = ok']);
});

test('a pointer that cannot be read is reported, not thrown', () => {
  expect(run('files', 'DeleteFileW', [num(0xdead0000)], num(1))[0]).toMatch(/^DeleteFileW\("<unreadable 0xdead0000>"\) = ok$/);
});

test('registry: predefined roots are named (also sign-extended), other keys are handles; values are decoded by type', () => {
  expect(run('registry', 'RegOpenKeyExW', [num(0xffffffff80000002n), wide('SOFTWARE\\Acme')], num(0))).toEqual(['RegOpenKeyExW(HKLM, "SOFTWARE\\Acme") = ok']);
  expect(run('registry', 'RegOpenKeyExW', [num(0x80000001), wide('Environment')], num(2))).toEqual(['RegOpenKeyExW(HKCU, "Environment") = error 2']);
  expect(run('registry', 'RegQueryValueExW', [num(0x2c4), wide('Path')], num(0))).toEqual(['RegQueryValueExW(key 0x2c4, value "Path") = ok']);
  expect(run('registry', 'RegSetValueExW', [num(0x2c4), wide('Name'), NULL, num(1), wide('hello'), num(12)])).toEqual(['RegSetValueExW(key 0x2c4, value "Name", REG_SZ, "hello")']);
  expect(run('registry', 'RegSetValueExW', [num(0x2c4), wide('N'), NULL, num(4), bytes(u32(0x1234)), num(4)])).toEqual(['RegSetValueExW(key 0x2c4, value "N", REG_DWORD, 0x1234)']);
  expect(run('registry', 'RegSetValueExW', [num(0x2c4), wide('B'), NULL, num(3), bytes([1, 2, 3]), num(3)])).toEqual(['RegSetValueExW(key 0x2c4, value "B", REG_BINARY, 3 bytes)']);
});

test('processes: command lines, access rights, protections and the start of what is written', () => {
  expect(run('processes', 'CreateProcessW', [NULL, wide('cmd.exe /c whoami'), NULL, NULL, num(0), num(0x4)])).toEqual(['CreateProcessW(app NULL, command line "cmd.exe /c whoami", CREATE_SUSPENDED)']);
  expect(run('processes', 'OpenProcess', [num(0x1fffff), num(0), num(4321)], num(0x88))).toEqual(['OpenProcess(pid 4321, PROCESS_ALL_ACCESS) = handle 0x88']);
  expect(run('processes', 'OpenProcess', [num(0x38), num(0), num(7)], NULL)).toEqual(['OpenProcess(pid 7, PROCESS_VM_WRITE|PROCESS_VM_READ|PROCESS_VM_OPERATION) = failed']);
  expect(run('processes', 'VirtualAllocEx', [num(0x88), NULL, num(4096), num(0x3000), num(0x40)], num(0x7f0000))).toEqual(['VirtualAllocEx(process 0x88, 4096 bytes, RWX) = 0x7f0000']);
  expect(run('processes', 'WriteProcessMemory', [num(0x88), num(0x7f0000), bytes([0x4d, 0x5a, 0x90]), num(3)])).toEqual(['WriteProcessMemory(process 0x88, at 0x7f0000, 3 bytes: 4d 5a 90)']);
});

test('network: IPv4 and IPv6 socket addresses, names and HTTP requests', () => {
  const v4 = bytes([2, 0, 0x01, 0xbb, 93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0]);
  expect(run('network', 'connect', [num(0x1f4), v4, num(16)], num(0))).toEqual(['connect(socket 500, 93.184.216.34:443) = ok']);
  const v6 = bytes([23, 0, 0x00, 0x50, 0, 0, 0, 0, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
  expect(run('network', 'WSAConnect', [num(8), v6, num(28)])).toEqual(['WSAConnect(socket 8, [2001:db8:0:0:0:0:0:1]:80)']);
  expect(run('network', 'GetAddrInfoW', [wide('example.com'), NULL])).toEqual(['GetAddrInfoW("example.com", service NULL)']);
  expect(run('network', 'getaddrinfo', [ansi('example.org'), ansi('443')])).toEqual(['getaddrinfo("example.org", service "443")']);
  expect(run('network', 'WinHttpConnect', [num(1), wide('api.example.com'), num(443)])).toEqual(['WinHttpConnect("api.example.com", port 443)']);
  expect(run('network', 'WinHttpOpenRequest', [num(1), wide('POST'), wide('/v1/login'), NULL, NULL, NULL, num(0x800000)])).toEqual(['WinHttpOpenRequest(POST "/v1/login", https)']);
  expect(run('network', 'HttpOpenRequestW', [num(1), NULL, wide('/index.html')])).toEqual(['HttpOpenRequestW(GET "/index.html")']);
});

test('ioctls: the control code is taken apart and the input buffer starts the line', () => {
  // CTL_CODE(FILE_DEVICE_UNKNOWN 0x22, function 0x801, METHOD_NEITHER 3, FILE_ANY_ACCESS 0) = 0x222007
  const input = bytes([0xde, 0xad, 0xbe, 0xef]);
  expect(run('ioctls', 'NtDeviceIoControlFile', [num(0x2a0), NULL, NULL, NULL, num(0x1000), num(0x222007), input, num(4), NULL, num(64)], num(0)))
    .toEqual(['NtDeviceIoControlFile(handle 0x2a0, code 0x222007 [device 0x22, function 0x801, NEITHER, ANY], in 4 bytes: de ad be ef, out 64 bytes) = 0x0']);
  // FSCTL_GET_REPARSE_POINT = CTL_CODE(FILE_DEVICE_FILE_SYSTEM 9, 42, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x900a8
  expect(run('ioctls', 'NtFsControlFile', [num(0x2a0), NULL, NULL, NULL, num(0x1000), num(0x900a8), NULL, num(0), NULL, num(16384)], num(0xc0000275))[0])
    .toBe('NtFsControlFile(handle 0x2a0, code 0x900a8 [device 0x9, function 0x2a, BUFFERED, ANY], in 0 bytes, out 16384 bytes) = 0xc0000275');
});

test('pipes: name, direction, instance limit and whether security was given', () => {
  expect(run('pipes', 'CreateNamedPipeW', [wide('\\\\.\\pipe\\demo'), num(3), num(0), num(255), num(0), num(0), num(0), NULL], num(0x300)))
    .toEqual(['CreateNamedPipeW("\\\\.\\pipe\\demo", duplex, instances unlimited, default security) = handle 0x300']);
  expect(run('pipes', 'CreateNamedPipeW', [wide('p'), num(1), num(0), num(1), num(0), num(0), num(0), num(0x5000)], num(0xffffffffffffffffn))[0])
    .toBe('CreateNamedPipeW("p", inbound, instances 1, custom security) = INVALID_HANDLE_VALUE');
});

// RPC_CLIENT_INTERFACE / RPC_SERVER_INTERFACE: u32 Length, then GUID + version.
const SCM = [0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03]; // 367abb81-9844-35f1-ad32-98f038001003
const iface = () => bytes([...u32(0x60), ...SCM, 2, 0, 0, 0]);

test('rpc client: the interface id is read through the stub descriptor, and the procedure number is shown', () => {
  const stubDesc = bytes(u64(iface().v));            // MIDL_STUB_DESC starts with RpcInterfaceInformation
  const proxyInfo = bytes(u64(stubDesc.v));          // MIDL_STUBLESS_PROXY_INFO starts with pStubDesc
  expect(run('rpc', 'NdrClientCall3', [proxyInfo, num(15)])).toEqual(['RPC call out: interface 367abb81-9844-35f1-ad32-98f038001003 v2.0, procedure 15']);
  // NdrClientCall2: the procedure number is in the format string, after 2 bytes, or after 6 when the header carries RPC flags.
  expect(run('rpc', 'NdrClientCall2', [stubDesc, bytes([0x00, 0x48, 0, 0, 0, 0, 0x1b, 0x00])])).toEqual(['RPC call out: interface 367abb81-9844-35f1-ad32-98f038001003 v2.0, procedure 27']);
  expect(run('rpc', 'NdrClientCall2', [stubDesc, bytes([0x32, 0x40, 0x07, 0x00])])).toEqual(['RPC call out: interface 367abb81-9844-35f1-ad32-98f038001003 v2.0, procedure 7']);
  expect(run('rpc', 'NdrClientCall3', [num(0xbad), num(1)])).toEqual(['RPC call out: interface unknown interface, procedure 1']);
});

test('rpc server: procedure and interface come from the RPC_MESSAGE, on 64-bit and 32-bit', () => {
  const info = iface();
  // x64: Handle 0, DataRepresentation 8, Buffer 0x10, BufferLength 0x18, ProcNum 0x1c, TransferSyntax 0x20, RpcInterfaceInformation 0x28
  const msg64 = bytes([...u64(1n), ...u32(0x10), ...u32(0), ...u64(0x5000n), ...u32(64), ...u32(9), ...u64(0n), ...u64(info.v)]);
  expect(run('rpc', 'NdrServerCall2', [msg64])).toEqual(['RPC call in: interface 367abb81-9844-35f1-ad32-98f038001003 v2.0, procedure 9']);
  // x86: Handle 0, DataRepresentation 4, Buffer 8, BufferLength 0xc, ProcNum 0x10, TransferSyntax 0x14, RpcInterfaceInformation 0x18
  const msg32 = bytes([...u32(1), ...u32(0x10), ...u32(0x5000), ...u32(64), ...u32(3), ...u32(0), ...u32(Number(info.v)), ...u32(0)]);
  expect(run('rpc', 'NdrServerCallAll', [msg32], num(0), 4)).toEqual(['RPC call in: interface 367abb81-9844-35f1-ad32-98f038001003 v2.0, procedure 3']);
});
