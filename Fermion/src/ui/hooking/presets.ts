// Ready-made sets of hooks for Windows targets: the functions people hook
// first when they want to see what a program does to files, the registry,
// other processes, the network, drivers, pipes and RPC. Each hook comes with
// a handler that already decodes the arguments, so nothing has to be written
// to get a useful log; the handler is ordinary hook code and can be edited
// afterwards like any other.
//
// Handlers are written with String.raw so backslashes are what they look
// like. They must not contain a backtick or "${".

export interface PresetHook {
  fn: string;          // exported function name, exactly
  modules: string[];   // where to look, first hit wins (kernelbase before its forwarders)
  handler: string;
  callers?: boolean;   // record callers (off for the chattiest functions)
}
export interface Preset { id: string; label: string; about: string; hooks: PresetHook[]; }

// Shared by every handler: read strings without throwing, print them quoted,
// and print numbers as hex.
const LIB = String.raw`
  const W = (p) => { try { return p.isNull() ? null : p.readUtf16String(); } catch (e) { return '<unreadable ' + p + '>'; } };
  // Quoted as written, so Windows paths keep their single backslashes; a control character is shown as its code.
  const q = (s) => (s === null ? 'NULL' : '"' + String(s).replace(/[\x00-\x1f]/g, (c) => '<' + c.charCodeAt(0) + '>') + '"');
  const x = (n) => '0x' + (n >>> 0).toString(16);
  const flags = (v, names) => { const out = []; let rest = v >>> 0; for (const k in names) { const bit = names[k] >>> 0; if (bit && ((rest & bit) >>> 0) === bit) { out.push(k); rest = (rest & ~bit) >>> 0; } } if (rest || !out.length) out.push(x(rest)); return out.join('|'); };`;

// A handler is one expression: a function that sets up the helpers and
// returns { onEnter, onLeave }.
const handler = (body: string, extra = '') => `(function () {${LIB}${extra}\n  return {\n${body}\n  };\n})()`;

const ACCESS = String.raw`
  const ACCESS = { GENERIC_READ: 0x80000000, GENERIC_WRITE: 0x40000000, GENERIC_EXECUTE: 0x20000000, GENERIC_ALL: 0x10000000, DELETE: 0x10000 };`;

const HKEY = String.raw`
  const ROOTS = { 0x80000000: 'HKCR', 0x80000001: 'HKCU', 0x80000002: 'HKLM', 0x80000003: 'HKU', 0x80000005: 'HKCC' };
  // A predefined root is a small constant, sign-extended on 64-bit Windows; anything else is an open key's handle.
  const key = (h) => { const n = h.toUInt32(); const s = h.toString(); const low = n.toString(16); return (ROOTS[n] && (s === '0x' + low || s === '0xffffffff' + low)) ? ROOTS[n] : 'key ' + s; };`;

const FILES: Preset = {
  id: 'files',
  label: 'Files',
  about: 'Files and directories being opened, created, deleted and renamed.',
  hooks: [
    { fn: 'CreateFileW', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) {
      const how = { 1: 'CREATE_NEW', 2: 'CREATE_ALWAYS', 3: 'OPEN_EXISTING', 4: 'OPEN_ALWAYS', 5: 'TRUNCATE_EXISTING' };
      const d = args[4].toUInt32();
      this.text = 'CreateFileW(' + q(W(args[0])) + ', ' + flags(args[1].toUInt32(), ACCESS) + ', ' + (how[d] || d) + ')';
    },
    onLeave(log, retval) {
      log(this.text + ' = ' + (retval.toInt32() === -1 ? 'INVALID_HANDLE_VALUE' : 'handle ' + retval));
    }`, ACCESS) },
    { fn: 'DeleteFileW', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) { this.text = 'DeleteFileW(' + q(W(args[0])) + ')'; },
    onLeave(log, retval) { log(this.text + ' = ' + (retval.toInt32() ? 'ok' : 'failed')); }`) },
    { fn: 'MoveFileExW', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) { this.text = 'MoveFileExW(' + q(W(args[0])) + ' -> ' + q(W(args[1])) + ', flags ' + x(args[2].toUInt32()) + ')'; },
    onLeave(log, retval) { log(this.text + ' = ' + (retval.toInt32() ? 'ok' : 'failed')); }`) },
    { fn: 'CreateDirectoryW', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) { this.text = 'CreateDirectoryW(' + q(W(args[0])) + ')'; },
    onLeave(log, retval) { log(this.text + ' = ' + (retval.toInt32() ? 'ok' : 'failed')); }`) },
  ],
};

const REGISTRY: Preset = {
  id: 'registry',
  label: 'Registry',
  about: 'Registry keys opened and created, and values read, written and deleted.',
  hooks: [
    { fn: 'RegOpenKeyExW', modules: ['kernelbase.dll', 'advapi32.dll'], handler: handler(String.raw`    onEnter(log, args) { this.text = 'RegOpenKeyExW(' + key(args[0]) + ', ' + q(W(args[1])) + ')'; },
    onLeave(log, retval) { log(this.text + ' = ' + (retval.toInt32() === 0 ? 'ok' : 'error ' + retval.toInt32())); }`, HKEY) },
    { fn: 'RegCreateKeyExW', modules: ['kernelbase.dll', 'advapi32.dll'], handler: handler(String.raw`    onEnter(log, args) { this.text = 'RegCreateKeyExW(' + key(args[0]) + ', ' + q(W(args[1])) + ')'; },
    onLeave(log, retval) { log(this.text + ' = ' + (retval.toInt32() === 0 ? 'ok' : 'error ' + retval.toInt32())); }`, HKEY) },
    { fn: 'RegQueryValueExW', modules: ['kernelbase.dll', 'advapi32.dll'], handler: handler(String.raw`    onEnter(log, args) { this.text = 'RegQueryValueExW(' + key(args[0]) + ', value ' + q(W(args[1])) + ')'; },
    onLeave(log, retval) { log(this.text + ' = ' + (retval.toInt32() === 0 ? 'ok' : 'error ' + retval.toInt32())); }`, HKEY), callers: false },
    { fn: 'RegSetValueExW', modules: ['kernelbase.dll', 'advapi32.dll'], handler: handler(String.raw`    onEnter(log, args) {
      const types = { 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD', 7: 'REG_MULTI_SZ', 11: 'REG_QWORD' };
      const type = args[3].toUInt32();
      const size = args[5].toUInt32();
      let data = size + ' bytes';
      try {
        if (!args[4].isNull()) {
          if (type === 1 || type === 2) data = q(args[4].readUtf16String(Math.min(size, 1024) / 2).replace(/\0+$/, ''));
          else if (type === 4 && size >= 4) data = x(args[4].readU32());
        }
      } catch (e) { /* keep the size */ }
      log('RegSetValueExW(' + key(args[0]) + ', value ' + q(W(args[1])) + ', ' + (types[type] || 'type ' + type) + ', ' + data + ')');
    }`, HKEY) },
    { fn: 'RegDeleteValueW', modules: ['kernelbase.dll', 'advapi32.dll'], handler: handler(String.raw`    onEnter(log, args) { log('RegDeleteValueW(' + key(args[0]) + ', value ' + q(W(args[1])) + ')'); }`, HKEY) },
    { fn: 'RegDeleteKeyExW', modules: ['kernelbase.dll', 'advapi32.dll'], handler: handler(String.raw`    onEnter(log, args) { log('RegDeleteKeyExW(' + key(args[0]) + ', ' + q(W(args[1])) + ')'); }`, HKEY) },
  ],
};

const PROCESSES: Preset = {
  id: 'processes',
  label: 'Processes and injection',
  about: 'Programs started, other processes opened, memory allocated and written in them, remote threads, and libraries loaded.',
  hooks: [
    { fn: 'CreateProcessW', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) {
      const f = args[5].toUInt32();
      log('CreateProcessW(app ' + q(W(args[0])) + ', command line ' + q(W(args[1])) + ', ' + flags(f, { CREATE_SUSPENDED: 0x4, DEBUG_PROCESS: 0x1, CREATE_NEW_CONSOLE: 0x10, CREATE_NO_WINDOW: 0x8000000, EXTENDED_STARTUPINFO_PRESENT: 0x80000 }) + ')');
    }`) },
    { fn: 'OpenProcess', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) {
      const rights = { PROCESS_ALL_ACCESS: 0x1fffff, PROCESS_VM_WRITE: 0x20, PROCESS_VM_READ: 0x10, PROCESS_VM_OPERATION: 0x8, PROCESS_CREATE_THREAD: 0x2, PROCESS_DUP_HANDLE: 0x40, PROCESS_QUERY_INFORMATION: 0x400, PROCESS_QUERY_LIMITED_INFORMATION: 0x1000, PROCESS_TERMINATE: 0x1 };
      this.text = 'OpenProcess(pid ' + args[2].toUInt32() + ', ' + flags(args[0].toUInt32(), rights) + ')';
    },
    onLeave(log, retval) { log(this.text + ' = ' + (retval.isNull() ? 'failed' : 'handle ' + retval)); }`) },
    { fn: 'VirtualAllocEx', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) {
      const prot = { 0x40: 'RWX', 0x20: 'RX', 0x04: 'RW', 0x02: 'R', 0x10: 'X', 0x80: 'WCX', 0x01: 'NOACCESS' };
      const p = args[4].toUInt32();
      this.text = 'VirtualAllocEx(process ' + args[0] + ', ' + args[2].toUInt32() + ' bytes, ' + (prot[p & 0xff] || x(p)) + ')';
    },
    onLeave(log, retval) { log(this.text + ' = ' + retval); }`) },
    { fn: 'WriteProcessMemory', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) {
      const n = args[3].toUInt32();
      let head = '';
      try { head = Array.from(new Uint8Array(args[2].readByteArray(Math.min(n, 16))), (b) => (b < 16 ? '0' : '') + b.toString(16)).join(' '); } catch (e) { /* unreadable */ }
      log('WriteProcessMemory(process ' + args[0] + ', at ' + args[1] + ', ' + n + ' bytes' + (head ? ': ' + head + (n > 16 ? ' ...' : '') : '') + ')');
    }`) },
    { fn: 'CreateRemoteThreadEx', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) { log('CreateRemoteThreadEx(process ' + args[0] + ', start ' + args[3] + ', parameter ' + args[4] + ', flags ' + x(args[5].toUInt32()) + ')'); }`) },
    { fn: 'LoadLibraryExW', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) { this.text = 'LoadLibraryExW(' + q(W(args[0])) + ', flags ' + x(args[2].toUInt32()) + ')'; },
    onLeave(log, retval) { log(this.text + ' = ' + (retval.isNull() ? 'failed' : retval)); }`) },
  ],
};

const SOCKADDR = String.raw`
  const addr = (p, len) => {
    try {
      if (p.isNull()) return 'NULL';
      const family = p.readU16();
      const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
      if (family === 2) return [4, 5, 6, 7].map((i) => p.add(i).readU8()).join('.') + ':' + port;
      if (family === 23) { const g = []; for (let i = 0; i < 16; i += 2) g.push(((p.add(8 + i).readU8() << 8) | p.add(9 + i).readU8()).toString(16)); return '[' + g.join(':') + ']:' + port; }
      return 'address family ' + family;
    } catch (e) { return '<unreadable ' + p + '>'; }
  };`;

const NETWORK: Preset = {
  id: 'network',
  label: 'Network',
  about: 'Name lookups, connections, and HTTP requests made through WinHTTP and WinINet. A module that is not loaded yet is skipped: add the preset again once the program has used the network.',
  hooks: [
    { fn: 'GetAddrInfoW', modules: ['ws2_32.dll'], handler: handler(String.raw`    onEnter(log, args) { log('GetAddrInfoW(' + q(W(args[0])) + ', service ' + q(W(args[1])) + ')'); }`) },
    { fn: 'getaddrinfo', modules: ['ws2_32.dll'], handler: handler(String.raw`    onEnter(log, args) {
      const A = (p) => { try { return p.isNull() ? null : p.readAnsiString(); } catch (e) { return '<unreadable>'; } };
      log('getaddrinfo(' + q(A(args[0])) + ', service ' + q(A(args[1])) + ')');
    }`) },
    { fn: 'connect', modules: ['ws2_32.dll'], handler: handler(String.raw`    onEnter(log, args) { this.text = 'connect(socket ' + args[0].toUInt32() + ', ' + addr(args[1], args[2].toUInt32()) + ')'; },
    onLeave(log, retval) { log(this.text + ' = ' + (retval.toInt32() === 0 ? 'ok' : 'pending or failed')); }`, SOCKADDR) },
    { fn: 'WSAConnect', modules: ['ws2_32.dll'], handler: handler(String.raw`    onEnter(log, args) { log('WSAConnect(socket ' + args[0].toUInt32() + ', ' + addr(args[1], args[2].toUInt32()) + ')'); }`, SOCKADDR) },
    { fn: 'bind', modules: ['ws2_32.dll'], handler: handler(String.raw`    onEnter(log, args) { log('bind(socket ' + args[0].toUInt32() + ', ' + addr(args[1], args[2].toUInt32()) + ')'); }`, SOCKADDR) },
    { fn: 'WinHttpConnect', modules: ['winhttp.dll'], handler: handler(String.raw`    onEnter(log, args) { log('WinHttpConnect(' + q(W(args[1])) + ', port ' + (args[2].toUInt32() & 0xffff) + ')'); }`) },
    { fn: 'WinHttpOpenRequest', modules: ['winhttp.dll'], handler: handler(String.raw`    onEnter(log, args) { log('WinHttpOpenRequest(' + (W(args[1]) || 'GET') + ' ' + q(W(args[2])) + (args[6].toUInt32() & 0x800000 ? ', https' : '') + ')'); }`) },
    { fn: 'InternetConnectW', modules: ['wininet.dll'], handler: handler(String.raw`    onEnter(log, args) { log('InternetConnectW(' + q(W(args[1])) + ', port ' + (args[2].toUInt32() & 0xffff) + ')'); }`) },
    { fn: 'HttpOpenRequestW', modules: ['wininet.dll'], handler: handler(String.raw`    onEnter(log, args) { log('HttpOpenRequestW(' + (W(args[1]) || 'GET') + ' ' + q(W(args[2])) + ')'); }`) },
  ],
};

// NtDeviceIoControlFile and NtFsControlFile take the same arguments:
// (FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode,
//  InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength).
const ioctl = (name: string) => handler(String.raw`    onEnter(log, args) {
      const code = args[5].toUInt32();
      const method = ['BUFFERED', 'IN_DIRECT', 'OUT_DIRECT', 'NEITHER'][code & 3];
      const access = ['ANY', 'READ', 'WRITE', 'READ|WRITE'][(code >>> 14) & 3];
      const inLen = args[7].toUInt32();
      let head = '';
      try { if (inLen && !args[6].isNull()) head = Array.from(new Uint8Array(args[6].readByteArray(Math.min(inLen, 32))), (b) => (b < 16 ? '0' : '') + b.toString(16)).join(' '); } catch (e) { /* unreadable */ }
      this.text = '` + name + String.raw`(handle ' + args[0] + ', code ' + x(code) + ' [device ' + x(code >>> 16) + ', function ' + x((code >>> 2) & 0xfff) + ', ' + method + ', ' + access + '], in ' + inLen + ' bytes' + (head ? ': ' + head + (inLen > 32 ? ' ...' : '') : '') + ', out ' + args[9].toUInt32() + ' bytes)';
    },
    onLeave(log, retval) { log(this.text + ' = ' + x(retval.toUInt32())); }`);

const IOCTLS: Preset = {
  id: 'ioctls',
  label: 'Driver requests (IOCTLs)',
  about: 'Every control request the program sends to a driver or file system, with the control code taken apart and the start of the input buffer.',
  hooks: [
    { fn: 'NtDeviceIoControlFile', modules: ['ntdll.dll'], handler: ioctl('NtDeviceIoControlFile') },
    { fn: 'NtFsControlFile', modules: ['ntdll.dll'], handler: ioctl('NtFsControlFile') },
  ],
};

const PIPES: Preset = {
  id: 'pipes',
  label: 'Named pipes',
  about: 'Named pipes created by the program (as a server) and opened by it (as a client).',
  hooks: [
    { fn: 'CreateNamedPipeW', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) {
      const open = args[1].toUInt32();
      const dir = ['?', 'inbound', 'outbound', 'duplex'][open & 3];
      const max = args[3].toUInt32();
      this.text = 'CreateNamedPipeW(' + q(W(args[0])) + ', ' + dir + ', instances ' + (max === 255 ? 'unlimited' : max) + (args[7].isNull() ? ', default security' : ', custom security') + ')';
    },
    onLeave(log, retval) { log(this.text + ' = ' + (retval.toInt32() === -1 ? 'INVALID_HANDLE_VALUE' : 'handle ' + retval)); }`) },
    { fn: 'ConnectNamedPipe', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) { log('ConnectNamedPipe(handle ' + args[0] + '): waiting for a client'); }`) },
    { fn: 'WaitNamedPipeW', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) { log('WaitNamedPipeW(' + q(W(args[0])) + ')'); }`) },
    { fn: 'CallNamedPipeW', modules: ['kernelbase.dll', 'kernel32.dll'], handler: handler(String.raw`    onEnter(log, args) { log('CallNamedPipeW(' + q(W(args[0])) + ', ' + args[2].toUInt32() + ' bytes in)'); }`) },
    { fn: 'ImpersonateNamedPipeClient', modules: ['kernelbase.dll', 'advapi32.dll'], handler: handler(String.raw`    onEnter(log, args) { log('ImpersonateNamedPipeClient(handle ' + args[0] + ')'); }`) },
  ],
};

// The interface an RPC call belongs to is in the stub's data: an
// RPC_CLIENT_INTERFACE / RPC_SERVER_INTERFACE starts with a length and then
// the interface id (a GUID and a version).
const RPC_LIB = String.raw`
  const guid = (p) => {
    const h = (n, at) => { let s = ''; for (let i = 0; i < n; i++) { const b = p.add(at + i).readU8(); s += (b < 16 ? '0' : '') + b.toString(16); } return s; };
    const le = (n, at) => { let s = ''; for (let i = n - 1; i >= 0; i--) { const b = p.add(at + i).readU8(); s += (b < 16 ? '0' : '') + b.toString(16); } return s; };
    return le(4, 0) + '-' + le(2, 4) + '-' + le(2, 6) + '-' + h(2, 8) + '-' + h(6, 10);
  };
  const iface = (info) => { try { return info.isNull() ? 'unknown interface' : guid(info.add(4)) + ' v' + info.add(20).readU16() + '.' + info.add(22).readU16(); } catch (e) { return 'unknown interface'; } };`;

const RPC: Preset = {
  id: 'rpc',
  label: 'RPC',
  about: 'Remote procedure calls the program makes (client) and serves (server), with the interface id and the procedure number. Look the interface id up to find which service it is.',
  hooks: [
    // NdrClientCall3(MIDL_STUBLESS_PROXY_INFO*, nProcNum, pReturnValue, ...): the proxy info starts with the stub descriptor.
    { fn: 'NdrClientCall3', modules: ['rpcrt4.dll'], handler: handler(String.raw`    onEnter(log, args) {
      let text = 'unknown interface';
      try { text = iface(args[0].readPointer().readPointer()); } catch (e) { /* keep unknown */ }
      log('RPC call out: interface ' + text + ', procedure ' + args[1].toUInt32());
    }`, RPC_LIB) },
    // NdrClientCall2(PMIDL_STUB_DESC, PFORMAT_STRING, ...): the procedure number is in the format string.
    { fn: 'NdrClientCall2', modules: ['rpcrt4.dll'], handler: handler(String.raw`    onEnter(log, args) {
      let text = 'unknown interface';
      let proc = '?';
      try { text = iface(args[0].readPointer()); } catch (e) { /* keep unknown */ }
      try { const f = args[1]; proc = String(f.add(f.add(1).readU8() & 0x08 ? 6 : 2).readU16()); } catch (e) { /* keep ? */ }
      log('RPC call out: interface ' + text + ', procedure ' + proc);
    }`, RPC_LIB) },
    // The server stubs take an RPC_MESSAGE*: ProcNum, then (after the transfer syntax) the interface.
    ...['NdrServerCall2', 'NdrServerCallAll', 'NdrServerCallNdr64'].map((fn) => ({ fn, modules: ['rpcrt4.dll'], handler: handler(String.raw`    onEnter(log, args) {
      const ps = Process.pointerSize;
      const msg = args[0];
      let text = 'unknown interface';
      let proc = '?';
      try {
        // Handle, DataRepresentation, Buffer, BufferLength, ProcNum, TransferSyntax, RpcInterfaceInformation
        const afterBuffer = ps === 8 ? 0x18 : 0x0c;
        proc = String(msg.add(afterBuffer + 4).readU32() & 0xffff);
        text = iface(msg.add(afterBuffer + 8 + ps).readPointer());
      } catch (e) { /* keep unknown */ }
      log('RPC call in: interface ' + text + ', procedure ' + proc);
    }`, RPC_LIB) })),
  ],
};

export const PRESETS: Preset[] = [FILES, REGISTRY, PROCESSES, NETWORK, IOCTLS, PIPES, RPC];
