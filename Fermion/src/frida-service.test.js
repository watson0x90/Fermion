// Unit tests for the pure helpers of the Frida service (node:test). The frida
// require is lazy inside the class, so this file loads headless.
const { test } = require('node:test');
const assert = require('node:assert');
const { routeMessage, parseDeviceSpec } = require('./frida-service.js');

test('routeMessage sends SEND to trace only in trace mode', () => {
  assert.equal(routeMessage('SEND', true), 'trace');
  assert.equal(routeMessage('SEND', false), 'terminal');
  assert.equal(routeMessage('LOG', true), 'terminal');
  assert.equal(routeMessage('STATUS', false), 'terminal');
});

test('parseDeviceSpec splits socket@ specs from plain ids', () => {
  assert.deepEqual(parseDeviceSpec('socket@127.0.0.1:27042'), { kind: 'socket', value: '127.0.0.1:27042' });
  assert.deepEqual(parseDeviceSpec('local'), { kind: 'id', value: 'local' });
});

// Frida 17 reports ppid as a BigInt, which JSON.stringify cannot serialize.
// The old conversion threw and silently returned {} — dropping ppid, user and
// path for every process, so the process tree had no parents.
test('enumerateProcesses keeps ppid/user/path when frida reports ppid as a BigInt', async () => {
  const { FridaService } = require('./frida-service.js');
  const svc = new FridaService();
  let askedScope;
  svc._frida = {
    getDevice: async () => ({
      enumerateProcesses: async (opts) => {
        askedScope = opts && opts.scope;
        return [
          { pid: 2000, name: 'chrome.exe', parameters: { ppid: 1000n, user: 'me', path: 'C:\chrome.exe', started: '2026-01-01T00:00:00Z', icons: [{ huge: true }] } },
          { pid: 7, name: 'bare', parameters: {} },
        ];
      },
    }),
  };
  const out = await svc.enumerateProcesses();
  assert.equal(out[0].parameters.ppid, 1000);
  assert.equal(typeof out[0].parameters.ppid, 'number');
  assert.equal(out[0].parameters.user, 'me');
  assert.equal(out[0].parameters.path, 'C:\chrome.exe');
  assert.equal('icons' in out[0].parameters, false);
  assert.deepEqual(out[1], { pid: 7, name: 'bare', parameters: {} });
  // The result must survive IPC (structured clone) and JSON.
  assert.doesNotThrow(() => JSON.stringify(out));
  assert.doesNotThrow(() => structuredClone(out));
  // Icons are never used, so they are not requested from the device at all.
  assert.equal(askedScope, 'metadata');
});

test('toPlain: BigInt beyond the safe integer range becomes a string rather than a wrong number', () => {
  const { toPlain } = require('./frida-service.js');
  assert.deepEqual(toPlain({ a: 5n, b: 2n ** 60n, c: 'x' }), { a: 5, b: String(2n ** 60n), c: 'x' });
});
