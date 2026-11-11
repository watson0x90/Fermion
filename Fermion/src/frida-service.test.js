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
