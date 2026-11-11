// Unit test for the pure child-window options builder (node:test). The pure
// builder must be requirable headless — openWindow acquires @electron/remote
// lazily so this file loads under plain `node --test`.
const { test } = require('node:test');
const assert = require('node:assert');
const { buildWindowOptions } = require('./windows.js');

test('buildWindowOptions includes additionalArguments only when extraArgs given', () => {
  const withArgs = buildWindowOptions({ width: 420, height: 615, extraArgs: ['local'] });
  assert.equal(withArgs.width, 420);
  assert.equal(withArgs.webPreferences.nodeIntegration, true);
  assert.equal(withArgs.webPreferences.enableRemoteModule, true);
  assert.ok(Array.isArray(withArgs.webPreferences.additionalArguments));
  const noArgs = buildWindowOptions({ width: 420, height: 595 });
  assert.equal('additionalArguments' in noArgs.webPreferences, false);
});
