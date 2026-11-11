// Unit test for the pure child-window options builder (node:test). The pure
// builder must be requirable headless — openWindow acquires @electron/remote
// lazily so this file loads under plain `node --test`.
const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { buildWindowOptions, pagePath } = require('./windows.js');

test('pagePath resolves child-window HTML under pages/, not the src/ module dir', () => {
  const p = pagePath('device.html');
  // The module lives in src/, but the HTML lives in pages/ — the path must
  // climb out of src/ into pages/ (Review Focus #1 / the __dirname gotcha).
  assert.equal(path.basename(p), 'device.html');
  assert.equal(path.basename(path.dirname(p)), 'pages');
  assert.ok(path.isAbsolute(p), 'pagePath must be absolute');
  assert.ok(!/[\\/]src[\\/]device\.html$/.test(p), 'must not resolve to src/device.html');
});

test('buildWindowOptions includes additionalArguments only when extraArgs given', () => {
  const withArgs = buildWindowOptions({ width: 420, height: 615, extraArgs: ['local'] });
  assert.equal(withArgs.width, 420);
  // Secured child windows: no Node, isolated world.
  assert.equal(withArgs.webPreferences.nodeIntegration, false);
  assert.equal(withArgs.webPreferences.contextIsolation, true);
  assert.equal('enableRemoteModule' in withArgs.webPreferences, false);
  assert.ok(Array.isArray(withArgs.webPreferences.additionalArguments));
  const noArgs = buildWindowOptions({ width: 420, height: 595 });
  assert.equal('additionalArguments' in noArgs.webPreferences, false);
});
