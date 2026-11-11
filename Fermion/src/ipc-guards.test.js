// Unit tests for the IPC boundary guards (pure).
const { test } = require('node:test');
const assert = require('node:assert');
const { isAllowedPage, isSafeExternalUrl } = require('./ipc-guards.js');

test('isAllowedPage allows known child pages and rejects traversal/unknown', () => {
  for (const p of ['device.html', 'proc.html', 'instrument.html', 'trace.html', 'svg.html', 'about.html', 'docs.html']) {
    assert.equal(isAllowedPage(p), true, p);
  }
  assert.equal(isAllowedPage('../../etc/passwd'), false);
  assert.equal(isAllowedPage('../index.html'), false);
  assert.equal(isAllowedPage('nope.html'), false);
  assert.equal(isAllowedPage(42), false);
});

test('isSafeExternalUrl allows only http/https', () => {
  assert.equal(isSafeExternalUrl('https://github.com/watson0x90/Fermion'), true);
  assert.equal(isSafeExternalUrl('http://example.com'), true);
  assert.equal(isSafeExternalUrl('file:///etc/passwd'), false);
  assert.equal(isSafeExternalUrl('javascript:alert(1)'), false);
  assert.equal(isSafeExternalUrl(''), false);
  assert.equal(isSafeExternalUrl(null), false);
});
