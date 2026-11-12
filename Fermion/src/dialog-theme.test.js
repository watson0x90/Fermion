// Unit tests for the dialog theming helper (About / Docs windows).
const { test } = require('node:test');
const assert = require('node:assert');
const { applyTokens, readTokens } = require('./dialog-theme.js');

function fakeRoot() {
  const set = {};
  return { set, style: { setProperty: (k, v) => { set[k] = v; } } };
}

test('applyTokens sets the theme custom properties on the root element', () => {
  const root = fakeRoot();
  const n = applyTokens(root, { '--bg': '#1e1f1c', '--fg': '#f8f8f2', '--logo-filter': 'invert(1) brightness(1.35)', 'color-scheme': 'dark' });
  assert.equal(n, 4);
  assert.deepEqual(root.set, { '--bg': '#1e1f1c', '--fg': '#f8f8f2', '--logo-filter': 'invert(1) brightness(1.35)', 'color-scheme': 'dark' });
});

// The tokens come from localStorage, which any page of the app can write.
test('applyTokens ignores anything that is not a known kind of token or a plain colour/filter value', () => {
  const root = fakeRoot();
  const n = applyTokens(root, {
    '--bg': '#fff',
    'background': 'red',                       // not a custom property
    '--evil': 'url(https://example.com/x)',    // no urls
    '--x': 'expression(alert(1))',
    '--y': '#fff; background: url(x)',         // no declarations smuggled in a value
    '--z': 42,
    'color-scheme': 'dark; --bg: red',
  });
  assert.equal(n, 1);
  assert.deepEqual(root.set, { '--bg': '#fff' });
  assert.equal(applyTokens(root, null), 0);
  assert.equal(applyTokens(root, 'nope'), 0);
});

test('readTokens parses the stored JSON and survives missing or corrupt storage', () => {
  assert.deepEqual(readTokens({ getItem: () => '{"--bg":"#000"}' }), { '--bg': '#000' });
  assert.equal(readTokens({ getItem: () => 'not json' }), null);
  assert.equal(readTokens({ getItem: () => null }), null);
  assert.equal(readTokens({ getItem: () => { throw new Error('denied'); } }), null);
  assert.equal(readTokens({ getItem: () => '[1,2]' }), null);
});
