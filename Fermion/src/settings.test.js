// Unit tests for the settings persistence primitives (node:test).
// parseSettings and STORAGE_KEY are pure/constant — no localStorage needed,
// so this runs headless under plain `node --test`.
const { test } = require('node:test');
const assert = require('node:assert');
const { parseSettings, STORAGE_KEY } = require('./settings.js');

test('STORAGE_KEY is the existing localStorage key', () => {
  assert.equal(STORAGE_KEY, 'fermion_output_settings');
});

test('parseSettings round-trips a settings object', () => {
  assert.deepEqual(
    parseSettings('{"isVertical":false,"monacoTheme":"Cobalt","monacoWrap":true}'),
    { isVertical: false, monacoTheme: 'Cobalt', monacoWrap: true }
  );
});

test('parseSettings returns null for null/empty/invalid input without throwing', () => {
  assert.equal(parseSettings(null), null);
  assert.equal(parseSettings(''), null);
  assert.equal(parseSettings('{not json'), null);
});
