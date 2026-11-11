// Unit tests for the pure output model (Node built-in test runner).
//   node --test Fermion/src/output-model.test.js
const test = require('node:test');
const assert = require('node:assert');
const { formatMessage, OutputBuffer, KINDS } = require('./output-model');

test('send with a string payload -> SEND, text as-is', () => {
  assert.deepStrictEqual(formatMessage({ type: 'send', payload: 'hi' }), { kind: 'SEND', text: 'hi' });
});

test('send with an object payload -> SEND, pretty JSON (fixes [object Object])', () => {
  assert.deepStrictEqual(
    formatMessage({ type: 'send', payload: { a: 1 } }),
    { kind: 'SEND', text: '{\n  "a": 1\n}' }
  );
});

test('console.log (level info) -> LOG', () => {
  assert.deepStrictEqual(formatMessage({ type: 'log', level: 'info', payload: 'x' }), { kind: 'LOG', text: 'x' });
});

test('console.warn (level warning) -> WARN', () => {
  assert.deepStrictEqual(formatMessage({ type: 'log', level: 'warning', payload: 'w' }), { kind: 'WARN', text: 'w' });
});

test('console.error (level error) -> ERR', () => {
  assert.deepStrictEqual(formatMessage({ type: 'log', level: 'error', payload: 'e' }), { kind: 'ERR', text: 'e' });
});

test('uncaught error message -> ERR with stack', () => {
  assert.deepStrictEqual(
    formatMessage({ type: 'error', stack: 'Boom\n at a' }),
    { kind: 'ERR', text: 'Boom\n at a' }
  );
});

test('unknown message type -> STATUS, verbatim JSON', () => {
  const m = { type: 'wat', foo: 1 };
  assert.deepStrictEqual(formatMessage(m), { kind: 'STATUS', text: JSON.stringify(m) });
});

test('OutputBuffer caps size and evicts oldest', () => {
  const cap = 50;
  const buf = new OutputBuffer(cap);
  for (let i = 0; i < cap + 10; i++) buf.append({ kind: 'LOG', text: 'line-' + i });
  assert.strictEqual(buf.size, cap);
  // First 10 evicted; oldest remaining is line-10.
  assert.strictEqual(buf.entries()[0].text, 'line-10');
});

test('OutputBuffer.filtered returns only the active kinds', () => {
  const buf = new OutputBuffer(100);
  buf.append({ kind: 'LOG', text: 'a' });
  buf.append({ kind: 'WARN', text: 'b' });
  buf.append({ kind: 'ERR', text: 'c' });
  const warnOnly = buf.filtered(new Set(['WARN']));
  assert.deepStrictEqual(warnOnly, [{ kind: 'WARN', text: 'b' }]);
});

test('KINDS lists the five filterable kinds', () => {
  assert.deepStrictEqual(KINDS, ['LOG', 'WARN', 'ERR', 'SEND', 'STATUS']);
});
