import { asHitBatch, hookFromTarget, sameTarget, hitTime, hitLine, newHookId, DEFAULT_HANDLER, Hit } from './model';

const HIT = { seq: 3, id: 'h1', t: 1250, tid: 42, depth: 1, phase: 'enter', text: 'open(/etc/passwd)', bt: ['0x7ff100', '0x400100'] };

test('asHitBatch reads a batch from the hooks agent', () => {
  const b = asHitBatch({ fermionHooks: 'hits', hits: [HIT, { ...HIT, seq: 4, phase: 'leave', text: '=> 3', bt: undefined }], dropped: 2, counts: { h1: 9 } })!;
  expect(b.dropped).toBe(2);
  expect(b.counts).toEqual({ h1: 9 });
  expect(b.hits).toEqual([
    { seq: 3, id: 'h1', t: 1250, tid: 42, depth: 1, phase: 'enter', text: 'open(/etc/passwd)', error: false, bt: ['0x7ff100', '0x400100'] },
    { seq: 4, id: 'h1', t: 1250, tid: 42, depth: 1, phase: 'leave', text: '=> 3', error: false, bt: null },
  ]);
});

test('asHitBatch ignores anything that is not a hits batch', () => {
  for (const p of [null, 'x', 5, {}, { fermionHooks: 'other' }, { fermionTrace: 'dot' }]) expect(asHitBatch(p)).toBeNull();
});

// The batch comes from the instrumented process.
test('asHitBatch drops malformed hits and caps what it keeps', () => {
  const b = asHitBatch({
    fermionHooks: 'hits',
    hits: [
      null, 'x', { id: 5, text: 'no' }, { id: 'h1' },
      { id: 'h1', text: 'y'.repeat(9000), depth: 9999, tid: 'nope', t: NaN, phase: 'weird', error: 'yes', bt: ['0x10', '<img src=x>', 7, '0x' + 'f'.repeat(40)] },
      { id: 'h1', text: 'frames', bt: Array.from({ length: 100 }, (_, i) => '0x' + (i + 1).toString(16)) },
    ],
    dropped: -5,
    counts: { h1: 3.9, bad: 'x', neg: -1 },
  })!;
  expect(b.hits.length).toBe(2);
  expect(b.hits[0].text.length).toBe(4001);
  expect(b.hits[0]).toMatchObject({ depth: 64, tid: 0, t: 0, phase: 'enter', error: false, bt: ['0x10'] });
  expect(b.hits[1].bt!.length).toBe(32);
  expect(b.dropped).toBe(0);
  expect(b.counts).toEqual({ h1: 3 });
  const many = asHitBatch({ fermionHooks: 'hits', hits: Array.from({ length: 900 }, () => HIT) })!;
  expect(many.hits.length).toBe(500);
});

test('a new hook starts enabled, with the default handler, waiting to be installed', () => {
  const h = hookFromTarget({ name: 'kernel32.dll!CreateFileW', module: 'kernel32.dll', offset: 16, address: '0x7ff010' }, 'hk-1');
  expect(h).toEqual({
    id: 'hk-1', name: 'kernel32.dll!CreateFileW', module: 'kernel32.dll', offset: 16, address: '0x7ff010',
    code: DEFAULT_HANDLER, enabled: true, backtrace: true, status: 'waiting', error: '', calls: 0,
  });
  expect(newHookId()).not.toBe(newHookId());
  expect(newHookId()).toMatch(/^[A-Za-z0-9_-]{1,64}$/);
});

test('the default handler is a valid handler expression', () => {
  const lines: string[] = [];
  const handler = (0, eval)('(' + DEFAULT_HANDLER + '\n)');
  handler.onEnter((s: string) => lines.push(s), ['0x1', '0x2', '0x3', '0x4']);
  handler.onLeave((s: string) => lines.push(s), '0x0');
  expect(lines).toEqual(['(0x1, 0x2, 0x3, 0x4)', '=> 0x0']);
});

test('sameTarget: module + offset inside a module (the address moves between runs), the address outside one', () => {
  const a = { name: 'k!f', module: 'kernel32.dll', offset: 16, address: '0x7ff010' };
  expect(sameTarget(a, { ...a, module: 'KERNEL32.DLL', address: '0x1234010' })).toBe(true);
  expect(sameTarget(a, { ...a, offset: 32 })).toBe(false);
  const raw = { name: '0x9000', module: '', offset: null, address: '0x9000' };
  expect(sameTarget(raw, { ...raw, address: '0X9000' })).toBe(true);
  expect(sameTarget(raw, a)).toBe(false);
});

test('hitTime and hitLine', () => {
  expect(hitTime(1250)).toBe('+1.250s');
  expect(hitTime(0)).toBe('+0.000s');
  const hit = asHitBatch({ fermionHooks: 'hits', hits: [HIT] })!.hits[0] as Hit;
  expect(hitLine('libc!open', hit)).toBe('[hook] libc!open -> open(/etc/passwd)');
  expect(hitLine('libc!open', { ...hit, phase: 'leave', text: '=> 3' })).toBe('[hook] libc!open <- => 3');
});
