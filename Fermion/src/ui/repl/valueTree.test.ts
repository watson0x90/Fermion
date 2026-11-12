import { asValueNode, preview, leafText, Branch } from './valueTree';

const TREE = {
  t: 'obj', label: 'Object', n: 3, kids: [
    { k: 'name', v: { t: 'str', v: 'kernel32.dll' } },
    { k: 'base', v: { t: 'ptr', v: '0x7ff0' } },
    { k: 'list', v: { t: 'arr', n: 2, kids: [{ k: '0', v: { t: 'num', v: '1' } }, { k: '1', v: { t: 'num', v: '2' } }] } },
  ],
};

test('asValueNode rebuilds a tree from the agent', () => {
  expect(asValueNode(TREE)).toEqual({
    t: 'obj', label: 'Object', n: 3, more: 0, kids: [
      { k: 'name', v: { t: 'str', v: 'kernel32.dll' } },
      { k: 'base', v: { t: 'ptr', v: '0x7ff0' } },
      { k: 'list', v: { t: 'arr', label: 'Array', n: 2, more: 0, kids: [{ k: '0', v: { t: 'num', v: '1' } }, { k: '1', v: { t: 'num', v: '2' } }] } },
    ],
  });
  expect(asValueNode({ t: 'ptr', v: '0x1000' })).toEqual({ t: 'ptr', v: '0x1000' });
});

// The tree comes from the instrumented process.
test('asValueNode keeps only known shapes: unknown kinds, non-string text and stray fields are dropped', () => {
  for (const bad of [null, 'x', 5, [], {}, { t: 'script', v: 'x' }, { t: 'str', v: 5 }, { t: 'str' }]) expect(asValueNode(bad)).toBeNull();
  const n = asValueNode({
    t: 'obj', label: 7, n: 'many', more: -3, extra: '<img>', kids: [
      'junk', null, { k: 5, v: { t: 'num', v: '1' } }, { k: 'bad', v: { t: 'evil', v: 'x' } },
      { k: 'good', v: { t: 'num', v: '1', onclick: 'x' } },
    ],
  }) as Branch;
  expect(n).toEqual({ t: 'obj', label: 'Object', n: 1, more: 0, kids: [{ k: 'good', v: { t: 'num', v: '1' } }] });
});

test('asValueNode: a "pointer" that is not an address is not offered as one', () => {
  expect(asValueNode({ t: 'ptr', v: 'javascript:alert(1)' })).toEqual({ t: 'other', v: 'javascript:alert(1)' });
  expect(asValueNode({ t: 'ptr', v: '0x' + 'f'.repeat(30) })).toEqual({ t: 'other', v: '0x' + 'f'.repeat(30) });
});

test('asValueNode caps depth, size and text length', () => {
  let deep: unknown = { t: 'num', v: '1' };
  for (let i = 0; i < 40; i++) deep = { t: 'obj', label: 'Object', n: 1, kids: [{ k: 'next', v: deep }] };
  let node = asValueNode(deep)!;
  let depth = 0;
  while (node.t === 'obj') { node = node.kids[0].v; depth++; }
  expect(node).toEqual({ t: 'cut', v: '…' });
  expect(depth).toBe(10);

  const wide = { t: 'arr', n: 20000, kids: Array.from({ length: 20000 }, (_, i) => ({ k: String(i), v: { t: 'num', v: '1' } })) };
  expect((asValueNode(wide) as Branch).kids.length).toBeLessThan(8000);

  const long = asValueNode({ t: 'str', v: 'y'.repeat(9000) })!;
  expect((long as { v: string }).v.length).toBe(4001);
});

test('leafText quotes strings and nothing else', () => {
  expect(leafText({ t: 'str', v: 'a "b"' })).toBe('"a \\"b\\""');
  expect(leafText({ t: 'num', v: '42' })).toBe('42');
  expect(leafText({ t: 'ptr', v: '0x10' })).toBe('0x10');
});

test('preview: one line for a closed container, cut where it gets long', () => {
  const node = asValueNode(TREE)!;
  expect(preview(node)).toBe('Object {name: "kernel32.dll", base: 0x7ff0, list: Array(2)}');
  expect(preview((node as Branch).kids[2].v)).toBe('Array(2) [1, 2]');
  expect(preview(node, 30)).toBe('Object {name: "kernel32.dll", …}');
  expect(preview(asValueNode({ t: 'obj', label: 'Mod', n: 0, kids: [] })!)).toBe('Mod {}');
  expect(preview(asValueNode({ t: 'arr', n: 500, more: 499, kids: [{ k: '0', v: { t: 'num', v: '1' } }] })!)).toBe('Array(500) [1, …]');
  expect(preview(asValueNode({ t: 'obj', label: 'Object', n: 1, kids: [{ k: 'inner', v: { t: 'obj', label: 'Mod', n: 2, kids: [] } }] })!)).toBe('Object {inner: Mod {…}}');
});
