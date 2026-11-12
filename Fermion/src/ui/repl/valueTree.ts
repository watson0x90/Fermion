// A REPL result as a tree (see repl-agent.js). The tree comes from the target,
// so it is rebuilt here from scratch: only known shapes are kept, every text
// is a string, and depth and size are capped.

export type LeafKind = 'str' | 'num' | 'bool' | 'null' | 'undef' | 'fn' | 'ptr' | 'other' | 'cut';
export interface Leaf { t: LeafKind; v: string; }
export interface Branch { t: 'obj' | 'arr'; label: string; n: number; kids: { k: string; v: ValueNode }[]; more: number; }
export type ValueNode = Leaf | Branch;
export const isBranch = (node: ValueNode): node is Branch => node.t === 'obj' || node.t === 'arr';

const LEAVES: LeafKind[] = ['str', 'num', 'bool', 'null', 'undef', 'fn', 'ptr', 'other', 'cut'];
const MAX_DEPTH = 10;
const MAX_NODES = 8000;
const MAX_TEXT = 4000;
const POINTER = /^0x[0-9a-f]{1,16}$/i;

const clip = (s: string) => (s.length > MAX_TEXT ? s.slice(0, MAX_TEXT) + '…' : s);
const count = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.trunc(v) : 0);

export function asValueNode(raw: unknown): ValueNode | null {
  let nodes = 0;
  const walk = (value: unknown, depth: number): ValueNode | null => {
    if (!value || typeof value !== 'object' || ++nodes > MAX_NODES) return null;
    const r = value as Record<string, unknown>;
    if (r.t === 'obj' || r.t === 'arr') {
      if (depth >= MAX_DEPTH) return { t: 'cut', v: '…' };
      const kids: Branch['kids'] = [];
      if (Array.isArray(r.kids)) {
        for (const kid of r.kids) {
          if (!kid || typeof kid !== 'object') continue;
          const k = (kid as Record<string, unknown>).k;
          const v = walk((kid as Record<string, unknown>).v, depth + 1);
          if (typeof k === 'string' && v) kids.push({ k: clip(k), v });
        }
      }
      const label = r.t === 'arr' ? 'Array' : (typeof r.label === 'string' && r.label ? clip(r.label).slice(0, 80) : 'Object');
      return { t: r.t, label, n: Math.max(count(r.n), kids.length), kids, more: count(r.more) };
    }
    if (typeof r.t !== 'string' || !LEAVES.includes(r.t as LeafKind) || typeof r.v !== 'string') return null;
    // Only something that reads as an address is offered as one.
    if (r.t === 'ptr' && !POINTER.test(r.v)) return { t: 'other', v: clip(r.v) };
    return { t: r.t as LeafKind, v: clip(r.v) };
  };
  return walk(raw, 0);
}

// How a leaf is written: strings in quotes, everything else as it is.
export function leafText(leaf: Leaf): string {
  return leaf.t === 'str' ? JSON.stringify(leaf.v) : leaf.v;
}

// One line standing for a closed container: `Object {a: 1, b: "x", …}`.
export function preview(node: ValueNode, max = 64): string {
  if (!isBranch(node)) {
    const text = leafText(node);
    return text.length > max ? text.slice(0, max - 1) + '…' : text;
  }
  const open = node.t === 'arr' ? '[' : '{';
  const close = node.t === 'arr' ? ']' : '}';
  const head = node.t === 'arr' ? `Array(${node.n}) ` : `${node.label} `;
  let body = '';
  let cut = node.more > 0;
  for (const kid of node.kids) {
    const inner = kid.v.t === 'obj' ? kid.v.label + ' {…}' : kid.v.t === 'arr' ? `Array(${kid.v.n})` : preview(kid.v, 24);
    const part = (node.t === 'arr' ? '' : kid.k + ': ') + inner;
    if (body.length + part.length > max) { cut = true; break; }
    body += (body ? ', ' : '') + part;
  }
  return head + open + body + (cut ? (body ? ', …' : '…') : '') + close;
}
