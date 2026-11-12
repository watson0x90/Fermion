// The Hooks tab's data: a hook the operator placed, a function found by a
// search, and the hits the in-target agent reports.

export type SearchKind = 'exports' | 'imports' | 'symbols';

// A function found by a search. module + offset is where it is inside its
// module; a hook keeps that, so it is found again after the target restarts.
export interface Target { name: string; module: string; offset: number | null; address: string; }

export type HookStatus = 'on' | 'off' | 'waiting' | 'error';

export interface Hook extends Target {
  id: string;
  code: string;        // the handler, as last applied
  enabled: boolean;    // what the operator asked for
  backtrace: boolean;
  status: HookStatus;  // what is true in the target
  error: string;
  calls: number;
}

export interface Hit {
  seq: number;
  id: string;          // the hook
  t: number;           // ms since the hooks agent started
  tid: number;
  depth: number;
  phase: 'enter' | 'leave';
  text: string;
  error: boolean;
  bt: string[] | null; // return addresses, innermost first
}

export interface HitBatch { hits: Hit[]; dropped: number; counts: Record<string, number>; }

export interface Frame { address: string; name: string; where: string; }

export const DEFAULT_HANDLER = `({
  onEnter(log, args) {
    log('(' + args[0] + ', ' + args[1] + ', ' + args[2] + ', ' + args[3] + ')');
  },
  onLeave(log, retval) {
    log('=> ' + retval);
  }
})`;

const ADDRESS = /^0x[0-9a-f]{1,16}$/i;
const MAX_HITS_PER_BATCH = 500;
const MAX_FRAMES = 32;
const MAX_TEXT = 4000;

const int = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : 0);

// A batch of hits as sent by the hooks agent. It arrives from the target, so
// nothing in it is trusted: wrong shapes are dropped, sizes are capped, and
// every text stays a string.
export function asHitBatch(payload: unknown): HitBatch | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  if (p.fermionHooks !== 'hits') return null;
  const hits: Hit[] = [];
  if (Array.isArray(p.hits)) {
    for (const raw of p.hits.slice(0, MAX_HITS_PER_BATCH)) {
      if (!raw || typeof raw !== 'object') continue;
      const h = raw as Record<string, unknown>;
      if (typeof h.id !== 'string' || typeof h.text !== 'string') continue;
      const bt = Array.isArray(h.bt)
        ? h.bt.filter((a): a is string => typeof a === 'string' && ADDRESS.test(a)).slice(0, MAX_FRAMES)
        : null;
      hits.push({
        seq: int(h.seq), id: h.id, t: int(h.t), tid: int(h.tid), depth: Math.max(0, Math.min(64, int(h.depth))),
        phase: h.phase === 'leave' ? 'leave' : 'enter',
        text: h.text.length > MAX_TEXT ? h.text.slice(0, MAX_TEXT) + '…' : h.text,
        error: h.error === true,
        bt: bt && bt.length ? bt : null,
      });
    }
  }
  const counts: Record<string, number> = {};
  if (p.counts && typeof p.counts === 'object') {
    for (const [id, n] of Object.entries(p.counts as Record<string, unknown>)) if (typeof n === 'number' && n >= 0) counts[id] = int(n);
  }
  return { hits, dropped: Math.max(0, int(p.dropped)), counts };
}

let counter = 0;
export function newHookId(): string {
  counter++;
  return 'hk-' + Date.now().toString(36) + '-' + counter.toString(36);
}

export function hookFromTarget(target: Target, id = newHookId()): Hook {
  return {
    id, name: target.name, module: target.module, offset: target.offset, address: target.address,
    code: DEFAULT_HANDLER, enabled: true, backtrace: true, status: 'waiting', error: '', calls: 0,
  };
}

// The same place in the target? Inside a module that is module + offset (the
// address changes between runs); outside one it is the address.
export function sameTarget(a: Target, b: Target): boolean {
  if (a.module || b.module) return a.module.toLowerCase() === b.module.toLowerCase() && a.offset === b.offset;
  return a.address.toLowerCase() === b.address.toLowerCase();
}

// "+12.345s"
export function hitTime(ms: number): string {
  return '+' + (ms / 1000).toFixed(3) + 's';
}

// One hit as a line for the Output pane.
export function hitLine(hookName: string, hit: Hit): string {
  return `[hook] ${hookName} ${hit.phase === 'leave' ? '<-' : '->'} ${hit.text}`;
}
