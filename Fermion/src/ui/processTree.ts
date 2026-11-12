// Pure process-tree model for the Process tree panel: turns the flat process
// list from window.fermion.enumerateProcesses() (pid, name, parameters.ppid)
// into a hierarchy, and flattens it back into display rows under a filter, a
// collapse set, and an "only these pids" restriction. No DOM, no IPC.

export interface Proc {
  pid: number;
  name: string;
  parameters?: { ppid?: number; user?: string; path?: string; [k: string]: unknown };
}

export interface ProcNode {
  pid: number;
  name: string;
  user?: string;
  path?: string;
  children: ProcNode[];
}

export interface ProcRow {
  pid: number;
  name: string;
  user?: string;
  path?: string;
  depth: number;
  hasChildren: boolean; // has children that are visible under the current view
  collapsed: boolean;
  match: boolean;       // matches the filter itself (vs. shown only as a parent)
}

export interface FlattenOptions {
  filter?: string;
  collapsed?: Set<number>;
  only?: Set<number> | null;
}

const ppidOf = (p: Proc): number | undefined =>
  (typeof p.parameters?.ppid === 'number' ? p.parameters.ppid : undefined);

// Does this device tell us who started what? (Some remote devices do not.)
export function hasParentInfo(procs: Proc[]): boolean {
  return procs.some((p) => ppidOf(p) !== undefined);
}

// pid -> parent pid, for parents that are actually in the listing. A process
// naming itself (pid 0 on Windows) or a parent that has exited has no entry.
// Cycles are broken at the lowest pid in the cycle so every process stays
// reachable from a root exactly once.
function parentMap(procs: Proc[]): Map<number, number> {
  const known = new Set(procs.map((p) => p.pid));
  const parent = new Map<number, number>();
  for (const p of procs) {
    const pp = ppidOf(p);
    if (pp !== undefined && pp !== p.pid && known.has(pp) && !parent.has(p.pid)) parent.set(p.pid, pp);
  }
  for (const pid of [...known].sort((a, b) => a - b)) {
    const seen = new Set<number>([pid]);
    let cur = parent.get(pid);
    while (cur !== undefined) {
      if (cur === pid) { parent.delete(pid); break; } // walked back to the start: a cycle
      if (seen.has(cur)) break;                       // a cycle further up; handled from its own members
      seen.add(cur);
      cur = parent.get(cur);
    }
  }
  return parent;
}

export function buildTree(procs: Proc[]): ProcNode[] {
  const nodes = new Map<number, ProcNode>();
  for (const p of procs) {
    if (nodes.has(p.pid)) continue; // duplicate pid in the listing
    nodes.set(p.pid, {
      pid: p.pid,
      name: p.name,
      user: typeof p.parameters?.user === 'string' ? p.parameters.user : undefined,
      path: typeof p.parameters?.path === 'string' ? p.parameters.path : undefined,
      children: [],
    });
  }
  const parent = parentMap(procs);
  const roots: ProcNode[] = [];
  for (const node of nodes.values()) {
    const pp = parent.get(node.pid);
    const parentNode = pp === undefined ? undefined : nodes.get(pp);
    if (parentNode) parentNode.children.push(node); else roots.push(node);
  }
  const byPid = (a: ProcNode, b: ProcNode) => a.pid - b.pid;
  for (const node of nodes.values()) node.children.sort(byPid);
  return roots.sort(byPid);
}

// The attached process's line: every ancestor up to its root, the process, and
// everything beneath it. Empty for a pid that is not in the listing.
export function ancestryOf(procs: Proc[], pid: number): Set<number> {
  const out = new Set<number>();
  if (!procs.some((p) => p.pid === pid)) return out;
  const parent = new Map<number, number>();
  const kids = new Map<number, number[]>();
  for (const p of procs) {
    const pp = ppidOf(p);
    if (pp === undefined || pp === p.pid || parent.has(p.pid)) continue;
    parent.set(p.pid, pp);
    if (!kids.has(pp)) kids.set(pp, []);
    kids.get(pp)!.push(p.pid);
  }
  const known = new Set(procs.map((p) => p.pid));
  for (let cur: number | undefined = pid; cur !== undefined && known.has(cur) && !out.has(cur); cur = parent.get(cur)) out.add(cur);
  const stack = [pid];
  const seen = new Set<number>([pid]);
  while (stack.length) {
    for (const k of kids.get(stack.pop()!) ?? []) {
      if (seen.has(k)) continue;
      seen.add(k); out.add(k); stack.push(k);
    }
  }
  return out;
}

export function flattenTree(roots: ProcNode[], opts: FlattenOptions = {}): ProcRow[] {
  const needle = (opts.filter ?? '').trim().toLowerCase();
  const collapsed = opts.collapsed ?? new Set<number>();
  const only = opts.only ?? null;

  const matches = (n: ProcNode) => !needle || n.name.toLowerCase().includes(needle) || String(n.pid).includes(needle);
  // Shown if allowed by `only` and (it matches, or something beneath it does).
  const shown = new Map<ProcNode, boolean>();
  const isShown = (n: ProcNode): boolean => {
    const cached = shown.get(n);
    if (cached !== undefined) return cached;
    let v = false;
    if (!only || only.has(n.pid)) {
      v = matches(n);
      for (const c of n.children) if (isShown(c)) v = true; // visit all: fills the cache
    }
    shown.set(n, v);
    return v;
  };

  const rows: ProcRow[] = [];
  const walk = (n: ProcNode, depth: number) => {
    if (!isShown(n)) return;
    const kids = n.children.filter(isShown);
    // While filtering, a collapsed branch still opens to reveal its matches.
    const isCollapsed = !needle && collapsed.has(n.pid) && kids.length > 0;
    rows.push({
      pid: n.pid, name: n.name, user: n.user, path: n.path, depth,
      hasChildren: kids.length > 0, collapsed: isCollapsed, match: !!needle && matches(n),
    });
    if (!isCollapsed) for (const k of kids) walk(k, depth + 1);
  };
  for (const r of roots) walk(r, 0);
  return rows;
}
