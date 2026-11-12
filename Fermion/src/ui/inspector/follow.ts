// Helpers for the result of following a thread (Inspector → Threads → Follow):
// filtering the functions, grouping them by module, and writing them as CSV.

export interface FollowItem { address: string; name: string; module: string; count: number; }
export interface FollowModule { name: string; calls: number; functions: number; }
export type FollowMode = 'all' | 'app' | 'module';
export interface FollowScope { mode: FollowMode; module: string; }
export interface FollowGroup extends FollowModule { items: FollowItem[]; }

// Case-insensitive match on the function name, its module or its address.
export function filterFollow(items: FollowItem[], needle: string): FollowItem[] {
  const n = needle.trim().toLowerCase();
  if (!n) return items;
  return items.filter((i) => i.name.toLowerCase().includes(n) || (i.module ?? '').toLowerCase().includes(n) || i.address.toLowerCase().includes(n));
}

// One group per module, most calls first. `modules` are the totals the agent
// counted over every function, including those it did not list; without them
// (an older agent, or a filtered list) the totals are those of the rows given.
export function groupFollow(items: FollowItem[], modules: FollowModule[] | null | undefined): FollowGroup[] {
  const byName = new Map<string, FollowGroup>();
  const group = (name: string) => {
    let g = byName.get(name);
    if (!g) { g = { name, calls: 0, functions: 0, items: [] }; byName.set(name, g); }
    return g;
  };
  const counted = !!modules && modules.length > 0;
  if (counted) for (const m of modules!) { const g = group(m.name); g.calls = m.calls; g.functions = m.functions; }
  for (const item of items) {
    const g = group(item.module ?? '');
    g.items.push(item);
    if (!counted) { g.calls += item.count; g.functions++; }
  }
  return [...byName.values()].sort((a, b) => b.calls - a.calls);
}

export const moduleLabel = (name: string) => name || '(no module)';

// A cell a spreadsheet would treat as a formula gets a leading apostrophe;
// cells with separators, quotes or line breaks are quoted.
function cell(value: string | number): string {
  let s = String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

export function followCsv(items: FollowItem[]): string {
  let out = 'calls,module,function,address\r\n';
  for (const i of items) out += [i.count, cell(i.module ?? ''), cell(i.name), cell(i.address)].join(',') + '\r\n';
  return out;
}

// '' for a follow of everything.
export function scopeText(scope: FollowScope | null | undefined): string {
  if (!scope || scope.mode === 'all') return '';
  return scope.mode === 'app' ? 'system libraries not followed' : `only ${scope.module} followed`;
}
