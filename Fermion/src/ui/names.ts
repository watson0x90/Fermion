// Names the operator has given to addresses. A bookmark's label is such a
// name: once a place is bookmarked and labelled, every view that shows that
// address (a backtrace, a call target, the caller of a hook, the call stack
// of a memory access or an allocation) shows the label instead of whatever
// the target could say about it, which in a program without symbols is often
// just the nearest export, far away.
//
// A place inside a module is known by module and offset, so a name still
// fits when the module loads somewhere else. An address a little after a
// named one (inside the same function, most likely) is shown as name+offset.
import { useMemo } from 'react';
import { useSelector } from 'react-redux';
import { Bookmark } from './store/bookmarksSlice';

export interface Named { label: string; delta: number; } // delta 0: exactly the named address

// How far after a named address its name still applies.
export const NEAR = 0x1000;

export interface NameIndex {
  size: number;
  // where: "module+0xoffset" as the agent reports it; address: the absolute address.
  find(where: string | null | undefined, address?: string | null): Named | null;
  // The text to show for an address: the operator's name, else `fallback`
  // (the target's symbol), else where it is.
  show(where: string | null | undefined, address: string | null | undefined, fallback: string | null | undefined): string;
}

export function parseWhere(where: string | null | undefined): { module: string; offset: number } | null {
  const m = /^(.+)\+0x([0-9a-f]{1,13})$/i.exec(where ?? '');
  return m ? { module: m[1], offset: parseInt(m[2], 16) } : null;
}

export const nameText = (n: Named) => (n.delta ? `${n.label}+0x${n.delta.toString(16)}` : n.label);

// A label that only repeats where the place is tells nothing new.
function isName(label: string): boolean {
  const t = label.trim();
  return t !== '' && !/^0x[0-9a-f]+$/i.test(t) && parseWhere(t) === null;
}

const EMPTY: NameIndex = { size: 0, find: () => null, show: (where, address, fallback) => fallback || where || address || '' };

export function buildNameIndex(bookmarks: Bookmark[]): NameIndex {
  const byModule = new Map<string, { offset: number; label: string }[]>();
  const byAddress = new Map<string, string>();
  let size = 0;
  for (const b of bookmarks) {
    if (!isName(b.label)) continue;
    const label = b.label.trim();
    if (b.module && b.offset !== null) {
      const key = b.module.toLowerCase();
      if (!byModule.has(key)) byModule.set(key, []);
      (byModule.get(key) as { offset: number; label: string }[]).push({ offset: b.offset, label });
    } else {
      byAddress.set(b.address.toLowerCase(), label);
    }
    size++;
  }
  if (!size) return EMPTY;
  byModule.forEach((list) => list.sort((a, b) => a.offset - b.offset));

  const find = (where: string | null | undefined, address?: string | null): Named | null => {
    const place = parseWhere(where);
    if (place) {
      const list = byModule.get(place.module.toLowerCase());
      if (!list) return null;
      // The last name at or before the offset.
      let lo = 0, hi = list.length - 1, at = -1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (list[mid].offset <= place.offset) { at = mid; lo = mid + 1; } else hi = mid - 1;
      }
      if (at < 0) return null;
      const delta = place.offset - list[at].offset;
      return delta < NEAR ? { label: list[at].label, delta } : null;
    }
    const label = byAddress.get((address ?? where ?? '').toLowerCase());
    return label ? { label, delta: 0 } : null;
  };
  return {
    size,
    find,
    show: (where, address, fallback) => {
      const named = find(where, address);
      return named ? nameText(named) : fallback || where || address || '';
    },
  };
}

// The names in the current set of bookmarks (none in a store without bookmarks).
export function useNames(): NameIndex {
  const items = useSelector((s: { bookmarks?: { items: Bookmark[] } }) => s.bookmarks?.items);
  return useMemo(() => (items && items.length ? buildNameIndex(items) : EMPTY), [items]);
}
