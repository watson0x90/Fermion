// Allocators of the program's own, for heap tracking. Many programs do not
// take every block from the system: they have a pool or an arena. Heap
// tracking can follow those too when told which function allocates (and which
// of its arguments is the size) and which one frees (and which argument is the
// block). They are kept in this window; the main process checks them again.
export interface OwnAllocator { alloc: string; size: number; free: string; pointer: number; }

export const OWN_KEY = 'fermion.heapAllocators';
export const MAX_OWN = 8;
export const MAX_ARG = 7;
// 'module!function' or 'module+0xoffset' (the same test the main process applies).
const PLACE = /^[^\s!+][^!+]{0,127}(![^\s!]{1,256}|\+0x[0-9a-fA-F]{1,12})$/;
export const isPlace = (text: string) => PLACE.test(text.trim());

// What is wrong with a row, in words ('' when it can be used).
export function allocatorError(a: OwnAllocator): string {
  if (!a.alloc.trim()) return 'Name the function that allocates.';
  if (!isPlace(a.alloc)) return 'Write the allocating function as module!function or module+0xoffset.';
  if (a.free.trim() && !isPlace(a.free)) return 'Write the freeing function as module!function or module+0xoffset.';
  return '';
}

const arg = (v: unknown) => (Number.isInteger(v) && (v as number) >= 0 && (v as number) <= MAX_ARG ? (v as number) : 0);

// Any value -> a list of rows holding only what a row has.
export function cleanAllocators(raw: unknown): OwnAllocator[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((r) => r && typeof r === 'object' && !Array.isArray(r)).slice(0, MAX_OWN).map((r) => ({
    alloc: typeof r.alloc === 'string' ? r.alloc.slice(0, 400) : '',
    size: arg(r.size),
    free: typeof r.free === 'string' ? r.free.slice(0, 400) : '',
    pointer: arg(r.pointer),
  }));
}

export function loadAllocators(): OwnAllocator[] {
  try {
    const saved = localStorage.getItem(OWN_KEY);
    if (saved) return cleanAllocators(JSON.parse(saved));
  } catch { /* storage unavailable or damaged: none */ }
  return [];
}

export function saveAllocators(list: OwnAllocator[]): void {
  try { localStorage.setItem(OWN_KEY, JSON.stringify(cleanAllocators(list))); } catch { /* storage may be unavailable */ }
}

// The rows as heap tracking is started with them.
export function allocatorArgs(list: OwnAllocator[]) {
  return list.map((a) => ({ alloc: a.alloc.trim(), size: a.size, free: a.free.trim() || null, pointer: a.pointer }));
}
