// One menu for every address shown in the app: right-click an address (or
// press the menu key on it) to copy it, open it in Memory or Disassembly, or
// hook it. Components spread addrMenu(address) onto the element; the menu
// itself is drawn once, by <AddressMenu/> in the layout.
import { parseAddress } from './inspector/format';

export interface MenuRequest { address: string; x: number; y: number; }

type Listener = (request: MenuRequest | null) => void;
const listeners = new Set<Listener>();

export function onAddressMenu(listener: Listener): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export function closeAddressMenu() {
  listeners.forEach((l) => l(null));
}

// Opens the menu at a point. Anything that is not an address is ignored.
export function openAddressMenu(address: string, x: number, y: number): boolean {
  const parsed = parseAddress(address);
  if (!parsed) return false;
  listeners.forEach((l) => l({ address: parsed, x, y }));
  return true;
}

interface MenuEvent { preventDefault(): void; stopPropagation(): void; clientX: number; clientY: number; currentTarget: unknown; }

// Props that give an element the address menu.
export function addrMenu(address: string | null | undefined) {
  return {
    onContextMenu: (e: MenuEvent) => {
      if (!address || !parseAddress(address)) return;
      e.preventDefault();
      e.stopPropagation();
      // The menu key reports no pointer position: open at the element instead.
      let { clientX: x, clientY: y } = e;
      const el = e.currentTarget as { getBoundingClientRect?: () => DOMRect } | null;
      if (!x && !y && el?.getBoundingClientRect) {
        const r = el.getBoundingClientRect();
        x = r.left + 8;
        y = r.bottom;
      }
      openAddressMenu(address, x, y);
    },
  };
}
