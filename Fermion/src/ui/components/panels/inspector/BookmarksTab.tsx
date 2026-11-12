import { useMemo } from 'react';
import { useAppDispatch, useAppSelector } from '../../../store';
import { bookmarksActions, Bookmark } from '../../../store/bookmarksSlice';
import { addAddress } from '../../../inspector/format';
import { inspectApi, useInspect, Listing } from '../../../inspector/useInspect';
import { addrMenu } from '../../../addressMenu';
import { Icon } from '../../Icon';

interface Mod { name: string; base: string; }

const where = (b: Bookmark) => (b.module ? `${b.module}+0x${(b.offset ?? 0).toString(16)}` : b.address);

// Bookmarks: places the operator saved, from the address menu. A bookmark
// inside a module is kept as module + offset, so it still points at the same
// code or data when the module is loaded somewhere else, in a later run.
// Bookmarks are saved with Fermion and are there in every session.
export function BookmarksTab({ active, attached, onOpen }: { active: boolean; attached: boolean; onOpen: (view: 'memory' | 'code', address: string) => void }) {
  const dispatch = useAppDispatch();
  const items = useAppSelector((s) => s.bookmarks.items);
  // Where each module is in this session, to turn module + offset into an address.
  const mods = useInspect<Listing<Mod>>(() => inspectApi().modules(), 'bookmark-modules', active && attached && items.some((b) => b.module));
  const bases = useMemo(() => {
    const map = new Map<string, string>();
    for (const m of mods.data?.items ?? []) map.set(m.name.toLowerCase(), m.base);
    return map;
  }, [mods.data]);

  // The address now, or null when it cannot be known (not attached, or the
  // module is not loaded in this process).
  const resolve = (b: Bookmark): string | null => {
    if (!attached) return null;
    if (!b.module) return b.address;
    const base = bases.get(b.module.toLowerCase());
    return base ? addAddress(base, b.offset ?? 0) : null;
  };

  return (
    <div className="insp-tab bm-tab">
      <div className="ptool">
        <span className="grow">Right-click any address and choose Bookmark to add one. Bookmarks are kept between sessions.</span>
        <span className="count" data-testid="bm-count">{items.length} {items.length === 1 ? 'bookmark' : 'bookmarks'}</span>
      </div>
      {mods.error && <div className="insp-note err" role="alert">Could not list modules: {mods.error}</div>}
      <div className="bm-list" data-testid="bm-list">
        {items.map((b) => {
          const address = resolve(b);
          const missing = attached && b.module !== '' && !address && !mods.loading && !!mods.data;
          return (
            <div className="bm-row" key={b.id} data-testid="bm-row" {...addrMenu(address)}>
              <div className="bm-main">
                <input
                  className="bm-label"
                  data-testid="bm-label"
                  aria-label="Bookmark name"
                  spellCheck={false}
                  value={b.label}
                  onChange={(e) => dispatch(bookmarksActions.changed({ id: b.id, label: e.target.value }))}
                />
                <span className="bm-where mono" data-testid="bm-where" title={address ? 'Now at ' + address : undefined}>
                  {where(b)}{address && b.module ? ' · ' + address : ''}{missing ? ' · not loaded in this process' : ''}
                </span>
                <input
                  className="bm-note"
                  data-testid="bm-note"
                  aria-label="Note"
                  placeholder="Add a note"
                  value={b.note}
                  onChange={(e) => dispatch(bookmarksActions.changed({ id: b.id, note: e.target.value }))}
                />
              </div>
              <div className="bm-actions">
                <button className="pill" data-testid="bm-open-memory" disabled={!address} title={address ? 'Open in Memory' : 'Attach to a process that has this module loaded'} onClick={() => address && onOpen('memory', address)}>Memory</button>
                <button className="pill" data-testid="bm-open-code" disabled={!address} title={address ? 'Open in Disassembly' : 'Attach to a process that has this module loaded'} onClick={() => address && onOpen('code', address)}>Disassembly</button>
                <button className="pill ico" data-testid="bm-remove" aria-label={'Remove the bookmark ' + b.label} title="Remove this bookmark" onClick={() => dispatch(bookmarksActions.removed(b.id))}><Icon name="clear" size={12} /></button>
              </div>
            </div>
          );
        })}
        {!items.length && (
          <div className="insp-empty">
            No bookmarks yet. Right-click an address anywhere in Fermion (a register, a symbol, an instruction, a pointer in a REPL result) and choose Bookmark. It is saved here with a name and a note, and stays between sessions.
          </div>
        )}
      </div>
    </div>
  );
}
