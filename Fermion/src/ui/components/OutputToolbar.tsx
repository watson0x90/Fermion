import { useRef, useState, KeyboardEvent, MutableRefObject } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { outputActions, KINDS } from '../store/outputSlice';
import { clearTerminal } from '../bridge';
import { Icon } from './Icon';

// The SEND kind is displayed as "MSG" (output is color-only, so the chip is the
// only place the kind is named — the internal kind stays SEND).
const LABEL: Record<string, string> = { LOG: 'LOG', WARN: 'WARN', ERR: 'ERR', SEND: 'MSG', STATUS: 'STATUS' };

const HISTORY_MAX = 50;
const HISTORY_KEY = 'fermion.searchHistory';

// Earlier searches, shared by the main window and the detached Output window.
function loadSearchHistory(): string[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((x) => typeof x === 'string' && x.length > 0 && x.length <= 500).slice(-HISTORY_MAX);
  } catch {
    return [];
  }
}

/* eslint-disable @typescript-eslint/no-explicit-any */
const outputApi = () => (window as any).fermion?.output;

// `standalone` = this toolbar is running in the detached Output window: the
// pop-out button becomes "dock", and every toolbar change is relayed to the
// main window so the pane comes back in the same state when docked.
export function OutputToolbar({ ctrlRef, standalone = false }: { ctrlRef: MutableRefObject<any>; standalone?: boolean }) {
  const dispatch = useAppDispatch();
  const filters = useAppSelector((s) => s.output.filters);
  const follow = useAppSelector((s) => s.output.follow);
  const [q, setQ] = useState('');
  const [regex, setRegex] = useState(true);
  const relay = (msg: Record<string, unknown>) => { if (standalone) outputApi()?.send?.(msg); };

  const save = async () => {
    const text: string = ctrlRef.current?.getText() ?? '';
    if (!text.trim()) return;
    // An export: it must not become the script file that Ctrl-S writes to.
    await window.fermion.exportFile(text, { title: 'Save Frida Output', defaultPath: 'frida-output.txt' });
  };

  // ---- search: live as you type, with a history on Up/Down ----
  const inputRef = useRef<HTMLInputElement>(null);
  const history = useRef<string[]>(loadSearchHistory()); // oldest first; kept across restarts
  const cursor = useRef(-1);            // -1 = not browsing; else steps back from newest
  const draft = useRef('');             // what was typed before browsing history

  // Show `value` in the box and search for it without moving off the current
  // match (incremental); an empty value clears the search instead.
  const live = (value: string, useRegex = regex) => {
    setQ(value);
    if (value) ctrlRef.current?.searchNext(value, { regex: useRegex, incremental: true });
    else ctrlRef.current?.clearSearch?.();
  };
  const remember = (value: string) => {
    const h = history.current;
    if (!value || h[h.length - 1] === value) return;
    h.push(value);
    if (h.length > HISTORY_MAX) h.shift();
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(h)); } catch { /* storage unavailable */ }
  };
  const clearSearch = () => {
    remember(q);
    cursor.current = -1;
    live('');
    inputRef.current?.focus();
  };
  const onSearchKey = (e: KeyboardEvent<HTMLInputElement>) => {
    const h = history.current;
    if (e.key === 'Enter') {
      if (!q) return;
      remember(q);
      cursor.current = -1;
      if (e.shiftKey) ctrlRef.current?.searchPrev?.(q, { regex });
      else ctrlRef.current?.searchNext(q, { regex });
    } else if (e.key === 'Escape') {
      if (q) clearSearch();
    } else if (e.key === 'ArrowUp') {
      if (!h.length) return;
      e.preventDefault();
      if (cursor.current === -1) draft.current = q;
      cursor.current = Math.min(cursor.current + 1, h.length - 1);
      live(h[h.length - 1 - cursor.current]);
    } else if (e.key === 'ArrowDown') {
      if (cursor.current === -1) return;
      e.preventDefault();
      cursor.current -= 1;
      live(cursor.current === -1 ? draft.current : h[h.length - 1 - cursor.current]);
    }
  };

  // Two rows: kind filters on the left with the action icons pinned top-right
  // (the chips wrap under themselves on a narrow pane; the icons never move),
  // then the search box on its own row underneath.
  return (
    <div className="otool">
      <div className="otool-main">
        <div className="otool-filters">
          <span className="ttl">Output</span>
          {KINDS.map((k) => (
            <button
              key={k}
              data-testid={'flt-' + k}
              className={'chip ' + k.toLowerCase() + (filters[k] ? ' on' : '')}
              onClick={() => { dispatch(outputActions.toggleFilter(k)); ctrlRef.current?.setFilter(k, !filters[k]); relay({ t: 'filter', kind: k, on: !filters[k] }); }}
            >
              <span className="d" />{LABEL[k]}
            </button>
          ))}
        </div>
        <div className="otool-actions" data-testid="output-actions">
          {standalone
            ? <button className="ic" data-testid="dock-output" title="Dock Output back into the main window" onClick={() => outputApi()?.dock?.()}><Icon name="dock" size={15} /></button>
            : <button className="ic" data-testid="detach-output" title="Detach Output into its own window" onClick={() => outputApi()?.detach?.()}><Icon name="popout" size={15} /></button>}
          <button className={'ic' + (follow ? ' on' : '')} data-testid="follow-output" title="Follow tail" onClick={() => { dispatch(outputActions.setFollow(!follow)); ctrlRef.current?.setFollow(!follow); relay({ t: 'follow', on: !follow }); }}><Icon name="follow" size={15} /></button>
          <button className="ic" data-testid="clear-output" title="Clear" onClick={() => { if (standalone) { relay({ t: 'clear' }); return; } clearTerminal(); dispatch(outputActions.clear()); }}><Icon name="clear" size={15} /></button>
          <button className="ic" data-testid="save-output" title="Save output" onClick={save}><Icon name="floppy" size={15} /></button>
        </div>
      </div>
      <div className="otool-search">
        <span className="search">
          <Icon name="search" size={13} />
          <input
            data-testid="output-search"
            placeholder={regex ? 'Search output (regex) — ↑↓ history' : 'Search output — ↑↓ history'}
            ref={inputRef}
            value={q}
            onChange={(e) => { cursor.current = -1; live(e.target.value); }}
            onKeyDown={onSearchKey}
            onBlur={() => remember(q)}
          />
          {q && (
            <button className="x" data-testid="search-clear" title="Clear search (Esc)" onMouseDown={(e) => e.preventDefault()} onClick={clearSearch}>
              <Icon name="close" size={13} />
            </button>
          )}
          <button
            className={'rx' + (regex ? ' on' : '')}
            data-testid="search-regex"
            aria-pressed={regex}
            title={regex ? 'Regex search is on — click for plain text' : 'Plain-text search — click for regex'}
            onClick={() => { setRegex(!regex); if (q) live(q, !regex); }}
          >
            .*
          </button>
        </span>
      </div>
    </div>
  );
}
