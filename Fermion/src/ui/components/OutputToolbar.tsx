import { useState, MutableRefObject } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { outputActions, KINDS } from '../store/outputSlice';
import { clearTerminal } from '../bridge';
import { Icon } from './Icon';

// The SEND kind is displayed as "MSG" (output is color-only, so the chip is the
// only place the kind is named — the internal kind stays SEND).
const LABEL: Record<string, string> = { LOG: 'LOG', WARN: 'WARN', ERR: 'ERR', SEND: 'MSG', STATUS: 'STATUS' };

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
    await window.fermion.saveFile(text, { title: 'Save Frida Output', defaultPath: 'frida-output.txt' });
  };

  const search = (back: boolean) => {
    if (!q) return;
    if (back) ctrlRef.current?.searchPrev?.(q, { regex });
    else ctrlRef.current?.searchNext(q, { regex });
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
            placeholder={regex ? 'Search output (regex)' : 'Search output'}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') search(e.shiftKey); }}
          />
          <button
            className={'rx' + (regex ? ' on' : '')}
            data-testid="search-regex"
            aria-pressed={regex}
            title={regex ? 'Regex search is on — click for plain text' : 'Plain-text search — click for regex'}
            onClick={() => setRegex(!regex)}
          >
            .*
          </button>
        </span>
      </div>
    </div>
  );
}
