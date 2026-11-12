import { useState, MutableRefObject } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { outputActions, KINDS } from '../store/outputSlice';
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
  const relay = (msg: Record<string, unknown>) => { if (standalone) outputApi()?.send?.(msg); };

  const save = async () => {
    const text: string = ctrlRef.current?.getText() ?? '';
    if (!text.trim()) return;
    await window.fermion.saveFile(text, { title: 'Save Frida Output', defaultPath: 'frida-output.txt' });
  };

  return (
    <div className="otool">
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
      <span className="sp" />
      {standalone
        ? <button className="ic" data-testid="dock-output" title="Dock Output back into the main window" onClick={() => outputApi()?.dock?.()}><Icon name="dock" size={15} /></button>
        : <button className="ic" data-testid="detach-output" title="Detach Output into its own window" onClick={() => outputApi()?.detach?.()}><Icon name="popout" size={15} /></button>}
      <button className={'ic' + (follow ? ' on' : '')} title="Follow tail" onClick={() => { dispatch(outputActions.setFollow(!follow)); ctrlRef.current?.setFollow(!follow); relay({ t: 'follow', on: !follow }); }}><Icon name="follow" size={15} /></button>
      <button className="ic" data-testid="clear-output" title="Clear" onClick={() => { ctrlRef.current?.clear(); dispatch(outputActions.clear()); relay({ t: 'clear' }); }}><Icon name="clear" size={15} /></button>
      <button className="ic" title="Save output" onClick={save}><Icon name="save" size={15} /></button>
      <span className="search">
        <Icon name="search" size={13} />
        <input
          placeholder="search"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && q) ctrlRef.current?.searchNext(q); }}
        />
      </span>
    </div>
  );
}
