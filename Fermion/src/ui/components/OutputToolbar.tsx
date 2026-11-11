import { useState, MutableRefObject } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { outputActions, KINDS } from '../store/outputSlice';
import { Icon } from './Icon';

// The SEND kind is displayed as "MSG" (output is color-only, so the chip is the
// only place the kind is named — the internal kind stays SEND).
const LABEL: Record<string, string> = { LOG: 'LOG', WARN: 'WARN', ERR: 'ERR', SEND: 'MSG', STATUS: 'STATUS' };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function OutputToolbar({ ctrlRef }: { ctrlRef: MutableRefObject<any> }) {
  const dispatch = useAppDispatch();
  const filters = useAppSelector((s) => s.output.filters);
  const follow = useAppSelector((s) => s.output.follow);
  const [q, setQ] = useState('');

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
          onClick={() => { dispatch(outputActions.toggleFilter(k)); ctrlRef.current?.setFilter(k, !filters[k]); }}
        >
          <span className="d" />{LABEL[k]}
        </button>
      ))}
      <span className="sp" />
      <button className="ic" data-testid="detach-output" title="Detach Output — coming soon" disabled><Icon name="popout" size={15} /></button>
      <button className={'ic' + (follow ? ' on' : '')} title="Follow tail" onClick={() => { dispatch(outputActions.setFollow(!follow)); ctrlRef.current?.setFollow(!follow); }}><Icon name="follow" size={15} /></button>
      <button className="ic" data-testid="clear-output" title="Clear" onClick={() => { ctrlRef.current?.clear(); dispatch(outputActions.clear()); }}><Icon name="clear" size={15} /></button>
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
