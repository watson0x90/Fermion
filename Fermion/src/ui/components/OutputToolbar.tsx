import { useState, MutableRefObject } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { outputActions, KINDS } from '../store/outputSlice';

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
          {LABEL[k]}
        </button>
      ))}
      <span className="sp" />
      <button className={'ic' + (follow ? ' on' : '')} title="Follow" onClick={() => { dispatch(outputActions.setFollow(!follow)); ctrlRef.current?.setFollow(!follow); }}>⤓</button>
      <button className="ic" data-testid="clear-output" title="Clear" onClick={() => { ctrlRef.current?.clear(); dispatch(outputActions.clear()); }}>🗑</button>
      <button className="ic" title="Save" onClick={save}>⤵</button>
      <input
        className="search"
        placeholder="search…"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter' && q) ctrlRef.current?.searchNext(q); }}
      />
    </div>
  );
}
