import { addrMenu } from '../../../addressMenu';
import { useEffect, useMemo, useState } from 'react';
import { Icon } from '../../Icon';
import { fmtSize } from '../../../inspector/format';
import { inspectApi, useInspect, Listing } from '../../../inspector/useInspect';

interface Mod { name: string; base: string; size: number; path: string; }
interface Sym { type: string; name: string; module?: string; address: string | null; }
interface Str { address: string; where: string; kind: string; length: number; text: string; }
interface Strings { module: string; items: Str[]; total: number; truncated: boolean; scanned: number; timedOut: boolean; }
type Kind = 'exports' | 'imports' | 'strings';
const SEARCH_PAUSE_MS = 400; // a strings search starts this long after the last key

const MAX_ROWS = 1000; // symbols rendered at once; the filter searches all of them

// Modules loaded in the target. Selecting one lists its exports or imports;
// any address opens in the Memory tab.
export function ModulesTab({ active, onViewMemory }: { active: boolean; onViewMemory: (address: string) => void }) {
  const mods = useInspect<Listing<Mod>>(() => inspectApi().modules(), 'modules', active);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [kind, setKind] = useState<Kind>('exports');
  // Strings are searched in the target: the text typed is sent once typing pauses.
  const [strQuery, setStrQuery] = useState('');
  const [strMin, setStrMin] = useState(5);
  const [symFilter, setSymFilter] = useState('');

  const syms = useInspect<Listing<Sym>>(
    () => (kind === 'exports' ? inspectApi().exports(selected) : inspectApi().imports(selected)),
    `${selected}|${kind}`,
    active && selected != null && kind !== 'strings',
  );
  useEffect(() => {
    if (kind !== 'strings') return;
    const t = setTimeout(() => setStrQuery(symFilter.trim().slice(0, 100)), SEARCH_PAUSE_MS);
    return () => clearTimeout(t);
  }, [symFilter, kind]);
  const strs = useInspect<Strings>(
    () => inspectApi().strings(selected, { text: strQuery, min: strMin }),
    `${selected}|strings|${strMin}|${strQuery}`,
    active && selected != null && kind === 'strings',
  );

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const items = mods.data?.items ?? [];
    return needle ? items.filter((m) => m.name.toLowerCase().includes(needle) || m.base.includes(needle)) : items;
  }, [mods.data, filter]);

  const symRows = useMemo(() => {
    const needle = symFilter.trim().toLowerCase();
    const items = syms.data?.items ?? [];
    return needle ? items.filter((s) => s.name.toLowerCase().includes(needle) || (s.module ?? '').toLowerCase().includes(needle)) : items;
  }, [syms.data, symFilter]);

  const selectedMod = mods.data?.items.find((m) => m.name === selected) ?? null;

  return (
    <div className="insp-tab">
      <div className="ptool">
        <span className="search insp-filter"><Icon name="search" size={13} />
          <input data-testid="mod-filter" placeholder="Filter modules" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </span>
        <span className="grow" />
        <span className="count" data-testid="mod-count">
          {mods.loading && !mods.data ? 'loading…' : filter.trim() ? `${rows.length} of ${mods.data?.total ?? 0} modules` : `${mods.data?.total ?? 0} modules`}
        </span>
        <button className="pill" data-testid="mod-refresh" onClick={mods.reload}><Icon name="refresh" size={12} />Refresh</button>
      </div>
      {mods.error && <div className="insp-note err" role="alert">Could not list modules: {mods.error}</div>}

      <div className="insp-list" role="listbox" aria-label="Modules">
        <div className="insp-head mod-cols" aria-hidden="true"><span>Module</span><span className="num">Base</span><span className="num">Size</span></div>
        {rows.map((m) => (
          <div
            key={m.base + m.name}
            role="option"
            aria-selected={selected === m.name}
            data-testid={'mod-row-' + m.name}
            className={'insp-row mod-cols' + (selected === m.name ? ' sel' : '')}
            title={m.path}
            onClick={() => { setSelected(m.name); setSymFilter(''); }}
          >
            <span className="nm">{m.name}</span>
            <span className="num mono">{m.base}</span>
            <span className="num mono dim">{fmtSize(m.size)}</span>
          </div>
        ))}
        {!rows.length && !mods.loading && !mods.error && <div className="insp-empty">{mods.data?.total ? 'No module matches the filter.' : 'No modules.'}</div>}
      </div>

      {selectedMod && (
        <div className="insp-detail" data-testid="mod-detail">
          <div className="ptool">
            <strong className="insp-title" title={selectedMod.path}>{selectedMod.name}</strong>
            <span className="seg">
              <button className={kind === 'exports' ? 'on' : ''} data-testid="sym-kind-exports" aria-pressed={kind === 'exports'} onClick={() => setKind('exports')}>Exports</button>
              <button className={kind === 'imports' ? 'on' : ''} data-testid="sym-kind-imports" aria-pressed={kind === 'imports'} onClick={() => setKind('imports')}>Imports</button>
              <button className={kind === 'strings' ? 'on' : ''} data-testid="sym-kind-strings" aria-pressed={kind === 'strings'} onClick={() => { setKind('strings'); setStrQuery(symFilter.trim().slice(0, 100)); }}>Strings</button>
            </span>
            <span className="search insp-filter"><Icon name="search" size={13} />
              <input data-testid="sym-filter" placeholder={kind === 'strings' ? 'Search strings' : 'Filter ' + kind} value={symFilter} maxLength={kind === 'strings' ? 100 : undefined} onChange={(e) => setSymFilter(e.target.value)} />
            </span>
            {kind === 'strings' && (
              <select className="mini" data-testid="str-min" aria-label="Shortest string" title="The shortest run of characters that counts as a string" value={strMin} onChange={(e) => setStrMin(Number(e.target.value))}>
                {[4, 5, 8, 12, 16, 32].map((v) => <option key={v} value={v}>{v}+ chars</option>)}
              </select>
            )}
            <span className="grow" />
            <span className="count" data-testid="sym-count">
              {kind === 'strings'
                ? (strs.loading ? 'searching…' : strs.data ? `${strs.data.items.length.toLocaleString()}${strs.data.truncated ? ' of ' + strs.data.total.toLocaleString() : ''} strings` : '')
                : syms.loading ? 'loading…' : `${symRows.length}${symFilter.trim() ? ' of ' + (syms.data?.items.length ?? 0) : ''} ${kind}`}
            </span>
            <button className="pill" data-testid="mod-view-memory" title="Open this module's base address in the Memory tab" onClick={() => onViewMemory(selectedMod.base)}>View memory</button>
          </div>
          {kind === 'strings' ? (
            <>
              {strs.error && <div className="insp-note err" role="alert" data-testid="str-error">Could not list strings: {strs.error}</div>}
              {strs.data?.timedOut && <div className="insp-note" data-testid="str-timeout">The module is large: the search stopped after {(strs.data.scanned / 1048576).toFixed(0)} MB. Strings further on are missing.</div>}
              {strs.data?.truncated && <div className="insp-note" data-testid="str-truncated">Showing the first {strs.data.items.length.toLocaleString()} of {strs.data.total.toLocaleString()}. Search to narrow them.</div>}
              <div className="insp-list">
                {(strs.data?.items ?? []).slice(0, MAX_ROWS * 2).map((s) => (
                  <div key={s.address + s.kind} className="insp-row sym-cols" data-testid="str-row" title={`${s.where} · ${s.length} characters${s.length > s.text.length ? ' (cut)' : ''} — right-click the address to find what refers to it`}>
                    <span className={'tag ' + (s.kind === 'utf16' ? 'var' : 'fn')} title={s.kind === 'utf16' ? 'UTF-16' : 'ASCII'}>{s.kind === 'utf16' ? 'w' : 'a'}</span>
                    <span className="nm mono">{s.text}{s.length > s.text.length ? '…' : ''}</span>
                    <button className="addr mono" data-testid="str-addr" title="Open in the Memory tab (right-click for more, such as Find references)" {...addrMenu(s.address)} onClick={() => onViewMemory(s.address)}>{s.address}</button>
                  </div>
                ))}
                {strs.data && !strs.data.items.length && !strs.loading && <div className="insp-empty">{strQuery ? 'No string contains that.' : 'No strings were found in this module.'}</div>}
              </div>
            </>
          ) : (
          <>
          {syms.error && <div className="insp-note err" role="alert">Could not list {kind}: {syms.error}</div>}
          {syms.data?.truncated && <div className="insp-note">Showing the first {syms.data.items.length.toLocaleString()} of {syms.data.total.toLocaleString()} {kind}.</div>}
          <div className="insp-list">
            {symRows.slice(0, MAX_ROWS).map((s, i) => (
              <div key={s.name + i} className="insp-row sym-cols" data-testid="sym-row" title={s.module ? `${s.module}!${s.name}` : s.name}>
                <span className={'tag ' + (s.type === 'variable' ? 'var' : 'fn')}>{s.type === 'variable' ? 'var' : 'fn'}</span>
                <span className="nm mono">{s.name}{kind === 'imports' && s.module ? <span className="dim"> · {s.module}</span> : null}</span>
                {s.address
                  ? <button className="addr mono" data-testid="sym-addr" title="Open in the Memory tab (right-click for more)" {...addrMenu(s.address)} onClick={() => onViewMemory(s.address as string)}>{s.address}</button>
                  : <span className="num mono dim">—</span>}
              </div>
            ))}
            {symRows.length > MAX_ROWS && <div className="insp-empty">Showing {MAX_ROWS.toLocaleString()} of {symRows.length.toLocaleString()} — filter to narrow.</div>}
            {!symRows.length && !syms.loading && !syms.error && <div className="insp-empty">{syms.data?.items.length ? `No ${kind} match the filter.` : `This module has no ${kind}.`}</div>}
          </div>
          </>
          )}
        </div>
      )}
    </div>
  );
}
