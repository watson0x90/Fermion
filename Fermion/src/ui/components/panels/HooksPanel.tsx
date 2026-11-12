import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useAppDispatch, useAppSelector } from '../../store';
import { hooksActions } from '../../store/hooksSlice';
import { cleanIpcError } from '../../inspector/format';
import { Frame, Hit, Hook, SearchKind, Target, hitTime, sameTarget } from '../../hooking/model';
import { addTarget, applyHandler, installAll, removeHook, setEnabled } from '../../hooking/ops';
import { Icon } from '../Icon';
import { addrMenu } from '../../addressMenu';
import { SetPicker } from '../SetPicker';
import { CodeEditor } from '../CodeEditor';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion?.hooks;

const ADD_ALL_MAX = 50;    // hooks placed by one "Add all"
const HITS_SHOWN = 300;    // newest hits rendered
const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;

interface Found { items: Target[]; total: number; truncated: boolean; }

const KIND_HINT: Record<SearchKind, string> = {
  exports: 'Functions that modules export',
  imports: 'Functions a module imports (module!function: the module is the one importing)',
  symbols: 'Functions named in debug symbols, exported or not',
};

const STATUS_TEXT: Record<Hook['status'], string> = {
  on: 'hooked',
  off: 'off',
  waiting: 'placed on attach',
  error: 'not placed',
};

// Hooks: find functions in the attached process and hook them, without writing
// a script. Each hook has its own handler (what to log on entry and on return)
// and an on/off switch; what the hooks log is listed here and, optionally, in
// Output. Hooks are kept across sessions and placed again on the next attach.
export function HooksPanel() {
  const dispatch = useAppDispatch();
  const isAttached = useAppSelector((s) => s.session.isAttached);
  const { hooks, selected, hits, dropped, echo } = useAppSelector((s) => s.hooks);
  const hook = hooks.find((h) => h.id === selected) ?? null;

  // ---- placing the hooks in a new session ----
  const hooksRef = useRef(hooks);
  hooksRef.current = hooks;
  useEffect(() => {
    if (!isAttached) { dispatch(hooksActions.sessionEnded()); return; } // however the session ended
    // A spawn places the hooks itself, before the program runs: skip those.
    const waiting = hooksRef.current.filter((h) => h.status !== 'on' && h.status !== 'off');
    if (waiting.length) installAll(dispatch, waiting);
  }, [isAttached, dispatch]);

  // ---- search ----
  const [kind, setKind] = useState<SearchKind>('exports');
  const [query, setQuery] = useState('');
  const [found, setFound] = useState<Found | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState('');
  const request = useRef(0);

  const search = async () => {
    const q = query.trim();
    if (!q || !isAttached) return;
    const id = ++request.current;
    setSearching(true);
    setSearchError('');
    try {
      const r = await api().search(kind, q);
      if (id !== request.current) return;
      setFound({ items: Array.isArray(r?.items) ? r.items : [], total: Number(r?.total) || 0, truncated: !!r?.truncated });
    } catch (e) {
      if (id !== request.current) return;
      setFound(null);
      setSearchError(cleanIpcError(e));
    } finally {
      if (id === request.current) setSearching(false);
    }
  };

  const isHooked = (t: Target) => hooks.some((h) => sameTarget(h, t));
  const addable = useMemo(() => (found?.items ?? []).filter((t) => !hooks.some((h) => sameTarget(h, t))), [found, hooks]);
  const add = (t: Target) => addTarget(dispatch, t, isAttached);
  const addAll = async () => { for (const t of addable.slice(0, ADD_ALL_MAX)) await addTarget(dispatch, t, isAttached); };

  // ---- the selected hook ----
  const [view, setView] = useState<'hits' | 'handler'>('hits');
  const [allHits, setAllHits] = useState(false);
  const [draft, setDraft] = useState('');
  const [draftBt, setDraftBt] = useState(true);
  const [codeError, setCodeError] = useState('');
  const [applying, setApplying] = useState(false);
  // The editor follows the selected hook; unapplied text for another hook is dropped.
  useEffect(() => {
    setDraft(hook?.code ?? '');
    setDraftBt(hook?.backtrace ?? true);
    setCodeError('');
  }, [hook?.id]);
  const changed = !!hook && (draft !== hook.code || draftBt !== hook.backtrace);

  const apply = async () => {
    if (!hook || applying) return;
    setApplying(true);
    setCodeError(await applyHandler(dispatch, hook, draft, draftBt, isAttached));
    setApplying(false);
  };
  const revert = () => { if (hook) { setDraft(hook.code); setDraftBt(hook.backtrace); setCodeError(''); } };
  // ---- hits ----
  const names = useMemo(() => new Map(hooks.map((h) => [h.id, h.name])), [hooks]);
  const shownHits = useMemo(() => {
    const mine = allHits || !hook ? hits : hits.filter((h) => h.id === hook.id);
    return mine.slice(-HITS_SHOWN);
  }, [hits, hook, allHits]);
  const hitCount = allHits || !hook ? hits.length : hits.reduce((n, h) => n + (h.id === hook.id ? 1 : 0), 0);

  const [open, setOpen] = useState<number | null>(null); // the hit whose backtrace is shown
  const [frames, setFrames] = useState<Record<number, Frame[] | string>>({});
  const toggleFrames = async (hit: Hit) => {
    if (!hit.bt) return;
    if (open === hit.seq) { setOpen(null); return; }
    setOpen(hit.seq);
    if (Array.isArray(frames[hit.seq])) return; // an earlier failure is asked again
    try {
      const r = await api().symbolicate(hit.bt);
      setFrames((f) => ({ ...f, [hit.seq]: Array.isArray(r) ? r : [] }));
    } catch (e) {
      setFrames((f) => ({ ...f, [hit.seq]: 'Could not name the callers: ' + cleanIpcError(e) }));
    }
  };

  // Keep the newest hit in view unless the operator scrolled up to read.
  const listRef = useRef<HTMLDivElement>(null);
  const pinned = useRef(true);
  const onHitsScroll = () => {
    const el = listRef.current;
    if (el) pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
  };
  useLayoutEffect(() => {
    const el = listRef.current;
    if (el && pinned.current) el.scrollTop = el.scrollHeight;
  }, [shownHits, view]);

  return (
    <div className="hooks-panel" data-testid="hooks-panel">
      <div className="ptool hook-search">
        <select className="mini" data-testid="hook-kind" aria-label="Where to search" title={KIND_HINT[kind]} value={kind} onChange={(e) => setKind(e.target.value as SearchKind)}>
          <option value="exports">Exports</option>
          <option value="imports">Imports</option>
          <option value="symbols">Debug symbols</option>
        </select>
        <span className="search insp-filter"><Icon name="search" size={13} />
          <input
            data-testid="hook-query"
            aria-label="Function to find"
            placeholder="function, or module!function — * matches anything"
            spellCheck={false}
            value={query}
            disabled={!isAttached}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') search(); }}
          />
        </span>
        <button className="pill" data-testid="hook-search" disabled={!isAttached || !query.trim() || searching} onClick={search}>{searching ? 'Searching…' : 'Find'}</button>
        <SetPicker />
      </div>
      {!isAttached && (
        <div className="insp-note" data-testid="hook-detached">
          Attach to a process to find functions.{hooks.length ? ' Your hooks are kept and are placed again when you attach.' : ''}
        </div>
      )}
      {searchError && <div className="insp-note err" role="alert">{searchError}</div>}
      {found && (
        <div className="hook-results" data-testid="hook-results">
          <div className="hook-results-head">
            <span className="count" data-testid="hook-search-status">
              {found.total === 0 ? 'No function matches.' : plural(found.total, 'function') + (found.truncated ? ` — showing the first ${found.items.length}` : '')}
            </span>
            <span className="grow" />
            {addable.length > 1 && (
              <button className="pill" data-testid="hook-add-all" title={`Hook the ${Math.min(addable.length, ADD_ALL_MAX)} functions listed that are not hooked yet`} onClick={addAll}>
                Add {addable.length > ADD_ALL_MAX ? `first ${ADD_ALL_MAX}` : `all ${addable.length}`}
              </button>
            )}
            <button className="pill ico" data-testid="hook-results-close" aria-label="Close the results" title="Close the results" onClick={() => setFound(null)}><Icon name="close" size={11} /></button>
          </div>
          <div className="hook-results-list">
            {found.items.map((t) => {
              const done = isHooked(t);
              return (
                <div className="hook-result" key={t.address} data-testid="hook-result" {...addrMenu(t.address)}>
                  <span className="nm mono" title={t.address}>{t.name}</span>
                  <span className="ad mono">{t.address}</span>
                  <button className="pill" data-testid="hook-add" disabled={done} onClick={() => add(t)}>{done ? 'Hooked' : 'Hook'}</button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="hook-list" role="listbox" aria-label="Hooks" data-testid="hook-list">
        {hooks.map((h) => (
          <div
            key={h.id}
            role="option"
            aria-selected={h.id === selected}
            data-testid={'hook-row-' + h.id}
            className={'hook-row' + (h.id === selected ? ' sel' : '') + (h.enabled ? '' : ' offrow')}
            {...addrMenu(h.address)}
            onClick={() => dispatch(hooksActions.selected(h.id))}
          >
            <input
              type="checkbox"
              data-testid="hook-toggle"
              aria-label={(h.enabled ? 'Switch off ' : 'Switch on ') + h.name}
              checked={h.enabled}
              onClick={(e) => e.stopPropagation()}
              onChange={(e) => setEnabled(dispatch, h, e.target.checked, isAttached)}
            />
            <span className="nm mono" title={h.name + ' · ' + h.address}>{h.name}</span>
            <span className={'st ' + h.status} data-testid="hook-status" title={h.error || STATUS_TEXT[h.status]}>{STATUS_TEXT[h.status]}</span>
            <span className="calls" data-testid="hook-calls" title="Times the function was called while hooked">{h.calls.toLocaleString()}</span>
            <button className="pill ico" data-testid="hook-remove" aria-label={'Remove the hook on ' + h.name} title="Remove this hook" onClick={(e) => { e.stopPropagation(); removeHook(dispatch, h, isAttached); }}><Icon name="clear" size={12} /></button>
          </div>
        ))}
        {!hooks.length && (
          <div className="insp-empty" data-testid="hook-empty">
            No hooks yet. Find a function above and press Hook: each call is then listed here, with its arguments, return value and where it was called from.
          </div>
        )}
      </div>

      {hook && (
        <div className="hook-detail" data-testid="hook-detail">
          <div className="ptool">
            <div className="seg" role="tablist" aria-label="Hook views">
              <button role="tab" aria-selected={view === 'hits'} data-testid="hook-tab-hits" className={view === 'hits' ? 'on' : ''} onClick={() => setView('hits')}>Calls</button>
              <button role="tab" aria-selected={view === 'handler'} data-testid="hook-tab-handler" className={view === 'handler' ? 'on' : ''} onClick={() => setView('handler')}>Handler{changed ? ' •' : ''}</button>
            </div>
            <strong className="insp-title mono" title={hook.name}>{hook.name}</strong>
            <span className="grow" />
            {view === 'hits' && (
              <>
                <span className="count" data-testid="hook-hit-count">
                  {plural(hitCount, 'line')}{dropped ? ` · ${dropped.toLocaleString()} dropped` : ''}
                </span>
                <button className={'pill' + (allHits ? ' on' : '')} data-testid="hook-hits-all" aria-pressed={allHits} title="Show what every hook logged, not only this one" onClick={() => setAllHits(!allHits)}>All hooks</button>
                <button className={'pill' + (echo ? ' on' : '')} data-testid="hook-echo" aria-pressed={echo} title="Also print what hooks log in the Output pane" onClick={() => dispatch(hooksActions.echoSet(!echo))}>Output</button>
                <button className="pill ico" data-testid="hook-hits-clear" aria-label="Clear the calls listed" title="Clear the calls listed" onClick={() => { dispatch(hooksActions.hitsCleared()); setFrames({}); setOpen(null); }}><Icon name="clear" size={12} /></button>
              </>
            )}
            {view === 'handler' && (
              <>
                <label className="chk" title="Record where each call came from. Costs time on every call that logs; switch it off for very busy functions.">
                  <input type="checkbox" data-testid="hook-backtrace" checked={draftBt} onChange={(e) => setDraftBt(e.target.checked)} />Callers
                </label>
                <button className="pill" data-testid="hook-revert" disabled={!changed} onClick={revert}>Revert</button>
                <button className="pill on" data-testid="hook-apply" disabled={!changed || applying || !draft.trim()} title="Use this handler from the next call (Ctrl+Enter)" onClick={apply}>Apply</button>
              </>
            )}
          </div>
          {hook.status === 'error' && <div className="insp-note err" role="alert" data-testid="hook-error">This hook is not placed: {hook.error}</div>}

          {view === 'handler' && (
            <div className="hook-code">
              {codeError && <div className="insp-note err" role="alert" data-testid="hook-code-error">{codeError}</div>}
              <CodeEditor testId="hook-code" label="Handler" value={draft} onChange={setDraft} onApply={apply} exposeAs="MonacoHookEditor" />
              <div className="hook-code-help">
                <code>log(…)</code> adds a line to Calls. <code>args[n]</code> and <code>retval</code> are pointers: read them with <code>.readUtf8String()</code>, <code>.readUtf16String()</code>, <code>.toInt32()</code>. <code>retval.replace(x)</code> changes what the function returns. <code>this</code> is shared between onEnter and onLeave.
              </div>
            </div>
          )}

          {view === 'hits' && (
            <div className="hook-hits" ref={listRef} onScroll={onHitsScroll} data-testid="hook-hits">
              {shownHits.map((hit) => {
                const fr = frames[hit.seq];
                return (
                  <div key={hit.seq} className={'hook-hit' + (hit.error ? ' err' : '') + (hit.bt ? ' has-bt' : '')} data-testid="hook-hit">
                    <button
                      className="hit-line"
                      disabled={!hit.bt}
                      aria-expanded={hit.bt ? open === hit.seq : undefined}
                      title={hit.bt ? 'Show where this call came from' : undefined}
                      onClick={() => toggleFrames(hit)}
                    >
                      <span className="ht">{hitTime(hit.t)}</span>
                      <span className="hd" title={'thread ' + hit.tid}>{hit.tid}</span>
                      <span className="hx mono" style={{ paddingLeft: Math.min(hit.depth, 12) * 10 }}>
                        <span className="ph">{hit.phase === 'leave' ? '←' : '→'}</span>
                        {allHits && <span className="hn">{names.get(hit.id) ?? ''} </span>}
                        {hit.text}
                      </span>
                    </button>
                    {open === hit.seq && hit.bt && (
                      <div className="hook-frames" data-testid="hook-frames">
                        {fr === undefined && <div className="insp-empty">Naming the callers…</div>}
                        {typeof fr === 'string' && <div className="insp-note err" role="alert">{fr}</div>}
                        {Array.isArray(fr) && (() => {
                          // Callers inside a module are listed. The unwinder also returns
                          // addresses that belong to no module (JIT code, or stack values
                          // it mistook for return addresses): those are only counted.
                          const inModule = fr.filter((f) => f.name || !/^0x/.test(f.where));
                          const others = fr.length - inModule.length;
                          return (
                            <>
                              {inModule.map((f, i) => (
                                <div className="hook-frame" key={f.address + i} data-testid="hook-frame" {...addrMenu(f.address)}>
                                  <span className="fi">{i}</span>
                                  <span className="mono" title={f.address + ' · ' + f.where}>{f.name || f.where}</span>
                                </div>
                              ))}
                              {others > 0 && (
                                <div className="hook-frame dim" data-testid="hook-frames-other" title={fr.filter((f) => !inModule.includes(f)).map((f) => f.address).join('  ')}>
                                  <span className="fi">+</span>
                                  <span>{others.toLocaleString()} more outside any module (JIT code or unwinder noise)</span>
                                </div>
                              )}
                              {!fr.length && <div className="insp-empty">No callers were recorded.</div>}
                            </>
                          );
                        })()}
                      </div>
                    )}
                  </div>
                );
              })}
              {!shownHits.length && (
                <div className="insp-empty">
                  {hook.status === 'on' ? 'Nothing logged yet. Lines appear when the function is called.' : 'Nothing logged yet.'}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
