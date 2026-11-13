import { addrMenu } from '../../../addressMenu';
import { useEffect, useRef, useState } from 'react';
import { Icon } from '../../Icon';
import { parseAddress, cleanIpcError } from '../../../inspector/format';
import { inspectApi, useInspect, Listing } from '../../../inspector/useInspect';
import { FollowItem, FollowModule, FollowMode, FollowScope, scopeText } from '../../../inspector/follow';
import { FollowResults } from './FollowResults';
import { usePrefs } from '../../../store/prefsSlice';
import { useNames } from '../../../names';

interface Thr { id: number; name: string; state: string; pc: string | null; where: string; registers: Record<string, string>; }

interface FollowResult { threadId: number | null; calls: number; total: number; truncated: boolean; endedBy: string; items: FollowItem[]; modules?: FollowModule[]; scope?: FollowScope | null; }
interface Mod { name: string; }
interface Frame { address: string; where: string; symbol: string; }

// Threads of the target with where each one is; selecting a thread shows its
// register context and a backtrace. Pointer-like values open in the Memory tab.
export function ThreadsTab({ active, onViewMemory }: { active: boolean; onViewMemory: (address: string) => void }) {
  const [auto, setAuto] = useState(false);
  const prefs = usePrefs();
  const names = useNames();
  const threads = useInspect<Listing<Thr>>(() => inspectApi().threads(), 'threads', active, auto ? prefs.autoRefreshSeconds * 1000 : 0);
  const [selected, setSelected] = useState<number | null>(null);
  const thread = threads.data?.items.find((t) => t.id === selected) ?? null;

  const trace = useInspect<Listing<Frame>>(
    () => inspectApi().backtrace(selected),
    `bt|${selected}|${thread?.pc ?? ''}`,
    active && thread != null,
  );

  // ---- following a thread with Stalker ----
  const [following, setFollowing] = useState<number | null>(null);
  const [followBusy, setFollowBusy] = useState(false);
  const [followRes, setFollowRes] = useState<FollowResult | null>(null);
  const [followErr, setFollowErr] = useState('');
  // What the follow covers: everything, everything but system libraries, or
  // one module. Stalker does not go into what is left out.
  const [scopeMode, setScopeMode] = useState<FollowMode>(prefs.followScope);
  const [scopeModule, setScopeModule] = useState('');
  const [activeScope, setActiveScope] = useState<FollowScope | null>(null);
  const [run, setRun] = useState(0); // a new result view (filter cleared) per follow
  const moduleNames = useInspect<Listing<Mod>>(() => inspectApi().modules(), 'follow-modules', active && scopeMode === 'module');
  const scopeReady = scopeMode !== 'module' || scopeModule.trim() !== '';
  const maxSeconds = useRef(15);
  const limitTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const followingRef = useRef<number | null>(null);
  followingRef.current = following;

  const stopFollow = async () => {
    if (limitTimer.current) { clearTimeout(limitTimer.current); limitTimer.current = null; }
    setFollowBusy(true);
    try {
      setFollowRes(await inspectApi().unfollow());
      setFollowErr('');
    } catch (e) {
      setFollowErr('Could not collect the calls: ' + cleanIpcError(e));
    } finally {
      setFollowing(null);
      setFollowBusy(false);
    }
  };
  const startFollow = async (id: number) => {
    setFollowBusy(true);
    setFollowErr('');
    setFollowRes(null);
    try {
      const asked: FollowScope = { mode: scopeMode, module: scopeMode === 'module' ? scopeModule.trim() : '' };
      const r = await inspectApi().follow(id, asked);
      maxSeconds.current = Number(r?.maxSeconds) || 15;
      setActiveScope(r?.scope ?? asked);
      setRun((n) => n + 1);
      setFollowing(id);
      // The agent stops by itself at the limit; collect the result then.
      limitTimer.current = setTimeout(() => { if (followingRef.current !== null) stopFollow(); }, maxSeconds.current * 1000 + 300);
    } catch (e) {
      setFollowErr(cleanIpcError(e));
    } finally {
      setFollowBusy(false);
    }
  };
  // Leaving the Inspector for a new session: do not leave a thread being stalked.
  useEffect(() => () => {
    if (limitTimer.current) clearTimeout(limitTimer.current);
    if (followingRef.current !== null) inspectApi()?.unfollow?.().catch(() => {});
  }, []);

  const dash = (text: string) => (text ? ' — ' + text : '');
  const followStatus = following !== null
    ? `Following thread ${following} — counting the calls it makes (up to ${maxSeconds.current} seconds)` + dash(scopeText(activeScope)) + '.'
    : followRes
      ? `${followRes.calls.toLocaleString()} calls to ${followRes.total.toLocaleString()} functions`
        + dash(scopeText(followRes.scope ?? activeScope))
        + (followRes.endedBy === 'limit' ? ` — stopped at the ${maxSeconds.current} second limit` : '')
        + (followRes.truncated ? ` — showing the ${followRes.items.length} most-called` : '')
      : '';

  return (
    <div className="insp-tab">
      <div className="ptool">
        <span className="grow">Register values are a snapshot from the last refresh.</span>
        <span className="count" data-testid="thr-count">{threads.loading && !threads.data ? 'loading…' : `${threads.data?.total ?? 0} threads`}</span>
        <button className={'pill' + (auto ? ' on' : '')} data-testid="thr-auto" aria-pressed={auto} title={`Re-read the threads every ${prefs.autoRefreshSeconds === 1 ? 'second' : prefs.autoRefreshSeconds + ' seconds'} while this view is open`} onClick={() => setAuto(!auto)}>Auto</button>
        <button className="pill" data-testid="thr-refresh" onClick={threads.reload}><Icon name="refresh" size={12} />Refresh</button>
      </div>
      {threads.error && <div className="insp-note err" role="alert">Could not list threads: {threads.error}</div>}

      <div className="insp-list" role="listbox" aria-label="Threads">
        <div className="insp-head thr-cols" aria-hidden="true"><span className="num">TID</span><span>State</span><span>Where</span></div>
        {(threads.data?.items ?? []).map((t) => (
          <div
            key={t.id}
            role="option"
            aria-selected={selected === t.id}
            data-testid={'thr-row-' + t.id}
            className={'insp-row thr-cols' + (selected === t.id ? ' sel' : '')}
            onClick={() => setSelected(t.id)}
          >
            <span className="num mono">{t.id}</span>
            <span className={'state ' + t.state}>{t.state}</span>
            <span className="nm mono">{t.name ? <span className="dim">{t.name} · </span> : null}{t.where}</span>
          </div>
        ))}
        {!threads.data?.items.length && !threads.loading && !threads.error && <div className="insp-empty">No threads.</div>}
      </div>

      {thread && (
        <div className="insp-detail" data-testid="thr-detail">
          <div className="ptool">
            <strong className="insp-title">Thread {thread.id}{thread.name ? ' · ' + thread.name : ''}</strong>
            <span className="grow" />
            <span className="count">{trace.loading ? 'unwinding…' : `${trace.data?.items.length ?? 0} frames`}</span>
            <select
              className="mini"
              data-testid="thr-follow-scope"
              aria-label="What to follow"
              value={scopeMode}
              disabled={following !== null || followBusy}
              title="What Follow covers. Leaving code out makes the thread run faster while followed: calls into it are still counted, what happens inside it is not."
              onChange={(e) => setScopeMode(e.target.value as FollowMode)}
            >
              <option value="all">Follow everything</option>
              <option value="app">Skip system libraries</option>
              <option value="module">Only one module</option>
            </select>
            {scopeMode === 'module' && (
              <>
                <input
                  className="mini follow-module"
                  data-testid="thr-follow-module"
                  aria-label="Module to follow"
                  placeholder="module name"
                  list="thr-follow-modules"
                  spellCheck={false}
                  value={scopeModule}
                  disabled={following !== null || followBusy}
                  onChange={(e) => setScopeModule(e.target.value)}
                />
                <datalist id="thr-follow-modules">
                  {(moduleNames.data?.items ?? []).map((m) => <option key={m.name} value={m.name} />)}
                </datalist>
              </>
            )}
            <button
              className={'pill' + (following !== null ? ' on' : '')}
              data-testid="thr-follow"
              disabled={followBusy || (following === null && !scopeReady)}
              title={following !== null
                ? 'Stop following and show the calls counted'
                : !scopeReady
                  ? 'Enter the name of the module to follow'
                  : 'Follow this thread with Stalker and count the calls it makes. Heavier than the other views: it slows the thread while it runs.'}
              onClick={() => (following !== null ? stopFollow() : startFollow(thread.id))}
            >
              <Icon name={following !== null ? 'stop' : 'play'} size={11} />{following !== null ? 'Stop' : 'Follow'}
            </button>
          </div>
          {followErr && <div className="insp-note err" role="alert">{followErr}</div>}
          {followStatus && (
            <div className="insp-note" data-testid="thr-follow-status">
              {followStatus}
              {following === null && followRes && <button className="linkbtn" data-testid="thr-follow-dismiss" onClick={() => setFollowRes(null)}>back to backtrace</button>}
            </div>
          )}
          <div className="insp-split">
            <div className="regs" data-testid="thr-registers">
              {Object.entries(thread.registers).map(([name, value]) => {
                const addr = parseAddress(value);
                return (
                  <div className="reg" key={name}>
                    <span className="rn">{name}</span>
                    {addr
                      ? <button className="addr mono" data-testid={'reg-' + name} title="Open in the Memory tab (right-click for more)" {...addrMenu(addr)} onClick={() => onViewMemory(addr)}>{value}</button>
                      : <span className="mono" data-testid={'reg-' + name}>{value}</span>}
                  </div>
                );
              })}
              {!Object.keys(thread.registers).length && <div className="insp-empty">No register context for this thread.</div>}
            </div>
            {following === null && followRes ? (
              <FollowResults key={run} threadId={followRes.threadId} items={followRes.items} modules={followRes.modules} onViewMemory={onViewMemory} />
            ) : (
            <div className="frames">
              {trace.error && <div className="insp-note err" role="alert">Could not unwind: {trace.error}</div>}
              {(trace.data?.items ?? []).map((f, i) => (
                <div className="frame" key={f.address + i} data-testid="bt-row">
                  <span className="fi">{i}</span>
                  <button className="fsym mono" title={`${f.address} · ${f.where} — open in the Memory tab (right-click for more)`} {...addrMenu(f.address)} onClick={() => onViewMemory(f.address)}>{names.show(f.where, f.address, f.symbol)}</button>
                </div>
              ))}
            </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
