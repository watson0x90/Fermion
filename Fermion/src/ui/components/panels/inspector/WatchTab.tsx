import { useEffect, useRef, useState } from 'react';
import { cleanIpcError, parseAddress } from '../../../inspector/format';
import { inspectApi } from '../../../inspector/useInspect';
import { addrMenu } from '../../../addressMenu';
import { writeTerminal } from '../../../bridge';
import { usePrefs } from '../../../store/prefsSlice';
import { Goto } from './MemoryTab';

interface Frame { address: string; where: string; symbol: string; }
export interface WatchPlace { op: string; from: string; where: string; symbol: string; hits: number; near: number; last: string | null; threads: number[]; frames: Frame[]; }
export interface WatchResult {
  watching: boolean; endedBy: string; address: string | null; size: number; seconds: number; hits: number; near: number;
  places: number; truncated: boolean; error: string; items: WatchPlace[];
}
export type WatchMode = 'auto' | 'sampled';
interface Started { watching: boolean; address: string; size: number; mode?: string; reason?: string; threads?: number; pages: number; pageSize: number; maxSeconds: number; protection: string; }

export const MAX_WATCH_BYTES = 4096;
const POLL_MS = 500;
const n = (v: number) => v.toLocaleString('en-US');
const plural = (count: number, word: string, many = word + 's') => `${n(count)} ${count === 1 ? word : many}`;

// "8" -> 8; anything that is not 1..4096 -> null.
export function parseWatchSize(text: string): number | null {
  const t = text.trim();
  if (!/^\d{1,4}$/.test(t)) return null;
  const v = Number(t);
  return v >= 1 && v <= MAX_WATCH_BYTES ? v : null;
}

// One sentence for what a watch has seen on the bytes themselves.
export function watchLine(r: WatchResult): string {
  const places = r.items.filter((i) => i.hits > 0).length;
  return `${plural(r.hits, 'access', 'accesses')} from ${plural(places, 'place')} in ${r.seconds} s`;
}

const placeKey = (p: WatchPlace) => p.op + '|' + p.from;

// Watch: which code reads or writes some bytes of data. The agent traps the
// page holding them and samples the accesses; this view starts and stops the
// watch and lists the places the accesses came from, each with a call stack.
export function WatchTab({ goto }: { goto: Goto | null }) {
  const [address, setAddress] = useState('');
  const [size, setSize] = useState('8');
  const prefs = usePrefs();
  const [mode, setMode] = useState<WatchMode>(prefs.watchMode);
  const [started, setStarted] = useState<Started | null>(null);
  const [result, setResult] = useState<WatchResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [showNear, setShowNear] = useState(false);
  const [selected, setSelected] = useState('');
  const watchingRef = useRef(false);
  watchingRef.current = started !== null;

  // An address handed over from the address menu: fill it in, start nothing.
  useEffect(() => { if (goto && !watchingRef.current) setAddress(goto.address); }, [goto?.n]); // keyed on the hand-off counter only

  const parsed = parseAddress(address.trim());
  const bytes = parseWatchSize(size);
  const ready = !!parsed && bytes !== null;

  const finish = (r: WatchResult) => {
    setResult(r);
    setStarted(null);
    if (r.address) writeTerminal('STATUS', `[+] Memory watch on ${r.address} (${plural(r.size, 'byte')}): ${watchLine(r)}`);
  };

  const stop = async () => {
    if (busy) return;
    setBusy(true);
    try {
      finish(await inspectApi().watchStop());
    } catch (e) {
      setError('Could not stop the watch: ' + cleanIpcError(e));
      setStarted(null);
    } finally {
      setBusy(false);
    }
  };

  const start = async () => {
    if (busy || !parsed || bytes === null) return;
    setBusy(true);
    setError('');
    try {
      const s: Started = await inspectApi().watchStart(parsed, bytes, mode);
      setResult(null);
      setSelected('');
      setStarted(s);
    } catch (e) {
      setError(cleanIpcError(e));
    } finally {
      setBusy(false);
    }
  };

  // While it runs, ask what has been seen. A watch that has ended by itself
  // (the time limit, or the memory was freed) is collected here.
  const finishRef = useRef(finish);
  finishRef.current = finish;
  useEffect(() => {
    if (!started) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout>;
    const ask = async () => {
      try {
        const r: WatchResult = await inspectApi().watchHits();
        if (!live) return;
        if (r.watching) setResult(r); else { finishRef.current(r); return; }
      } catch { /* the session ended: the panel is about to be replaced */ }
      if (live) timer = setTimeout(ask, POLL_MS);
    };
    ask();
    return () => { live = false; clearTimeout(timer); };
  }, [started]);

  // The view goes away with its session: take the trap off the page.
  useEffect(() => () => { if (watchingRef.current) inspectApi()?.watchStop?.().catch(() => {}); }, []);

  const items = result ? result.items.filter((i) => showNear || i.hits > 0) : [];
  const picked = items.find((i) => placeKey(i) === selected) ?? null;
  const ended = result && !started ? result.endedBy : '';

  return (
    <div className="insp-tab watch-tab">
      <div className="ptool">
        <input className="mini watch-address" data-testid="watch-address" aria-label="Address to watch" placeholder="address, e.g. 0x7ff6a2c41000" spellCheck={false} value={address} disabled={!!started || busy}
          onChange={(e) => setAddress(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && ready && !started) start(); }} />
        <input className="mini watch-size" data-testid="watch-size" aria-label="Bytes to watch" title={'How many bytes, 1 to ' + n(MAX_WATCH_BYTES)} inputMode="numeric" value={size} disabled={!!started || busy} onChange={(e) => setSize(e.target.value)} />
        <span>bytes</span>
        <select className="mini" data-testid="watch-mode" aria-label="How to watch" value={mode} disabled={!!started || busy} onChange={(e) => setMode(e.target.value as WatchMode)}
          title="Exact counts every access with the processor's hardware watchpoints (Windows; a few aligned bytes). The page trap works on anything up to 4,096 bytes but only samples.">
          <option value="auto">Exact when possible</option>
          <option value="sampled">Sampled (page trap)</option>
        </select>
        <button className={'pill' + (started ? ' on' : '')} data-testid="watch-toggle" disabled={busy || (!started && !ready)} onClick={started ? stop : start}>
          {started ? (busy ? 'Stopping…' : 'Stop') : busy ? 'Starting…' : 'Watch'}
        </button>
        <span className="grow" />
        {result && <span className="count" data-testid="watch-line">{watchLine(result)}</span>}
      </div>

      {error && <div className="insp-note err" role="alert" data-testid="watch-error">{error}</div>}
      {started && started.mode === 'exact' && (
        <div className="insp-note" data-testid="watch-status">
          Watching {plural(started.size, 'byte')} at {started.address} exactly: every access is counted, on {plural(started.threads ?? 0, 'thread')} and any that start. Use the program now, then press Stop.
          The address of a place is the instruction after the one that touched the bytes. It stops by itself after {Math.round(started.maxSeconds / 60)} minutes or 200,000 accesses.
        </div>
      )}
      {started && started.mode !== 'exact' && (
        <div className="insp-note" data-testid="watch-status">
          Watching {plural(started.size, 'byte')} at {started.address}. Use the program now, then press Stop.
          Accesses are sampled, so the counts are a lower bound: after each one the watch needs a few milliseconds to come back.
          A system call that is handed this memory fails while it is watched. It stops by itself after {Math.round(started.maxSeconds / 60)} minutes.
          {started.reason ? ` These bytes could not be watched exactly: ${started.reason}.` : ''}
        </div>
      )}
      {ended === 'limit' && <div className="insp-note" data-testid="watch-ended">The watch stopped at its limit.</div>}
      {ended === 'lost' && <div className="insp-note err" data-testid="watch-ended">The watch ended: the memory can no longer be trapped (it was probably freed){result?.error ? ': ' + result.error : ''}.</div>}

      {!started && !result && !error && (
        <div className="insp-empty big" data-testid="watch-empty">
          See which code reads or writes some bytes of data. Enter an address, or right-click one anywhere and choose Watch reads and writes;
          press Watch, then use the program. Each place that touched the bytes is listed with its call stack.
        </div>
      )}

      {result && (
        <>
          {result.near > 0 && (
            <div className="insp-note watch-near" data-testid="watch-near">
              {plural(result.near, 'access', 'accesses')} to other bytes on the same page {showNear ? 'are listed too' : 'are not listed'}.
              <button className="pill" data-testid="watch-near-toggle" onClick={() => setShowNear(!showNear)}>{showNear ? 'Hide them' : 'Show them'}</button>
            </div>
          )}
          <div className="insp-list">
            <div className="insp-head watch-cols" aria-hidden="true"><span>Access</span><span>From</span><span className="num">Times</span><span>Last byte</span><span>Threads</span></div>
            {items.map((p) => (
              <div key={placeKey(p)} className={'insp-row watch-cols' + (placeKey(p) === selected ? ' sel' : '')} role="option" aria-selected={placeKey(p) === selected} tabIndex={0} data-testid="watch-row"
                title={p.from} onClick={() => setSelected(placeKey(p))} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelected(placeKey(p)); } }} {...addrMenu(p.from)}>
                <span className={'op ' + p.op}>{p.op}</span>
                <span className="nm">{p.symbol || p.where}</span>
                <span className="num mono">{n(p.hits)}{showNear && p.near ? ' + ' + n(p.near) : ''}</span>
                <span className="nm mono dim">{p.last ?? ''}</span>
                <span className="nm dim">{p.threads.join(', ')}</span>
              </div>
            ))}
            {!items.length && <div className="insp-empty">{started ? 'Nothing has touched the bytes yet.' : 'Nothing touched the bytes while they were watched.'}</div>}
            {result.truncated && <div className="insp-empty">More places touched the page than are listed.</div>}
          </div>
          {picked && (
            <div className="watch-stack" data-testid="watch-stack">
              <div className="watch-stack-head">
                Call stack of the first {picked.op} from <span className="mono" {...addrMenu(picked.from)}>{picked.where}</span>
              </div>
              {picked.frames.map((f, i) => (
                <div key={i + f.address} className="insp-row watch-frame" data-testid="watch-frame" {...addrMenu(f.address)}><span className="nm">{f.symbol || f.where}</span><span className="nm mono dim">{f.address}</span></div>
              ))}
              {!picked.frames.length && <div className="insp-empty">No call stack was taken for this place: it only touched other bytes of the page.</div>}
            </div>
          )}
        </>
      )}
    </div>
  );
}
