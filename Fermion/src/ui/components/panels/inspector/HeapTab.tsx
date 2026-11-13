import { useEffect, useRef, useState } from 'react';
import { cleanIpcError, fmtSize, parseAddress } from '../../../inspector/format';
import { inspectApi } from '../../../inspector/useInspect';
import { addrMenu } from '../../../addressMenu';
import { writeTerminal } from '../../../bridge';
import { Goto } from './MemoryTab';

interface Frame { address: string | null; where: string; symbol: string; }
interface Site { frames: Frame[]; blocks: number; bytes: number; }
export interface HeapStatus {
  tracking: boolean; endedBy: string; seconds: number; min: number; max: number; functions: string[];
  allocs: number; frees: number; live: number; liveBytes: number; freedKept: number; overflow: boolean; siteCount: number; sites: Site[];
}
export interface HeapBlock { address: string; size: number; offset: number; thread: number; at: number; frames: Frame[]; freed: { thread: number; at: number; frames: Frame[] } | null; }
export interface HeapFound { address: string; tracking: boolean; live: HeapBlock | null; freed: HeapBlock[]; freedTotal: number; }
interface Started { tracking: boolean; functions: string[]; min: number; max: number; maxSeconds: number; maxLive: number; maxFreed: number; }

const MAX_SIZE = 0xffffffff;
const POLL_MS = 1000;
const n = (v: number) => v.toLocaleString('en-US');
const plural = (count: number, word: string) => `${n(count)} ${word}${count === 1 ? '' : 's'}`;

// The two size fields -> { min, max } (blank is no limit, sent as 0); null when they make no sense.
export function parseHeapSizes(minText: string, maxText: string): { min: number; max: number } | null {
  const one = (text: string) => {
    const t = text.trim();
    if (!t) return 0;
    if (!/^\d{1,10}$/.test(t)) return null;
    const v = Number(t);
    return v <= MAX_SIZE ? v : null;
  };
  const min = one(minText);
  const max = one(maxText);
  if (min === null || max === null) return null;
  if (max !== 0 && max < min) return null;
  return { min, max };
}

export function sizesText(min: number, max: number): string {
  if (!min && !max) return 'any size';
  if (min && !max) return `${plural(min, 'byte')} or more`;
  if (min === max) return `exactly ${plural(min, 'byte')}`;
  return `${n(min)} to ${plural(max, 'byte')}`;
}

export function countsLine(s: HeapStatus): string {
  return `${n(s.allocs)} allocated, ${n(s.frees)} freed, ${n(s.live)} live (${fmtSize(s.liveBytes)})`;
}

// What it means for an address to be where it was found.
export function heapVerdict(f: HeapFound): string {
  if (f.live && f.freed.length) {
    return `${f.address} is inside a live block. The same memory belonged to ${plural(f.freedTotal, 'block')} freed earlier: a pointer kept from before now reaches the new block.`;
  }
  if (f.live) return `${f.address} is inside a live block.`;
  if (f.freed.length) return `${f.address} is inside a block that has been freed. Using it now is a use after free.`;
  return `${f.address} is not inside any block recorded since tracking began. Blocks allocated before that, or outside the size range, are not known.`;
}

const frameName = (f: Frame) => f.symbol || f.where;

function Frames({ title, frames }: { title: string; frames: Frame[] }) {
  return (
    <div className="heap-stack">
      <div className="heap-stack-head">{title}</div>
      {frames.map((f, i) => (
        <div key={i + (f.address ?? '')} className="insp-row heap-frame" data-testid="heap-frame" {...addrMenu(f.address)}><span className="nm">{frameName(f)}</span><span className="nm mono dim">{f.address}</span></div>
      ))}
      {!frames.length && <div className="insp-empty">No call stack could be taken.</div>}
    </div>
  );
}

function Block({ block, kind }: { block: HeapBlock; kind: 'live' | 'freed' }) {
  return (
    <div className={'heap-block ' + kind} data-testid="heap-block" data-kind={kind}>
      <div className="heap-block-head">
        <span className={'tag ' + kind}>{kind}</span>
        <span>{plural(block.size, 'byte')} at <span className="mono" {...addrMenu(block.address)}>{block.address}</span>; the address is byte +0x{block.offset.toString(16)}</span>
      </div>
      <Frames title={`Allocated by thread ${block.thread}, ${block.at} s into tracking`} frames={block.frames} />
      {block.freed && <Frames title={`Freed by thread ${block.freed.thread}, ${block.freed.at} s into tracking`} frames={block.freed.frames} />}
    </div>
  );
}

// Heap: record the blocks the program allocates and frees, with the call
// stack of each, and say which block an address is in or was in. That is the
// question behind a use after free: who allocated this, who freed it, and has
// the memory been handed out again?
export function HeapTab({ goto }: { goto: Goto | null }) {
  const [minText, setMinText] = useState('');
  const [maxText, setMaxText] = useState('');
  const [started, setStarted] = useState<Started | null>(null);
  const [status, setStatus] = useState<HeapStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [address, setAddress] = useState('');
  const [found, setFound] = useState<HeapFound | null>(null);
  const trackingRef = useRef(false);
  trackingRef.current = started !== null;
  const knownRef = useRef(false);
  knownRef.current = started !== null || status !== null;

  const sizes = parseHeapSizes(minText, maxText);
  const parsed = parseAddress(address.trim());
  const known = started !== null || status !== null; // something has been recorded to ask about

  const find = async (at: string | null) => {
    if (!at) return;
    setError('');
    try {
      setFound(await inspectApi().heapFind(at));
    } catch (e) {
      setFound(null);
      setError(cleanIpcError(e));
    }
  };

  // An address handed over from the address menu: look it up if there is anything to look in.
  const findRef = useRef(find);
  findRef.current = find;
  useEffect(() => {
    if (!goto) return;
    setAddress(goto.address);
    if (knownRef.current) findRef.current(parseAddress(goto.address));
  }, [goto?.n]); // keyed on the hand-off counter only

  const finish = (s: HeapStatus) => {
    setStatus(s);
    setStarted(null);
    writeTerminal('STATUS', `[+] Heap tracking (${sizesText(s.min, s.max)}): ${countsLine(s)}`);
  };

  const stop = async () => {
    if (busy) return;
    setBusy(true);
    try {
      finish(await inspectApi().heapStop());
    } catch (e) {
      setError('Could not stop tracking: ' + cleanIpcError(e));
      setStarted(null);
    } finally {
      setBusy(false);
    }
  };

  const start = async () => {
    if (busy || !sizes) return;
    setBusy(true);
    setError('');
    try {
      const s: Started = await inspectApi().heapStart(sizes);
      setStatus(null);
      setFound(null);
      setStarted(s);
    } catch (e) {
      setError(cleanIpcError(e));
    } finally {
      setBusy(false);
    }
  };

  // While it runs, ask for the counts. Tracking that has ended by itself (the
  // time limit) is collected here.
  const finishRef = useRef(finish);
  finishRef.current = finish;
  useEffect(() => {
    if (!started) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout>;
    const ask = async () => {
      try {
        const s: HeapStatus = await inspectApi().heapStatus();
        if (!live) return;
        if (s.tracking) setStatus(s); else { finishRef.current(s); return; }
      } catch { /* the session ended: the panel is about to be replaced */ }
      if (live) timer = setTimeout(ask, POLL_MS);
    };
    ask();
    return () => { live = false; clearTimeout(timer); };
  }, [started]);

  // The view goes away with its session: take the hooks off the allocator.
  useEffect(() => () => { if (trackingRef.current) inspectApi()?.heapStop?.().catch(() => {}); }, []);

  const ended = status && !started ? status.endedBy : '';

  return (
    <div className="insp-tab heap-tab">
      <div className="ptool">
        <span>Blocks from</span>
        <input className="mini heap-size" data-testid="heap-min" aria-label="Smallest block size to track, in bytes" placeholder="any" inputMode="numeric" value={minText} disabled={!!started || busy} onChange={(e) => setMinText(e.target.value)} />
        <span>to</span>
        <input className="mini heap-size" data-testid="heap-max" aria-label="Largest block size to track, in bytes" placeholder="any" inputMode="numeric" value={maxText} disabled={!!started || busy} onChange={(e) => setMaxText(e.target.value)} />
        <span>bytes</span>
        <button className={'pill' + (started ? ' on' : '')} data-testid="heap-toggle" disabled={busy || (!started && !sizes)} onClick={started ? stop : start}
          title="Record the blocks the program allocates and frees, each with its call stack">
          {started ? (busy ? 'Stopping…' : 'Stop') : busy ? 'Starting…' : 'Track'}
        </button>
        <span className="grow" />
        {status && <span className="count" data-testid="heap-counts">{countsLine(status)}</span>}
      </div>
      <div className="ptool">
        <input className="mini heap-address" data-testid="heap-address" aria-label="Address to find the block of" placeholder="address to look up, e.g. 0x1d2f2c68010" spellCheck={false} value={address}
          onChange={(e) => setAddress(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && parsed && known) find(parsed); }} />
        <button className="pill" data-testid="heap-find" disabled={!parsed || !known} title={known ? 'Which block is this address in, or was it in?' : 'Track the heap first'} onClick={() => find(parsed)}>Find block</button>
      </div>

      {error && <div className="insp-note err" role="alert" data-testid="heap-error">{error}</div>}
      {started && (
        <div className="insp-note" data-testid="heap-status">
          Tracking blocks of {sizesText(started.min, started.max)} through {started.functions.join(', ')}. Use the program now.
          {!started.min && !started.max ? ' Taking a call stack for every block slows a program that allocates a lot: give a size range to keep it fast.' : ''}
          {' '}It stops by itself after {Math.round(started.maxSeconds / 60)} minutes; the newest {n(started.maxFreed)} freed blocks are kept.
        </div>
      )}
      {ended === 'limit' && <div className="insp-note" data-testid="heap-ended">Tracking stopped at its time limit. What was recorded can still be looked up.</div>}
      {status?.overflow && <div className="insp-note err" data-testid="heap-overflow">More than {n(started?.maxLive ?? 200000)} blocks were live at once: later ones were not recorded. Give a size range.</div>}

      {!known && !error && (
        <div className="insp-empty big" data-testid="heap-empty">
          Find out which block an address is in, who allocated it and who freed it. Press Track, use the program, then look an address up
          (or right-click one anywhere and choose Find heap block). Only blocks allocated while tracking runs are known.
        </div>
      )}

      <div className="heap-body">
        {found && (
          <div className="heap-found" data-testid="heap-found">
            <div className={'heap-verdict' + (!found.live && found.freed.length ? ' uaf' : '')} data-testid="heap-verdict">{heapVerdict(found)}</div>
            {found.live && <Block block={found.live} kind="live" />}
            {found.freed.map((b, i) => <Block key={i + b.address + b.at} block={b} kind="freed" />)}
            {found.freedTotal > found.freed.length && <div className="insp-empty">{n(found.freedTotal - found.freed.length)} older freed blocks at this address are not shown.</div>}
          </div>
        )}
        {status && (
          <div className="heap-sites">
            <div className="insp-head heap-cols" aria-hidden="true"><span>Live memory was allocated by</span><span className="num">Blocks</span><span className="num">Bytes</span></div>
            {status.sites.map((s, i) => (
              <div key={i + (s.frames[0]?.address ?? '')} className="insp-row heap-cols" data-testid="heap-site" title={s.frames.map(frameName).join('  <  ')} {...addrMenu(s.frames[0]?.address)}>
                <span className="nm">{s.frames.length ? s.frames.map(frameName).join('  <  ') : '(no call stack)'}</span>
                <span className="num mono">{n(s.blocks)}</span>
                <span className="num mono dim">{fmtSize(s.bytes)}</span>
              </div>
            ))}
            {!status.sites.length && <div className="insp-empty">No tracked block is live.</div>}
            {status.siteCount > status.sites.length && <div className="insp-empty">{n(status.siteCount - status.sites.length)} more places hold less memory.</div>}
          </div>
        )}
      </div>
    </div>
  );
}
