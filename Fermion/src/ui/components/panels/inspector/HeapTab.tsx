import { useEffect, useRef, useState } from 'react';
import { cleanIpcError, fmtSize, parseAddress } from '../../../inspector/format';
import { inspectApi } from '../../../inspector/useInspect';
import { addrMenu } from '../../../addressMenu';
import { writeTerminal } from '../../../bridge';
import { Goto } from './MemoryTab';
import { useNames, NameIndex } from '../../../names';
import { OwnAllocator, MAX_OWN, MAX_ARG, allocatorArgs, allocatorError, loadAllocators, saveAllocators } from '../../../inspector/heapAllocators';

interface Frame { address: string | null; where: string; symbol: string; }
interface Site { frames: Frame[]; blocks: number; bytes: number; }
export interface HeapStatus {
  tracking: boolean; endedBy: string; seconds: number; min: number; max: number; functions: string[];
  allocs: number; frees: number; live: number; liveBytes: number; freedKept: number; overflow: boolean; siteCount: number; sites: Site[];
}
export interface HeapBlock { address: string; size: number; offset: number; thread: number; at: number; frames: Frame[]; freed: { thread: number; at: number; frames: Frame[] } | null; }
// What Windows itself says about the address, from a walk of its heaps.
export interface HeapSystem { state: 'live' | 'free' | 'none'; address: string | null; size: number; offset: number; timedOut: boolean; }
export interface HeapFound { address: string; tracking: boolean; live: HeapBlock | null; freed: HeapBlock[]; freedTotal: number; system?: HeapSystem | null; }
interface Started { tracking: boolean; functions: string[]; min: number; max: number; maxSeconds: number; maxLive: number; maxFreed: number; }

const MAX_SIZE = 0xffffffff;
const ORDINALS = ['1st', '2nd', '3rd', '4th', '5th', '6th', '7th', '8th'];
const ARGS = Array.from({ length: MAX_ARG + 1 }, (_, i) => i);
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
  const sys = f.system ?? null;
  if (sys?.state === 'live') {
    return `${f.address} is inside a live block that was not recorded: it was allocated before tracking began or is outside the size range, so no call stack is known.`
      + (f.freed.length ? ` The same memory belonged to ${plural(f.freedTotal, 'recorded block')} freed earlier.` : '');
  }
  if (sys?.state === 'free') {
    return `${f.address} is in heap memory that is free right now. A pointer to it is stale: using it is a use after free.`
      + (f.freed.length ? '' : ' The block it was in was freed before tracking began, so who freed it is not known.');
  }
  if (f.freed.length) return `${f.address} is inside a block that has been freed. Using it now is a use after free.`;
  if (sys) {
    return `${f.address} is not inside any block in use.`
      + (sys.timedOut ? ' The heaps could not all be walked in time, so this is not certain.' : ' It may not be heap memory at all, or it may be a small block that was freed: those are not always listed as free space.');
  }
  return `${f.address} is not inside any block recorded since tracking began. Blocks allocated before that, or outside the size range, are not known.`;
}

// The operator's name for the place, else the target's symbol, else where it is.
const frameName = (names: NameIndex, f: Frame) => names.show(f.where, f.address, f.symbol);

function Frames({ title, frames }: { title: string; frames: Frame[] }) {
  const names = useNames();
  return (
    <div className="heap-stack">
      <div className="heap-stack-head">{title}</div>
      {frames.map((f, i) => (
        <div key={i + (f.address ?? '')} className="insp-row heap-frame" data-testid="heap-frame" {...addrMenu(f.address)}><span className="nm">{frameName(names, f)}</span><span className="nm mono dim">{f.address}</span></div>
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
  const names = useNames();
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

  const sizes = parseHeapSizes(minText, maxText);
  const parsed = parseAddress(address.trim());

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

  // An address handed over from the address menu: look it up.
  const findRef = useRef(find);
  findRef.current = find;
  useEffect(() => {
    if (!goto) return;
    setAddress(goto.address);
    findRef.current(parseAddress(goto.address));
  }, [goto?.n]); // keyed on the hand-off counter only

  const finish = (s: HeapStatus) => {
    setStatus(s);
    setStarted(null);
    writeTerminal('STATUS', `[+] Heap tracking (${sizesText(s.min, s.max)}): ${countsLine(s)}`);
  };

  // Allocators of the program's own (a pool, an arena), tracked beside the system's.
  const [own, setOwn] = useState<OwnAllocator[]>(loadAllocators);
  const [ownOpen, setOwnOpen] = useState(false);
  const changeOwn = (next: OwnAllocator[]) => { setOwn(next); saveAllocators(next); };
  const editOwn = (i: number, change: Partial<OwnAllocator>) => changeOwn(own.map((a, k) => (k === i ? { ...a, ...change } : a)));
  const ownError = own.map(allocatorError).find(Boolean) ?? '';

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
    if (busy || !sizes || ownError) return;
    setBusy(true);
    setError('');
    try {
      const s: Started = own.length ? await inspectApi().heapStart(sizes, allocatorArgs(own)) : await inspectApi().heapStart(sizes);
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
        <button className={'pill' + (started ? ' on' : '')} data-testid="heap-toggle" disabled={busy || (!started && (!sizes || !!ownError))} onClick={started ? stop : start}
          title="Record the blocks the program allocates and frees, each with its call stack">
          {started ? (busy ? 'Stopping…' : 'Stop') : busy ? 'Starting…' : 'Track'}
        </button>
        <button className={'pill' + (ownOpen ? ' on' : '')} data-testid="heap-own-toggle" aria-expanded={ownOpen} title="Track a pool or arena allocator of the program's own, beside the system's" onClick={() => setOwnOpen(!ownOpen)}>
          Own allocators{own.length ? ` (${own.length})` : ''}
        </button>
        <span className="grow" />
        {status && <span className="count" data-testid="heap-counts">{countsLine(status)}</span>}
      </div>
      <div className="ptool">
        <input className="mini heap-address" data-testid="heap-address" aria-label="Address to find the block of" placeholder="address to look up, e.g. 0x1d2f2c68010" spellCheck={false} value={address}
          onChange={(e) => setAddress(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && parsed) find(parsed); }} />
        <button className="pill" data-testid="heap-find" disabled={!parsed} title="Which block is this address in, or was it in?" onClick={() => find(parsed)}>Find block</button>
      </div>

      {ownOpen && (
        <div className="heap-own" data-testid="heap-own">
          <div className="heap-own-help">
            A program that hands out memory from a pool or an arena of its own does not ask the system for each block. Name the function that allocates and the one that frees
            (as <code>module!function</code>, or <code>module+0xoffset</code> for one without a name) and say which argument is the size and which is the block. The result of the allocating function is taken as the block.
          </div>
          {own.map((a, i) => {
            const wrong = allocatorError(a);
            return (
              <div key={i} className="heap-own-row" data-testid="heap-own-row">
                <input className="mini heap-own-fn" data-testid="heap-own-alloc" aria-label="Function that allocates" placeholder="allocates: module!function" spellCheck={false} disabled={!!started} value={a.alloc} onChange={(e) => editOwn(i, { alloc: e.target.value })} />
                <span>size is</span>
                <select data-testid="heap-own-size" aria-label="Which argument is the size" disabled={!!started} value={a.size} onChange={(e) => editOwn(i, { size: Number(e.target.value) })}>
                  {ARGS.map((v) => <option key={v} value={v}>{ORDINALS[v]} argument</option>)}
                </select>
                <input className="mini heap-own-fn" data-testid="heap-own-free" aria-label="Function that frees (optional)" placeholder="frees: module!function (optional)" spellCheck={false} disabled={!!started} value={a.free} onChange={(e) => editOwn(i, { free: e.target.value })} />
                <span>block is</span>
                <select data-testid="heap-own-pointer" aria-label="Which argument is the block being freed" disabled={!!started || !a.free.trim()} value={a.pointer} onChange={(e) => editOwn(i, { pointer: Number(e.target.value) })}>
                  {ARGS.map((v) => <option key={v} value={v}>{ORDINALS[v]} argument</option>)}
                </select>
                <button className="pill" data-testid="heap-own-remove" aria-label="Remove this allocator" title="Remove" disabled={!!started} onClick={() => changeOwn(own.filter((_, k) => k !== i))}>Remove</button>
                {wrong && a.alloc.trim() && <span className="heap-own-wrong" role="alert" data-testid="heap-own-wrong">{wrong}</span>}
              </div>
            );
          })}
          <div className="heap-own-row">
            <button className="pill" data-testid="heap-own-add" disabled={!!started || own.length >= MAX_OWN} onClick={() => changeOwn([...own, { alloc: '', size: 0, free: '', pointer: 0 }])}>Add an allocator</button>
            {own.length >= MAX_OWN && <span className="heap-own-help">Up to {MAX_OWN}.</span>}
            {ownError && !started && <span className="heap-own-help" data-testid="heap-own-pending">Complete or remove the unfinished allocator to start tracking.</span>}
          </div>
        </div>
      )}
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

      {!started && !status && !found && !error && (
        <div className="insp-empty big" data-testid="heap-empty">
          Find out which block an address is in, who allocated it and who freed it. Press Track, use the program, then look an address up
          (or right-click one anywhere and choose Find heap block). Who allocated and freed a block is known only for blocks allocated while tracking runs;
          on Windows an address can be looked up without tracking, and you are told the block it is in.
        </div>
      )}

      <div className="heap-body">
        {found && (
          <div className="heap-found" data-testid="heap-found">
            <div className={'heap-verdict' + (!found.live && found.freed.length ? ' uaf' : '')} data-testid="heap-verdict">{heapVerdict(found)}</div>
            {found.system && found.system.state !== 'none' && !found.live && (
              <div className="heap-block" data-testid="heap-system">
                <div className="heap-block-head">
                  <span className={'tag ' + (found.system.state === 'live' ? 'live' : 'freed')}>{found.system.state === 'live' ? 'live' : 'free'}</span>
                  <span>{plural(found.system.size, 'byte')} at <span className="mono" {...addrMenu(found.system.address)}>{found.system.address}</span>; the address is byte +0x{found.system.offset.toString(16)}</span>
                  <span className="dim">as Windows lists it now</span>
                </div>
              </div>
            )}
            {found.live && <Block block={found.live} kind="live" />}
            {found.freed.map((b, i) => <Block key={i + b.address + b.at} block={b} kind="freed" />)}
            {found.freedTotal > found.freed.length && <div className="insp-empty">{n(found.freedTotal - found.freed.length)} older freed blocks at this address are not shown.</div>}
          </div>
        )}
        {status && (
          <div className="heap-sites">
            <div className="insp-head heap-cols" aria-hidden="true"><span>Live memory was allocated by</span><span className="num">Blocks</span><span className="num">Bytes</span></div>
            {status.sites.map((s, i) => (
              <div key={i + (s.frames[0]?.address ?? '')} className="insp-row heap-cols" data-testid="heap-site" title={s.frames.map((f) => frameName(names, f)).join('  <  ')} {...addrMenu(s.frames[0]?.address)}>
                <span className="nm">{s.frames.length ? s.frames.map((f) => frameName(names, f)).join('  <  ') : '(no call stack)'}</span>
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
