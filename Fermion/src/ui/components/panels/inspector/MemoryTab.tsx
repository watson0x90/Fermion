import { addrMenu } from '../../../addressMenu';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Icon } from '../../Icon';
import {
  fmtSize, hexRows, parseAddress, addAddress, pageBase, normalizePattern, textToPattern, cleanIpcError,
  parseBytes, spacedHex, overlaps,
} from '../../../inspector/format';
import { useAppSelector } from '../../../store';
import { writeTerminal } from '../../../bridge';
import { inspectApi, useInspect, Listing } from '../../../inspector/useInspect';

interface Range { base: string; size: number; protection: string; file: string; }
interface Match { address: string; size: number; where: string; }
interface ScanResult extends Listing<Match> { stopped: string; rangesScanned: number; rangesTotal: number; }
interface ReadResult { address: string; size: number; requested: number; hex: string; }
interface WriteResult { address: string; size: number; original: string; written: string; protection: string; }
// A write made in this session, kept so it can be put back.
interface Written extends WriteResult { n: number; pid: string; }
const MAX_WRITES_KEPT = 200;

const AUTO_MS = 2000;
const PAGE = 256;          // bytes per hex-view page
const WIDE_HEX_PX = 590;   // pane width that fits 16 bytes per row
const PROTECTIONS = [
  { value: 'r--', label: 'readable (r--)' },
  { value: 'rw-', label: 'writable (rw-)' },
  { value: 'r-x', label: 'executable (r-x)' },
  { value: 'rwx', label: 'rwx' },
];
const MAX_RANGE_ROWS = 1500;

export interface Goto { address: string; n: number; }

// Memory: the target's ranges, a hex view of any address, a pattern scan, and
// — only with Edit switched on — writing bytes. Every write is listed with
// the bytes it replaced, and can be put back.
export function MemoryTab({ active, goto }: { active: boolean; goto: Goto | null }) {
  const [address, setAddress] = useState<string | null>(null); // top of the hex view
  const [addrInput, setAddrInput] = useState('');
  const [addrError, setAddrError] = useState('');
  const [highlight, setHighlight] = useState<{ start: string; length: number } | null>(null);
  const [mode, setMode] = useState<'ranges' | 'scan' | 'writes'>('ranges');
  const [protection, setProtection] = useState('r--');
  const [rangeFilter, setRangeFilter] = useState('');

  const [scanAs, setScanAs] = useState<'hex' | 'text'>('hex');
  const [pattern, setPattern] = useState('');
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState('');
  const [scanning, setScanning] = useState(false);

  const ranges = useInspect<Listing<Range>>(() => inspectApi().ranges(protection), 'ranges|' + protection, active);
  const [auto, setAuto] = useState(false);
  const view = useInspect<ReadResult>(() => inspectApi().read(address, PAGE), 'read|' + address, active && address != null, auto ? AUTO_MS : 0);

  // Show `target` in the hex view, optionally marking `length` bytes from it.
  const show = (target: string, length = 0) => {
    setAddress(pageBase(target));
    setAddrInput(target);
    setAddrError('');
    setHighlight(length > 0 ? { start: target, length } : null);
  };

  // An address handed over from the Modules or Threads tab.
  useEffect(() => { if (goto) show(goto.address, 1); }, [goto?.n]); // keyed on the hand-off counter only

  const go = () => {
    const parsed = parseAddress(addrInput);
    if (!parsed) { setAddrError('Enter a hex address, e.g. 0x7ff000'); return; }
    if (pageBase(parsed) === address) view.reload(); // same place: read it again
    show(parsed, 1);
  };
  const page = (delta: number) => { if (address) { const next = pageBase(addAddress(address, delta)); setAddress(next); setAddrInput(next); } };

  const runScan = async () => {
    const pat = normalizePattern(scanAs === 'text' ? textToPattern(pattern) : pattern);
    if (!pat) {
      setScanError(scanAs === 'text'
        ? 'Enter at least two characters of text to find.'
        : 'Enter hex bytes with at least two concrete bytes, e.g. 4d 5a ?? 00 (?? matches any byte).');
      return;
    }
    setScanError('');
    setScanning(true);
    try {
      setScan(await inspectApi().scan(pat, protection));
    } catch (e) {
      setScan(null);
      setScanError(cleanIpcError(e));
    } finally {
      setScanning(false);
    }
  };

  // ---- editing ----
  const pid = useAppSelector((s) => s.session?.currentPid ?? null);
  const [editing, setEditing] = useState(false);
  const [editAt, setEditAt] = useState<string | null>(null); // where the next write starts
  const [editAs, setEditAs] = useState<'hex' | 'text'>('hex');
  const [editInput, setEditInput] = useState('');
  const [editError, setEditError] = useState('');
  const [writing, setWriting] = useState(false);
  const [writes, setWrites] = useState<Written[]>([]);
  const writeCount = useRef(0);
  // Writes belong to a process: those made in another one are not offered.
  const mine = useMemo(() => writes.filter((w) => w.pid === pid), [writes, pid]);
  const parsed = parseBytes(editInput, editAs);
  const newSize = parsed.hex.length / 2;

  const stopEditing = () => { setEditing(false); setEditAt(null); setEditInput(''); setEditError(''); };
  const doWrite = async () => {
    if (!editAt || !parsed.hex || writing) return;
    setWriting(true);
    setEditError('');
    try {
      const r: WriteResult = await inspectApi().write(editAt, parsed.hex);
      const entry: Written = { ...r, n: ++writeCount.current, pid: pid ?? '' };
      setWrites((list) => [...list, entry].slice(-MAX_WRITES_KEPT));
      writeTerminal('STATUS', `[+] Wrote ${r.size} byte${r.size === 1 ? '' : 's'} at ${r.address}: ${spacedHex(r.written)} (was ${spacedHex(r.original)})`);
      setEditInput('');
      setHighlight({ start: r.address, length: r.size });
      view.reload();
    } catch (e) {
      setEditError(cleanIpcError(e));
    } finally {
      setWriting(false);
    }
  };
  // Put back what a write replaced. A later write over the same bytes has to
  // be put back first, or its bytes would be lost.
  const [revertError, setRevertError] = useState('');
  const revert = async (w: Written) => {
    const later = mine.find((o) => o.n > w.n && overlaps(o, w));
    if (later) { setRevertError(`The write at ${later.address} was made later over the same bytes. Revert that one first.`); return; }
    setRevertError('');
    try {
      await inspectApi().write(w.address, w.original);
      setWrites((list) => list.filter((o) => o.n !== w.n));
      writeTerminal('STATUS', `[+] Reverted ${w.size} byte${w.size === 1 ? '' : 's'} at ${w.address} to ${spacedHex(w.original)}`);
      setHighlight({ start: w.address, length: w.size });
      view.reload();
    } catch (e) {
      setRevertError(cleanIpcError(e));
    }
  };

  const rangeRows = useMemo(() => {
    const needle = rangeFilter.trim().toLowerCase();
    const items = ranges.data?.items ?? [];
    return needle ? items.filter((r) => r.base.includes(needle) || r.file.toLowerCase().includes(needle)) : items;
  }, [ranges.data, rangeFilter]);

  // 16 bytes per row when the pane is wide enough for address + hex + text,
  // otherwise 8, so the text column is never pushed out of view.
  const hexRef = useRef<HTMLDivElement>(null);
  const [perRow, setPerRow] = useState(16);
  useEffect(() => {
    const el = hexRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const fit = () => { if (el.clientWidth > 0) setPerRow(el.clientWidth >= WIDE_HEX_PX ? 16 : 8); };
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    fit();
    return () => ro.disconnect();
  }, []);

  const rows = view.data ? hexRows(view.data.hex, view.data.address, perRow) : [];
  const hl = highlight ? { from: BigInt(highlight.start), to: BigInt(highlight.start) + BigInt(highlight.length) } : null;
  // The bytes a write would replace: marked in the view, and shown as "was".
  const target = editAt ? { from: BigInt(editAt), to: BigInt(editAt) + BigInt(Math.max(1, newSize)) } : null;
  const was = (() => {
    if (!editAt || !view.data || !newSize) return '';
    const off = Number(BigInt(editAt) - BigInt(view.data.address));
    if (off < 0 || off + newSize > view.data.size) return '';
    return view.data.hex.slice(off * 2, (off + newSize) * 2);
  })();

  return (
    <div className="insp-tab">
      <div className="ptool">
        <span className={'search insp-filter addr-box' + (addrError ? ' bad' : '')}>
          <input
            data-testid="mem-addr"
            aria-label="Address"
            placeholder="Address (hex), e.g. 0x7ff000"
            value={addrInput}
            onChange={(e) => { setAddrInput(e.target.value); setAddrError(''); }}
            onKeyDown={(e) => { if (e.key === 'Enter') go(); }}
          />
        </span>
        <button className="pill" data-testid="mem-go" onClick={go}>Go</button>
        <button className="pill" data-testid="mem-prev" title="Previous 256 bytes" disabled={!address} onClick={() => page(-PAGE)}>◀</button>
        <button className="pill" data-testid="mem-next" title="Next 256 bytes" disabled={!address} onClick={() => page(PAGE)}>▶</button>
        <button className={'pill' + (auto ? ' on' : '')} data-testid="mem-auto" aria-pressed={auto} title="Re-read these bytes every 2 seconds, to watch memory change" onClick={() => setAuto(!auto)}>Auto</button>
        <button className={'pill' + (editing ? ' on warn' : '')} data-testid="mem-edit" aria-pressed={editing} title="Allow writing bytes into the process. Off, nothing here changes the target." onClick={() => (editing ? stopEditing() : setEditing(true))}>Edit</button>
        <span className="grow" />
        <span className="count">{view.loading ? 'reading…' : view.data ? `${view.data.size} bytes` : ''}</span>
      </div>
      {addrError && <div className="insp-note err" role="alert">{addrError}</div>}
      {editing && (
        <div className="mem-editbar" data-testid="mem-editbar">
          {!editAt ? (
            <span className="hint">Editing is on. Click a byte in the view to choose where to write.</span>
          ) : (
            <>
              <span>Write at <span className="mono" data-testid="mem-edit-at">{editAt}</span></span>
              <select className="mini" data-testid="mem-edit-as" aria-label="Write as" value={editAs} onChange={(e) => { setEditAs(e.target.value as 'hex' | 'text'); setEditError(''); }}>
                <option value="hex">hex bytes</option>
                <option value="text">text</option>
              </select>
              <span className={'search insp-filter' + (parsed.error ? ' bad' : '')}>
                <input
                  data-testid="mem-edit-input"
                  aria-label="Bytes to write"
                  placeholder={editAs === 'hex' ? '90 90' : 'text to write'}
                  spellCheck={false}
                  value={editInput}
                  onChange={(e) => { setEditInput(e.target.value); setEditError(''); }}
                  onKeyDown={(e) => { if (e.key === 'Escape') stopEditing(); }}
                />
              </span>
              <button className="pill warn" data-testid="mem-write" disabled={!parsed.hex || writing} onClick={doWrite}>
                {writing ? 'Writing…' : newSize ? `Write ${newSize} byte${newSize === 1 ? '' : 's'}` : 'Write'}
              </button>
              <button className="pill" data-testid="mem-edit-cancel" onClick={() => { setEditAt(null); setEditInput(''); setEditError(''); }}>Cancel</button>
              {newSize > 0 && (
                <span className="preview mono" data-testid="mem-edit-preview">
                  {was ? `${spacedHex(was)} → ` : ''}{spacedHex(parsed.hex)}
                </span>
              )}
            </>
          )}
        </div>
      )}
      {editing && (parsed.error || editError) && <div className="insp-note err" role="alert" data-testid="mem-edit-error">{parsed.error || editError}</div>}

      <div className="hexview" data-testid="hexview" ref={hexRef}>
        {!address && <div className="insp-empty">Pick a range below, or enter an address, to read memory here.</div>}
        {view.error && <div className="insp-note err" role="alert" data-testid="hex-error">{view.error}</div>}
        {rows.map((r) => (
          <div className="hexrow" key={r.address} data-testid="hex-row">
            <span className="ha" {...addrMenu(r.address)}>{r.address}</span>
            <span className="hb">
              {r.bytes.map((b, i) => {
                const at = BigInt(r.address) + BigInt(i);
                const cls = (hl && at >= hl.from && at < hl.to ? 'hl ' : '') + (target && at >= target.from && at < target.to ? 'tgt ' : '') + (i === perRow / 2 ? 'gap' : '');
                return editing
                  ? <span key={i} className={cls + ' pick'} data-testid="hex-byte" onClick={() => { setEditAt('0x' + at.toString(16)); setEditError(''); }}>{b}</span>
                  : <span key={i} className={cls}>{b}</span>;
              })}
            </span>
            <span className="hc">{r.ascii}</span>
          </div>
        ))}
        {view.data && view.data.size < view.data.requested && (
          <div className="insp-note">Only {view.data.size} of {view.data.requested} bytes are readable here.</div>
        )}
      </div>

      <div className="insp-detail grow">
        <div className="ptool">
          <span className="seg">
            <button className={mode === 'ranges' ? 'on' : ''} data-testid="mem-mode-ranges" aria-pressed={mode === 'ranges'} onClick={() => setMode('ranges')}>Ranges</button>
            <button className={mode === 'scan' ? 'on' : ''} data-testid="mem-mode-scan" aria-pressed={mode === 'scan'} onClick={() => setMode('scan')}>Scan</button>
            <button className={mode === 'writes' ? 'on' : ''} data-testid="mem-mode-writes" aria-pressed={mode === 'writes'} onClick={() => setMode('writes')}>Writes{mine.length ? ` (${mine.length})` : ''}</button>
          </span>
          {mode !== 'writes' && <select className="mini" data-testid="range-prot" aria-label="Protection" value={protection} onChange={(e) => setProtection(e.target.value)} title="Ranges with at least this protection">
            {PROTECTIONS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
          </select>}
          {mode === 'writes' ? (
            <span className="grow">What you wrote in this process, newest last. Revert puts the earlier bytes back.</span>
          ) : mode === 'ranges' ? (
            <>
              <span className="search insp-filter"><Icon name="search" size={13} />
                <input data-testid="range-filter" placeholder="Filter by address or file" value={rangeFilter} onChange={(e) => setRangeFilter(e.target.value)} />
              </span>
              <span className="grow" />
              <span className="count" data-testid="range-count">{ranges.loading && !ranges.data ? 'loading…' : `${rangeRows.length}${rangeFilter.trim() ? ' of ' + (ranges.data?.total ?? 0) : ''} ranges`}</span>
              <button className="pill" data-testid="range-refresh" onClick={ranges.reload}><Icon name="refresh" size={12} />Refresh</button>
            </>
          ) : (
            <>
              <select className="mini" data-testid="scan-as" aria-label="Pattern type" value={scanAs} onChange={(e) => setScanAs(e.target.value as 'hex' | 'text')}>
                <option value="hex">hex bytes</option>
                <option value="text">text</option>
              </select>
              <span className="search insp-filter">
                <input
                  data-testid="scan-pattern"
                  aria-label="Scan pattern"
                  placeholder={scanAs === 'hex' ? '4d 5a ?? 00' : 'text to find'}
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter' && !scanning) runScan(); }}
                />
              </span>
              <button className="pill" data-testid="scan-run" disabled={scanning} onClick={runScan}>{scanning ? 'Scanning…' : 'Scan'}</button>
            </>
          )}
        </div>

        {mode === 'writes' ? (
          <>
            {revertError && <div className="insp-note err" role="alert" data-testid="mem-revert-error">{revertError}</div>}
            <div className="insp-list">
              {mine.map((w) => (
                <div key={w.n} className="insp-row write-cols" data-testid="write-row" {...addrMenu(w.address)} onClick={() => show(w.address, w.size)}>
                  <span className="mono">{w.address}</span>
                  <span className="mono dim">{w.size} B</span>
                  <span className="nm mono" title={`was ${spacedHex(w.original, 64)}
now ${spacedHex(w.written, 64)}`}>{spacedHex(w.original, 8)} → {spacedHex(w.written, 8)}</span>
                  <button className="pill" data-testid="write-revert" onClick={(e) => { e.stopPropagation(); revert(w); }}>Revert</button>
                </div>
              ))}
              {!mine.length && <div className="insp-empty">Nothing has been written in this process. Switch Edit on above the hex view to write bytes.</div>}
            </div>
          </>
        ) : mode === 'ranges' ? (
          <>
            {ranges.error && <div className="insp-note err" role="alert">Could not list ranges: {ranges.error}</div>}
            <div className="insp-list">
              <div className="insp-head rng-cols" aria-hidden="true"><span className="num">Base</span><span className="num">Size</span><span>Prot</span><span>File</span></div>
              {rangeRows.slice(0, MAX_RANGE_ROWS).map((r) => (
                <div key={r.base} className={'insp-row rng-cols' + (address === pageBase(r.base) ? ' sel' : '')} data-testid="range-row" title={r.file} {...addrMenu(r.base)} onClick={() => show(r.base)}>
                  <span className="num mono">{r.base}</span>
                  <span className="num mono dim">{fmtSize(r.size)}</span>
                  <span className="mono">{r.protection}</span>
                  <span className="nm dim">{r.file ? r.file.split(/[\\/]/).pop() : ''}</span>
                </div>
              ))}
              {rangeRows.length > MAX_RANGE_ROWS && <div className="insp-empty">Showing {MAX_RANGE_ROWS.toLocaleString()} of {rangeRows.length.toLocaleString()} — filter to narrow.</div>}
              {!rangeRows.length && !ranges.loading && !ranges.error && <div className="insp-empty">No ranges.</div>}
            </div>
          </>
        ) : (
          <>
            {scanError && <div className="insp-note err" role="alert">{scanError}</div>}
            {scan && (
              <div className="insp-note" data-testid="scan-status">
                {scan.items.length} match{scan.items.length === 1 ? '' : 'es'} in {scan.rangesScanned} of {scan.rangesTotal} ranges
                {scan.stopped === 'limit' ? ' — stopped at the match limit' : scan.stopped === 'time' ? ' — stopped at the time limit' : ''}.
              </div>
            )}
            <div className="insp-list">
              {(scan?.items ?? []).map((m) => (
                <div key={m.address} className="insp-row scan-cols" data-testid="scan-row" {...addrMenu(m.address)} onClick={() => show(m.address, m.size)}>
                  <span className="mono">{m.address}</span>
                  <span className="nm mono dim">{m.where !== m.address ? m.where : ''}</span>
                </div>
              ))}
              {!scan && !scanError && <div className="insp-empty">Search the selected ranges for a byte pattern or text. Scanning stops after 500 matches or 8 seconds.</div>}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
