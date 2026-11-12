import { useEffect, useMemo, useRef, useState } from 'react';
import { Icon } from '../../Icon';
import {
  fmtSize, hexRows, parseAddress, addAddress, pageBase, normalizePattern, textToPattern, cleanIpcError,
} from '../../../inspector/format';
import { inspectApi, useInspect, Listing } from '../../../inspector/useInspect';

interface Range { base: string; size: number; protection: string; file: string; }
interface Match { address: string; size: number; where: string; }
interface ScanResult extends Listing<Match> { stopped: string; rangesScanned: number; rangesTotal: number; }
interface ReadResult { address: string; size: number; requested: number; hex: string; }

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

// Memory: the target's ranges, a hex view of any address, and a pattern scan.
// Nothing here writes to the target.
export function MemoryTab({ active, goto }: { active: boolean; goto: Goto | null }) {
  const [address, setAddress] = useState<string | null>(null); // top of the hex view
  const [addrInput, setAddrInput] = useState('');
  const [addrError, setAddrError] = useState('');
  const [highlight, setHighlight] = useState<{ start: string; length: number } | null>(null);
  const [mode, setMode] = useState<'ranges' | 'scan'>('ranges');
  const [protection, setProtection] = useState('r--');
  const [rangeFilter, setRangeFilter] = useState('');

  const [scanAs, setScanAs] = useState<'hex' | 'text'>('hex');
  const [pattern, setPattern] = useState('');
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState('');
  const [scanning, setScanning] = useState(false);

  const ranges = useInspect<Listing<Range>>(() => inspectApi().ranges(protection), 'ranges|' + protection, active);
  const view = useInspect<ReadResult>(() => inspectApi().read(address, PAGE), 'read|' + address, active && address != null);

  // Show `target` in the hex view, optionally marking `length` bytes from it.
  const show = (target: string, length = 0) => {
    setAddress(pageBase(target));
    setAddrInput(target);
    setAddrError('');
    setHighlight(length > 0 ? { start: target, length } : null);
  };

  // An address handed over from the Modules or Threads tab.
  useEffect(() => { if (goto) show(goto.address, 1); /* eslint-disable-next-line */ }, [goto?.n]);

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
        <span className="grow" />
        <span className="count">{view.loading ? 'reading…' : view.data ? `${view.data.size} bytes` : ''}</span>
      </div>
      {addrError && <div className="insp-note err" role="alert">{addrError}</div>}

      <div className="hexview" data-testid="hexview" ref={hexRef}>
        {!address && <div className="insp-empty">Pick a range below, or enter an address, to read memory here.</div>}
        {view.error && <div className="insp-note err" role="alert" data-testid="hex-error">{view.error}</div>}
        {rows.map((r) => (
          <div className="hexrow" key={r.address} data-testid="hex-row">
            <span className="ha">{r.address}</span>
            <span className="hb">
              {r.bytes.map((b, i) => {
                const at = BigInt(r.address) + BigInt(i);
                return <span key={i} className={(hl && at >= hl.from && at < hl.to ? 'hl ' : '') + (i === perRow / 2 ? 'gap' : '')}>{b}</span>;
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
          </span>
          <select className="mini" data-testid="range-prot" aria-label="Protection" value={protection} onChange={(e) => setProtection(e.target.value)} title="Ranges with at least this protection">
            {PROTECTIONS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
          </select>
          {mode === 'ranges' ? (
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

        {mode === 'ranges' ? (
          <>
            {ranges.error && <div className="insp-note err" role="alert">Could not list ranges: {ranges.error}</div>}
            <div className="insp-list">
              <div className="insp-head rng-cols" aria-hidden="true"><span className="num">Base</span><span className="num">Size</span><span>Prot</span><span>File</span></div>
              {rangeRows.slice(0, MAX_RANGE_ROWS).map((r) => (
                <div key={r.base} className={'insp-row rng-cols' + (address === pageBase(r.base) ? ' sel' : '')} data-testid="range-row" title={r.file} onClick={() => show(r.base)}>
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
                <div key={m.address} className="insp-row scan-cols" data-testid="scan-row" onClick={() => show(m.address, m.size)}>
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
