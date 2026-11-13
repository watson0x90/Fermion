import { useEffect, useRef, useState } from 'react';
import { Icon } from '../../Icon';
import { parseAddress, cleanIpcError } from '../../../inspector/format';
import { inspectApi } from '../../../inspector/useInspect';
import { addrMenu } from '../../../addressMenu';
import { Goto } from './MemoryTab';

interface Insn { address: string; size: number; bytes: string; text: string; kind: string; target: string | null; targetName: string; }
interface Listing { address: string; next: string; stopped: string; where: string; symbol: string; protection: string; items: Insn[]; }

const CHUNK = 60;       // instructions per request
import { useNames, parseWhere, nameText } from '../../../names';

const MAX_SHOWN = 2000; // instructions kept in one listing

const STOPPED: Record<string, string> = {
  end: 'End of this memory range.',
  undecodable: 'The bytes that follow are not an instruction.',
};

// Disassembly: the instructions at an address, read from the target. Calls and
// jumps to a fixed address can be followed (Back returns), and every address
// has the address menu. Nothing here writes to the target.
export function CodeTab({ goto }: { goto: Goto | null }) {
  const [input, setInput] = useState('');
  const [inputError, setInputError] = useState('');
  const [listing, setListing] = useState<Listing | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<string[]>([]); // where Back goes
  const request = useRef(0);
  const listRef = useRef<HTMLDivElement>(null);
  // Names the operator gave to addresses. The listing says where its first
  // instruction is (module + offset); any other address of that module
  // follows from it, which is how an instruction or a call target is matched.
  const names = useNames();
  const place = listing ? parseWhere(listing.where) : null;
  const whereOf = (address: string | null): string | null => {
    if (!place || !listing || !address || !names.size) return null;
    try {
      const offset = BigInt(address) - BigInt(listing.address) + BigInt(place.offset);
      return offset >= 0n ? `${place.module}+0x${offset.toString(16)}` : null;
    } catch { return null; }
  };
  // The operator's name for where the listing starts, then what the target calls it.
  const heading = (l: Listing): string => {
    const theirs = l.symbol || l.where;
    const named = names.find(l.where, l.address);
    return named ? `${nameText(named)} · ${theirs}` : theirs;
  };
  const labelAt = (address: string): string => {
    if (!names.size) return '';
    const n = names.find(whereOf(address), address);
    return n && n.delta === 0 ? n.label : '';
  };
  const targetLabel = (target: string | null): string => {
    if (!names.size || !target) return '';
    const n = names.find(whereOf(target), target);
    return n ? nameText(n) : '';
  };

  const load = async (address: string, from: Listing | null) => {
    const id = ++request.current;
    setLoading(true);
    setError('');
    try {
      const r: Listing = await inspectApi().disassemble(from ? from.next : address, CHUNK);
      if (id !== request.current) return;
      if (from) {
        setListing({ ...from, next: r.next, stopped: r.stopped, items: from.items.concat(r.items).slice(0, MAX_SHOWN) });
      } else {
        setListing(r);
        if (listRef.current) listRef.current.scrollTop = 0;
      }
    } catch (e) {
      if (id !== request.current) return;
      if (!from) setListing(null);
      setError(cleanIpcError(e));
    } finally {
      if (id === request.current) setLoading(false);
    }
  };

  // Show another place. `remember` puts the current one on the Back list.
  const show = (address: string, remember: boolean) => {
    if (remember && listing) setHistory((h) => h.concat(listing.address).slice(-50));
    setInput(address);
    setInputError('');
    load(address, null);
  };

  useEffect(() => { if (goto) show(goto.address, true); }, [goto?.n]); // keyed on the hand-off counter only

  const go = () => {
    const parsed = parseAddress(input);
    if (!parsed) { setInputError('Enter a hex address, e.g. 0x7ff000'); return; }
    show(parsed, true);
  };
  const back = () => {
    const previous = history[history.length - 1];
    if (!previous) return;
    setHistory((h) => h.slice(0, -1));
    show(previous, false);
  };

  const full = !!listing && listing.items.length >= MAX_SHOWN;
  const executable = !listing || listing.protection.charAt(2) === 'x';

  return (
    <div className="insp-tab code-tab">
      <div className="ptool">
        <button className="pill ico" data-testid="code-back" aria-label="Back" title="Back to where you were" disabled={!history.length} onClick={back}>◀</button>
        <span className={'search insp-filter addr-box' + (inputError ? ' bad' : '')}>
          <input
            data-testid="code-addr"
            aria-label="Address to disassemble"
            placeholder="Address, e.g. 0x7ff000"
            spellCheck={false}
            value={input}
            onChange={(e) => { setInput(e.target.value); setInputError(''); }}
            onKeyDown={(e) => { if (e.key === 'Enter') go(); }}
          />
        </span>
        <button className="pill" data-testid="code-go" onClick={go}>Go</button>
        <span className="grow" />
        {listing && <span className="count" data-testid="code-where" title={listing.where}>{heading(listing)} · {listing.protection}</span>}
      </div>
      {inputError && <div className="insp-note err" role="alert">{inputError}</div>}
      {error && <div className="insp-note err" role="alert" data-testid="code-error">{error}</div>}
      {listing && !executable && <div className="insp-note" data-testid="code-not-exec">This memory is not executable, so these bytes may not be code.</div>}

      <div className="code-list mono" ref={listRef} data-testid="code-list">
        {(listing?.items ?? []).map((i) => (
          <div className={'code-row' + (i.kind ? ' k-' + i.kind : '')} key={i.address} data-testid="code-row">
            {/* A name the operator gave this very instruction is shown above it, like a label. */}
            {labelAt(i.address) && <span className="clabel" data-testid="code-label">{labelAt(i.address)}:</span>}
            <span className="ca" {...addrMenu(i.address)} tabIndex={0} title="Right-click for the address menu">{i.address}</span>
            <span className="cb">{i.bytes}</span>
            <span className="ct">
              {/* With a target to follow, its name stands in for the raw address. */}
              <span className="cx" title={i.text}>{i.target ? i.text.split(' ')[0] : i.text}</span>
              {i.target && (
                <button
                  className="ctgt"
                  data-testid="code-target"
                  title={'Go to ' + i.target + ' (right-click for more)'}
                  onClick={() => show(i.target as string, true)}
                  {...addrMenu(i.target)}
                >
                  <Icon name="chevron" size={10} />{targetLabel(i.target) || i.targetName || i.target}
                </button>
              )}
            </span>
          </div>
        ))}
        {!listing && !error && !loading && (
          <div className="insp-empty">Enter an address, or right-click any address in Fermion and choose Open in Disassembly.</div>
        )}
        {listing && (
          <div className="code-foot">
            {listing.stopped
              ? <span data-testid="code-stopped">{STOPPED[listing.stopped] ?? 'The listing ends here.'}</span>
              : full
                ? <span data-testid="code-stopped">Showing {MAX_SHOWN.toLocaleString()} instructions. Go to {listing.next} to continue.</span>
                : <button className="pill" data-testid="code-more" disabled={loading} onClick={() => load(listing.address, listing)}>{loading ? 'Reading…' : 'More'}</button>}
          </div>
        )}
        {loading && !listing && <div className="insp-empty">Reading…</div>}
      </div>
    </div>
  );
}
