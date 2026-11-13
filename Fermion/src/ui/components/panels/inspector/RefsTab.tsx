import { useEffect, useRef, useState } from 'react';
import { cleanIpcError, parseAddress } from '../../../inspector/format';
import { inspectApi } from '../../../inspector/useInspect';
import { addrMenu } from '../../../addressMenu';
import { useNames } from '../../../names';
import { AddressView } from '../../../store/uiSlice';
import { Goto } from './MemoryTab';

interface CodeRef { address: string; where: string; text: string; }
interface PointerRef { address: string; where: string; }
export interface RefsResult {
  address: string; module: string; pointers: PointerRef[]; code: CodeRef[];
  relative: boolean; unconfirmed: number; truncated: boolean; timedOut: boolean;
}

const plural = (count: number, word: string) => `${count.toLocaleString('en-US')} ${word}${count === 1 ? '' : 's'}`;

// One sentence for what was found.
export function refsLine(r: RefsResult): string {
  return `${plural(r.code.length, 'instruction')} and ${plural(r.pointers.length, 'pointer')} in ${r.module} refer to ${r.address}`;
}

// References: what refers to an address. Instructions that reach it (calls,
// jumps, and code that takes the address of a string or a global) and
// pointers to it (tables, vtables, saved callbacks), searched in one module:
// the one the address is in, unless another is named.
export function RefsTab({ goto, onOpen }: { goto: Goto | null; onOpen: (view: AddressView, address: string) => void }) {
  const names = useNames();
  const [address, setAddress] = useState('');
  const [moduleName, setModuleName] = useState('');
  const [result, setResult] = useState<RefsResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const request = useRef(0);
  const parsed = parseAddress(address.trim());

  const find = async (at: string | null, inModule: string) => {
    if (!at) return;
    const id = ++request.current;
    setBusy(true);
    setError('');
    try {
      const r: RefsResult = await inspectApi().refs(at, inModule.trim() || undefined);
      if (id === request.current) setResult(r);
    } catch (e) {
      if (id === request.current) { setResult(null); setError(cleanIpcError(e)); }
    } finally {
      if (id === request.current) setBusy(false);
    }
  };

  // An address handed over from the address menu: look for references to it, in its own module.
  const findRef = useRef(find);
  findRef.current = find;
  useEffect(() => {
    if (!goto) return;
    setAddress(goto.address);
    setModuleName('');
    findRef.current(parseAddress(goto.address), '');
  }, [goto?.n]); // keyed on the hand-off counter only

  return (
    <div className="insp-tab refs-tab">
      <div className="ptool">
        <input className="mini refs-address" data-testid="refs-address" aria-label="Address to find references to" placeholder="address, e.g. 0x7ff6a2c41000" spellCheck={false} value={address}
          onChange={(e) => setAddress(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && parsed && !busy) find(parsed, moduleName); }} />
        <span>in</span>
        <input className="mini refs-module" data-testid="refs-module" aria-label="Module to search" placeholder="its own module" spellCheck={false} value={moduleName}
          title="The module to search. Left empty, the module the address is in." onChange={(e) => setModuleName(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && parsed && !busy) find(parsed, moduleName); }} />
        <button className="pill" data-testid="refs-find" disabled={!parsed || busy} onClick={() => find(parsed, moduleName)}>{busy ? 'Searching…' : 'Find references'}</button>
        <span className="grow" />
        {result && !busy && <span className="count" data-testid="refs-count">{plural(result.code.length + result.pointers.length, 'reference')}</span>}
      </div>

      {error && <div className="insp-note err" role="alert" data-testid="refs-error">{error}</div>}
      {!result && !error && !busy && (
        <div className="insp-empty big" data-testid="refs-empty">
          Find what refers to an address: the instructions that call it, jump to it or take its address, and the pointers to it.
          Enter an address, or right-click one anywhere (a string, a function, a global) and choose Find references.
        </div>
      )}
      {busy && <div className="insp-note" data-testid="refs-busy">Searching the module. A large one takes a few seconds.</div>}

      {result && !busy && (
        <>
          <div className="insp-note" data-testid="refs-line">
            {refsLine(result)}.
            {result.truncated ? ' Only the first 200 of each kind are listed.' : ''}
            {result.timedOut ? ' The search ran out of time before the whole module was read, so some may be missing.' : ''}
            {!result.relative ? ' On this processor only pointers are searched for, not instructions that reach the address relative to themselves.' : ''}
          </div>
          <div className="insp-list">
            <div className="insp-head refs-cols" aria-hidden="true"><span>Instruction</span><span>In</span><span className="num">Address</span></div>
            {result.code.map((c, i) => (
              <div key={c.address + i} className="insp-row refs-cols" data-testid="refs-code" role="option" aria-selected={false} tabIndex={0} title={c.where + ' — open in Disassembly (right-click for more)'}
                onClick={() => onOpen('code', c.address)} onKeyDown={(e) => { if (e.key === 'Enter') onOpen('code', c.address); }} {...addrMenu(c.address)}>
                <span className="nm mono">{c.text}</span>
                <span className="nm dim">{names.show(c.where, c.address, '')}</span>
                <span className="num mono dim">{c.address}</span>
              </div>
            ))}
            {!result.code.length && <div className="insp-empty">No instruction in {result.module} refers to it.</div>}
            <div className="insp-head refs-cols" aria-hidden="true"><span>Pointer at</span><span /><span className="num">Address</span></div>
            {result.pointers.map((p, i) => (
              <div key={p.address + i} className="insp-row refs-cols" data-testid="refs-pointer" role="option" aria-selected={false} tabIndex={0} title={p.where + ' — open in Memory (right-click for more)'}
                onClick={() => onOpen('memory', p.address)} onKeyDown={(e) => { if (e.key === 'Enter') onOpen('memory', p.address); }} {...addrMenu(p.address)}>
                <span className="nm mono">{names.show(p.where, p.address, '')}</span>
                <span />
                <span className="num mono dim">{p.address}</span>
              </div>
            ))}
            {!result.pointers.length && <div className="insp-empty">No pointer to it in {result.module}.</div>}
          </div>
        </>
      )}
    </div>
  );
}
