import { useEffect, useState } from 'react';
import { useAppDispatch, useAppSelector } from '../../store';
import { uiActions, AddressView } from '../../store/uiSlice';
import { ModulesTab } from './inspector/ModulesTab';
import { MemoryTab, Goto } from './inspector/MemoryTab';
import { ThreadsTab } from './inspector/ThreadsTab';
import { CodeTab } from './inspector/CodeTab';

type Sub = 'modules' | 'memory' | 'code' | 'threads';
const SUBS: { id: Sub; label: string }[] = [
  { id: 'modules', label: 'Modules' },
  { id: 'memory', label: 'Memory' },
  { id: 'code', label: 'Disassembly' },
  { id: 'threads', label: 'Threads' },
];

// Inspector: read-only views of the attached process — its loaded modules
// (exports/imports), memory (ranges, hex view, scan), disassembly and threads
// (registers, backtrace). Each view loads when first shown and on Refresh; nothing here
// writes to the target.
export function InspectorPanel() {
  const isAttached = useAppSelector((s) => s.session.isAttached);
  const currentPid = useAppSelector((s) => s.session.currentPid);
  const panelActive = useAppSelector((s) => s.ui.activeTab === 'inspector');
  const [sub, setSub] = useState<Sub>('modules');
  const dispatch = useAppDispatch();
  const request = useAppSelector((s) => s.ui.addressRequest);
  // An address handed to the Memory or Disassembly view; it belongs to the
  // session it came from.
  const [goto, setGoto] = useState<(Goto & { view: AddressView; pid: string | null }) | null>(null);

  // The hand-off belongs to one session: forget it when the session ends, so a
  // later session (even on the same pid) does not open the old address.
  useEffect(() => { if (!isAttached) setGoto(null); }, [isAttached]);

  // A request to show an address — from this panel's own views, the address
  // menu, or another tab — opens the view it names.
  useEffect(() => {
    if (!request || !isAttached) return;
    setGoto({ view: request.view, address: request.address, n: request.n, pid: currentPid });
    setSub(request.view);
  }, [request?.n]); // keyed on the request counter only

  // "Open in Memory" from the Modules and Threads tabs.
  const viewMemory = (address: string) => dispatch(uiActions.openAddress({ view: 'memory', address }));
  const gotoFor = (view: AddressView) => (goto && goto.view === view && goto.pid === currentPid ? goto : null);

  return (
    <div className="inspector" data-testid="inspector-panel">
      <div className="subtabs" role="tablist" aria-label="Inspector views">
        {SUBS.map((s) => (
          <button key={s.id} role="tab" aria-selected={sub === s.id} data-testid={'insp-' + s.id} className={'subtab' + (sub === s.id ? ' on' : '')} onClick={() => setSub(s.id)}>
            {s.label}
          </button>
        ))}
      </div>
      {!isAttached ? (
        <div className="insp-empty big">Attach to a process to inspect its modules, memory, code and threads.</div>
      ) : (
        // Keyed by pid: a new session starts every view from scratch. All of them
        // stay mounted so switching views keeps filters, selection and scroll.
        <div className="insp-body" key={currentPid ?? 'none'}>
          <div className="insp-slot" hidden={sub !== 'modules'}><ModulesTab active={panelActive && sub === 'modules'} onViewMemory={viewMemory} /></div>
          <div className="insp-slot" hidden={sub !== 'memory'}><MemoryTab active={panelActive && sub === 'memory'} goto={gotoFor('memory')} /></div>
          <div className="insp-slot" hidden={sub !== 'code'}><CodeTab goto={gotoFor('code')} /></div>
          <div className="insp-slot" hidden={sub !== 'threads'}><ThreadsTab active={panelActive && sub === 'threads'} onViewMemory={viewMemory} /></div>
        </div>
      )}
    </div>
  );
}
