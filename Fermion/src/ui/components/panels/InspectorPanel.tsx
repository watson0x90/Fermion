import { useState } from 'react';
import { useAppSelector } from '../../store';
import { ModulesTab } from './inspector/ModulesTab';
import { MemoryTab, Goto } from './inspector/MemoryTab';
import { ThreadsTab } from './inspector/ThreadsTab';

type Sub = 'modules' | 'memory' | 'threads';
const SUBS: { id: Sub; label: string }[] = [
  { id: 'modules', label: 'Modules' },
  { id: 'memory', label: 'Memory' },
  { id: 'threads', label: 'Threads' },
];

// Inspector: read-only views of the attached process — its loaded modules
// (exports/imports), memory (ranges, hex view, scan) and threads (registers,
// backtrace). Each view loads when first shown and on Refresh; nothing here
// writes to the target.
export function InspectorPanel() {
  const isAttached = useAppSelector((s) => s.session.isAttached);
  const currentPid = useAppSelector((s) => s.session.currentPid);
  const panelActive = useAppSelector((s) => s.ui.activeTab === 'inspector');
  const [sub, setSub] = useState<Sub>('modules');
  // An address handed to the Memory tab; it belongs to the session it came from.
  const [goto, setGoto] = useState<(Goto & { pid: string | null }) | null>(null);

  // "Open in Memory" from the Modules and Threads tabs.
  const viewMemory = (address: string) => {
    setGoto((g) => ({ address, n: (g?.n ?? 0) + 1, pid: currentPid }));
    setSub('memory');
  };

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
        <div className="insp-empty big">Attach to a process to inspect its modules, memory and threads.</div>
      ) : (
        // Keyed by pid: a new session starts every view from scratch. All three
        // stay mounted so switching views keeps filters, selection and scroll.
        <div className="insp-body" key={currentPid ?? 'none'}>
          <div className="insp-slot" hidden={sub !== 'modules'}><ModulesTab active={panelActive && sub === 'modules'} onViewMemory={viewMemory} /></div>
          <div className="insp-slot" hidden={sub !== 'memory'}><MemoryTab active={panelActive && sub === 'memory'} goto={goto && goto.pid === currentPid ? goto : null} /></div>
          <div className="insp-slot" hidden={sub !== 'threads'}><ThreadsTab active={panelActive && sub === 'threads'} onViewMemory={viewMemory} /></div>
        </div>
      )}
    </div>
  );
}
