import { useState } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { changeSet, sameSet, setLabel } from '../workspace';

// Which program's hooks and bookmarks are shown. It follows the program you
// attach to or spawn; picking another set here uses that one instead (to
// reuse hooks made for another program, or to look at them between sessions).
export function SetPicker() {
  const dispatch = useAppDispatch();
  const kept = useAppSelector((s) => s.sets); // absent in a store without saved work
  const active = kept?.active ?? '';
  const others = kept?.others ?? [];
  const hooks = useAppSelector((s) => s.hooks?.hooks) ?? [];
  const attached = useAppSelector((s) => s.session.isAttached);
  const [busy, setBusy] = useState(false);

  const names = [active, ...others.map((o) => o.name)];
  if (!names.some((n) => n === '')) names.push(''); // the general set can always be chosen
  names.sort((a, b) => setLabel(a).toLowerCase().localeCompare(setLabel(b).toLowerCase()));

  const pick = async (name: string) => {
    if (busy || sameSet(name, active)) return;
    setBusy(true);
    try { await changeSet(dispatch, name, hooks, attached); } finally { setBusy(false); }
  };

  if (!kept) return null;
  return (
    <label className="set-pick" title="Hooks and bookmarks are kept per program. This follows the program you attach to or spawn; pick another set to use it instead.">
      <span>Set</span>
      <select className="mini" data-testid="set-pick" aria-label="Set of hooks and bookmarks" value={active} disabled={busy} onChange={(e) => pick(e.target.value)}>
        {names.map((n) => <option key={n} value={n}>{setLabel(n)}</option>)}
      </select>
    </label>
  );
}
