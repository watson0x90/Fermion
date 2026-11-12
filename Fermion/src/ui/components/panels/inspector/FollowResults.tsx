import { useMemo, useState } from 'react';
import { Icon } from '../../Icon';
import { FollowItem, FollowModule, filterFollow, groupFollow, followCsv, moduleLabel } from '../../../inspector/follow';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;
const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;

// The functions a followed thread called: a flat list, most-called first, or
// grouped by module with each module's totals. The filter applies to both, and
// Save writes the functions shown as CSV.
export function FollowResults({ threadId, items, modules, onViewMemory }: {
  threadId: number | null;
  items: FollowItem[];
  modules?: FollowModule[] | null;
  onViewMemory: (address: string) => void;
}) {
  const [filter, setFilter] = useState('');
  const [byModule, setByModule] = useState(false);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const filtering = filter.trim() !== '';

  const shown = useMemo(() => filterFollow(items, filter), [items, filter]);
  // Filtered: only the groups with a match, counted from the rows that match.
  const groups = useMemo(
    () => (byModule ? groupFollow(shown, filtering ? null : modules) : []),
    [byModule, shown, filtering, modules],
  );

  const save = () => {
    if (shown.length) api()?.exportFile?.(followCsv(shown), { title: 'Save Followed Calls', defaultPath: `thread-${threadId ?? 'x'}-calls.csv` });
  };

  const row = (f: FollowItem) => (
    <div className="frame follow" key={f.address} data-testid="follow-row">
      <span className="fc">{f.count.toLocaleString()}</span>
      <button className="fsym mono" title={f.address + ' — open in the Memory tab'} onClick={() => onViewMemory(f.address)}>{f.name}</button>
    </div>
  );

  return (
    <div className="frames follow-pane" data-testid="follow-results">
      {items.length > 0 && (
        <div className="follow-tools">
          <span className="search insp-filter"><Icon name="search" size={13} />
            <input data-testid="follow-filter" placeholder="Filter functions" aria-label="Filter functions" value={filter} onChange={(e) => setFilter(e.target.value)} />
          </span>
          <span className="count" data-testid="follow-shown">
            {filtering ? `${shown.length} of ${items.length}` : plural(items.length, 'function')}
          </span>
          <button className={'pill' + (byModule ? ' on' : '')} data-testid="follow-bymodule" aria-pressed={byModule} title="Group the functions by module, with each module's totals" onClick={() => setByModule(!byModule)}>By module</button>
          <button className="pill ico" data-testid="follow-save" aria-label="Save as CSV" title="Save the functions shown as a CSV file" disabled={!shown.length} onClick={save}><Icon name="floppy" size={13} /></button>
        </div>
      )}
      <div className="follow-list">
        {!byModule && shown.map(row)}
        {byModule && groups.map((g) => {
          const expanded = filtering || !!open[g.name];
          return (
            <div key={g.name || '\u0000'}>
              <button
                className="follow-group"
                data-testid="follow-group"
                aria-expanded={expanded}
                disabled={filtering}
                onClick={() => setOpen({ ...open, [g.name]: !open[g.name] })}
              >
                <span className={'chev' + (expanded ? ' open' : '')}><Icon name="chevron" size={11} /></span>
                <span className="gn mono">{moduleLabel(g.name)}</span>
                <span className="gt">{plural(g.calls, 'call')} · {plural(g.functions, 'function')}</span>
              </button>
              {expanded && g.items.map(row)}
              {expanded && !g.items.length && <div className="insp-empty">None of its functions are among the most-called listed.</div>}
            </div>
          );
        })}
        {!items.length && <div className="insp-empty">The thread made no calls while it was followed (it may have been waiting).</div>}
        {items.length > 0 && !shown.length && <div className="insp-empty">No function matches the filter.</div>}
      </div>
    </div>
  );
}
