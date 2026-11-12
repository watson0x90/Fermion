import { useEffect, useMemo, useRef, useState, CSSProperties } from 'react';
import { useAppDispatch, useAppSelector } from '../../store';
import { attachAndLoad } from '../../sessionOps';
import { buildTree, flattenTree, ancestryOf, hasParentInfo, Proc } from '../../processTree';
import { Icon } from '../Icon';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;

// Process tree: the active device's processes as a parent -> child hierarchy,
// so a target can be picked in context (which chrome.exe? whose child?). The
// attached process is highlighted; "Only ancestry" narrows the tree to its line.
export function ProcessTreePanel() {
  const dispatch = useAppDispatch();
  const active = useAppSelector((s) => s.ui.activeTab === 'tree');
  const deviceId = useAppSelector((s) => s.session.deviceId);
  const isAttached = useAppSelector((s) => s.session.isAttached);
  const currentPid = useAppSelector((s) => s.session.currentPid);

  const [procs, setProcs] = useState<Proc[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState('');
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  const [ancestry, setAncestry] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);
  const [busyPid, setBusyPid] = useState<number | null>(null);
  const [nonce, setNonce] = useState(0);
  const request = useRef(0);

  // Enumerate only while this tab is showing (every panel stays mounted), and
  // again on refresh or when the device changes.
  useEffect(() => {
    if (!active) return;
    const id = ++request.current;
    setLoading(true);
    Promise.resolve()
      .then(() => api().enumerateProcesses())
      .then((list: Proc[]) => {
        if (id !== request.current) return; // a newer request superseded this one
        setProcs(Array.isArray(list) ? list : []);
        setError('');
      })
      .catch((e: unknown) => {
        if (id !== request.current) return;
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => { if (id === request.current) setLoading(false); });
  }, [active, deviceId, nonce]);

  const attachedPid = isAttached && currentPid != null ? Number(currentPid) : null;
  const onlyAncestry = ancestry && attachedPid != null;
  const tree = useMemo(() => buildTree(procs), [procs]);
  const rows = useMemo(
    () => flattenTree(tree, { filter, collapsed, only: onlyAncestry ? ancestryOf(procs, attachedPid as number) : null }),
    [tree, procs, filter, collapsed, onlyAncestry, attachedPid],
  );

  const maxDepth = rows.reduce((m, r) => Math.max(m, r.depth), 0);

  // Bring the attached process into view when it becomes attached or the view
  // is narrowed to its ancestry (it is often deep in the tree).
  const attachedRow = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (attachedPid != null) attachedRow.current?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
  }, [attachedPid, onlyAncestry]);

  const toggle = (pid: number) => setCollapsed((prev) => {
    const next = new Set(prev);
    if (next.has(pid)) next.delete(pid); else next.add(pid);
    return next;
  });
  const attach = async (pid: number) => {
    if (isAttached || busyPid != null) return;
    setBusyPid(pid);
    try { await attachAndLoad(dispatch, pid); } finally { setBusyPid(null); }
  };

  const count = filter.trim() || onlyAncestry ? `${rows.length} of ${procs.length} processes` : `${procs.length} processes`;

  return (
    <div className="ptree" data-testid="tree-panel">
      <div className="ptool">
        <span className="search ptree-filter">
          <Icon name="search" size={13} />
          <input data-testid="tree-filter" placeholder="Filter by name or PID" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </span>
        <button
          className={'pill' + (onlyAncestry ? ' on' : '')}
          data-testid="tree-ancestry"
          aria-pressed={onlyAncestry}
          disabled={attachedPid == null}
          title={attachedPid == null ? 'Attach to a process to narrow the tree to its ancestry' : 'Show only the attached process, its parents and its children'}
          onClick={() => setAncestry(!onlyAncestry)}
        >
          Only ancestry
        </button>
        <span className="grow" />
        <span className="count" data-testid="tree-count">{loading && !procs.length ? 'loading…' : count}</span>
        <button className="pill" data-testid="tree-refresh" title="Refresh the process list" onClick={() => setNonce((n) => n + 1)}><Icon name="refresh" size={12} />Refresh</button>
      </div>

      {error && <div className="ptree-note err" role="alert">Could not list processes: {error}</div>}
      {!error && procs.length > 0 && !hasParentInfo(procs) && (
        <div className="ptree-note">This device does not report parent processes, so the list is flat.</div>
      )}

      <div className="ptree-rows" role="tree" aria-label="Process tree" style={{ '--maxd': maxDepth } as CSSProperties}>
        <div className="ptree-head" aria-hidden="true"><span>Process</span><span className="pid">PID</span><span className="usr">User</span><span /></div>
        {rows.map((r) => {
          const isAtt = r.pid === attachedPid;
          return (
            <div
              key={r.pid}
              role="treeitem"
              aria-level={r.depth + 1}
              aria-expanded={r.hasChildren ? !r.collapsed : undefined}
              aria-selected={selected === r.pid}
              data-pid={r.pid}
              data-testid={'proc-' + r.pid}
              className={'prow' + (isAtt ? ' attached' : '') + (r.match ? ' match' : '') + (selected === r.pid ? ' sel' : '')}
              title={r.path || r.name}
              style={{ '--d': r.depth } as CSSProperties}
              ref={isAtt ? attachedRow : undefined}
              onClick={() => setSelected(r.pid)}
              onDoubleClick={() => attach(r.pid)}
            >
              <span className="nm">
                {r.hasChildren
                  ? <button className={'twisty' + (r.collapsed ? '' : ' open')} data-testid="twisty" aria-label={r.collapsed ? 'Expand' : 'Collapse'} onClick={(e) => { e.stopPropagation(); toggle(r.pid); }} onDoubleClick={(e) => e.stopPropagation()}><Icon name="chevron" size={12} /></button>
                  : <span className="twisty none" />}
                <span className="name">{r.name}</span>
                {isAtt && <span className="badge">attached</span>}
              </span>
              <span className="pid">{r.pid}</span>
              <span className="usr">{r.user ?? ''}</span>
              <span className="act">
                {!isAttached && (
                  <button className="attach" data-testid="row-attach" disabled={busyPid != null} onClick={(e) => { e.stopPropagation(); attach(r.pid); }} onDoubleClick={(e) => e.stopPropagation()}>
                    {busyPid === r.pid ? 'Attaching…' : 'Attach'}
                  </button>
                )}
              </span>
            </div>
          );
        })}
        {!rows.length && !error && !loading && (
          <div className="ptree-empty">
            {procs.length ? `No process matches “${filter.trim()}”.` : 'No processes listed for this device.'}
          </div>
        )}
      </div>
    </div>
  );
}
