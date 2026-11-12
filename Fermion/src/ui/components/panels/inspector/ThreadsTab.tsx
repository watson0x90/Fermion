import { useState } from 'react';
import { Icon } from '../../Icon';
import { parseAddress } from '../../../inspector/format';
import { inspectApi, useInspect, Listing } from '../../../inspector/useInspect';

interface Thr { id: number; name: string; state: string; pc: string | null; where: string; registers: Record<string, string>; }
const AUTO_MS = 2000;

interface Frame { address: string; where: string; symbol: string; }

// Threads of the target with where each one is; selecting a thread shows its
// register context and a backtrace. Pointer-like values open in the Memory tab.
export function ThreadsTab({ active, onViewMemory }: { active: boolean; onViewMemory: (address: string) => void }) {
  const [auto, setAuto] = useState(false);
  const threads = useInspect<Listing<Thr>>(() => inspectApi().threads(), 'threads', active, auto ? AUTO_MS : 0);
  const [selected, setSelected] = useState<number | null>(null);
  const thread = threads.data?.items.find((t) => t.id === selected) ?? null;

  const trace = useInspect<Listing<Frame>>(
    () => inspectApi().backtrace(selected),
    `bt|${selected}|${thread?.pc ?? ''}`,
    active && thread != null,
  );

  return (
    <div className="insp-tab">
      <div className="ptool">
        <span className="grow">Register values are a snapshot from the last refresh.</span>
        <span className="count" data-testid="thr-count">{threads.loading && !threads.data ? 'loading…' : `${threads.data?.total ?? 0} threads`}</span>
        <button className={'pill' + (auto ? ' on' : '')} data-testid="thr-auto" aria-pressed={auto} title="Re-read the threads every 2 seconds while this view is open" onClick={() => setAuto(!auto)}>Auto</button>
        <button className="pill" data-testid="thr-refresh" onClick={threads.reload}><Icon name="refresh" size={12} />Refresh</button>
      </div>
      {threads.error && <div className="insp-note err" role="alert">Could not list threads: {threads.error}</div>}

      <div className="insp-list" role="listbox" aria-label="Threads">
        <div className="insp-head thr-cols" aria-hidden="true"><span className="num">TID</span><span>State</span><span>Where</span></div>
        {(threads.data?.items ?? []).map((t) => (
          <div
            key={t.id}
            role="option"
            aria-selected={selected === t.id}
            data-testid={'thr-row-' + t.id}
            className={'insp-row thr-cols' + (selected === t.id ? ' sel' : '')}
            onClick={() => setSelected(t.id)}
          >
            <span className="num mono">{t.id}</span>
            <span className={'state ' + t.state}>{t.state}</span>
            <span className="nm mono">{t.name ? <span className="dim">{t.name} · </span> : null}{t.where}</span>
          </div>
        ))}
        {!threads.data?.items.length && !threads.loading && !threads.error && <div className="insp-empty">No threads.</div>}
      </div>

      {thread && (
        <div className="insp-detail" data-testid="thr-detail">
          <div className="ptool">
            <strong className="insp-title">Thread {thread.id}{thread.name ? ' · ' + thread.name : ''}</strong>
            <span className="grow" />
            <span className="count">{trace.loading ? 'unwinding…' : `${trace.data?.items.length ?? 0} frames`}</span>
          </div>
          <div className="insp-split">
            <div className="regs" data-testid="thr-registers">
              {Object.entries(thread.registers).map(([name, value]) => {
                const addr = parseAddress(value);
                return (
                  <div className="reg" key={name}>
                    <span className="rn">{name}</span>
                    {addr
                      ? <button className="addr mono" data-testid={'reg-' + name} title="Open in the Memory tab" onClick={() => onViewMemory(addr)}>{value}</button>
                      : <span className="mono" data-testid={'reg-' + name}>{value}</span>}
                  </div>
                );
              })}
              {!Object.keys(thread.registers).length && <div className="insp-empty">No register context for this thread.</div>}
            </div>
            <div className="frames">
              {trace.error && <div className="insp-note err" role="alert">Could not unwind: {trace.error}</div>}
              {(trace.data?.items ?? []).map((f, i) => (
                <div className="frame" key={f.address + i} data-testid="bt-row">
                  <span className="fi">{i}</span>
                  <button className="fsym mono" title={`${f.address} · ${f.where} — open in the Memory tab`} onClick={() => onViewMemory(f.address)}>{f.symbol || f.where}</button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
