import { useEffect, useRef, useState } from 'react';
import { cleanIpcError, fmtSize } from '../../../inspector/format';
import { inspectApi, useInspect, Listing } from '../../../inspector/useInspect';
import { FollowMode, FollowScope } from '../../../inspector/follow';
import { writeTerminal } from '../../../bridge';

interface Thr { id: number; name: string; }
interface Mod { name: string; }
interface CoverModule { name: string; path: string; blocks: number; bytes: number; }
export interface CoverSummary {
  recorded: boolean; threads: number; all: boolean; seconds: number; blocks: number; bytes: number; unmapped: number;
  overflow: boolean; endedBy: string; scope: FollowScope | null; modules: CoverModule[]; moduleCount: number; drcovBytes: number;
}
interface Started { recording: boolean; threads: number; maxSeconds: number; maxBlocks: number; scope: FollowScope; excluded: number; }

const n = (v: number) => v.toLocaleString('en-US');

// One sentence for a finished recording.
export function coverLine(s: CoverSummary): string {
  return `${n(s.blocks)} basic block${s.blocks === 1 ? '' : 's'} (${fmtSize(s.bytes)} of code) in ${n(s.moduleCount)} module${s.moduleCount === 1 ? '' : 's'}, `
    + `on ${s.threads} thread${s.threads === 1 ? '' : 's'} over ${s.seconds} s`;
}

// Coverage: record which code runs while you use the program, then save it
// as a drcov file (for Lighthouse in IDA or Binary Ninja, Dragondance in
// Ghidra) or as a text report that names the functions (for reading, or for
// giving to a language model).
export function CoverageTab({ active }: { active: boolean }) {
  const [who, setWho] = useState('all'); // 'all' or a thread id
  const [scopeMode, setScopeMode] = useState<FollowMode>('app');
  const [scopeModule, setScopeModule] = useState('');
  const [recording, setRecording] = useState<Started | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<CoverSummary | null>(null);
  const [saved, setSaved] = useState('');
  const [elapsed, setElapsed] = useState(0);
  const threads = useInspect<Listing<Thr>>(() => inspectApi().threads(), 'cover-threads', active && !recording);
  const moduleNames = useInspect<Listing<Mod>>(() => inspectApi().modules(), 'cover-modules', active && scopeMode === 'module');
  const scopeReady = scopeMode !== 'module' || scopeModule.trim() !== '';
  const recordingRef = useRef(false);
  recordingRef.current = recording !== null;

  const stop = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const summary: CoverSummary = await inspectApi().coverStop();
      setResult(summary.recorded ? summary : null);
      setError(summary.recorded ? '' : 'Nothing was recorded.');
      if (summary.recorded) writeTerminal('STATUS', '[+] Coverage: ' + coverLine(summary));
    } catch (e) {
      setError('Could not collect the coverage: ' + cleanIpcError(e));
    } finally {
      setRecording(null);
      setBusy(false);
    }
  };

  const start = async () => {
    if (busy || !scopeReady) return;
    setBusy(true);
    setError('');
    setSaved('');
    try {
      const scope: FollowScope = { mode: scopeMode, module: scopeMode === 'module' ? scopeModule.trim() : '' };
      const started: Started = await inspectApi().coverStart(who === 'all' ? 'all' : Number(who), scope);
      setResult(null);
      setElapsed(0);
      setRecording(started);
    } catch (e) {
      setError(cleanIpcError(e));
    } finally {
      setBusy(false);
    }
  };

  // The clock, and the agent's own time limit: collect when it is reached.
  const stopRef = useRef(stop);
  stopRef.current = stop;
  useEffect(() => {
    if (!recording) return;
    const began = Date.now();
    const tick = setInterval(() => {
      const s = Math.floor((Date.now() - began) / 1000);
      setElapsed(s);
      if (s >= recording.maxSeconds) stopRef.current();
    }, 1000);
    return () => clearInterval(tick);
  }, [recording]);

  // Leaving the view with a recording running would keep the target slowed
  // down with nothing to show for it: stop it.
  useEffect(() => () => { if (recordingRef.current) inspectApi()?.coverStop?.().catch(() => {}); }, []);

  const save = async (format: 'drcov' | 'text') => {
    setError('');
    try {
      const r = await inspectApi().coverSave(format);
      if (!r?.path) return; // cancelled
      setSaved(r.path);
      writeTerminal('STATUS', `[+] Coverage ${format === 'text' ? 'report' : 'file (drcov)'} saved: ${r.path}`);
    } catch (e) {
      setError('Could not save: ' + cleanIpcError(e));
    }
  };

  return (
    <div className="insp-tab cover-tab">
      <div className="ptool">
        <select className="mini" data-testid="cover-who" aria-label="Threads to record" value={who} disabled={!!recording || busy} onChange={(e) => setWho(e.target.value)} title="Record every thread, including ones that start while recording, or just one">
          <option value="all">All threads</option>
          {(threads.data?.items ?? []).map((t) => <option key={t.id} value={t.id}>Thread {t.id}{t.name ? ' · ' + t.name : ''}</option>)}
        </select>
        <select className="mini" data-testid="cover-scope" aria-label="What to record" value={scopeMode} disabled={!!recording || busy} onChange={(e) => setScopeMode(e.target.value as FollowMode)} title="Code outside the scope is not recorded, and runs at full speed">
          <option value="app">Everything except system libraries</option>
          <option value="module">One module</option>
          <option value="all">Everything</option>
        </select>
        {scopeMode === 'module' && (
          <>
            <input className="mini follow-module" data-testid="cover-module" aria-label="Module to record" placeholder="module name" list="cover-modules" spellCheck={false} value={scopeModule} disabled={!!recording || busy} onChange={(e) => setScopeModule(e.target.value)} />
            <datalist id="cover-modules">
              {(moduleNames.data?.items ?? []).map((m) => <option key={m.name} value={m.name} />)}
            </datalist>
          </>
        )}
        <button className={'pill' + (recording ? ' on' : '')} data-testid="cover-toggle" disabled={busy || (!recording && !scopeReady)} onClick={recording ? stop : start}>
          {recording ? (busy ? 'Collecting…' : 'Stop') : busy ? 'Starting…' : 'Record'}
        </button>
        <span className="grow" />
        {recording && <span className="count" data-testid="cover-clock">{elapsed} s</span>}
      </div>

      {error && <div className="insp-note err" role="alert" data-testid="cover-error">{error}</div>}
      {recording && (
        <div className="insp-note" data-testid="cover-status">
          Recording on {recording.threads} thread{recording.threads === 1 ? '' : 's'}. Use the program now, then press Stop.
          The program runs slower while this is on. It stops by itself after {Math.round(recording.maxSeconds / 60)} minutes or {n(recording.maxBlocks)} blocks.
        </div>
      )}

      {!recording && !result && !error && (
        <div className="insp-empty big" data-testid="cover-empty">
          Record which code runs while you use the program: press Record, do the thing you are interested in, press Stop.
          The result can be saved as a drcov file for Lighthouse or Dragondance, or as a text report that names the functions.
        </div>
      )}

      {result && (
        <>
          <div className="cover-result" data-testid="cover-result">
            <div className="cover-line" data-testid="cover-line">
              {coverLine(result)}.
              {result.endedBy === 'limit' ? ' It stopped at the limit.' : ''}
              {result.overflow ? ' The block limit was reached: later code is missing.' : ''}
              {result.unmapped ? ` ${n(result.unmapped)} more blocks ran outside every module (generated code) and are not in the files.` : ''}
            </div>
            <div className="btns">
              <button className="pill" data-testid="cover-save-drcov" disabled={!result.blocks} title="For Lighthouse (IDA, Binary Ninja), Dragondance (Ghidra) and other tools that read drcov" onClick={() => save('drcov')}>Save drcov…</button>
              <button className="pill" data-testid="cover-save-text" disabled={!result.blocks} title="Plain text: the modules and the functions that ran, with the units explained. Readable by a person or a language model." onClick={() => save('text')}>Save text report…</button>
              {saved && <span className="saved" data-testid="cover-saved" title={saved}>Saved to {saved}</span>}
            </div>
          </div>
          <div className="insp-list">
            <div className="insp-head cover-cols" aria-hidden="true"><span>Module</span><span className="num">Blocks</span><span className="num">Code</span><span>Path</span></div>
            {result.modules.map((m) => (
              <div key={m.path || m.name} className="insp-row cover-cols" data-testid="cover-row" title={m.path}>
                <span className="nm">{m.name}</span>
                <span className="num mono">{n(m.blocks)}</span>
                <span className="num mono dim">{fmtSize(m.bytes)}</span>
                <span className="nm dim">{m.path}</span>
              </div>
            ))}
            {result.moduleCount > result.modules.length && <div className="insp-empty">{n(result.moduleCount - result.modules.length)} more modules are in the saved files.</div>}
            {!result.modules.length && <div className="insp-empty">No code inside a module ran in the scope you chose.</div>}
          </div>
        </>
      )}
    </div>
  );
}
