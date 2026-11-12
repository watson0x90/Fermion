import { useEffect, useRef, useState } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { sessionActions } from '../store/sessionSlice';
import { setTraceSink, writeTerminal } from '../bridge';
import { asTraceMessage, buildTraceScript, svgToDataUrl, svgNaturalWidth } from '../graph/trace';
import { cleanIpcError } from '../inspector/format';
import { Icon } from './Icon';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;
const scriptSrc = () => (window as any).MonacoCodeEditor?.getValue?.() ?? '';

const ZOOM_STEPS = [25, 50, 75, 100, 150, 200, 300, 400];
const MAX_SUGGESTIONS = 200;

interface Stats { graphs: number; calls: number; edges: number; truncated: boolean; }

// Graph: trace one exported function. While tracing, the editor's script is
// replaced by Fermion's tracer (src/tools/trace.js); each time the function
// runs, the calls made inside it come back as a Graphviz graph, rendered to
// SVG in the main process. Stop puts the editor's script back.
export function GraphPanel() {
  const dispatch = useAppDispatch();
  const traceMode = useAppSelector((s) => s.session.traceMode);
  const isAttached = useAppSelector((s) => s.session.isAttached);
  const [mod, setMod] = useState('');
  const [sym, setSym] = useState('');
  const [svg, setSvg] = useState('');
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [stats, setStats] = useState<Stats | null>(null);
  const [busy, setBusy] = useState(false);
  // Percent of the graph's natural size (readable text); null = shrink to fit the pane.
  const [zoom, setZoom] = useState<number | null>(100);
  const [modules, setModules] = useState<string[]>([]);
  const [exportsOf, setExportsOf] = useState<{ module: string; names: string[] }>({ module: '', names: [] });
  const renderId = useRef(0);
  const stopRef = useRef<(why?: string) => void>(() => {});

  // Put the editor's script back and leave trace mode.
  const stop = async (why?: string) => {
    dispatch(sessionActions.setTraceMode(false));
    setStatus('');
    if (why) setError(why);
    try {
      await api().reloadScript(scriptSrc());
      dispatch(sessionActions.scriptLoaded());
    } catch (e) {
      writeTerminal('ERR', '[!] Error reloading script: ' + cleanIpcError(e));
    }
  };
  stopRef.current = stop;

  useEffect(() => {
    // While tracing, the tracer's send() payloads arrive here.
    setTraceSink((payload) => {
      const msg = asTraceMessage(payload);
      if (!msg) return;
      if (msg.fermionTrace === 'ready') {
        setStatus(`Tracing ${msg.target} at ${msg.address} — waiting for it to be called.`);
      } else if (msg.fermionTrace === 'error') {
        stopRef.current(msg.message);
      } else {
        const id = ++renderId.current;
        setStats((s) => ({ graphs: (s?.graphs ?? 0) + 1, calls: msg.calls, edges: msg.edges, truncated: msg.truncated }));
        Promise.resolve()
          .then(() => api().renderGraph(msg.dot))
          .then((out: string) => { if (id === renderId.current) { setSvg(String(out)); setError(''); } }) // newest graph wins
          .catch((e: unknown) => { if (id === renderId.current) setError('Could not draw the graph: ' + cleanIpcError(e)); });
      }
    });
    return () => setTraceSink(null);
  }, []);

  const onTrace = async () => {
    if (!isAttached || !sym.trim() || busy) return;
    setBusy(true);
    setError('');
    setStats(null);
    setStatus('Starting…');
    // Trace mode goes on BEFORE the tracer loads, so its first message (ready,
    // or an error) is routed here and not to Output.
    dispatch(sessionActions.setTraceMode(true));
    try {
      const res = await fetch('../src/tools/trace.js');
      await api().reloadScript(buildTraceScript(await res.text(), mod, sym));
    } catch (e) {
      dispatch(sessionActions.setTraceMode(false));
      setStatus('');
      setError('Could not start the trace: ' + cleanIpcError(e));
    } finally {
      setBusy(false);
    }
  };

  // Suggestions come from the Inspector's read-only listings, loaded on demand.
  const loadModules = () => {
    if (!isAttached || modules.length) return;
    api()?.inspect?.modules?.().then((r: any) => setModules((r?.items ?? []).map((m: any) => String(m.name)))).catch(() => {});
  };
  const loadExports = () => {
    const name = mod.trim();
    if (!isAttached || !name || exportsOf.module === name) return;
    api()?.inspect?.exports?.(name)
      .then((r: any) => setExportsOf({ module: name, names: (r?.items ?? []).filter((e: any) => e.type === 'function').map((e: any) => String(e.name)) }))
      .catch(() => setExportsOf({ module: name, names: [] }));
  };
  const symNeedle = sym.trim().toLowerCase();
  const symOptions = exportsOf.module === mod.trim()
    ? exportsOf.names.filter((n) => n.toLowerCase().includes(symNeedle)).slice(0, MAX_SUGGESTIONS)
    : [];

  const step = (dir: 1 | -1) => {
    if (zoom === null) { setZoom(100); return; } // leaving Fit starts again from natural size
    const next = dir > 0 ? ZOOM_STEPS.find((z) => z > zoom) : [...ZOOM_STEPS].reverse().find((z) => z < zoom);
    if (next) setZoom(next);
  };
  const natural = svg ? svgNaturalWidth(svg) : null;
  const imgStyle = zoom === null
    ? { maxWidth: '100%' }
    : natural ? { width: Math.round((natural * zoom) / 100) + 'px', maxWidth: 'none' } : { width: zoom + '%', maxWidth: 'none' };
  const save = () => { if (svg) api()?.saveFile?.(svg, { title: 'Save Trace Graph', defaultPath: 'trace.svg' }); };

  return (
    <div className="graphpanel" data-testid="graph-panel">
      <div className="ptool">
        <input className="pill gin" aria-label="module" data-testid="graph-module" list="graph-modules" placeholder="module, e.g. kernel32.dll" value={mod} disabled={traceMode} onFocus={loadModules} onChange={(e) => setMod(e.target.value)} />
        <datalist id="graph-modules">{modules.map((m) => <option key={m} value={m} />)}</datalist>
        <input className="pill gin" aria-label="symbol" data-testid="graph-symbol" list="graph-symbols" placeholder="exported function" value={sym} disabled={traceMode} onFocus={loadExports} onChange={(e) => setSym(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') onTrace(); }} />
        <datalist id="graph-symbols">{symOptions.map((n) => <option key={n} value={n} />)}</datalist>
        {traceMode
          ? <button className="pill on" data-testid="graph-stop" onClick={() => stop()}><Icon name="stop" size={11} />Stop</button>
          : <button className="pill" data-testid="graph-trace" onClick={onTrace} disabled={!isAttached || !sym.trim() || busy} title={!isAttached ? 'Attach to a process first' : !sym.trim() ? 'Enter the function to trace' : 'Replace the loaded script with the tracer and trace this function'}><Icon name="play" size={11} />Trace</button>}
      </div>

      {error && <div className="graph-note err" role="alert">{error}</div>}
      {(status || stats || svg) && (
        <div className="graph-bar">
          <span className="grow" data-testid="graph-status">
            {stats
              ? `${stats.graphs} graph${stats.graphs === 1 ? '' : 's'} so far · latest: ${stats.calls.toLocaleString()} calls, ${stats.edges} distinct${stats.truncated ? ' (cut short: too many to draw)' : ''}${traceMode ? '' : ' · stopped'}`
              : status}
          </span>
          {svg && (
            <>
              <button className="pill" data-testid="graph-zoom-out" title="Zoom out" onClick={() => step(-1)}>−</button>
              <span className="zoomlvl" data-testid="graph-zoom-level">{zoom === null ? 'Fit' : zoom + '%'}</span>
              <button className="pill" data-testid="graph-zoom-in" title="Zoom in" onClick={() => step(1)}>+</button>
              <button className={'pill' + (zoom === null ? ' on' : '')} data-testid="graph-zoom-fit" title="Shrink the whole graph to fit the pane" aria-pressed={zoom === null} onClick={() => setZoom(null)}>Fit</button>
              <button className="pill" data-testid="graph-save" title="Save the graph as SVG" onClick={save}><Icon name="floppy" size={12} />Save</button>
            </>
          )}
        </div>
      )}

      <div className="graph-svg" data-testid="graph-svg">
        {svg
          ? <img data-testid="graph-img" alt="Call graph of the traced function" src={svgToDataUrl(svg)} style={imgStyle} draggable={false} />
          : (
            <div className="graph-empty">
              {isAttached
                ? <>Enter a module and one of its exported functions, then press Trace. Each time the function runs, the calls it makes are drawn here. While tracing, the script from the Editor is replaced by the tracer; Stop puts it back.</>
                : <>Attach to a process to trace a function.</>}
            </div>
          )}
      </div>
    </div>
  );
}
