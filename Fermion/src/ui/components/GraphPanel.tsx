import { useEffect, useState } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { sessionActions } from '../store/sessionSlice';
import { setTraceSink } from '../bridge';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;
const scriptSrc = () => (window as any).MonacoCodeEditor?.getValue?.() ?? '';

// Graph panel: enter trace mode (reload with the Graphviz tracer), receive DOT
// via the bridge trace sink, render it to SVG in the main process. Replaces the
// trace.html pop-up + its node-graphviz usage. STOP reloads the editor script.
export function GraphPanel() {
  const dispatch = useAppDispatch();
  const traceMode = useAppSelector((s) => s.session.traceMode);
  const isAttached = useAppSelector((s) => s.session.isAttached);
  const [mod, setMod] = useState('');
  const [sym, setSym] = useState('');
  const [svg, setSvg] = useState('');

  useEffect(() => {
    // DOT payloads (while tracing) render to SVG in main and display here.
    setTraceSink((payload) => {
      api()?.renderGraph?.(String(payload)).then((s: string) => setSvg(s));
    });
    return () => setTraceSink(null);
  }, []);

  const onTrace = async () => {
    const res = await fetch('../src/tools/trace.js');
    const body = await res.text();
    const ptr = `var pFunctionPtr = Module.findExportByName("${mod}", "${sym}");`;
    await api().reloadScript(ptr + '\n' + body);
    dispatch(sessionActions.setTraceMode(true));
  };
  const onStop = async () => {
    dispatch(sessionActions.setTraceMode(false));
    await api().reloadScript(scriptSrc());
  };

  return (
    <div className="graphpanel">
      <div className="ptool">
        <input className="pill" aria-label="module" placeholder="module" value={mod} onChange={(e) => setMod(e.target.value)} />
        <input className="pill" aria-label="symbol" placeholder="symbol" value={sym} onChange={(e) => setSym(e.target.value)} />
        {traceMode
          ? <button className="pill" onClick={onStop}>STOP</button>
          : <button className="pill" onClick={onTrace} disabled={!isAttached}>Trace</button>}
      </div>
      {/* graphviz SVG (XML-escaped labels); same sink the old trace.html used */}
      <div className="graph-svg" data-testid="graph-svg" dangerouslySetInnerHTML={{ __html: svg }} />
    </div>
  );
}
