import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session, { sessionActions } from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui from '../store/uiSlice';
import { GraphPanel } from './GraphPanel';
import { initBridge, setTerminalSink } from '../bridge';
import { buildTraceScript, svgToDataUrl, asTraceMessage, svgNaturalWidth } from '../graph/trace';

/* eslint-disable @typescript-eslint/no-explicit-any */
let calls: any[];
let fermion: any;
let emit: (payload: unknown) => void; // a send() from the loaded script
let lines: string[];

function setup({ attached = true } = {}) {
  calls = [];
  lines = [];
  setTerminalSink({ write: (k: string, t: string) => { lines.push(k + ' ' + t); } });
  (window as any).MonacoCodeEditor = { getValue: () => 'USERSCRIPT' };
  let onMessage: (m: any) => void = () => {};
  fermion = {
    onMessage: (cb: any) => { onMessage = cb; }, onLog: () => {}, onDetached: () => {},
    reloadScript: vi.fn(async (s: string) => { calls.push(['reload', s]); }),
    renderGraph: vi.fn(async (dot: string) => `<svg width="300pt" height="150pt" xmlns="http://www.w3.org/2000/svg"><!--${dot}--></svg>`),
    saveFile: vi.fn(async () => 'C:/trace.svg'),
    inspect: {
      modules: vi.fn(async () => ({ items: [{ name: 'kernel32.dll' }, { name: 'ntdll.dll' }] })),
      exports: vi.fn(async () => ({ items: [{ type: 'function', name: 'CreateFileW' }, { type: 'variable', name: 'g_data' }, { type: 'function', name: 'CloseHandle' }] })),
    },
  };
  (window as any).fermion = fermion;
  (globalThis as any).fetch = vi.fn(async () => ({ text: async () => 'TRACER_BODY' }));
  const store = configureStore({ reducer: { session, output, ui } });
  initBridge(store, fermion); // the real routing: SEND -> trace sink while tracing
  emit = (payload) => act(() => { onMessage({ type: 'send', payload }); });
  if (attached) store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '1' }));
  render(<Provider store={store}><GraphPanel /></Provider>);
  return store;
}
afterEach(() => setTerminalSink(null));

const fill = (mod: string, sym: string) => {
  fireEvent.change(screen.getByTestId('graph-module'), { target: { value: mod } });
  fireEvent.change(screen.getByTestId('graph-symbol'), { target: { value: sym } });
};
const DOT = { fermionTrace: 'dot', dot: 'digraph Trace { "a" -> "b"; }', calls: 12, edges: 5, truncated: false };

test('pure: the tracer is told what to hook as JSON data, so names cannot inject code', () => {
  const s = buildTraceScript('BODY', ' k32.dll ', 'open"); evil(); ("');
  expect(s.split('\n')[0]).toBe('var FERMION_TRACE = {"module":"k32.dll","symbol":"open\\"); evil(); (\\""};');
  expect(s.endsWith('\nBODY')).toBe(true);
  // The first line is one declaration whose value is exactly the names given.
  expect(new Function(s.split('\n')[0] + '; return FERMION_TRACE;')()).toEqual({ module: 'k32.dll', symbol: 'open"); evil(); ("' });
});

test('pure: trace messages are recognized by shape; anything else is ignored', () => {
  expect(asTraceMessage({ fermionTrace: 'ready', address: '0x1', target: 'a!b' })).toEqual({ fermionTrace: 'ready', address: '0x1', target: 'a!b' });
  expect(asTraceMessage({ fermionTrace: 'dot', dot: 'digraph{}', calls: '3', edges: 2 })).toEqual({ fermionTrace: 'dot', dot: 'digraph{}', calls: 3, edges: 2, truncated: false });
  expect(asTraceMessage('digraph{}')).toBeNull();
  expect(asTraceMessage({ fermionTrace: 'dot' })).toBeNull();
  expect(asTraceMessage(null)).toBeNull();
  expect(svgToDataUrl('<svg>#</svg>')).toBe('data:image/svg+xml;charset=utf-8,%3Csvg%3E%23%3C%2Fsvg%3E');
});

test('Trace needs a session and a function name', () => {
  const store = setup({ attached: false });
  expect(screen.getByTestId('graph-trace')).toBeDisabled();
  expect(screen.getByTestId('graph-panel')).toHaveTextContent(/Attach to a process/);
  act(() => { store.dispatch(sessionActions.syncState({ isAttached: true, currentPid: '1' })); });
  expect(screen.getByTestId('graph-trace')).toBeDisabled(); // no symbol yet
  fill('', 'open');
  expect(screen.getByTestId('graph-trace')).not.toBeDisabled(); // module is optional
});

test('Trace loads the tracer for module!symbol and turns trace mode on before it loads', async () => {
  const store = setup();
  let modeDuringReload: boolean | null = null;
  fermion.reloadScript.mockImplementationOnce(async (s: string) => { modeDuringReload = store.getState().session.traceMode; calls.push(['reload', s]); });
  fill('kernel32.dll', 'CreateFileW');
  fireEvent.click(screen.getByTestId('graph-trace'));
  await waitFor(() => expect(calls.length).toBe(1));
  expect(modeDuringReload).toBe(true); // so the tracer's first message is not lost to Output
  expect(calls[0][1]).toBe('var FERMION_TRACE = {"module":"kernel32.dll","symbol":"CreateFileW"};\nTRACER_BODY');
  expect(screen.getByTestId('graph-stop')).toBeInTheDocument();
  expect(screen.getByTestId('graph-module')).toBeDisabled();

  emit({ fermionTrace: 'ready', address: '0x7ff1000', target: 'kernel32.dll!CreateFileW' });
  expect(screen.getByTestId('graph-status')).toHaveTextContent('Tracing kernel32.dll!CreateFileW at 0x7ff1000 — waiting for it to be called.');
  expect(lines).toEqual([]); // tracer messages do not go to Output
});

test('a graph from the tracer is rendered and shown as an image, never inserted as markup', async () => {
  setup();
  fill('kernel32.dll', 'CreateFileW');
  fireEvent.click(screen.getByTestId('graph-trace'));
  await waitFor(() => expect(calls.length).toBe(1));
  emit(DOT);
  const img = await screen.findByTestId('graph-img');
  expect(fermion.renderGraph).toHaveBeenCalledWith(DOT.dot);
  expect(img.getAttribute('src')).toMatch(/^data:image\/svg\+xml;charset=utf-8,%3Csvg/);
  expect(screen.getByTestId('graph-svg').querySelector('svg')).toBeNull();
  expect(screen.getByTestId('graph-status')).toHaveTextContent('1 graph so far · latest: 12 calls, 5 distinct');

  emit({ ...DOT, calls: 30000, edges: 400, truncated: true });
  await waitFor(() => expect(screen.getByTestId('graph-status')).toHaveTextContent('2 graphs so far · latest: 30,000 calls, 400 distinct (cut short: too many to draw)'));
});

test('markup smuggled through a symbol name stays inert', async () => {
  setup();
  fill('', 'open');
  fireEvent.click(screen.getByTestId('graph-trace'));
  await waitFor(() => expect(calls.length).toBe(1));
  fermion.renderGraph.mockResolvedValueOnce('<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><script>window.pwned = 1</script><text>x</text></a></svg>');
  emit(DOT);
  await screen.findByTestId('graph-img');
  const pane = screen.getByTestId('graph-svg');
  expect(pane.querySelector('script')).toBeNull();
  expect(pane.querySelector('a')).toBeNull();
  expect((window as any).pwned).toBeUndefined();
});

test('the tracer reporting an error stops the trace, shows why, and restores the editor script', async () => {
  const store = setup();
  fill('nope.dll', 'open');
  fireEvent.click(screen.getByTestId('graph-trace'));
  await waitFor(() => expect(calls.length).toBe(1));
  emit({ fermionTrace: 'error', message: 'Module not found: nope.dll' });
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Module not found: nope.dll'));
  await waitFor(() => expect(calls[1]).toEqual(['reload', 'USERSCRIPT']));
  expect(store.getState().session.traceMode).toBe(false);
  expect(screen.getByTestId('graph-trace')).toBeInTheDocument();
});

test('a tracer that fails to load leaves trace mode off and says so', async () => {
  const store = setup();
  fermion.reloadScript.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:invoke': Error: script is destroyed"));
  fill('kernel32.dll', 'CreateFileW');
  fireEvent.click(screen.getByTestId('graph-trace'));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Could not start the trace: script is destroyed'));
  expect(store.getState().session.traceMode).toBe(false);
});

test('a graph that cannot be drawn shows the reason and keeps tracing', async () => {
  const store = setup();
  fill('', 'open');
  fireEvent.click(screen.getByTestId('graph-trace'));
  await waitFor(() => expect(calls.length).toBe(1));
  fermion.renderGraph.mockRejectedValueOnce(new Error('syntax error in line 3'));
  emit(DOT);
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Could not draw the graph: syntax error in line 3'));
  expect(store.getState().session.traceMode).toBe(true);
});

test('when graphs arrive faster than they render, the newest one is shown', async () => {
  setup();
  fill('', 'open');
  fireEvent.click(screen.getByTestId('graph-trace'));
  await waitFor(() => expect(calls.length).toBe(1));
  let finishFirst: (v: string) => void = () => {};
  fermion.renderGraph.mockImplementationOnce(() => new Promise((r) => { finishFirst = r; }));
  emit({ ...DOT, dot: 'digraph { first }' });
  emit({ ...DOT, dot: 'digraph { second }' });
  const img = await screen.findByTestId('graph-img');
  await act(async () => { finishFirst('<svg><!--STALE--></svg>'); });
  expect(decodeURIComponent(img.getAttribute('src')!)).toContain('second');
  expect(decodeURIComponent(screen.getByTestId('graph-img').getAttribute('src')!)).not.toContain('STALE');
});

test('Stop leaves trace mode, reloads the editor script, and keeps the last graph on screen', async () => {
  const store = setup();
  fill('', 'open');
  fireEvent.click(screen.getByTestId('graph-trace'));
  await waitFor(() => expect(calls.length).toBe(1));
  emit(DOT);
  await screen.findByTestId('graph-img');
  fireEvent.click(screen.getByTestId('graph-stop'));
  await waitFor(() => expect(calls[1]).toEqual(['reload', 'USERSCRIPT']));
  expect(store.getState().session.traceMode).toBe(false);
  await waitFor(() => expect(store.getState().session.hasScript).toBe(true));
  expect(screen.getByTestId('graph-img')).toBeInTheDocument();
  expect(screen.getByTestId('graph-status')).toHaveTextContent('stopped');
});

test('output from an ordinary script is not treated as a graph', async () => {
  setup();
  emit({ some: 'payload' });          // not tracing: goes to Output
  expect(lines.length).toBe(1);
  fill('', 'open');
  fireEvent.click(screen.getByTestId('graph-trace'));
  await waitFor(() => expect(calls.length).toBe(1));
  emit('digraph { legacy }');         // tracing, but not a tracer message
  await new Promise((r) => setTimeout(r, 20));
  expect(fermion.renderGraph).not.toHaveBeenCalled();
});

test('pure: the natural width of a Graphviz SVG, in pixels', () => {
  expect(svgNaturalWidth('<svg width="300pt" height="150pt">')).toBe(400);
  expect(svgNaturalWidth('<?xml version="1.0"?>\n<svg width="120px">')).toBe(120);
  expect(svgNaturalWidth('<svg viewBox="0 0 10 10">')).toBeNull();
});

test('the graph opens at its natural, readable size; zoom scales it; Fit shrinks it to the pane; Save writes the SVG', async () => {
  setup();
  fill('', 'open');
  fireEvent.click(screen.getByTestId('graph-trace'));
  await waitFor(() => expect(calls.length).toBe(1));
  expect(screen.queryByTestId('graph-save')).toBeNull(); // nothing to save or zoom yet
  emit(DOT);
  const img = await screen.findByTestId('graph-img');
  expect(img.style.width).toBe('400px');   // 300pt at 100%
  expect(screen.getByTestId('graph-zoom-level')).toHaveTextContent('100%');
  fireEvent.click(screen.getByTestId('graph-zoom-in'));
  expect(img.style.width).toBe('600px');
  fireEvent.click(screen.getByTestId('graph-zoom-out'));
  fireEvent.click(screen.getByTestId('graph-zoom-out'));
  expect(img.style.width).toBe('300px');
  fireEvent.click(screen.getByTestId('graph-zoom-fit'));
  expect(img.style.maxWidth).toBe('100%');
  expect(img.style.width).toBe('');
  fireEvent.click(screen.getByTestId('graph-zoom-in')); // from Fit, zoom starts again at 100%
  expect(img.style.width).toBe('400px');
  fireEvent.click(screen.getByTestId('graph-save'));
  expect(fermion.saveFile).toHaveBeenCalledWith(expect.stringContaining('<svg'), expect.objectContaining({ defaultPath: 'trace.svg' }));
});

test('module and function suggestions come from the attached process', async () => {
  setup();
  fireEvent.focus(screen.getByTestId('graph-module'));
  await waitFor(() => expect(document.querySelectorAll('#graph-modules option').length).toBe(2));
  fireEvent.change(screen.getByTestId('graph-module'), { target: { value: 'kernel32.dll' } });
  fireEvent.focus(screen.getByTestId('graph-symbol'));
  await waitFor(() => expect(fermion.inspect.exports).toHaveBeenCalledWith('kernel32.dll'));
  await waitFor(() => expect([...document.querySelectorAll('#graph-symbols option')].map((o) => o.getAttribute('value'))).toEqual(['CreateFileW', 'CloseHandle'])); // functions only
  fireEvent.change(screen.getByTestId('graph-symbol'), { target: { value: 'close' } });
  expect([...document.querySelectorAll('#graph-symbols option')].map((o) => o.getAttribute('value'))).toEqual(['CloseHandle']);
});
