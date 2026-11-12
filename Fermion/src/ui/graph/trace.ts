// Pure helpers for the Graph panel.

// Messages the tracer (src/tools/trace.js) sends while tracing.
export type TraceMessage =
  | { fermionTrace: 'ready'; address: string; target: string }
  | { fermionTrace: 'error'; message: string }
  | { fermionTrace: 'dot'; dot: string; calls: number; edges: number; truncated: boolean };

export function asTraceMessage(payload: unknown): TraceMessage | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  if (p.fermionTrace === 'ready' && typeof p.address === 'string') return { fermionTrace: 'ready', address: p.address, target: String(p.target ?? '') };
  if (p.fermionTrace === 'error') return { fermionTrace: 'error', message: String(p.message ?? 'Trace failed') };
  if (p.fermionTrace === 'dot' && typeof p.dot === 'string') {
    return { fermionTrace: 'dot', dot: p.dot, calls: Number(p.calls) || 0, edges: Number(p.edges) || 0, truncated: !!p.truncated };
  }
  return null;
}

// The script loaded while tracing: the tracer, told what to hook. The names are
// passed as JSON data, never spliced into code, so a quote in a module or
// symbol name cannot change what runs.
export function buildTraceScript(tracerSource: string, moduleName: string, symbol: string): string {
  return `var FERMION_TRACE = ${JSON.stringify({ module: moduleName.trim(), symbol: symbol.trim() })};\n${tracerSource}`;
}

// The graph is shown through an <img>, not inserted as markup: an image cannot
// run script or follow links, whatever names the target put in its symbols.
export function svgToDataUrl(svg: string): string {
  return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
}

// Graphviz sizes its SVG in points (width="300pt"); a browser pixel is 3/4 pt.
// Null when the SVG states no width.
export function svgNaturalWidth(svg: string): number | null {
  const m = /<svg\b[^>]*?\swidth="([\d.]+)(pt|px)?"/.exec(svg);
  if (!m) return null;
  const n = parseFloat(m[1]);
  if (!isFinite(n) || n <= 0) return null;
  return Math.round(m[2] === 'pt' ? (n * 4) / 3 : n);
}
