import { useEffect, useRef } from 'react';
import { useAppSelector } from '../store';
import { KINDS } from '../store/outputSlice';
import { setTerminalSink } from '../bridge';
import { applyTheme, loadSavedTheme } from '../theme/themeEngine';
import { PREFS_KEY, applyPrefs, loadPrefs, outputLook } from '../prefs';
import { OutputToolbar } from './OutputToolbar';
// The existing xterm controller (reused, mounted imperatively).
import { createTerminal } from '../../terminal.js';
import '@xterm/xterm/css/xterm.css';

// Output pane — the fixed primary surface. xterm is mounted imperatively (never
// React children) so streaming output never re-renders the tree.
//
// `standalone` = running in the detached Output window. In the main window the
// pane stays mounted while Output is detached (only hidden), so its terminal
// keeps the full history and is simply shown again when docked.
export function OutputPane({ standalone = false }: { standalone?: boolean }) {
  const hostRef = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ctrlRef = useRef<any>(null);
  const filters = useAppSelector((s) => s.output.filters);
  const follow = useAppSelector((s) => s.output.follow);
  const hidden = useAppSelector((s) => s.ui.outputDetached) && !standalone;

  useEffect(() => {
    if (!hostRef.current) return;
    const ctrl = createTerminal(hostRef.current);
    ctrlRef.current = ctrl;
    setTerminalSink(ctrl); // the bridge writes here
    // Expose the controller for the Playwright test surface.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (window as any).__fermion = { ...(window as any).__fermion, terminal: ctrl };
    // Theme the freshly-created terminal to match the active app theme.
    applyTheme(loadSavedTheme());
    if (ctrl.setLook) ctrl.setLook(outputLook(loadPrefs()));
    else ctrl.setFontSize?.(loadPrefs().outputFontSize);
    // The detached window has no Settings of its own: it follows the main window's.
    const onStorage = (e: StorageEvent) => { if (standalone && e.key === PREFS_KEY) applyPrefs(loadPrefs()); };
    if (standalone) { applyPrefs(loadPrefs()); window.addEventListener('storage', onStorage); }
    ctrl.fit();
    // Throttle fit() to one call per frame. xterm's fit is synchronous and
    // reflows the terminal; running it on every resize event during a live drag
    // starves the renderer and makes the chrome (status bar) stop repainting.
    let raf = 0;
    const onResize = () => { if (raf) return; raf = requestAnimationFrame(() => { raf = 0; ctrl.fit(); }); };
    window.addEventListener('resize', onResize);
    // The pane also changes size without the window doing so: the toolbar wraps
    // onto another row, the rail expands, Output docks. Refit on those too, or
    // the terminal keeps its old rows/columns and runs past the pane.
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(onResize) : null;
    ro?.observe(hostRef.current);
    return () => {
      ro?.disconnect();
      window.removeEventListener('storage', onStorage);
      window.removeEventListener('resize', onResize);
      if (raf) cancelAnimationFrame(raf);
      setTerminalSink(null);
      ctrl.dispose();
      ctrlRef.current = null;
    };
  }, []);

  useEffect(() => {
    const ctrl = ctrlRef.current;
    if (!ctrl) return;
    for (const k of KINDS) ctrl.setFilter(k, filters[k]);
  }, [filters]);

  useEffect(() => { ctrlRef.current?.setFollow(follow); }, [follow]);

  // Coming back from detached: the terminal was laid out at zero size while
  // hidden, so refit it (and re-pin the tail) once it is visible again.
  useEffect(() => {
    if (hidden) return;
    const id = requestAnimationFrame(() => {
      ctrlRef.current?.fit();
      if (follow) ctrlRef.current?.setFollow(true);
    });
    return () => cancelAnimationFrame(id);
  }, [hidden]);

  return (
    <div className="output" data-testid="output-pane" hidden={hidden}>
      <OutputToolbar ctrlRef={ctrlRef} standalone={standalone} />
      <div className="obody" ref={hostRef} />
    </div>
  );
}
