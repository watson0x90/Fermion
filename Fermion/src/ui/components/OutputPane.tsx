import { useEffect, useRef } from 'react';
import { useAppSelector } from '../store';
import { KINDS } from '../store/outputSlice';
import { setTerminalSink } from '../bridge';
import { applyTheme, loadSavedTheme } from '../theme/themeEngine';
import { OutputToolbar } from './OutputToolbar';
// The existing xterm controller (reused, mounted imperatively).
import { createTerminal } from '../../terminal.js';
import '@xterm/xterm/css/xterm.css';

// Output pane — the fixed primary surface. xterm is mounted imperatively (never
// React children) so streaming output never re-renders the tree.
export function OutputPane() {
  const hostRef = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ctrlRef = useRef<any>(null);
  const filters = useAppSelector((s) => s.output.filters);
  const follow = useAppSelector((s) => s.output.follow);

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
    ctrl.fit();
    // Throttle fit() to one call per frame. xterm's fit is synchronous and
    // reflows the terminal; running it on every resize event during a live drag
    // starves the renderer and makes the chrome (status bar) stop repainting.
    let raf = 0;
    const onResize = () => { if (raf) return; raf = requestAnimationFrame(() => { raf = 0; ctrl.fit(); }); };
    window.addEventListener('resize', onResize);
    return () => {
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

  return (
    <div className="output" data-testid="output-pane">
      <OutputToolbar ctrlRef={ctrlRef} />
      <div className="obody" ref={hostRef} />
    </div>
  );
}
