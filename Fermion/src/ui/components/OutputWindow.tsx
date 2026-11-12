import { useEffect } from 'react';
import { TitleBar } from './TitleBar';
import { OutputPane } from './OutputPane';
import { useAppSelector } from '../store';
import { applyTheme } from '../theme/themeEngine';
import '../styles/shell.css';

// The detached Output window: a slim title bar over the Output pane, nothing
// else. It mirrors the main window (see outputDetach.ts); closing it — or its
// dock button — puts Output back in the main window.
export function OutputWindow() {
  const theme = useAppSelector((s) => s.ui.theme);
  useEffect(() => { applyTheme(theme); }, [theme]);

  // Child effects run first, so the terminal exists (and is the sink) by the
  // time this asks the main window for the snapshot.
  useEffect(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (window as any).fermion?.output?.send?.({ t: 'ready' });
  }, []);

  return (
    <div className="app output-window" data-testid="output-window">
      <TitleBar subtitle="Output" />
      <div className="body">
        <OutputPane standalone />
      </div>
    </div>
  );
}
