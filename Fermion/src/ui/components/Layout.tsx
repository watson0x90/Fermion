import { useEffect, useMemo } from 'react';
import { TitleBar } from './TitleBar';
import { Rail } from './Rail';
import { Sidebar } from './Sidebar';
import { LeftToolbox } from './LeftToolbox';
import { OutputPane } from './OutputPane';
import { StatusBar } from './StatusBar';
import { Settings } from './Settings';
import { AddressMenu } from './AddressMenu';
import { useKeybinds } from '../hooks/useKeybinds';
import { useAppSelector } from '../store';
import { applyTheme } from '../theme/themeEngine';
import { usePrefs } from '../store/prefsSlice';
import { savePrefs, applyPrefs, limitsOf } from '../prefs';
import '../styles/shell.css';

// The A/L1 frame: title bar on top; then [activity rail | Session sidebar |
// toolbox | Output]; status bar at the bottom. While Output is detached into its
// own window, its column is dropped and the toolbox takes the freed width.
export function Layout() {
  useKeybinds(); // Ctrl-S/O/T, Alt-C, F5/Ctrl-R prevention
  const theme = useAppSelector((s) => s.ui.theme);
  const railOpen = useAppSelector((s) => s.ui.railOpen);
  const outputDetached = useAppSelector((s) => s.ui.outputDetached);
  // Re-skin the whole app whenever the theme changes (and on first mount, so the
  // chrome is themed before Monaco exists).
  useEffect(() => { applyTheme(theme); }, [theme]);
  // Preferences are saved and applied to the editors and the terminal as they change.
  const prefs = usePrefs();
  useEffect(() => { savePrefs(prefs); applyPrefs(prefs); }, [prefs]);
  // The limits are enforced in the main process: it is told at the start and whenever one changes.
  const limits = useMemo(() => JSON.stringify(limitsOf(prefs)), [prefs]);
  useEffect(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    try { Promise.resolve((window as any).fermion?.setLimits?.(JSON.parse(limits))).catch(() => {}); } catch { /* not in Electron */ }
  }, [limits]);
  return (
    <div className={'app' + (railOpen ? ' rail-open' : '') + (outputDetached ? ' output-detached' : '')} data-testid="app-root">
      <TitleBar />
      <div className="body">
        <Rail />
        <Sidebar />
        <LeftToolbox />
        <OutputPane />
        <Settings />
      </div>
      <StatusBar />
      <AddressMenu />
    </div>
  );
}
