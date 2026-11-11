import { useEffect } from 'react';
import { TitleBar } from './TitleBar';
import { ActivityBar } from './ActivityBar';
import { Sidebar } from './Sidebar';
import { LeftToolbox } from './LeftToolbox';
import { OutputPane } from './OutputPane';
import { StatusBar } from './StatusBar';
import { useKeybinds } from '../hooks/useKeybinds';
import { useAppSelector } from '../store';
import { applyTheme } from '../theme/themeEngine';
import '../styles/shell.css';

// The A/L1 frame: title bar on top; then [activity rail | Session sidebar |
// toolbox | Output]; status bar at the bottom.
export function Layout() {
  useKeybinds(); // Ctrl-S/O/T, Alt-C, F5/Ctrl-R prevention
  const theme = useAppSelector((s) => s.ui.theme);
  const railOpen = useAppSelector((s) => s.ui.railOpen);
  // Re-skin the whole app whenever the theme changes (and on first mount, so the
  // chrome is themed before Monaco exists).
  useEffect(() => { applyTheme(theme); }, [theme]);
  return (
    <div className={'app' + (railOpen ? ' rail-open' : '')} data-testid="app-root">
      <TitleBar />
      <div className="body">
        <ActivityBar />
        <Sidebar />
        <LeftToolbox />
        <OutputPane />
      </div>
      <StatusBar />
    </div>
  );
}
