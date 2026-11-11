import { ActivityBar } from './ActivityBar';
import { Sidebar } from './Sidebar';
import { LeftToolbox } from './LeftToolbox';
import { OutputPane } from './OutputPane';
import { StatusBar } from './StatusBar';
import { useKeybinds } from '../hooks/useKeybinds';
import '../styles/shell.css';

// The A/L1 frame: activity bar | Session sidebar | [toolbox | Output] + status.
export function Layout() {
  useKeybinds(); // Ctrl-S/O/T, Alt-C, F5/Ctrl-R prevention
  return (
    <div className="app" data-testid="app-root">
      <ActivityBar />
      <Sidebar />
      <div className="main">
        <div className="work">
          <LeftToolbox />
          <OutputPane />
        </div>
        <StatusBar />
      </div>
    </div>
  );
}
