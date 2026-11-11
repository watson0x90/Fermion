import { ActivityBar } from './ActivityBar';
import { Sidebar } from './Sidebar';
import { LeftToolbox } from './LeftToolbox';
import { OutputPane } from './OutputPane';
import { StatusBar } from './StatusBar';
import '../styles/shell.css';

// The A/L1 frame: activity bar | Session sidebar | [toolbox | Output] + status.
export function Layout() {
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
