import { useAppDispatch, useAppSelector } from '../store';
import { uiActions, ToolboxTab } from '../store/uiSlice';
import { Icon, IconName } from './Icon';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;

// Views the rail jumps to (also reachable via the toolbox tab row).
const VIEWS: { tab: ToolboxTab; icon: IconName; label: string }[] = [
  { tab: 'editor', icon: 'session', label: 'Session' },
  { tab: 'graph', icon: 'graph', label: 'Graph' },
  { tab: 'tree', icon: 'tree', label: 'Process tree' },
  { tab: 'inspector', icon: 'inspect', label: 'Inspector' },
];

// The activity rail: collapsible (icons) ⇄ expandable (icons + labels). Jumps to
// a toolbox view, opens Docs/About as child windows, and toggles Settings.
export function Rail() {
  const dispatch = useAppDispatch();
  const active = useAppSelector((s) => s.ui.activeTab);
  const railOpen = useAppSelector((s) => s.ui.railOpen);
  const settingsOpen = useAppSelector((s) => s.ui.settingsOpen);

  return (
    <nav className={'rail' + (railOpen ? ' wide' : '')} data-testid="activity-bar" aria-label="Activity">
      <button className="toggle" data-testid="rail-toggle" title={railOpen ? 'Collapse rail' : 'Expand labels'} onClick={() => dispatch(uiActions.toggleRail())}>
        <Icon name="expand" size={20} /><span className="lbl">{railOpen ? 'Collapse' : 'Expand'}</span>
      </button>
      {VIEWS.map((v) => (
        <button
          key={v.tab}
          className={active === v.tab ? 'on' : ''}
          data-testid={`rail-${v.tab}`}
          title={v.label}
          onClick={() => dispatch(uiActions.setActiveTab(v.tab))}
        >
          <Icon name={v.icon} size={20} /><span className="lbl">{v.label}</span>
        </button>
      ))}
      <span className="spring" />
      <button data-testid="open-docs" title="Docs" onClick={() => api()?.openWindow?.('docs.html', { width: 800, height: 800 })}>
        <Icon name="docs" size={20} /><span className="lbl">Docs</span>
      </button>
      <button data-testid="open-about" title="About" onClick={() => api()?.openWindow?.('about.html', { width: 460, height: 270 })}>
        <Icon name="info" size={20} /><span className="lbl">About</span>
      </button>
      <button className={settingsOpen ? 'hot' : ''} data-testid="open-settings" title="Settings" onClick={() => dispatch(uiActions.toggleSettings())}>
        <Icon name="gear" size={20} /><span className="lbl">Settings</span>
      </button>
    </nav>
  );
}
