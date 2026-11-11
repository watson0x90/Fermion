import { useAppDispatch, useAppSelector } from '../store';
import { uiActions, ToolboxTab } from '../store/uiSlice';
import { EditorPane } from './EditorPane';
import { GraphPanel } from './GraphPanel';
import { ReplPanel } from './panels/ReplPanel';
import { InspectorPanel } from './panels/InspectorPanel';
import { ProcessTreePanel } from './panels/ProcessTreePanel';

const TABS: { id: ToolboxTab; label: string }[] = [
  { id: 'editor', label: 'Editor' },
  { id: 'repl', label: 'REPL' },
  { id: 'graph', label: 'Graph' },
  { id: 'tree', label: 'Process tree' },
  { id: 'inspector', label: 'Inspector' },
];

// Editor (Task 5) and Graph (Task 6) are live; REPL, Process-tree, and Inspector
// are Phase-3 stub panels (Task 8) occupying their final slots.
function PanelBody({ tab }: { tab: ToolboxTab }) {
  return (
    <div className="panel-body" data-testid={`panel-${tab}`}>
      {tab === 'editor' ? <EditorPane />
        : tab === 'graph' ? <GraphPanel />
          : tab === 'repl' ? <ReplPanel />
            : tab === 'tree' ? <ProcessTreePanel />
              : tab === 'inspector' ? <InspectorPanel />
                : <div className="stub">{TABS.find((t) => t.id === tab)?.label}</div>}
    </div>
  );
}

export function LeftToolbox() {
  const active = useAppSelector((s) => s.ui.activeTab);
  const dispatch = useAppDispatch();
  return (
    <div className="toolbox">
      <div className="tabrow" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={active === t.id}
            className={'tab' + (active === t.id ? ' on' : '')}
            onClick={() => dispatch(uiActions.setActiveTab(t.id))}
          >
            {t.label}
          </button>
        ))}
      </div>
      <PanelBody tab={active} />
    </div>
  );
}
