import { useAppDispatch, useAppSelector } from '../store';
import { uiActions, ToolboxTab } from '../store/uiSlice';

const TABS: { id: ToolboxTab; label: string }[] = [
  { id: 'editor', label: 'Editor' },
  { id: 'repl', label: 'REPL' },
  { id: 'graph', label: 'Graph' },
  { id: 'tree', label: 'Process tree' },
  { id: 'inspector', label: 'Inspector' },
];

// Panel bodies are stubbed in Task 3; Editor (Task 5), Graph + Process (Task 6),
// and REPL/Inspector/Process-tree (Phase 3 stubs, Task 8) replace these.
function PanelBody({ tab }: { tab: ToolboxTab }) {
  return (
    <div className="panel-body" data-testid={`panel-${tab}`}>
      <div className="stub">{TABS.find((t) => t.id === tab)?.label} — coming soon</div>
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
