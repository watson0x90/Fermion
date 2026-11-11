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
//
// Every panel stays MOUNTED; only the active one is visible (inactive ones are
// `hidden`). The Editor's Monaco instance is referenced globally via
// window.MonacoCodeEditor by the always-visible Session sidebar + Graph panel,
// and unmounting it on a tab switch would dangle that handle to a disposed
// editor (and lose the user's script) — so panels are hidden, never unmounted.
const PANELS: { id: ToolboxTab; el: JSX.Element }[] = [
  { id: 'editor', el: <EditorPane /> },
  { id: 'repl', el: <ReplPanel /> },
  { id: 'graph', el: <GraphPanel /> },
  { id: 'tree', el: <ProcessTreePanel /> },
  { id: 'inspector', el: <InspectorPanel /> },
];

function PanelBody({ active }: { active: ToolboxTab }) {
  return (
    <div className="panel-body">
      {PANELS.map((p) => (
        <div
          key={p.id}
          className="panel-slot"
          data-testid={`panel-${p.id}`}
          hidden={active !== p.id}
        >
          {p.el}
        </div>
      ))}
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
      <PanelBody active={active} />
    </div>
  );
}
