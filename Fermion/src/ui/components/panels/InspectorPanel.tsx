// Phase 3 stub: inspect the TARGET — its loaded modules, memory ranges, and
// threads — enumerated from the attached session. The slot and title are in
// place now so the Phase 3 feature drops in here.
export function InspectorPanel() {
  return (
    <div className="panel-stub" data-testid="inspector-panel">
      <h3>Inspector</h3>
      <p>Target modules, memory, and threads — coming in Phase 3.</p>
      <ul className="stub-list">
        <li>Modules</li>
        <li>Memory</li>
        <li>Threads</li>
      </ul>
    </div>
  );
}
