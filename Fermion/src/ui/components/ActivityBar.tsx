// Slim activity bar (top-level nav). Session is the active view in Phase 2.
export function ActivityBar() {
  return (
    <div className="act" data-testid="activity-bar">
      <div className="on" title="Session">⧉</div>
      <div title="Files">▤</div>
      <div title="Docs">ⓘ</div>
    </div>
  );
}
