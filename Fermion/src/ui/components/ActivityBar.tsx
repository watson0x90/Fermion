/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;

// Slim activity bar (top-level nav). Session is the active view in Phase 2.
// About/Docs open as secured child windows (same IPC + dims as the old
// renderer); A/L1 has no application menu, so they live here.
export function ActivityBar() {
  const openDocs = () => api()?.openWindow?.('docs.html', { width: 800, height: 800 });
  const openAbout = () => api()?.openWindow?.('about.html', { width: 460, height: 270 });
  return (
    <div className="act" data-testid="activity-bar">
      <div className="on" title="Session">⧉</div>
      <div title="Docs" data-testid="open-docs" onClick={openDocs}>▤</div>
      <div title="About" data-testid="open-about" onClick={openAbout}>ⓘ</div>
    </div>
  );
}
