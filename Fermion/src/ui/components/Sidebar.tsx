import { SessionControls } from './SessionControls';

// Session sidebar — device/process pickers, Attach/Reload/Detach, Spawn.
export function Sidebar() {
  return (
    <div className="side" data-testid="sidebar">
      <SessionControls />
    </div>
  );
}
