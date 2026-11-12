import { useAppSelector } from '../store';

export function StatusBar() {
  const s = useAppSelector((st) => st.session);
  const count = useAppSelector((st) => st.output.count);
  const outputDetached = useAppSelector((st) => st.ui.outputDetached);
  return (
    <div className="statusbar" data-testid="status-bar">
      <span className="s"><span className="dot" /> {s.deviceId}</span>
      <span className={'s' + (s.isAttached ? ' on' : '')}>{s.isAttached && s.currentPid ? `attached · pid ${s.currentPid}` : 'not attached'}</span>
      <span className="s">{s.hasScript ? 'script loaded' : 'no script'}</span>
      <span className={'s' + (s.traceMode ? ' on' : '')}>trace: {s.traceMode ? 'on' : 'off'}</span>
      <span className="grow" />
      {outputDetached && (
        // The way back from the main window when the Output window is buried
        // behind others or parked on another screen.
        <button
          className="s link"
          data-testid="status-dock-output"
          title="Dock Output back into this window"
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          onClick={() => (window as any).fermion?.output?.dock?.()}
        >
          Output detached · dock
        </button>
      )}
      <span className="s">{count} msgs</span>
    </div>
  );
}
