import { useAppSelector } from '../store';

export function StatusBar() {
  const s = useAppSelector((st) => st.session);
  const count = useAppSelector((st) => st.output.count);
  return (
    <div className="statusbar" data-testid="status-bar">
      <span><span className="dot">●</span> {s.deviceId}</span>
      <span>{s.isAttached && s.currentPid ? `PID ${s.currentPid}` : 'not attached'}</span>
      <span>{s.hasScript ? 'script loaded' : 'no script'}</span>
      <span>trace: {s.traceMode ? 'on' : 'off'}</span>
      <span style={{ marginLeft: 'auto' }}>{count} msgs</span>
    </div>
  );
}
