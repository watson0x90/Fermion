import { useAppSelector } from '../store';

export function StatusBar() {
  const s = useAppSelector((st) => st.session);
  const count = useAppSelector((st) => st.output.count);
  return (
    <div className="statusbar" data-testid="status-bar">
      <span className="s"><span className="dot" /> {s.deviceId}</span>
      <span className={'s' + (s.isAttached ? ' on' : '')}>{s.isAttached && s.currentPid ? `attached · pid ${s.currentPid}` : 'not attached'}</span>
      <span className="s">{s.hasScript ? 'script loaded' : 'no script'}</span>
      <span className={'s' + (s.traceMode ? ' on' : '')}>trace: {s.traceMode ? 'on' : 'off'}</span>
      <span className="grow" />
      <span className="s">{count} msgs</span>
    </div>
  );
}
