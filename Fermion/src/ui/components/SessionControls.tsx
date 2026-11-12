import { useEffect, useState } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { sessionActions } from '../store/sessionSlice';
import { attachAndLoad, reloadFromEditor } from '../sessionOps';
import { writeTerminal } from '../bridge';
import { Icon } from './Icon';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;
const scriptSrc = () => (window as any).MonacoCodeEditor?.getValue?.() ?? '';

interface Dev { id: string; name: string }
interface Proc { pid: number; name: string }

// Session sidebar: device + process pickers, Attach/Reload/Detach, Spawn.
// Replaces the device/proc/instrument pop-up windows. Drives window.fermion
// directly (the IPC boundary is unchanged) and mirrors state into the store.
export function SessionControls() {
  const dispatch = useAppDispatch();
  const isAttached = useAppSelector((s) => s.session.isAttached);
  const hasScript = useAppSelector((s) => s.session.hasScript);
  const [devices, setDevices] = useState<Dev[]>([]);
  const [procs, setProcs] = useState<Proc[]>([]);
  const [pid, setPid] = useState('');
  const [spawnPath, setSpawnPath] = useState('');
  const [spawnArgs, setSpawnArgs] = useState('');
  const [remote, setRemote] = useState('');
  const [connecting, setConnecting] = useState(false);
  const deviceId = useAppSelector((s) => s.session.deviceId);

  const loadDevices = () => api()?.enumerateDevices?.().then(setDevices);
  const loadProcs = () => api()?.enumerateProcesses?.().then((p: Proc[]) => setProcs([...p].sort((a, b) => a.pid - b.pid)));
  useEffect(() => { loadDevices(); }, []);

  const onDevice = async (id: string) => {
    try {
      const effective = await api().setDevice(id);
      dispatch(sessionActions.setDevice(effective));
    } catch (e) {
      writeTerminal('ERR', '[!] Could not select device: ' + (e instanceof Error ? e.message : String(e)));
    }
  };

  // Add a remote frida-server by address (host or host:port) and switch to it.
  const onRemote = async () => {
    const host = remote.trim();
    if (!host || connecting) return;
    setConnecting(true);
    try {
      const effective = await api().setDevice('socket@' + host);
      dispatch(sessionActions.setDevice(effective));
      await loadDevices();
      setRemote('');
      writeTerminal('STATUS', '[+] Remote device added: ' + effective);
    } catch (e) {
      writeTerminal('ERR', '[!] Could not connect to ' + host + ': ' + (e instanceof Error ? e.message : String(e)));
    } finally {
      setConnecting(false);
    }
  };

  const onAttach = async () => {
    if (!pid) return;
    await attachAndLoad(dispatch, Number(pid)); // shared with the Process tree
  };
  const onReload = () => reloadFromEditor(dispatch);
  const onDetach = async () => {
    await api().detach();
    dispatch(sessionActions.detached());
  };
  const onSpawn = async () => {
    const { pid: spid } = await api().spawn(spawnPath, spawnArgs);
    dispatch(sessionActions.syncState(await api().getState()));
    await api().loadScript(scriptSrc());
    dispatch(sessionActions.scriptLoaded());
    await api().resume(spid);
  };

  return (
    <div className="session">
      <div className="group">
        <h4>Session</h4>
        <div className="field">
          <label>Device</label>
          <select className="sel" aria-label="device" value={deviceId} onChange={(e) => onDevice(e.target.value)}>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.id}</option>)}
            {!devices.some((d) => d.id === deviceId) && <option value={deviceId}>{deviceId}</option>}
          </select>
          <div className="row">
            <input
              className="sel"
              aria-label="remote device"
              placeholder="Remote host:port"
              title="Address of a frida-server to connect to, e.g. 192.168.1.20:27042"
              value={remote}
              onChange={(e) => setRemote(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') onRemote(); }}
            />
            <button className="iconbtn" data-testid="remote-connect" title="Connect to this frida-server" disabled={!remote.trim() || connecting} onClick={onRemote}><Icon name="plus" size={15} /></button>
          </div>
        </div>
        <div className="field">
          <label>Process</label>
          <div className="row">
            <select className="sel" aria-label="process" value={pid} onFocus={loadProcs} onChange={(e) => setPid(e.target.value)}>
              <option value="">select process…</option>
              {procs.map((p) => <option key={p.pid} value={p.pid}>{p.name} · {p.pid}</option>)}
            </select>
            <button className="iconbtn" title="Refresh processes" onClick={loadProcs}><Icon name="refresh" size={15} /></button>
          </div>
        </div>
        <div className="btns">
          <button className="btn primary" data-testid="attach" onClick={onAttach} disabled={isAttached}><Icon name="play" size={13} />Attach</button>
          <button className="btn ghost" data-testid="reload" onClick={onReload} disabled={!hasScript}><Icon name="reload" size={13} />Reload</button>
          <button className="btn ghost" data-testid="detach" onClick={onDetach} disabled={!isAttached}><Icon name="stop" size={13} />Detach</button>
        </div>
      </div>
      <div className="group">
        <h4>Spawn new</h4>
        <div className="field"><input className="sel" aria-label="spawn path" placeholder="Executable path" value={spawnPath} onChange={(e) => setSpawnPath(e.target.value)} /></div>
        <div className="field"><input className="sel" aria-label="spawn args" placeholder="Arguments (optional)" value={spawnArgs} onChange={(e) => setSpawnArgs(e.target.value)} /></div>
        <button className="btn wide" onClick={onSpawn} disabled={!spawnPath || isAttached}><Icon name="play" size={14} />Spawn &amp; suspend</button>
      </div>
    </div>
  );
}
