import { useEffect, useState } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { sessionActions } from '../store/sessionSlice';

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

  const loadDevices = () => api()?.enumerateDevices?.().then(setDevices);
  const loadProcs = () => api()?.enumerateProcesses?.().then((p: Proc[]) => setProcs([...p].sort((a, b) => a.pid - b.pid)));
  useEffect(() => { loadDevices(); }, []);

  const onDevice = async (id: string) => {
    const effective = await api().setDevice(id);
    dispatch(sessionActions.setDevice(effective));
  };
  const onAttach = async () => {
    if (!pid) return;
    await api().attach(Number(pid));
    dispatch(sessionActions.syncState(await api().getState()));
    await api().loadScript(scriptSrc());
    dispatch(sessionActions.scriptLoaded());
  };
  const onReload = async () => {
    await api().reloadScript(scriptSrc());
    dispatch(sessionActions.scriptLoaded());
  };
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
      <h4>Session</h4>
      <select className="sel" aria-label="device" onChange={(e) => onDevice(e.target.value)}>
        {devices.map((d) => <option key={d.id} value={d.id}>{d.id}</option>)}
      </select>
      <div className="row">
        <select className="sel" aria-label="process" value={pid} onFocus={loadProcs} onChange={(e) => setPid(e.target.value)}>
          <option value="">select process…</option>
          {procs.map((p) => <option key={p.pid} value={p.pid}>{p.name} · {p.pid}</option>)}
        </select>
        <button title="refresh" onClick={loadProcs}>⟳</button>
      </div>
      <div className="btns">
        <button className="btn" data-testid="attach" onClick={onAttach} disabled={isAttached}>Attach</button>
        <button className="btn ghost" data-testid="reload" onClick={onReload} disabled={!hasScript}>Reload</button>
        <button className="btn ghost" data-testid="detach" onClick={onDetach} disabled={!isAttached}>Detach</button>
      </div>
      <h4 style={{ marginTop: 12 }}>Spawn new…</h4>
      <input className="sel" aria-label="spawn path" placeholder="path" value={spawnPath} onChange={(e) => setSpawnPath(e.target.value)} />
      <input className="sel" aria-label="spawn args" placeholder="args" value={spawnArgs} onChange={(e) => setSpawnArgs(e.target.value)} />
      <button className="btn" onClick={onSpawn} disabled={!spawnPath || isAttached}>Spawn</button>
    </div>
  );
}
