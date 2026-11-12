import { useEffect, useState } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { sessionActions } from '../store/sessionSlice';
import { attachAndLoad, reloadFromEditor, spawnAndLoad, resumeSpawned, reconnect } from '../sessionOps';
import { endedText, envCount, parseEnv, targetLabel } from '../session/launch';
import { writeTerminal } from '../bridge';
import { Icon } from './Icon';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;

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
  const [spawnEnv, setSpawnEnv] = useState('');
  const [spawnCwd, setSpawnCwd] = useState('');
  const [spawnSuspended, setSpawnSuspended] = useState(false);
  const [optionsOpen, setOptionsOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reconnectNote, setReconnectNote] = useState('');
  const target = useAppSelector((s) => s.session.target);
  const ended = useAppSelector((s) => s.session.ended);
  const suspendedPid = useAppSelector((s) => s.session.suspendedPid);
  const hooks = useAppSelector((s) => s.hooks?.hooks ?? []);
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
    await attachAndLoad(dispatch, Number(pid), procs.find((p) => String(p.pid) === pid)?.name ?? ''); // shared with the Process tree
  };
  const onReload = () => reloadFromEditor(dispatch);
  const onDetach = async () => {
    await api().detach();
    dispatch(sessionActions.detached('user'));
  };
  const envError = parseEnv(spawnEnv).error;
  const optionsSet = envCount(spawnEnv) + (spawnCwd.trim() ? 1 : 0) + (spawnSuspended ? 1 : 0);
  const onSpawn = async () => {
    if (busy || envError) return;
    setBusy(true);
    setReconnectNote('');
    try {
      await spawnAndLoad(dispatch, { path: spawnPath, args: spawnArgs, env: spawnEnv, cwd: spawnCwd, suspended: spawnSuspended }, hooks);
    } finally {
      setBusy(false);
    }
  };
  const onReconnect = async () => {
    if (!target || busy) return;
    setBusy(true);
    setReconnectNote('');
    try {
      setReconnectNote(await reconnect(dispatch, target, hooks));
    } finally {
      setBusy(false);
    }
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
        {isAttached && suspendedPid !== null && (
          <div className="session-note" data-testid="session-suspended">
            <span>Process {suspendedPid} is suspended: nothing in it has run yet.</span>
            <button className="btn primary" data-testid="resume" onClick={() => resumeSpawned(dispatch, suspendedPid)}><Icon name="play" size={13} />Resume</button>
          </div>
        )}
        {!isAttached && ended && target && (
          <div className="session-note" data-testid="session-ended">
            <span>
              <strong>{endedText(ended)}</strong> Last session: {targetLabel(target)}.
            </span>
            {reconnectNote && <span className="err" role="alert" data-testid="reconnect-note">{reconnectNote}</span>}
            <div className="btns">
              <button className="btn primary" data-testid="reconnect" disabled={busy} onClick={onReconnect}>
                <Icon name="reload" size={13} />{target.kind === 'spawn' ? 'Spawn again' : 'Attach again'}
              </button>
              <button className="btn ghost" data-testid="ended-dismiss" onClick={() => { setReconnectNote(''); dispatch(sessionActions.endedDismissed()); }}>Dismiss</button>
            </div>
          </div>
        )}
      </div>
      <div className="group">
        <h4>Spawn new</h4>
        <div className="field"><input className="sel" aria-label="spawn path" placeholder="Executable path" value={spawnPath} onChange={(e) => setSpawnPath(e.target.value)} /></div>
        <div className="field"><input className="sel" aria-label="spawn args" placeholder="Arguments (optional)" title='Separated by spaces. Put quotes around an argument that contains spaces: --file "C:\My Files\a.txt"' value={spawnArgs} onChange={(e) => setSpawnArgs(e.target.value)} /></div>
        <button className="linkrow" data-testid="spawn-options-toggle" aria-expanded={optionsOpen} onClick={() => setOptionsOpen(!optionsOpen)}>
          <span className={'chev' + (optionsOpen ? ' open' : '')}><Icon name="chevron" size={11} /></span>
          Options{optionsSet ? ` (${optionsSet} set)` : ''}
        </button>
        {optionsOpen && (
          <>
            <div className="field">
              <label htmlFor="spawn-env">Environment</label>
              <textarea
                id="spawn-env"
                className="sel mono"
                aria-label="environment"
                placeholder={'NAME=value, one per line'}
                title="Variables added to the environment the program would get anyway. Lines starting with # are ignored."
                spellCheck={false}
                rows={3}
                value={spawnEnv}
                onChange={(e) => setSpawnEnv(e.target.value)}
              />
              {envError && <span className="err" role="alert" data-testid="spawn-env-error">{envError}</span>}
            </div>
            <div className="field">
              <label htmlFor="spawn-cwd">Working directory</label>
              <input id="spawn-cwd" className="sel" aria-label="working directory" placeholder="Where the program starts (optional)" spellCheck={false} value={spawnCwd} onChange={(e) => setSpawnCwd(e.target.value)} />
            </div>
            <label className="chk" title="Leave the program suspended after the script and hooks are in place, so you can add hooks or look around before anything in it runs. Press Resume to let it go.">
              <input type="checkbox" data-testid="spawn-suspended" checked={spawnSuspended} onChange={(e) => setSpawnSuspended(e.target.checked)} />Start suspended
            </label>
          </>
        )}
        <button className="btn wide" data-testid="spawn" onClick={onSpawn} disabled={!spawnPath.trim() || isAttached || busy || !!envError}><Icon name="play" size={14} />{spawnSuspended ? 'Spawn suspended' : 'Spawn'}</button>
      </div>
    </div>
  );
}
