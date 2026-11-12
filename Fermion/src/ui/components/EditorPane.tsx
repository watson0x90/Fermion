import { useEffect, useState } from 'react';
import { useMonaco } from '../hooks/useMonaco';
import { writeTerminal } from '../bridge';
import { useAppDispatch, useAppSelector } from '../store';
import { reloadFromEditor } from '../sessionOps';
import { useStore } from 'react-redux';
import { fileLabel, noteEdit, openScript, openRecentScript, saveScript, saveScriptAs } from '../fileOps';
import { Icon } from './Icon';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = () => (window as any).fermion;

function makeBanner(fermion: string, frida: string): string {
  return [
    '// Fermion v' + fermion + ' -> Frida v' + frida,
    '//   https://github.com/frida/frida/releases/tag/' + frida,
    '//',
    '// + Output uses send(...) / console.log — both stream to the Output pane.',
    '// + Ctrl-S save · Ctrl-O open · Ctrl-T reload the attached script',
    '',
    '// write your Frida script here',
    '',
  ].join('\n');
}

function MonacoHost({ value }: { value: string }) {
  const dispatch = useAppDispatch();
  const { hostRef } = useMonaco(value, () => noteEdit(dispatch));
  return <div className="editor-host" ref={hostRef} style={{ height: '100%', width: '100%' }} />;
}

function toggleWrap() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ed = (window as any).MonacoCodeEditor;
  if (!ed) return;
  const next = ed.getRawOptions?.().wordWrap === 'on' ? 'off' : 'on';
  ed.updateOptions({ wordWrap: next });
}

export function EditorPane() {
  const [value, setValue] = useState<string | null>(null);
  const dispatch = useAppDispatch();
  const isAttached = useAppSelector((s) => s.session.isAttached);
  const [reloading, setReloading] = useState(false);
  const store = useStore();
  const filePath = useAppSelector((s) => s.ui.filePath);
  const dirty = useAppSelector((s) => s.ui.dirty);
  const [recent, setRecent] = useState<string[] | null>(null); // null = menu closed
  const toggleRecent = async () => {
    if (recent) { setRecent(null); return; }
    try { setRecent(await api().recentFiles()); } catch { setRecent([]); }
  };
  const pickRecent = (p: string) => { setRecent(null); openRecentScript(dispatch, store.getState, p); };
  const reload = async () => {
    setReloading(true);
    try { await reloadFromEditor(dispatch); } finally { setReloading(false); }
  };

  useEffect(() => {
    let cancelled = false;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const f = (window as any).fermion;
    f?.versions?.().then((v: { fermion: string; frida: string }) => {
      if (cancelled) return;
      setValue(makeBanner(v.fermion, v.frida));
      writeTerminal('STATUS', `[+] Fermion v${v.fermion} -> Frida v${v.frida}`);
    });
    return () => { cancelled = true; };
  }, []);

  if (value == null) return <div className="stub">loading editor…</div>;

  return (
    <div className="editorpane">
      <div className="ptool">
        <span className="grow fname" data-testid="editor-file" title={filePath ?? 'This script has not been saved to a file'}>
          {fileLabel(filePath)}
          {dirty && <span className="dot" data-testid="editor-dirty" title="Unsaved changes" aria-label="unsaved changes">●</span>}
        </span>
        <button className="pill ico" data-testid="editor-open" title="Open a script (Ctrl-O)" onClick={() => openScript(dispatch, store.getState)}><Icon name="folder" size={13} /></button>
        <span className="menu-anchor">
          <button className={'pill ico' + (recent ? ' on' : '')} data-testid="editor-recent" title="Recent scripts" aria-expanded={!!recent} onClick={toggleRecent}><Icon name="clock" size={13} /></button>
          {recent && (
            <>
              <div className="menu-scrim" onClick={() => setRecent(null)} />
              <div className="menu" role="menu" data-testid="editor-recent-menu">
                {recent.map((p) => (
                  <button key={p} role="menuitem" data-testid="editor-recent-item" title={p} onClick={() => pickRecent(p)}>
                    <span className="mn">{fileLabel(p)}</span>
                    <span className="md">{p.slice(0, Math.max(0, p.length - fileLabel(p).length - 1))}</span>
                  </button>
                ))}
                {!recent.length && <div className="menu-empty">No recent scripts yet. Files you open or save appear here.</div>}
              </div>
            </>
          )}
        </span>
        <button className="pill ico" data-testid="editor-save" title={filePath ? 'Save (Ctrl-S)' : 'Save to a file (Ctrl-S)'} onClick={() => saveScript(dispatch, store.getState)}><Icon name="floppy" size={13} /></button>
        <button className="pill ico" data-testid="editor-save-as" title="Save as a new file" onClick={() => saveScriptAs(dispatch)}><Icon name="saveas" size={13} /></button>
        <button
          className="pill"
          data-testid="editor-reload"
          disabled={!isAttached || reloading}
          title={isAttached ? 'Reload this script into the attached process (Ctrl-T)' : 'Attach to a process to reload the script into it'}
          onClick={reload}
        >
          <Icon name="reload" size={12} />{reloading ? 'Reloading…' : 'Reload'}
        </button>
        <button className="pill" onClick={toggleWrap}><Icon name="wrap" size={12} />Wrap</button>
      </div>
      <MonacoHost value={value} />
    </div>
  );
}
