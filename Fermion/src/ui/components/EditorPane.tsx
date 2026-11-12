import { useEffect, useState } from 'react';
import { useMonaco } from '../hooks/useMonaco';
import { writeTerminal } from '../bridge';
import { useAppDispatch, useAppSelector } from '../store';
import { reloadFromEditor } from '../sessionOps';
import { Icon } from './Icon';

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
  const { hostRef } = useMonaco(value);
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
        <span className="grow">script.js — JavaScript</span>
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
