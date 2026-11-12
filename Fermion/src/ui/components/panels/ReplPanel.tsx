import { useEffect, useRef, useState, KeyboardEvent } from 'react';
import { useAppSelector } from '../../store';
import { writeTerminal } from '../../bridge';
import { Icon } from '../Icon';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;

interface Entry {
  id: number;
  code: string;
  status: 'running' | 'ok' | 'err';
  text: string;
  stack?: string;
}

const MAX_ENTRIES = 500;
const HISTORY_MAX = 200;

// REPL: a `frida>` prompt evaluated in the attached process. Entries run in
// Fermion's REPL agent — its own script in the session — so the REPL works with
// or without a loaded script and keeps its variables across script reloads.
// Each entry and its result are also written to Output, next to hook output.
export function ReplPanel() {
  const isAttached = useAppSelector((s) => s.session.isAttached);
  const active = useAppSelector((s) => s.ui.activeTab === 'repl');
  const [entries, setEntries] = useState<Entry[]>([]);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);

  const inputRef = useRef<HTMLTextAreaElement>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const nextId = useRef(1);
  const history = useRef<string[]>([]); // oldest first
  const cursor = useRef(-1);            // -1 = not browsing; else steps back from newest
  const draft = useRef('');

  // Keep the newest entry in view, and put the caret back once a run finishes.
  useEffect(() => { const el = logRef.current; if (el) el.scrollTop = el.scrollHeight; }, [entries]);
  useEffect(() => { if (!busy && active && isAttached) inputRef.current?.focus(); }, [busy, active, isAttached]);

  const finish = (id: number, patch: Partial<Entry>) =>
    setEntries((prev) => prev.map((e) => (e.id === id ? { ...e, ...patch } : e))); // no-op if cleared meanwhile

  const run = async () => {
    const src = code.trim();
    if (!src || busy || !isAttached) return;
    const h = history.current;
    if (h[h.length - 1] !== src) { h.push(src); if (h.length > HISTORY_MAX) h.shift(); }
    cursor.current = -1;
    const id = nextId.current++;
    setEntries((prev) => [...prev, { id, code: src, status: 'running' as const, text: 'running…' }].slice(-MAX_ENTRIES));
    setCode('');
    setBusy(true);
    writeTerminal('STATUS', 'frida> ' + src);
    try {
      const r = await api().evaluate(src);
      if (r && r.ok) {
        finish(id, { status: 'ok', text: String(r.text) });
        writeTerminal('LOG', String(r.text));
      } else {
        const error = String((r && r.error) || 'Evaluation failed');
        finish(id, { status: 'err', text: error, stack: r && r.stack ? String(r.stack) : '' });
        writeTerminal('ERR', error);
      }
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      finish(id, { status: 'err', text: error });
      writeTerminal('ERR', error);
    } finally {
      setBusy(false);
    }
  };

  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    const h = history.current;
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      run();
    } else if (e.key === 'ArrowUp' && !code.includes('\n')) {
      // Single-line entries only: in a multi-line entry the arrows move the caret.
      if (!h.length) return;
      e.preventDefault();
      if (cursor.current === -1) draft.current = code;
      cursor.current = Math.min(cursor.current + 1, h.length - 1);
      setCode(h[h.length - 1 - cursor.current]);
    } else if (e.key === 'ArrowDown' && !code.includes('\n')) {
      if (cursor.current === -1) return;
      e.preventDefault();
      cursor.current -= 1;
      setCode(cursor.current === -1 ? draft.current : h[h.length - 1 - cursor.current]);
    }
  };

  return (
    <div className="repl" data-testid="repl-panel">
      <div className="ptool">
        <span className="grow">REPL — runs in the attached process</span>
        <button className="pill" data-testid="repl-clear" title="Clear the transcript (history is kept)" onClick={() => setEntries([])} disabled={!entries.length}>
          <Icon name="clear" size={12} />Clear
        </button>
      </div>
      <div className="repl-log" ref={logRef} onClick={() => { if (!String(window.getSelection?.() ?? '')) inputRef.current?.focus(); }}>
        {!entries.length && (
          <div className="repl-hint">
            {isAttached
              ? <>Type an expression and press Enter — for example <code>Process.id</code> or <code>Process.enumerateModules()[0]</code>. Variables you define stay available. The REPL has its own scope, separate from the script in the Editor.</>
              : <>Attach to a process to use the REPL.</>}
          </div>
        )}
        {entries.map((e) => (
          <div className="repl-entry" data-testid="repl-entry" key={e.id}>
            <div className="repl-in"><span className="prompt">frida&gt;</span><pre>{e.code}</pre></div>
            <pre className={'repl-out ' + (e.status === 'running' ? 'run' : e.status)} data-testid="repl-result" title={e.stack || undefined}>{e.text}</pre>
          </div>
        ))}
      </div>
      <div className={'repl-prompt' + (isAttached ? '' : ' off')}>
        <span className="prompt">frida&gt;</span>
        <textarea
          ref={inputRef}
          data-testid="repl-input"
          aria-label="REPL input"
          rows={Math.min(8, Math.max(1, code.split('\n').length))}
          spellCheck={false}
          placeholder={isAttached ? 'Enter to run · Shift+Enter: new line' : 'Not attached'}
          style={{ overflowY: code.split('\n').length > 8 ? 'auto' : 'hidden' }}
          value={code}
          disabled={!isAttached || busy}
          onChange={(e) => { cursor.current = -1; setCode(e.target.value); }}
          onKeyDown={onKey}
        />
      </div>
    </div>
  );
}
