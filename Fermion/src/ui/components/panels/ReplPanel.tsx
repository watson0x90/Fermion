import { useEffect, useLayoutEffect, useRef, useState, KeyboardEvent } from 'react';
import { useAppSelector } from '../../store';
import { writeTerminal } from '../../bridge';
import {
  parseHelpCommand, formatHelp, formatOverview, commonPrefix, loadHelpIndex, Inspection,
} from '../../repl/help';
import { Icon } from '../Icon';
import { ValueNode, asValueNode } from '../../repl/valueTree';
import { ValueTree } from './ValueTree';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;

interface Entry {
  id: number;
  code: string;
  status: 'running' | 'ok' | 'err' | 'help';
  text: string;
  stack?: string;
  tree?: ValueNode; // the result as an expandable tree, when it has parts
}

interface Choice { name: string; kind: string; }
// Completions on offer: they replace code[from, end).
interface Choices { from: number; end: number; items: Choice[]; truncated: boolean; }

const MAX_ENTRIES = 500;
const HISTORY_MAX = 200;
const NAME_CHAIN = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/;

// Ask one of the REPL agent's helpers (`__fermion.complete/inspect/globals`).
// They go through evaluate like any entry, but silently: nothing is added to
// the transcript, the history or Output. Null when the answer is unusable.
async function agentCall(expr: string): Promise<any> {
  try {
    const r = await api().evaluate(expr);
    return r && r.ok ? JSON.parse(String(r.text)) : null;
  } catch {
    return null;
  }
}

// REPL: a `frida>` prompt evaluated in the attached process. Entries run in
// Fermion's REPL agent — its own script in the session — so the REPL works with
// or without a loaded script and keeps its variables across script reloads.
// Each entry and its result are also written to Output, next to hook output.
// Tab completes the name being typed; `help <name>` shows its documentation.
export function ReplPanel() {
  const isAttached = useAppSelector((s) => s.session.isAttached);
  const active = useAppSelector((s) => s.ui.activeTab === 'repl');
  const [entries, setEntries] = useState<Entry[]>([]);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [choices, setChoicesRaw] = useState<Choices | null>(null);
  const [choiceIdx, setChoiceIdx] = useState(-1); // highlighted completion; -1 = none
  const setChoices = (c: Choices | null) => { setChoicesRaw(c); setChoiceIdx(-1); };

  const inputRef = useRef<HTMLTextAreaElement>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const nextId = useRef(1);
  const history = useRef<string[]>([]); // oldest first
  const cursor = useRef(-1);            // -1 = not browsing; else steps back from newest
  const draft = useRef('');
  const codeRef = useRef(code);
  codeRef.current = code;
  // A caret position to apply once `value` has rendered — and only for that
  // exact text, so it can never land on something typed afterwards.
  const caretAfterRender = useRef<{ at: number; value: string } | null>(null);

  // Keep the newest entry in view, and put the caret back once a run finishes.
  useEffect(() => { const el = logRef.current; if (el) el.scrollTop = el.scrollHeight; }, [entries]);
  useEffect(() => { if (!busy && active && isAttached) inputRef.current?.focus(); }, [busy, active, isAttached]);
  // After a completion is inserted, the caret goes right after it.
  useLayoutEffect(() => {
    const pending = caretAfterRender.current;
    if (!pending) return;
    caretAfterRender.current = null;
    if (pending.value === code) inputRef.current?.setSelectionRange(pending.at, pending.at);
  }, [code]);

  const finish = (id: number, patch: Partial<Entry>) =>
    setEntries((prev) => prev.map((e) => (e.id === id ? { ...e, ...patch } : e))); // no-op if cleared meanwhile

  // `help …`: documentation from the index plus a live look at the value.
  const helpText = async (topic: string): Promise<string> => {
    const index = await loadHelpIndex();
    if (!topic) return formatOverview((await agentCall('__fermion.globals()')) ?? [], index);
    // Only a plain dotted name is looked up in the target; anything else is
    // reported as unknown rather than evaluated.
    const live: Inspection | null = NAME_CHAIN.test(topic) ? await agentCall(`__fermion.inspect(${JSON.stringify(topic)})`) : null;
    return formatHelp(topic, live ?? { found: false, name: topic }, index);
  };

  const run = async () => {
    const src = code.trim();
    if (!src || busy || !isAttached) return;
    const h = history.current;
    if (h[h.length - 1] !== src) { h.push(src); if (h.length > HISTORY_MAX) h.shift(); }
    cursor.current = -1;
    const id = nextId.current++;
    setEntries((prev) => [...prev, { id, code: src, status: 'running' as const, text: 'running…' }].slice(-MAX_ENTRIES));
    setCode('');
    setChoices(null);
    setBusy(true);
    const help = parseHelpCommand(src);
    try {
      if (help) {
        finish(id, { status: 'help', text: await helpText(help.topic) });
        return;
      }
      writeTerminal('STATUS', 'frida> ' + src);
      const r = await api().evaluate(src);
      if (r && r.ok) {
        finish(id, { status: 'ok', text: String(r.text), tree: asValueNode(r.tree) ?? undefined });
        writeTerminal('LOG', String(r.text));
      } else if (r && r.cancelled) {
        // The user stopped it: shown in the transcript, but not an error in Output.
        finish(id, { status: 'err', text: String(r.error || 'Cancelled.') });
        writeTerminal('STATUS', '[REPL] entry cancelled');
      } else {
        const error = String((r && r.error) || 'Evaluation failed');
        finish(id, { status: 'err', text: error, stack: r && r.stack ? String(r.stack) : '' });
        writeTerminal('ERR', error);
      }
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      finish(id, { status: 'err', text: error });
      if (!help) writeTerminal('ERR', error);
    } finally {
      setBusy(false);
    }
  };

  // Stop waiting for the running entry. The service ends it as "cancelled" and
  // restarts the REPL agent; run() above then finishes normally.
  const cancel = () => { if (busy) api().cancelEvaluate?.(); };
  // Escape cancels too. The prompt is disabled while an entry runs, so the key
  // is listened for on the document, only while this tab is showing.
  useEffect(() => {
    if (!busy || !active) return;
    const onEsc = (e: globalThis.KeyboardEvent) => { if (e.key === 'Escape') { e.preventDefault(); api().cancelEvaluate?.(); } };
    document.addEventListener('keydown', onEsc);
    return () => document.removeEventListener('keydown', onEsc);
  }, [busy, active]);

  // Replace code[from, end) with `text` and leave the caret after it.
  const insert = (from: number, end: number, text: string) => {
    const current = codeRef.current;
    const next = current.slice(0, from) + text + current.slice(end);
    const at = from + text.length;
    if (next === current) {
      // Nothing to insert (the name was already complete): no render will
      // follow, so place the caret now rather than leaving a request pending.
      inputRef.current?.setSelectionRange(at, at);
    } else {
      caretAfterRender.current = { at, value: next };
      setCode(next);
    }
    return at;
  };

  const complete = async () => {
    if (!isAttached || busy) return;
    const before = codeRef.current;
    const caret = inputRef.current?.selectionStart ?? before.length;
    const res = await agentCall(`__fermion.complete(${JSON.stringify(before.slice(0, caret))})`);
    if (codeRef.current !== before) return; // the entry changed while we asked
    const items: Choice[] = Array.isArray(res?.items) ? res.items : [];
    if (!items.length || typeof res.from !== 'number') { setChoices(null); return; }
    if (items.length === 1) { insert(res.from, caret, items[0].name); setChoices(null); return; }
    // Several fit: fill in what they share, then list them.
    const shared = commonPrefix(items.map((i) => i.name));
    const end = shared.length > caret - res.from ? insert(res.from, caret, shared) : caret;
    setChoices({ from: res.from, end, items, truncated: !!res.truncated });
  };

  const pick = (choice: Choice) => {
    if (!choices) return;
    insert(choices.from, choices.end, choice.name);
    setChoices(null);
    inputRef.current?.focus();
  };

  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    const h = history.current;
    // While completions are listed, the arrows walk them; Enter or Tab accepts
    // the highlighted one. With nothing highlighted, the keys keep their usual
    // meaning (Enter runs the entry, Tab completes again).
    if (choices && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      const n = choices.items.length;
      setChoiceIdx((i) => (e.key === 'ArrowDown' ? (i + 1) % n : (i <= 0 ? n - 1 : i - 1)));
    } else if (choices && choiceIdx >= 0 && (e.key === 'Enter' || e.key === 'Tab') && !e.shiftKey) {
      e.preventDefault();
      pick(choices.items[choiceIdx]);
    } else if (e.key === 'Tab' && !e.shiftKey) {
      e.preventDefault(); // keep the focus in the prompt
      complete();
    } else if (e.key === 'Escape' && choices) {
      e.preventDefault();
      setChoices(null);
    } else if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      run();
    } else if (e.key === 'ArrowUp' && !code.includes('\n')) {
      // Single-line entries only: in a multi-line entry the arrows move the caret.
      if (!h.length) return;
      e.preventDefault();
      setChoices(null);
      if (cursor.current === -1) draft.current = code;
      cursor.current = Math.min(cursor.current + 1, h.length - 1);
      setCode(h[h.length - 1 - cursor.current]);
    } else if (e.key === 'ArrowDown' && !code.includes('\n')) {
      if (cursor.current === -1) return;
      e.preventDefault();
      setChoices(null);
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
              ? <>Type an expression and press Enter — for example <code>Process.id</code> or <code>Process.enumerateModules()[0]</code>. Press <code>Tab</code> to complete a name, and type <code>help</code> or <code>help Process</code> for documentation. Variables declared with <code>var</code> stay available between entries (<code>let</code> and <code>const</code> do not). The REPL has its own scope, separate from the script in the Editor. A running entry can be cancelled, and is stopped by itself after 20 seconds.</>
              : <>Attach to a process to use the REPL.</>}
          </div>
        )}
        {entries.map((e) => (
          <div className="repl-entry" data-testid="repl-entry" key={e.id}>
            <div className="repl-in"><span className="prompt">frida&gt;</span><pre>{e.code}</pre></div>
            {e.tree
              ? <div className="repl-out ok vtree" data-testid="repl-result"><ValueTree node={e.tree} open /></div>
              : <pre className={'repl-out ' + (e.status === 'running' ? 'run' : e.status)} data-testid="repl-result" title={e.stack || undefined}>{e.text}</pre>}
          </div>
        ))}
      </div>
      {choices && (
        <div className="repl-choices" data-testid="repl-choices" role="listbox" aria-label="Completions">
          {choices.items.map((c, i) => (
            // onMouseDown: keep the focus (and the caret) in the prompt.
            <button
              key={c.name}
              role="option"
              aria-selected={i === choiceIdx}
              ref={i === choiceIdx ? (el) => el?.scrollIntoView?.({ block: 'nearest' }) : undefined}
              className={'choice ' + c.kind + (i === choiceIdx ? ' on' : '')}
              data-testid="repl-choice"
              onMouseDown={(ev) => ev.preventDefault()}
              onClick={() => pick(c)}
            >
              {c.name}{c.kind === 'function' ? '()' : ''}
            </button>
          ))}
          {choices.truncated && <span className="more">… more — keep typing to narrow</span>}
        </div>
      )}
      <div className={'repl-prompt' + (isAttached ? '' : ' off')}>
        <span className="prompt">frida&gt;</span>
        <textarea
          ref={inputRef}
          data-testid="repl-input"
          aria-label="REPL input"
          rows={Math.min(8, Math.max(1, code.split('\n').length))}
          spellCheck={false}
          placeholder={busy ? 'Running… Esc or Cancel to stop' : isAttached ? 'Enter to run · Tab to complete · help' : 'Not attached'}
          style={{ overflowY: code.split('\n').length > 8 ? 'auto' : 'hidden' }}
          value={code}
          disabled={!isAttached || busy}
          onChange={(e) => { cursor.current = -1; setChoices(null); setCode(e.target.value); }}
          onKeyDown={onKey}
        />
        {busy && <button className="pill" data-testid="repl-cancel" title="Stop waiting for this entry (Esc). The REPL is restarted." onClick={cancel}><Icon name="stop" size={11} />Cancel</button>}
      </div>
    </div>
  );
}
