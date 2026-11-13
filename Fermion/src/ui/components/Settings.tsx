import { CSSProperties, KeyboardEvent, ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { uiActions } from '../store/uiSlice';
import { prefsActions, usePrefs } from '../store/prefsSlice';
import { Prefs, Section, DEFAULT_PREFS, SECTION_OF, EDITOR_LINE, OUTPUT_LINE, FONT_MIN, FONT_MAX, REFRESH_MIN, REFRESH_MAX, TAB_SIZES } from '../prefs';
import { BUILT_IN_FONT, SYSTEM_FONT, FONT_NAME_MAX, cleanFontName, fontStack, fontState, installedFonts } from '../fonts';
import { themeNames, themeMeta } from '../theme/themeEngine';
import { Icon } from './Icon';

const SECTIONS: { id: Section; label: string }[] = [
  { id: 'appearance', label: 'Appearance' },
  { id: 'editor', label: 'Editor' },
  { id: 'output', label: 'Output' },
  { id: 'inspector', label: 'Inspector' },
  { id: 'session', label: 'Session' },
];
const KEYS = Object.keys(DEFAULT_PREFS) as (keyof Prefs)[];
const changedIn = (prefs: Prefs, section?: Section) => KEYS.filter((k) => (!section || SECTION_OF[k] === section) && prefs[k] !== DEFAULT_PREFS[k]);
const UNDO_MS = 8000;
let lastSection: Section = 'appearance'; // where Settings was left, until the app closes

// One setting: its name (and what it does) on the left, its control on the
// right. A dot before the name says it differs from the default; clicking the
// dot puts that one setting back.
function Row({ k, id, label, hint, children }: { k: keyof Prefs; id: string; label: string; hint?: string; children: ReactNode }) {
  const dispatch = useAppDispatch();
  const prefs = usePrefs();
  const changed = prefs[k] !== DEFAULT_PREFS[k];
  return (
    <div className="setrow">
      {changed
        ? <button className="setdot" data-testid={id + '-changed'} title="Changed. Click to use the default again." aria-label={`${label}: changed from the default. Use the default again.`}
            onClick={() => dispatch(prefsActions.changed({ [k]: DEFAULT_PREFS[k] } as Partial<Prefs>))} />
        : <span />}
      <div className="lblbox">
        <label htmlFor={'set-' + id}>{label}</label>
        {hint && <span className="hint">{hint}</span>}
      </div>
      <div className="ctl">{children}</div>
    </div>
  );
}

// A whole number between two bounds: minus, the number, plus. The buttons
// repeat while held. The number can be typed: what is typed takes effect as
// soon as it is a number in range, and is brought into range (or dropped, when
// it is not a number) on Enter or on leaving the field.
function Stepper({ id, label, value, min, max, unit, onChange }: { id: string; label: string; value: number; min: number; max: number; unit: string; onChange: (v: number) => void }) {
  const [draft, setDraft] = useState<string | null>(null);
  const live = useRef(value);
  live.current = value;
  const timers = useRef<{ wait?: ReturnType<typeof setTimeout>; every?: ReturnType<typeof setInterval>; held: boolean }>({ held: false });
  const clamp = (v: number) => Math.min(max, Math.max(min, Math.round(v)));
  const to = (v: number) => { setDraft(null); const next = clamp(v); if (next !== live.current) { live.current = next; onChange(next); } };
  const release = () => { clearTimeout(timers.current.wait); clearInterval(timers.current.every); };
  useEffect(() => release, []);
  const hold = (by: number) => () => {
    release();
    timers.current.held = false;
    timers.current.wait = setTimeout(() => {
      timers.current.held = true;
      timers.current.every = setInterval(() => to(live.current + by), 60);
    }, 400);
  };
  const click = (by: number) => () => { if (timers.current.held) { timers.current.held = false; return; } to(value + by); };
  const commit = () => {
    if (draft == null) return;
    const v = Number(draft);
    if (draft.trim() !== '' && Number.isFinite(v)) to(v); else setDraft(null);
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    const by = e.key === 'ArrowUp' ? 1 : e.key === 'ArrowDown' ? -1 : e.key === 'PageUp' ? 2 : e.key === 'PageDown' ? -2 : 0;
    if (by) { e.preventDefault(); to(value + by); }
    else if (e.key === 'Home') { e.preventDefault(); to(min); }
    else if (e.key === 'End') { e.preventDefault(); to(max); }
    else if (e.key === 'Enter') { e.preventDefault(); commit(); }
    else if (e.key === 'Escape' && draft != null) { e.stopPropagation(); setDraft(null); }
  };
  const button = (by: number, name: string, sign: string, off: boolean) => (
    <button type="button" tabIndex={-1} data-testid={`${id}-${name}`} aria-label={`${label}: ${by > 0 ? 'larger' : 'smaller'}`} disabled={off}
      onClick={click(by)} onPointerDown={hold(by)} onPointerUp={release} onPointerLeave={release}>{sign}</button>
  );
  return (
    <span className="stepper">
      {button(-1, 'minus', '−', value <= min)}
      <span className="val">
        <input id={'set-' + id} data-testid={id} role="spinbutton" inputMode="numeric" autoComplete="off" spellCheck={false}
          aria-valuemin={min} aria-valuemax={max} aria-valuenow={value} aria-valuetext={`${value} ${unit}`}
          value={draft ?? String(value)}
          onChange={(e) => {
            const text = e.target.value;
            setDraft(text);
            const v = Number(text);
            if (/^\d+$/.test(text.trim()) && v >= min && v <= max && v !== live.current) { live.current = v; onChange(v); }
          }}
          onBlur={commit} onKeyDown={onKey} />
        <span className="unit">{unit}</span>
      </span>
      {button(1, 'plus', '+', value >= max)}
    </span>
  );
}

// A few short choices, one of which is chosen: left and right arrows move.
function Choice<T extends string | number>({ id, label, value, choices, onChange }: { id: string; label: string; value: T; choices: { v: T; label: string }[]; onChange: (v: T) => void }) {
  const move = (e: KeyboardEvent<HTMLDivElement>) => {
    const by = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
    if (!by) return;
    e.preventDefault();
    e.stopPropagation();
    const at = choices.findIndex((c) => c.v === value);
    const next = choices[(at + by + choices.length) % choices.length];
    onChange(next.v);
    (e.currentTarget.querySelector(`[data-v="${next.v}"]`) as HTMLElement | null)?.focus();
  };
  return (
    <div className="seg" role="radiogroup" aria-label={label} id={'set-' + id} onKeyDown={move}>
      {choices.map((c) => (
        <button key={String(c.v)} type="button" role="radio" aria-checked={c.v === value} tabIndex={c.v === value ? 0 : -1} data-v={c.v}
          className={c.v === value ? 'on' : ''} data-testid={`${id}-${c.v}`} onClick={() => onChange(c.v)}>{c.label}</button>
      ))}
    </div>
  );
}

const OTHER = '\u0000other';
// A fixed-width font: the built-in one, those of a known set that are installed
// here, the system's own, or any installed family by name.
function FontPicker({ id, value, onChange }: { id: string; value: string; onChange: (v: string) => void }) {
  const listed = useMemo(() => [BUILT_IN_FONT, ...installedFonts(), SYSTEM_FONT], []);
  const [other, setOther] = useState(!listed.includes(value));
  const [draft, setDraft] = useState(listed.includes(value) ? '' : value);
  // Changed from outside (a reset): show what is now chosen.
  useEffect(() => {
    if (listed.includes(value)) { setOther(false); setDraft(''); } else { setOther(true); setDraft(value); }
  }, [value, listed]);
  const state = other && !listed.includes(value) ? fontState(value) : 'installed';
  const commit = () => { const name = draft.trim() ? cleanFontName(draft, '') : ''; if (name) { setDraft(name); if (name !== value) onChange(name); } };
  return (
    <div className="fontpick">
      <select id={'set-' + id} data-testid={id} value={other ? OTHER : value}
        onChange={(e) => { if (e.target.value === OTHER) setOther(true); else { setOther(false); onChange(e.target.value); } }}>
        {listed.map((name) => <option key={name} value={name} style={{ fontFamily: fontStack(name) }}>{name === BUILT_IN_FONT ? name + ' (built in)' : name}</option>)}
        <option value={OTHER}>Another installed font…</option>
      </select>
      {other && (
        <input data-testid={id + '-custom'} aria-label="Font family name" placeholder="Font family name, e.g. Berkeley Mono" spellCheck={false} maxLength={FONT_NAME_MAX} value={draft}
          onChange={(e) => setDraft(e.target.value)} onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === 'Enter') { e.preventDefault(); commit(); }
            else if (e.key === 'Escape') { e.stopPropagation(); setDraft(listed.includes(value) ? '' : value); }
          }} />
      )}
      {state === 'missing' && <span className="note err" role="status" data-testid={id + '-missing'}>{value} is not installed on this computer. {BUILT_IN_FONT} is used instead.</span>}
      {state === 'proportional' && <span className="note" role="status" data-testid={id + '-proportional'}>{value} is not a fixed-width font. Columns will not line up.</span>}
    </div>
  );
}

const SPACING = [{ v: 'compact' as const, label: 'Compact' }, { v: 'normal' as const, label: 'Normal' }, { v: 'relaxed' as const, label: 'Relaxed' }];

// What the editor will look like: a few lines of a script in the chosen font,
// size and spacing (the second line starts with a tab, to show the tab width).
function EditorPreview({ prefs }: { prefs: Prefs }) {
  const line = EDITOR_LINE[prefs.editorLineSpacing] || 1.35;
  const style: CSSProperties = { fontFamily: fontStack(prefs.editorFontFamily), fontSize: prefs.editorFontSize, lineHeight: line, tabSize: prefs.editorTabSize };
  const n = (i: number) => (prefs.editorLineNumbers ? <span className="ln">{i}</span> : null);
  return (
    <div className="set-preview" data-testid="preview-editor" aria-hidden="true" style={style}>
      {n(1)}<span className="kw">Interceptor</span>.attach(ptr(<span className="st">"0x7ff6a1c0"</span>), {'{'}{'\n'}
      {n(2)}{'\t'}onEnter(args) {'{'} send(args[<span className="kw">0</span>].readUtf8String()); {'}'} <span className="cm">// 0O 1lI</span>{'\n'}
      {n(3)}{'}'});
    </div>
  );
}
function OutputPreview({ prefs }: { prefs: Prefs }) {
  const style: CSSProperties = { fontFamily: fontStack(prefs.outputFontFamily), fontSize: prefs.outputFontSize, lineHeight: OUTPUT_LINE[prefs.outputLineSpacing] * 1.2 };
  return (
    <div className="set-preview out" data-testid="preview-output" aria-hidden="true" style={style}>
      <span className="dim">[send]</span> {'{'} path: <span className="st">"/data/O0/l1I.dat"</span>, handle: 0x1a4 {'}'}{'\n'}
      7ff6a1c0  48 89 5c 24 08 57 48 83  ec 20 48 8b  <span className="dim">H..$.WH.. H.</span>{'\n'}
      <span className="err">Error: access violation accessing 0x10</span>
    </div>
  );
}

function Themes() {
  const dispatch = useAppDispatch();
  const current = useAppSelector((s) => s.ui.theme);
  const all = themeNames().map((name) => ({ name, m: themeMeta(name) }));
  const group = (dark: boolean) => {
    const items = all.filter((t) => t.m.dark === dark);
    if (!items.length) return null;
    return (
      <>
        <div className="set-sub">{dark ? 'Dark' : 'Light'}</div>
        <div className="themegrid" role="group" aria-label={(dark ? 'Dark' : 'Light') + ' color themes'}>
          {items.map(({ name, m }) => (
            <button key={name} type="button" className={'themeopt' + (name === current ? ' sel' : '')} data-testid={`theme-${name}`} aria-pressed={name === current}
              onClick={() => dispatch(uiActions.setTheme(name))}>
              <span className="sw" style={{ background: m.swatch }} aria-hidden="true">
                <i style={{ background: m.fg, width: '62%' }} /><i style={{ background: m.accent, width: '38%' }} /><i style={{ background: m.muted, width: '50%' }} />
              </span>
              <span className="meta">
                <span className="nm">{m.label}</span>
                {name === 'Kuroir' && <small>original Fermion</small>}
                <Icon name="tick" className="tick" size={14} />
              </span>
            </button>
          ))}
        </div>
      </>
    );
  };
  return <>{group(true)}{group(false)}</>;
}

function SettingsDialog() {
  const dispatch = useAppDispatch();
  const prefs = usePrefs();
  const [section, setSection] = useState<Section>(lastSection);
  const [undo, setUndo] = useState<Prefs | null>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const set = (change: Partial<Prefs>) => dispatch(prefsActions.changed(change));
  const close = () => dispatch(uiActions.toggleSettings(false));

  // Focus starts on the section list, and goes back to the gear on closing.
  useEffect(() => {
    (dialog.current?.querySelector('[role="tab"][aria-selected="true"]') as HTMLElement | null)?.focus();
    return () => { (document.querySelector('[data-testid="open-settings"]') as HTMLElement | null)?.focus?.(); };
  }, []);
  useEffect(() => { lastSection = section; }, [section]);
  useEffect(() => {
    if (!undo) return;
    const t = setTimeout(() => setUndo(null), UNDO_MS);
    return () => clearTimeout(t);
  }, [undo]);

  const reset = (which?: Section) => {
    const keys = changedIn(prefs, which);
    if (!keys.length) return;
    setUndo(prefs);
    if (which) dispatch(prefsActions.changed(Object.fromEntries(keys.map((k) => [k, DEFAULT_PREFS[k]])) as Partial<Prefs>));
    else dispatch(prefsActions.reset());
  };

  // Escape closes (a field that is being edited takes it first); Tab stays inside.
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    if (e.key !== 'Tab' || !dialog.current) return;
    const stops = [...dialog.current.querySelectorAll<HTMLElement>('button, select, input, [tabindex]')].filter((el) => !(el as HTMLButtonElement).disabled && el.tabIndex >= 0);
    if (!stops.length) return;
    const first = stops[0]; const last = stops[stops.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  const onNavKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const at = SECTIONS.findIndex((s) => s.id === section);
    const to = e.key === 'ArrowDown' ? (at + 1) % SECTIONS.length : e.key === 'ArrowUp' ? (at + SECTIONS.length - 1) % SECTIONS.length : e.key === 'Home' ? 0 : e.key === 'End' ? SECTIONS.length - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    setSection(SECTIONS[to].id);
    (e.currentTarget.querySelector(`[data-testid="settings-tab-${SECTIONS[to].id}"]`) as HTMLElement | null)?.focus();
  };

  const title = SECTIONS.find((s) => s.id === section)!.label;
  return (
    <div className="set-layer">
      <div className="set-scrim" data-testid="settings-scrim" onClick={close} />
      <div className="settings" ref={dialog} role="dialog" aria-modal="true" aria-labelledby="settings-title" data-testid="settings" onKeyDown={onKey}>
        <header>
          <span id="settings-title">Settings</span>
          <span className="grow" />
          <button type="button" className="set-close" data-testid="settings-close" aria-label="Close settings" title="Close (Esc)" onClick={close}><Icon name="close" size={15} /></button>
        </header>

        <div className="set-nav" role="tablist" aria-orientation="vertical" aria-label="Settings sections" onKeyDown={onNavKey}>
          {SECTIONS.map((s) => (
            <button key={s.id} type="button" role="tab" id={'settings-tab-' + s.id} aria-selected={s.id === section} aria-controls="settings-pane" tabIndex={s.id === section ? 0 : -1}
              data-testid={'settings-tab-' + s.id} onClick={() => setSection(s.id)}>
              {s.label}<span className="grow" />
              {changedIn(prefs, s.id).length > 0 && <span className="setdot" data-testid={'settings-tab-' + s.id + '-changed'} role="img" aria-label="Has changed settings" />}
            </button>
          ))}
        </div>

        <div className="set-pane" id="settings-pane" role="tabpanel" aria-labelledby={'settings-tab-' + section} data-testid={'settings-pane-' + section}>
          <h3>{title}</h3>
          {section === 'editor' && <EditorPreview prefs={prefs} />}
          {section === 'output' && <OutputPreview prefs={prefs} />}
          <div className="set-scroll">
            {section === 'appearance' && (
              <>
                <Themes />
                <div className="set-sub">Data</div>
                <Row k="dataFontFamily" id="pref-data-font" label="Data font" hint="Addresses, hex dumps, tables and the status bar.">
                  <FontPicker id="pref-data-font" value={prefs.dataFontFamily} onChange={(v) => set({ dataFontFamily: v })} />
                </Row>
                <div className="set-sample" data-testid="preview-data" aria-hidden="true">
                  <span className="dim">7ff6a1c0</span>  48 89 5c 24 08 57 48 83  ec 20 48 8b  <span className="dim">H..$.WH.. H.</span>{'\n'}
                  <span className="dim">kernel32.dll+0x1b0O</span>  CreateFileW  0O 1lI
                </div>
              </>
            )}

            {section === 'editor' && (
              <>
                <Row k="editorFontFamily" id="pref-editor-family" label="Font">
                  <FontPicker id="pref-editor-family" value={prefs.editorFontFamily} onChange={(v) => set({ editorFontFamily: v })} />
                </Row>
                <Row k="editorFontSize" id="pref-editor-font" label="Font size" hint="Hook handlers are shown two sizes smaller.">
                  <Stepper id="pref-editor-font" label="Editor font size" value={prefs.editorFontSize} min={FONT_MIN} max={FONT_MAX} unit="px" onChange={(v) => set({ editorFontSize: v })} />
                </Row>
                <Row k="editorLineSpacing" id="pref-editor-spacing" label="Line spacing">
                  <Choice id="pref-editor-spacing" label="Editor line spacing" value={prefs.editorLineSpacing} choices={SPACING} onChange={(v) => set({ editorLineSpacing: v })} />
                </Row>
                <Row k="editorLineNumbers" id="pref-editor-numbers" label="Line numbers">
                  <input type="checkbox" id="set-pref-editor-numbers" data-testid="pref-editor-numbers" checked={prefs.editorLineNumbers} onChange={(e) => set({ editorLineNumbers: e.target.checked })} />
                </Row>
                <Row k="editorWordWrap" id="pref-editor-wrap" label="Wrap long lines">
                  <input type="checkbox" id="set-pref-editor-wrap" data-testid="pref-editor-wrap" checked={prefs.editorWordWrap} onChange={(e) => set({ editorWordWrap: e.target.checked })} />
                </Row>
                <Row k="editorMinimap" id="pref-editor-minimap" label="Minimap" hint="An overview of the whole script at the right edge.">
                  <input type="checkbox" id="set-pref-editor-minimap" data-testid="pref-editor-minimap" checked={prefs.editorMinimap} onChange={(e) => set({ editorMinimap: e.target.checked })} />
                </Row>
                <Row k="editorTabSize" id="pref-editor-tab" label="Tab width" hint="Columns per indent. A script that is already indented keeps its own.">
                  <Choice id="pref-editor-tab" label="Tab width" value={prefs.editorTabSize} choices={TAB_SIZES.map((v) => ({ v: v as number, label: String(v) }))} onChange={(v) => set({ editorTabSize: v })} />
                </Row>
                <Row k="editorWhitespace" id="pref-editor-whitespace" label="Show spaces and tabs">
                  <Choice id="pref-editor-whitespace" label="Show spaces and tabs" value={prefs.editorWhitespace}
                    choices={[{ v: 'none', label: 'Never' }, { v: 'selection', label: 'In selection' }, { v: 'all', label: 'Always' }]} onChange={(v) => set({ editorWhitespace: v })} />
                </Row>
                <Row k="editorCursor" id="pref-editor-cursor" label="Cursor">
                  <Choice id="pref-editor-cursor" label="Editor cursor" value={prefs.editorCursor}
                    choices={[{ v: 'line', label: 'Line' }, { v: 'block', label: 'Block' }, { v: 'underline', label: 'Underline' }]} onChange={(v) => set({ editorCursor: v })} />
                </Row>
              </>
            )}

            {section === 'output' && (
              <>
                <Row k="outputFontFamily" id="pref-output-family" label="Font">
                  <FontPicker id="pref-output-family" value={prefs.outputFontFamily} onChange={(v) => set({ outputFontFamily: v })} />
                </Row>
                <Row k="outputFontSize" id="pref-output-font" label="Font size">
                  <Stepper id="pref-output-font" label="Output font size" value={prefs.outputFontSize} min={FONT_MIN} max={FONT_MAX} unit="px" onChange={(v) => set({ outputFontSize: v })} />
                </Row>
                <Row k="outputLineSpacing" id="pref-output-spacing" label="Line spacing">
                  <Choice id="pref-output-spacing" label="Output line spacing" value={prefs.outputLineSpacing} choices={SPACING} onChange={(v) => set({ outputLineSpacing: v })} />
                </Row>
                <Row k="outputCursor" id="pref-output-cursor" label="Cursor">
                  <Choice id="pref-output-cursor" label="Output cursor" value={prefs.outputCursor}
                    choices={[{ v: 'bar', label: 'Line' }, { v: 'block', label: 'Block' }, { v: 'underline', label: 'Underline' }]} onChange={(v) => set({ outputCursor: v })} />
                </Row>
              </>
            )}

            {section === 'inspector' && (
              <>
                <p className="set-caption">What each view starts with in a new session. You can still change it in the view itself.</p>
                <Row k="coverScope" id="pref-cover-scope" label="Coverage records">
                  <select id="set-pref-cover-scope" data-testid="pref-cover-scope" value={prefs.coverScope} onChange={(e) => set({ coverScope: e.target.value as Prefs['coverScope'] })}>
                    <option value="app">All but system libraries</option>
                    <option value="all">Everything</option>
                  </select>
                </Row>
                <Row k="followScope" id="pref-follow-scope" label="Follow goes into">
                  <select id="set-pref-follow-scope" data-testid="pref-follow-scope" value={prefs.followScope} onChange={(e) => set({ followScope: e.target.value as Prefs['followScope'] })}>
                    <option value="all">Everything</option>
                    <option value="app">All but system libraries</option>
                  </select>
                </Row>
                <Row k="watchMode" id="pref-watch-mode" label="Memory watch">
                  <select id="set-pref-watch-mode" data-testid="pref-watch-mode" value={prefs.watchMode} onChange={(e) => set({ watchMode: e.target.value as Prefs['watchMode'] })}>
                    <option value="auto">Exact when possible</option>
                    <option value="sampled">Sampled (page trap)</option>
                  </select>
                </Row>
                <Row k="autoRefreshSeconds" id="pref-auto-refresh" label="Auto refresh every" hint="How often the Auto button re-reads Threads and Memory.">
                  <Stepper id="pref-auto-refresh" label="Auto refresh interval" value={prefs.autoRefreshSeconds} min={REFRESH_MIN} max={REFRESH_MAX} unit="s" onChange={(v) => set({ autoRefreshSeconds: v })} />
                </Row>
              </>
            )}

            {section === 'session' && (
              <Row k="catchChildren" id="pref-catch-children" label="Catch child processes when Fermion starts" hint="Whether Catch child processes is already switched on in the Session panel.">
                <input type="checkbox" id="set-pref-catch-children" data-testid="pref-catch-children" checked={prefs.catchChildren} onChange={(e) => set({ catchChildren: e.target.checked })} />
              </Row>
            )}
          </div>
        </div>

        <footer>
          {undo
            ? <span role="status" data-testid="pref-undo-note">Settings reset. <button type="button" className="link" data-testid="pref-undo" onClick={() => { set(undo); setUndo(null); }}>Undo</button></span>
            : <span>Changes apply as you make them and are kept on this computer.</span>}
          <span className="grow" />
          <button type="button" className="pill" data-testid="pref-reset-section" disabled={!changedIn(prefs, section).length} onClick={() => reset(section)}>Reset {title.toLowerCase()}</button>
          <button type="button" className="pill" data-testid="pref-reset" disabled={!changedIn(prefs).length} title="Every setting but the color theme" onClick={() => reset()}>Reset everything</button>
        </footer>
      </div>
    </div>
  );
}

// Settings (the rail's gear, or Ctrl+,): a dialog with the color theme and the
// preferences for how the editor, Output and the Inspector look and start out.
// Everything here is kept in this window; nothing is sent to the target.
export function Settings() {
  const open = useAppSelector((s) => s.ui.settingsOpen);
  return open ? <SettingsDialog /> : null;
}
