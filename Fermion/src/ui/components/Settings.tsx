import { ReactNode } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { uiActions } from '../store/uiSlice';
import { prefsActions, usePrefs } from '../store/prefsSlice';
import { Prefs, DEFAULT_PREFS, FONT_MIN, FONT_MAX, REFRESH_MIN, REFRESH_MAX } from '../prefs';
import { themeNames, themeMeta } from '../theme/themeEngine';
import { Icon } from './Icon';

function Row({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="setrow" title={hint}>
      <span className="lbl">{label}</span>
      {children}
    </label>
  );
}

// A whole number between two bounds, changed by typing or with the arrows.
function NumberField({ id, value, min, max, unit, onChange }: { id: string; value: number; min: number; max: number; unit: string; onChange: (v: number) => void }) {
  return (
    <span className="setnum">
      <input type="number" data-testid={id} min={min} max={max} step={1} value={value}
        onChange={(e) => { const v = Number(e.target.value); if (e.target.value !== '' && Number.isFinite(v)) onChange(v); }} />
      <span className="unit">{unit}</span>
    </span>
  );
}

// Settings (opened from the rail gear): the colour theme, and preferences for
// how the editor, Output and Inspector look and start out. Everything here is
// kept in this window; nothing is sent to the target.
export function Settings() {
  const dispatch = useAppDispatch();
  const open = useAppSelector((s) => s.ui.settingsOpen);
  const current = useAppSelector((s) => s.ui.theme);
  const prefs = usePrefs();
  if (!open) return null;
  const set = (change: Partial<Prefs>) => dispatch(prefsActions.changed(change));
  const isDefault = (Object.keys(DEFAULT_PREFS) as (keyof Prefs)[]).every((k) => prefs[k] === DEFAULT_PREFS[k]);

  return (
    <>
      <div className="scrim" data-testid="settings-scrim" onClick={() => dispatch(uiActions.toggleSettings(false))} />
      <div className="settings" role="dialog" aria-label="Settings" data-testid="settings">
        <header><Icon name="gear" size={15} /> Settings</header>
        <div className="sect">
          <h5>Editor</h5>
          <Row label="Font size" hint="The script editor. Hook handlers are shown two sizes smaller.">
            <NumberField id="pref-editor-font" value={prefs.editorFontSize} min={FONT_MIN} max={FONT_MAX} unit="px" onChange={(v) => set({ editorFontSize: v })} />
          </Row>
          <Row label="Minimap" hint="The overview of the whole script at the right edge of the editor">
            <input type="checkbox" data-testid="pref-editor-minimap" checked={prefs.editorMinimap} onChange={(e) => set({ editorMinimap: e.target.checked })} />
          </Row>
          <Row label="Wrap long lines">
            <input type="checkbox" data-testid="pref-editor-wrap" checked={prefs.editorWordWrap} onChange={(e) => set({ editorWordWrap: e.target.checked })} />
          </Row>

          <h5>Output</h5>
          <Row label="Font size">
            <NumberField id="pref-output-font" value={prefs.outputFontSize} min={FONT_MIN} max={FONT_MAX} unit="px" onChange={(v) => set({ outputFontSize: v })} />
          </Row>

          <h5>Inspector</h5>
          <Row label="Coverage records" hint="What a coverage recording covers unless you choose otherwise. Takes effect in the next session.">
            <select data-testid="pref-cover-scope" value={prefs.coverScope} onChange={(e) => set({ coverScope: e.target.value as Prefs['coverScope'] })}>
              <option value="app">All but system libraries</option>
              <option value="all">Everything</option>
            </select>
          </Row>
          <Row label="Follow goes into" hint="What following a thread goes into unless you choose otherwise. Takes effect in the next session.">
            <select data-testid="pref-follow-scope" value={prefs.followScope} onChange={(e) => set({ followScope: e.target.value as Prefs['followScope'] })}>
              <option value="all">Everything</option>
              <option value="app">All but system libraries</option>
            </select>
          </Row>
          <Row label="Memory watch" hint="How a memory watch is kept unless you choose otherwise. Takes effect in the next session.">
            <select data-testid="pref-watch-mode" value={prefs.watchMode} onChange={(e) => set({ watchMode: e.target.value as Prefs['watchMode'] })}>
              <option value="auto">Exact when possible</option>
              <option value="sampled">Sampled (page trap)</option>
            </select>
          </Row>
          <Row label="Auto refresh every" hint="How often the Auto button on Threads and Memory re-reads">
            <NumberField id="pref-auto-refresh" value={prefs.autoRefreshSeconds} min={REFRESH_MIN} max={REFRESH_MAX} unit="s" onChange={(v) => set({ autoRefreshSeconds: v })} />
          </Row>

          <h5>Session</h5>
          <Row label="Catch child processes" hint="Whether Catch child processes is switched on when Fermion starts">
            <span className="setcheck">
              <input type="checkbox" data-testid="pref-catch-children" checked={prefs.catchChildren} onChange={(e) => set({ catchChildren: e.target.checked })} />
              <span className="unit">on at start</span>
            </span>
          </Row>

          <div className="setfoot">
            <button className="pill" data-testid="pref-reset" disabled={isDefault} onClick={() => dispatch(prefsActions.reset())}>Reset to defaults</button>
            <span className="unit">Kept on this computer.</span>
          </div>

          <h5>Color theme</h5>
          {themeNames().map((name) => {
            const m = themeMeta(name);
            const note = (name === 'Kuroir' ? 'original Fermion · ' : '') + (m.dark ? 'dark' : 'light');
            return (
              <button
                key={name}
                className={'themeopt' + (name === current ? ' sel' : '')}
                data-testid={`theme-${name}`}
                onClick={() => dispatch(uiActions.setTheme(name))}
              >
                <span className="sw" style={{ background: m.swatch }} />
                <span className="meta">{m.label}<small>{note}</small></span>
                <Icon name="tick" className="tick" size={15} />
              </button>
            );
          })}
        </div>
      </div>
    </>
  );
}
