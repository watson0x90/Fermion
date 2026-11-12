import { useAppDispatch, useAppSelector } from '../store';
import { uiActions } from '../store/uiSlice';
import { themeNames, themeMeta } from '../theme/themeEngine';
import { Icon } from './Icon';

// Settings menu (opened from the rail gear). Phase-2 holds the color-theme
// picker; selecting a theme dispatches setTheme, which Layout applies app-wide.
export function Settings() {
  const dispatch = useAppDispatch();
  const open = useAppSelector((s) => s.ui.settingsOpen);
  const current = useAppSelector((s) => s.ui.theme);
  if (!open) return null;

  return (
    <>
      <div className="scrim" data-testid="settings-scrim" onClick={() => dispatch(uiActions.toggleSettings(false))} />
      <div className="settings" role="dialog" aria-label="Settings" data-testid="settings">
        <header><Icon name="gear" size={15} /> Settings</header>
        <div className="sect">
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
