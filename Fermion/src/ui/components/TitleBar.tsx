import { useEffect, useState } from 'react';
import { Icon } from './Icon';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;

// Custom slim title bar for the frameless window: the original hand-lettered
// wordmark (inverted on dark themes via --logo-filter), a draggable strip, and
// real window controls that drive the main process over fermion.win.*.
export function TitleBar({ subtitle = 'Frida IDE' }: { subtitle?: string }) {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    const f = api();
    f?.win?.isMaximized?.().then((m: boolean) => setMaximized(!!m)).catch(() => {});
    const un = f?.onMaximizeChange?.((m: boolean) => setMaximized(!!m));
    return () => { if (typeof un === 'function') un(); };
  }, []);

  return (
    <div className="titlebar" data-testid="titlebar">
      <div className="brand">
        <Icon name="mark" className="mark" size={17} />
        <img className="wordmark" src="../src/images/fermion-alt.png" alt="Fermion" draggable={false} />
        <span className="sub">{subtitle}</span>
      </div>
      <div className="sp" />
      <div className="winctl">
        <button data-testid="win-min" title="Minimize" onClick={() => api()?.win?.minimize?.()}><Icon name="min" size={15} /></button>
        <button data-testid="win-max" title={maximized ? 'Restore' : 'Maximize'} onClick={() => api()?.win?.toggleMaximize?.()}><Icon name={maximized ? 'unmax' : 'max'} size={14} /></button>
        <button className="close" data-testid="win-close" title="Close" onClick={() => api()?.win?.close?.()}><Icon name="close" size={15} /></button>
      </div>
    </div>
  );
}
