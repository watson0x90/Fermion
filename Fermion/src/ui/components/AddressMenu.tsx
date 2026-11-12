import { useEffect, useLayoutEffect, useRef, useState, KeyboardEvent } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { uiActions } from '../store/uiSlice';
import { hooksActions } from '../store/hooksSlice';
import { MenuRequest, onAddressMenu } from '../addressMenu';
import { addTarget } from '../hooking/ops';
import { Target, sameTarget } from '../hooking/model';
import { writeTerminal } from '../bridge';
import { cleanIpcError } from '../inspector/format';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;

// The menu opened by right-clicking an address anywhere in the app.
export function AddressMenu() {
  const dispatch = useAppDispatch();
  const isAttached = useAppSelector((s) => s.session.isAttached);
  const hooks = useAppSelector((s) => s.hooks?.hooks ?? []);
  const [request, setRequest] = useState<MenuRequest | null>(null);
  const [pos, setPos] = useState({ left: 0, top: 0 });
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => onAddressMenu(setRequest), []);

  // Closing: a click elsewhere, Escape, scrolling, resizing, losing focus.
  useEffect(() => {
    if (!request) return;
    const close = () => setRequest(null);
    const onDown = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) close(); };
    const onKey = (e: globalThis.KeyboardEvent) => { if (e.key === 'Escape') { e.preventDefault(); close(); } };
    document.addEventListener('mousedown', onDown, true);
    document.addEventListener('keydown', onKey, true);
    document.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    window.addEventListener('blur', close);
    return () => {
      document.removeEventListener('mousedown', onDown, true);
      document.removeEventListener('keydown', onKey, true);
      document.removeEventListener('scroll', close, true);
      window.removeEventListener('resize', close);
      window.removeEventListener('blur', close);
    };
  }, [request]);

  // Keep the menu inside the window, and put the keyboard in it.
  useLayoutEffect(() => {
    if (!request || !ref.current) return;
    const r = ref.current.getBoundingClientRect();
    setPos({
      left: Math.max(4, Math.min(request.x, window.innerWidth - r.width - 4)),
      top: Math.max(4, Math.min(request.y, window.innerHeight - r.height - 4)),
    });
    ref.current.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus();
  }, [request]);

  if (!request) return null;
  const { address } = request;
  const done = (fn: () => unknown) => () => { setRequest(null); fn(); };

  const copy = () => { try { navigator.clipboard?.writeText(address); } catch { /* clipboard unavailable */ } };
  const open = (view: 'memory' | 'code') => dispatch(uiActions.openAddress({ view, address }));
  const hook = async () => {
    try {
      // The target describes the address (module + offset, name) so the hook
      // can be placed again in a later session.
      const found = await api().hooks.search('exports', address);
      const target: Target | undefined = found?.items?.[0];
      if (!target) throw new Error('Nothing to hook at ' + address);
      const existing = hooks.find((h) => sameTarget(h, target));
      const id = existing ? existing.id : (await addTarget(dispatch, target, true)).id;
      dispatch(hooksActions.selected(id));
      dispatch(uiActions.setActiveTab('hooks'));
    } catch (e) {
      writeTerminal('ERR', '[!] Could not hook ' + address + ': ' + cleanIpcError(e));
    }
  };

  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const items = [...(ref.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? [])];
    const at = items.indexOf(document.activeElement as HTMLButtonElement);
    items[(at + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length]?.focus();
  };

  const needsTarget = isAttached ? undefined : 'Attach to a process first';
  return (
    <div className="addr-menu" role="menu" aria-label={'Address ' + address} data-testid="addr-menu" ref={ref} style={pos} onKeyDown={onKey}>
      <div className="addr-menu-head mono">{address}</div>
      <button role="menuitem" data-testid="addr-menu-copy" onClick={done(copy)}>Copy address</button>
      <button role="menuitem" data-testid="addr-menu-memory" disabled={!isAttached} title={needsTarget} onClick={done(() => open('memory'))}>Open in Memory</button>
      <button role="menuitem" data-testid="addr-menu-code" disabled={!isAttached} title={needsTarget} onClick={done(() => open('code'))}>Open in Disassembly</button>
      <button role="menuitem" data-testid="addr-menu-hook" disabled={!isAttached} title={needsTarget} onClick={done(hook)}>Hook this address</button>
    </div>
  );
}
