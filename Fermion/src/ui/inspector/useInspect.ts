import { useCallback, useEffect, useRef, useState } from 'react';
import { cleanIpcError } from './format';

/* eslint-disable @typescript-eslint/no-explicit-any */
export const inspectApi = () => (window as any).fermion?.inspect;

// A capped list as returned by the inspector agent.
export interface Listing<T> { items: T[]; total: number; truncated: boolean; }

export interface InspectState<T> {
  data: T | null;
  error: string;
  loading: boolean;
  reload: () => void;
}

// Run one inspector call whenever `enabled` becomes true (so a view refreshes
// each time it is shown), whenever `key` changes, and on reload(). A response
// that arrives after a newer request was started is dropped. When the key
// changes, the previous result is cleared at once so it is never shown under
// the new selection. With `autoMs`, the call repeats that long after each answer.
export function useInspect<T>(call: () => Promise<T>, key: string, enabled: boolean, autoMs = 0): InspectState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [nonce, setNonce] = useState(0);
  const request = useRef(0);
  const callRef = useRef(call);
  callRef.current = call;
  const loadedKey = useRef<string | null>(null);

  useEffect(() => {
    if (!enabled) return;
    const id = ++request.current;
    if (loadedKey.current !== key) { loadedKey.current = key; setData(null); setError(''); }
    setLoading(true);
    Promise.resolve()
      .then(() => callRef.current())
      .then((d) => { if (id === request.current) { setData(d); setError(''); } })
      .catch((e) => { if (id === request.current) { setData(null); setError(cleanIpcError(e)); } })
      .finally(() => { if (id === request.current) setLoading(false); });
  }, [enabled, key, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  // Auto-refresh: ask again `autoMs` after the previous answer arrived. Waiting
  // for the answer first means a slow target is never piled up on.
  useEffect(() => {
    if (!enabled || !autoMs || loading) return;
    const t = setTimeout(reload, autoMs);
    return () => clearTimeout(t);
  }, [enabled, autoMs, loading, nonce, key, reload]);
  return { data, error, loading, reload };
}
