import { useEffect, useRef } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { outputActions } from '../store/outputSlice';
import { clearTerminal } from '../bridge';
import { reloadFromEditor } from '../sessionOps';
import { openScript, saveScript } from '../fileOps';
import { useStore } from 'react-redux';


// Global editor/app keybindings, ported from the vanilla renderer so Phase 2
// preserves them: Ctrl/Cmd-S save script, Ctrl/Cmd-O open file, Ctrl/Cmd-T
// reload the attached script, Alt-C clear output, and F5 / Ctrl-R refresh
// prevention. Mounted once from the Layout (always present).
export function useKeybinds() {
  const dispatch = useAppDispatch();
  const isAttached = useAppSelector((s) => s.session.isAttached);
  // Mirror live state into a ref so the document listener (bound once) reads
  // the current value without rebinding on every change.
  const attachedRef = useRef(isAttached);
  attachedRef.current = isAttached;
  const store = useStore();

  useEffect(() => {
    const isMac = /Mac/.test(window.navigator.platform);
    const mod = (e: KeyboardEvent) => (isMac ? e.metaKey : e.ctrlKey);

    const onKey = (e: KeyboardEvent) => {
      // Refresh prevention — a renderer reload would drop the session.
      if (e.key === 'F5' || (mod(e) && (e.key === 'r' || e.key === 'R'))) {
        e.preventDefault();
        return;
      }
      if (mod(e) && (e.key === 's' || e.key === 'S')) {
        e.preventDefault();
        saveScript(dispatch, store.getState);
        return;
      }
      if (mod(e) && (e.key === 'o' || e.key === 'O')) {
        e.preventDefault();
        openScript(dispatch, store.getState);
        return;
      }
      if (mod(e) && (e.key === 't' || e.key === 'T')) {
        e.preventDefault();
        reloadScript();
        return;
      }
      if (e.altKey && (e.key === 'c' || e.key === 'C')) {
        e.preventDefault();
        clearTerminal(); // also clears the detached Output window, if any
        dispatch(outputActions.clear());
      }
    };

    function reloadScript() {
      if (!attachedRef.current) return; // nothing to reload without a session
      reloadFromEditor(dispatch);
    }

    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [dispatch]);
}
