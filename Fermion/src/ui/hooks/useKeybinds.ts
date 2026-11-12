import { useEffect, useRef } from 'react';
import { useAppDispatch, useAppSelector } from '../store';
import { outputActions } from '../store/outputSlice';
import { writeTerminal, clearTerminal } from '../bridge';
import { reloadFromEditor } from '../sessionOps';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion;
const editor = () => (window as any).MonacoCodeEditor;

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
  const currentPath = useRef<string | null>(null);

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
        saveScript();
        return;
      }
      if (mod(e) && (e.key === 'o' || e.key === 'O')) {
        e.preventDefault();
        openScript();
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

    function saveScript() {
      const content: string = editor()?.getValue?.() ?? '';
      const f = api();
      if (!f) return;
      const known = currentPath.current;
      const p = known
        ? f.saveCurrentFile(content)
        : f.saveFile(content, { title: 'Fermion Save File' });
      Promise.resolve(p).then((savedPath: string | null | undefined) => {
        if (!savedPath) return;
        currentPath.current = savedPath;
        writeTerminal('STATUS', '[+] File saved..');
        writeTerminal('STATUS', '    |-> Path: ' + savedPath);
      }).catch((err: unknown) => writeTerminal('ERR', '[!] Error saving file: ' + err));
    }

    function openScript() {
      const f = api();
      if (!f) return;
      Promise.resolve(f.openFile()).then((result: { path: string; content: string } | null) => {
        if (!result) return;
        editor()?.setValue?.(result.content);
        currentPath.current = result.path;
        writeTerminal('STATUS', '[+] File opened..');
        writeTerminal('STATUS', '    |-> Path: ' + result.path);
      }).catch((err: unknown) => writeTerminal('ERR', '[!] Error opening file: ' + err));
    }

    function reloadScript() {
      if (!attachedRef.current) return; // nothing to reload without a session
      reloadFromEditor(dispatch);
    }

    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [dispatch]);
}
