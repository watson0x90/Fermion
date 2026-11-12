import { useEffect, useRef, KeyboardEvent } from 'react';
import { configureMonaco } from '../hooks/useMonaco';

/* eslint-disable @typescript-eslint/no-explicit-any */

interface Props {
  value: string;
  onChange: (value: string) => void;
  onApply?: () => void;      // Ctrl/Cmd+Enter and Ctrl/Cmd+S
  label: string;
  testId: string;
  // Where the editor is exposed on window, for the end-to-end tests.
  exposeAs?: string;
}

const hasMonaco = (): boolean => !!(window as any).require?.config;

// A small JavaScript editor for code that is not the main script (a hook's
// handler): the same Monaco as the Editor tab, with Frida's API completed
// and syntax errors marked. Where Monaco is not available it is a plain text
// box that behaves the same.
export function CodeEditor(props: Props) {
  return hasMonaco() ? <MonacoBox {...props} /> : <PlainBox {...props} />;
}

function MonacoBox({ value, onChange, onApply, label, testId, exposeAs }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const editorRef = useRef<any>(null);
  const latest = useRef({ onChange, onApply });
  latest.current = { onChange, onApply };
  const valueRef = useRef(value);
  valueRef.current = value;
  const setting = useRef(false); // true while the text is being replaced from outside

  useEffect(() => {
    const amd = (window as any).require;
    let disposed = false;
    amd.config({ baseUrl: '../node_modules/monaco-editor/min' });
    (window as any).module = undefined;
    amd(['vs/editor/editor.main'], () => {
      if (disposed || !hostRef.current) return;
      const monaco = (window as any).monaco;
      configureMonaco(monaco);
      const editor = monaco.editor.create(hostRef.current, {
        value: valueRef.current,
        language: 'javascript',
        automaticLayout: true,
        scrollBeyondLastLine: false,
        minimap: { enabled: false },
        lineNumbersMinChars: 3,
        fontSize: 12,
        tabSize: 2,
        ariaLabel: label,
      });
      editorRef.current = editor;
      if (exposeAs) (window as any)[exposeAs] = editor;
      editor.onDidChangeModelContent(() => { if (!setting.current) latest.current.onChange(editor.getValue()); });
      const apply = () => latest.current.onApply?.();
      editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, apply);
      editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, apply);
    });
    return () => {
      disposed = true;
      if (exposeAs && (window as any)[exposeAs] === editorRef.current) delete (window as any)[exposeAs];
      editorRef.current?.dispose();
      editorRef.current = null;
    };
    // Mounted once: the text is kept in step below.
  }, []);

  // The text changed from outside (another hook selected, Revert).
  useEffect(() => {
    const editor = editorRef.current;
    if (!editor || editor.getValue() === value) return;
    setting.current = true;
    try { editor.setValue(value); } finally { setting.current = false; }
  }, [value]);

  return <div className="code-editor" data-testid={testId} ref={hostRef} />;
}

function PlainBox({ value, onChange, onApply, label, testId }: Props) {
  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'Enter' || e.key === 's')) { e.preventDefault(); onApply?.(); return; }
    if (e.key === 'Tab' && !e.shiftKey) {
      // Tab indents instead of leaving the editor.
      e.preventDefault();
      const el = e.currentTarget;
      const { selectionStart: a, selectionEnd: b } = el;
      onChange(value.slice(0, a) + '  ' + value.slice(b));
      requestAnimationFrame(() => { el.selectionStart = el.selectionEnd = a + 2; });
    }
  };
  return (
    <textarea
      data-testid={testId}
      aria-label={label}
      className="mono"
      spellCheck={false}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={onKey}
    />
  );
}
