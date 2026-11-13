import { useEffect, useRef } from 'react';
import { applyTheme, loadSavedTheme } from '../theme/themeEngine';
import { editorOptions, loadPrefs } from '../prefs';

/* eslint-disable @typescript-eslint/no-explicit-any */

// Settings shared by every Monaco editor in the window; applied once.
let configured = false;
export function configureMonaco(monaco: any): void {
  if (configured) return;
  configured = true;
  // The script in the Editor tab is a TypeScript model. JavaScript models
  // (hook handlers) get syntax errors marked, but no type errors: their
  // arguments are untyped.
  monaco.languages.typescript.javascriptDefaults.setDiagnosticsOptions({
    noSemanticValidation: true,
    noSyntaxValidation: false,
    noSuggestionDiagnostics: true, // no fading of a handler's unused log/args
  });
  monaco.languages.typescript.javascriptDefaults.setCompilerOptions({
    target: monaco.languages.typescript.ScriptTarget.Latest,
    allowNonTsExtensions: true,
    allowJs: true,
  });
  monaco.languages.typescript.typescriptDefaults.setCompilerOptions({
    target: monaco.languages.typescript.ScriptTarget.Latest,
    allowNonTsExtensions: true,
    moduleResolution: monaco.languages.typescript.ModuleResolutionKind.NodeJs,
  });

  // frida-gum defs (XHR relative to the document), for both languages.
  try {
    const req = new XMLHttpRequest();
    req.onreadystatechange = () => {
      if (req.readyState === 4 && req.status >= 200 && req.status < 300) {
        monaco.languages.typescript.typescriptDefaults.addExtraLib(req.responseText, 'file:///frida-gum.d.ts');
        monaco.languages.typescript.javascriptDefaults.addExtraLib(req.responseText, 'file:///frida-gum.d.ts');
      }
    };
    req.open('GET', '../node_modules/@types/frida-gum/index.d.ts', true);
    req.send();
  } catch { /* defs are a nicety */ }
}

// Mount a Monaco editor into a ref'd container using the global AMD loader
// (window.require, from the loader.js <script> in index.html). Ported from the
// vanilla editor.js. Exposes the editor on window.MonacoCodeEditor (used by the
// attach/reload thunks + the Playwright test surface) and disposes on unmount.
export function useMonaco(initialValue: string, onEdit?: () => void) {
  const hostRef = useRef<HTMLDivElement>(null);
  const editorRef = useRef<any>(null);
  const onEditRef = useRef(onEdit);
  onEditRef.current = onEdit;

  useEffect(() => {
    const host = hostRef.current;
    const amd = (window as any).require;
    if (!host || !amd || !amd.config) return;
    let disposed = false;

    amd.config({ baseUrl: '../node_modules/monaco-editor/min' });
    (window as any).module = undefined; // monaco-css env workaround (no node here)

    amd(['vs/editor/editor.main'], () => {
      if (disposed || !hostRef.current) return;
      const monaco = (window as any).monaco;

      configureMonaco(monaco);

      // Define + select the active app theme on Monaco (and set the app tokens).
      applyTheme(loadSavedTheme());

      const editor = monaco.editor.create(hostRef.current, {
        value: initialValue,
        language: 'typescript',
        scrollBeyondLastLine: false,
        automaticLayout: true,
        ...editorOptions(loadPrefs()),
      });
      editorRef.current = editor;
      (window as any).MonacoCodeEditor = editor;
      // Any change to the text (typing, paste, undo) counts as an edit.
      editor.onDidChangeModelContent?.(() => onEditRef.current?.());
    });

    return () => {
      disposed = true;
      editorRef.current?.dispose();
      editorRef.current = null;
    };
    // Mount/dispose once — the editor is created imperatively, not from props.
  }, []);

  return { hostRef, editorRef };
}
