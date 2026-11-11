import { useEffect, useRef } from 'react';

/* eslint-disable @typescript-eslint/no-explicit-any */

// Mount a Monaco editor into a ref'd container using the global AMD loader
// (window.require, from the loader.js <script> in index.html). Ported from the
// vanilla editor.js. Exposes the editor on window.MonacoCodeEditor (used by the
// attach/reload thunks + the Playwright test surface) and disposes on unmount.
export function useMonaco(initialValue: string) {
  const hostRef = useRef<HTMLDivElement>(null);
  const editorRef = useRef<any>(null);

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
      const themes = (window as any).FermionThemes || {};

      monaco.languages.typescript.javascriptDefaults.setDiagnosticsOptions({
        noSemanticValidation: true,
        noSyntaxValidation: true,
      });
      monaco.languages.typescript.typescriptDefaults.setCompilerOptions({
        target: monaco.languages.typescript.ScriptTarget.Latest,
        allowNonTsExtensions: true,
        moduleResolution: monaco.languages.typescript.ModuleResolutionKind.NodeJs,
      });

      // frida-gum defs (XHR relative to the document).
      try {
        const req = new XMLHttpRequest();
        req.onreadystatechange = () => {
          if (req.readyState === 4 && req.status >= 200 && req.status < 300) {
            monaco.languages.typescript.typescriptDefaults.addExtraLib(req.responseText, 'file:///frida-gum.d.ts');
          }
        };
        req.open('GET', '../node_modules/@types/frida-gum/index.d.ts', true);
        req.send();
      } catch { /* defs are a nicety */ }

      if (themes.Kuroir) {
        monaco.editor.defineTheme('Kuroir', themes.Kuroir);
        monaco.editor.setTheme('Kuroir');
      }

      const editor = monaco.editor.create(hostRef.current, {
        value: initialValue,
        language: 'typescript',
        scrollBeyondLastLine: false,
        automaticLayout: true,
      });
      editorRef.current = editor;
      (window as any).MonacoCodeEditor = editor;
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
