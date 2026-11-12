import { useEffect, useRef, useState } from 'react';
import { writeTerminal } from '../bridge';
import { cleanIpcError } from '../inspector/format';
import { Icon } from './Icon';

/* eslint-disable @typescript-eslint/no-explicit-any */
const api = () => (window as any).fermion?.packages;

interface Pkg { name: string; version: string; description: string; }

// A JavaScript identifier for a package: "frida-objc-bridge" -> ObjC is what
// people expect, but only the well-known bridges have such a name; anything
// else gets its own name in camelCase.
const KNOWN: Record<string, string> = { 'frida-objc-bridge': 'ObjC', 'frida-java-bridge': 'Java', 'frida-swift-bridge': 'Swift', 'frida-fs': 'fs' };
export function importName(pkg: string): string {
  if (KNOWN[pkg]) return KNOWN[pkg];
  const base = pkg.split('/').pop() ?? pkg;
  const camel = base.replace(/[^A-Za-z0-9]+(.)?/g, (_m, c) => (c ? c.toUpperCase() : '')).replace(/^[^A-Za-z_$]+/, '');
  return camel || 'pkg';
}
// What npm accepts as a package name (optionally with an exact version or tag).
const SPEC = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*(?:@[0-9A-Za-z][0-9A-Za-z.+-]{0,63})?$/;
export const isPackageSpec = (text: string) => text.length <= 280 && SPEC.test(text);
const specName = (spec: string) => (spec.lastIndexOf('@') > 0 ? spec.slice(0, spec.lastIndexOf('@')) : spec);

export const importLine = (pkg: string) => `import ${importName(pkg)} from '${pkg}';`;

// Put an import for the package at the top of the script, once.
function addImport(pkg: string): boolean {
  const editor = (window as any).MonacoCodeEditor;
  const value: string = editor?.getValue?.() ?? '';
  if (!editor || new RegExp(`from\\s+['"]${pkg.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}['"]`).test(value)) return false;
  const text = importLine(pkg) + '\n';
  if (typeof editor.executeEdits === 'function') {
    // An edit, not a replacement: it can be undone.
    editor.executeEdits('fermion-packages', [{ range: { startLineNumber: 1, startColumn: 1, endLineNumber: 1, endColumn: 1 }, text, forceMoveMarkers: true }]);
  } else {
    editor.setValue(text + value);
  }
  return true;
}

// Packages: npm packages a script can import. Installed ones are listed with
// "Import" (adds the import line to the script); the search finds more on the
// npm registry. A script that imports a package is compiled when it is loaded.
export function PackagesPanel({ onClose }: { onClose: () => void }) {
  const [installed, setInstalled] = useState<Pkg[] | null>(null);
  const [query, setQuery] = useState('');
  const [found, setFound] = useState<{ items: Pkg[]; total: number; query: string } | null>(null);
  const [searching, setSearching] = useState(false);
  const [working, setWorking] = useState(''); // the package being installed or removed
  const [error, setError] = useState('');
  const request = useRef(0);

  const refresh = async () => {
    try { setInstalled(await api().list()); } catch (e) { setError(cleanIpcError(e)); setInstalled([]); }
  };
  useEffect(() => { refresh(); }, []);

  const search = async () => {
    const q = query.trim();
    if (!q) return;
    const id = ++request.current;
    setSearching(true);
    setError('');
    try {
      const r = await api().search(q);
      if (id === request.current) setFound({ items: Array.isArray(r?.items) ? r.items : [], total: Number(r?.total) || 0, query: q });
    } catch (e) {
      if (id === request.current) { setFound(null); setError('Could not search the npm registry: ' + cleanIpcError(e)); }
    } finally {
      if (id === request.current) setSearching(false);
    }
  };

  const install = async (name: string) => {
    if (working) return;
    setWorking(name);
    setError('');
    try {
      const r = await api().install(name);
      if (r?.cancelled) return;
      writeTerminal('STATUS', `[+] Installed ${r.name}@${r.version}. Use it with: ${importLine(r.name)}`);
      await refresh();
    } catch (e) {
      setError(cleanIpcError(e));
    } finally {
      setWorking('');
    }
  };

  const remove = async (name: string) => {
    if (working) return;
    setWorking(name);
    setError('');
    try {
      await api().remove(name);
      writeTerminal('STATUS', '[+] Removed ' + name);
      await refresh();
    } catch (e) {
      setError(cleanIpcError(e));
    } finally {
      setWorking('');
    }
  };

  const have = new Set((installed ?? []).map((p) => p.name));
  // The search only knows packages published for Frida. Any other npm package
  // can still be installed by typing its exact name.
  const byName = found && isPackageSpec(found.query) && !found.items.some((p) => p.name === specName(found.query)) ? found.query : '';

  return (
    <div className="pkg-panel" data-testid="packages-panel">
      <div className="pkg-head">
        <strong>Packages</strong>
        <span className="pkg-sub">npm packages your script can import. A script with an import is compiled when it is loaded.</span>
        <button className="pill ico" data-testid="pkg-close" aria-label="Close packages" title="Close" onClick={onClose}><Icon name="close" size={11} /></button>
      </div>
      {error && <div className="insp-note err" role="alert" data-testid="pkg-error">{error}</div>}

      <div className="pkg-list" data-testid="pkg-installed">
        {(installed ?? []).map((p) => (
          <div className="pkg-row" key={p.name} data-testid="pkg-row">
            <span className="pn mono">{p.name}</span>
            <span className="pv">{p.version}</span>
            <span className="pd" title={p.description}>{p.description}</span>
            <button className="pill" data-testid="pkg-import" title={'Add to the top of the script: ' + importLine(p.name)} onClick={() => { if (!addImport(p.name)) writeTerminal('STATUS', '[+] The script already imports ' + p.name); }}>Import</button>
            <button className="pill ico" data-testid="pkg-remove" aria-label={'Remove ' + p.name} title="Remove this package" disabled={!!working} onClick={() => remove(p.name)}><Icon name="clear" size={12} /></button>
          </div>
        ))}
        {installed && !installed.length && <div className="insp-empty">No packages installed. Search below, for example for <code>frida-fs</code> or <code>frida-objc-bridge</code>.</div>}
      </div>

      <div className="pkg-search">
        <span className="search insp-filter"><Icon name="search" size={13} />
          <input
            data-testid="pkg-query"
            aria-label="Search the npm registry"
            placeholder="Search Frida packages, or type an exact npm name"
            spellCheck={false}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') search(); }}
          />
        </span>
        <button className="pill" data-testid="pkg-search" disabled={!query.trim() || searching} onClick={search}>{searching ? 'Searching…' : 'Search'}</button>
      </div>
      {found && (
        <div className="pkg-list results" data-testid="pkg-results">
          {byName && (
            <div className="pkg-row" data-testid="pkg-result">
              <span className="pn mono">{byName}</span>
              <span className="pv" />
              <span className="pd">Not in Frida's package list. Install it from npm by this exact name.</span>
              <button className="pill" data-testid="pkg-install" disabled={have.has(specName(byName)) || !!working} onClick={() => install(byName)}>
                {have.has(specName(byName)) ? 'Installed' : working === byName ? 'Installing…' : 'Install'}
              </button>
            </div>
          )}
          {found.items.map((p) => (
            <div className="pkg-row" key={p.name} data-testid="pkg-result">
              <span className="pn mono">{p.name}</span>
              <span className="pv">{p.version}</span>
              <span className="pd" title={p.description}>{p.description}</span>
              <button className="pill" data-testid="pkg-install" disabled={have.has(p.name) || !!working} onClick={() => install(p.name)}>
                {have.has(p.name) ? 'Installed' : working === p.name ? 'Installing…' : 'Install'}
              </button>
            </div>
          ))}
          {!found.items.length && !byName && <div className="insp-empty">No package matches. To install any npm package, type its exact name.</div>}
          {found.total > found.items.length && found.items.length > 0 && <div className="pkg-more">Showing {found.items.length} of {found.total.toLocaleString()}. Refine the search to see others.</div>}
        </div>
      )}
    </div>
  );
}
