import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { vi } from 'vitest';
import { setTerminalSink } from '../bridge';
import { PackagesPanel, importName, importLine, isPackageSpec } from './PackagesPanel';

/* eslint-disable @typescript-eslint/no-explicit-any */
let packages: any;
let lines: string[];
let editorValue: string;
let edits: any[];
function setup({ installed = [{ name: 'frida-fs', version: '8.1.1', description: 'Create a stream from a filesystem resource' }] } = {}) {
  let have = installed.slice();
  packages = {
    list: vi.fn(async () => have.slice()),
    search: vi.fn(async () => ({ items: [
      { name: 'frida-fs', version: '8.1.1', description: 'fs' },
      { name: 'frida-objc-bridge', version: '8.0.6', description: 'Objective-C runtime interop from Frida' },
    ], total: 19 })),
    install: vi.fn(async (name: string) => { have = have.concat({ name, version: '8.0.6', description: 'd' }); return { name, version: '8.0.6', description: 'd', via: 'npm' }; }),
    remove: vi.fn(async (name: string) => { have = have.filter((p) => p.name !== name); return true; }),
  };
  lines = [];
  edits = [];
  editorValue = 'send(1);\n';
  setTerminalSink({ write: (k: string, t: string) => lines.push(k + ' ' + t) });
  (window as any).fermion = { packages };
  (window as any).MonacoCodeEditor = {
    getValue: () => editorValue,
    executeEdits: (_source: string, list: any[]) => { edits.push(list[0]); editorValue = list[0].text + editorValue; },
  };
  const onClose = vi.fn();
  render(<PackagesPanel onClose={onClose} />);
  return { onClose };
}
afterEach(() => setTerminalSink(null));

test('importName / importLine: the bridges get their usual names, others a camelCase one', () => {
  expect(importLine('frida-objc-bridge')).toBe("import ObjC from 'frida-objc-bridge';");
  expect(importLine('frida-java-bridge')).toBe("import Java from 'frida-java-bridge';");
  expect(importLine('frida-fs')).toBe("import fs from 'frida-fs';");
  expect(importName('frida-remote-stream')).toBe('fridaRemoteStream');
  expect(importName('@scope/my.pkg_name')).toBe('myPkgName');
  expect(importName('7zip')).toBe('zip');
  expect(importName('---')).toBe('pkg');
});

test('installed packages are listed with version and description', async () => {
  setup();
  const row = await screen.findByTestId('pkg-row');
  expect(row).toHaveTextContent('frida-fs');
  expect(row).toHaveTextContent('8.1.1');
  expect(row).toHaveTextContent('Create a stream from a filesystem resource');
});

test('nothing installed: says so and suggests what to search for', async () => {
  setup({ installed: [] });
  await waitFor(() => expect(screen.getByTestId('pkg-installed')).toHaveTextContent('No packages installed.'));
});

test('Import adds the import line to the top of the script as an undoable edit, once', async () => {
  setup();
  fireEvent.click(await screen.findByTestId('pkg-import'));
  expect(editorValue).toBe("import fs from 'frida-fs';\nsend(1);\n");
  expect(edits[0].range).toEqual({ startLineNumber: 1, startColumn: 1, endLineNumber: 1, endColumn: 1 });
  fireEvent.click(screen.getByTestId('pkg-import'));
  expect(edits.length).toBe(1);
  expect(lines).toContain('STATUS [+] The script already imports frida-fs');
});

test('search lists registry results; one that is installed says so and cannot be installed again', async () => {
  setup();
  expect(screen.getByTestId('pkg-search')).toBeDisabled();
  fireEvent.change(screen.getByTestId('pkg-query'), { target: { value: '  frida bridge ' } });
  fireEvent.keyDown(screen.getByTestId('pkg-query'), { key: 'Enter' });
  const rows = await screen.findAllByTestId('pkg-result');
  expect(packages.search).toHaveBeenCalledWith('frida bridge');
  expect(rows.length).toBe(2);
  expect(within(rows[0]).getByTestId('pkg-install')).toHaveTextContent('Installed');
  expect(within(rows[0]).getByTestId('pkg-install')).toBeDisabled();
  expect(within(rows[1]).getByTestId('pkg-install')).toHaveTextContent('Install');
  expect(screen.getByTestId('pkg-results')).toHaveTextContent('Showing 2 of 19.');
});

test('Install installs the package, lists it, and says how to use it', async () => {
  setup();
  fireEvent.change(screen.getByTestId('pkg-query'), { target: { value: 'frida bridge' } });
  fireEvent.click(screen.getByTestId('pkg-search'));
  const rows = await screen.findAllByTestId('pkg-result');
  fireEvent.click(within(rows[1]).getByTestId('pkg-install'));
  await waitFor(() => expect(screen.getAllByTestId('pkg-row').length).toBe(2));
  expect(packages.install).toHaveBeenCalledWith('frida-objc-bridge');
  expect(lines).toContain("STATUS [+] Installed frida-objc-bridge@8.0.6. Use it with: import ObjC from 'frida-objc-bridge';");
  await waitFor(() => expect(within(screen.getAllByTestId('pkg-result')[1]).getByTestId('pkg-install')).toHaveTextContent('Installed'));
});

test('an install the operator declines changes nothing and is not an error', async () => {
  setup();
  packages.install.mockResolvedValueOnce({ cancelled: true });
  fireEvent.change(screen.getByTestId('pkg-query'), { target: { value: 'frida bridge' } });
  fireEvent.click(screen.getByTestId('pkg-search'));
  fireEvent.click(within((await screen.findAllByTestId('pkg-result'))[1]).getByTestId('pkg-install'));
  await waitFor(() => expect(within(screen.getAllByTestId('pkg-result')[1]).getByTestId('pkg-install')).toHaveTextContent(/^Install$/));
  expect(screen.getAllByTestId('pkg-row').length).toBe(1);
  expect(screen.queryByTestId('pkg-error')).toBeNull();
  expect(lines).toEqual([]);
});

test('a failed install or search is reported in the panel', async () => {
  setup();
  packages.search.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:pkgSearch': Error: network unreachable"));
  fireEvent.change(screen.getByTestId('pkg-query'), { target: { value: 'frida bridge' } });
  fireEvent.click(screen.getByTestId('pkg-search'));
  await waitFor(() => expect(screen.getByTestId('pkg-error')).toHaveTextContent('Could not search the npm registry: network unreachable'));
  fireEvent.click(screen.getByTestId('pkg-search'));
  packages.install.mockRejectedValueOnce(new Error("Error invoking remote method 'fermion:pkgInstall': Error: Could not install frida-objc-bridge. npm was not found on this machine."));
  fireEvent.click(within((await screen.findAllByTestId('pkg-result'))[1]).getByTestId('pkg-install'));
  await waitFor(() => expect(screen.getByTestId('pkg-error')).toHaveTextContent('Could not install frida-objc-bridge. npm was not found on this machine.'));
});

test('Remove removes the package and updates the list; Close closes the panel', async () => {
  const { onClose } = setup();
  fireEvent.click(await screen.findByTestId('pkg-remove'));
  await waitFor(() => expect(screen.queryByTestId('pkg-row')).toBeNull());
  expect(packages.remove).toHaveBeenCalledWith('frida-fs');
  expect(lines).toContain('STATUS [+] Removed frida-fs');
  fireEvent.click(screen.getByTestId('pkg-close'));
  expect(onClose).toHaveBeenCalled();
});

test('package text from the registry is shown as text, never as markup', async () => {
  setup();
  packages.search.mockResolvedValueOnce({ items: [{ name: 'evil', version: '1.0.0', description: '<img src=x onerror=alert(1)>' }], total: 1 });
  fireEvent.change(screen.getByTestId('pkg-query'), { target: { value: 'evil' } });
  fireEvent.click(screen.getByTestId('pkg-search'));
  const row = await screen.findByTestId('pkg-result');
  expect(row).toHaveTextContent('<img src=x onerror=alert(1)>');
  expect(row.querySelector('img')).toBeNull();
});

test('a package that is not in the search results can be installed by its exact name', async () => {
  setup();
  packages.search.mockResolvedValueOnce({ items: [{ name: 'frida-objc-bridge', version: '8.0.6', description: 'd' }], total: 1 });
  fireEvent.change(screen.getByTestId('pkg-query'), { target: { value: 'is-number@7.0.0' } });
  fireEvent.click(screen.getByTestId('pkg-search'));
  const rows = await screen.findAllByTestId('pkg-result');
  expect(rows.length).toBe(2);
  // Offered first, above what the registry listed.
  expect(rows[0]).toHaveTextContent('is-number@7.0.0');
  expect(rows[0]).toHaveTextContent('Install it from npm by this exact name.');
  fireEvent.click(within(rows[0]).getByTestId('pkg-install'));
  await waitFor(() => expect(packages.install).toHaveBeenCalledWith('is-number@7.0.0'));
});

test('install by name is offered only for something npm would accept as a name', async () => {
  expect(isPackageSpec('frida-fs')).toBe(true);
  expect(isPackageSpec('@scope/pkg@1.2.3')).toBe(true);
  for (const bad of ['two words', 'Upper', '../x', 'a;b', 'a&&b', 'https://x/y.tgz', 'a@^1']) expect(isPackageSpec(bad)).toBe(false);
  setup();
  packages.search.mockResolvedValueOnce({ items: [], total: 0 });
  fireEvent.change(screen.getByTestId('pkg-query'), { target: { value: 'two words' } });
  fireEvent.click(screen.getByTestId('pkg-search'));
  await waitFor(() => expect(screen.getByTestId('pkg-results')).toHaveTextContent('No package matches. To install any npm package, type its exact name.'));
  expect(screen.queryByTestId('pkg-result')).toBeNull();
});

test('a package already in the results is not offered a second time by name', async () => {
  setup();
  fireEvent.change(screen.getByTestId('pkg-query'), { target: { value: 'frida-objc-bridge' } });
  fireEvent.click(screen.getByTestId('pkg-search'));
  expect((await screen.findAllByTestId('pkg-result')).length).toBe(2);
});
