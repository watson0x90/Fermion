// Unit tests for the help-index builder: it turns the Frida type definitions
// (@types/frida-gum, with their doc comments) into the lookup table behind the
// REPL's `help <name>`.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { buildHelpIndex } = require('./frida-help-index.js');

const FIXTURE = `
/**
 * Information about the current process.
 */
declare namespace Process {
    /**
     * PID of the current process.
     */
    const id: number;

    /**
     * Enumerates modules loaded right now.
     *
     * @param filter Only modules matching this.
     */
    function enumerateModules(filter?: string): Module[];

    /** Looks up a module by address. */
    function findModuleByAddress(address: NativePointerValue): Module | null;
    /** Looks up a module by name. */
    function findModuleByAddress(name: string): Module | null;

    function undocumented(): void;
}

declare class Module {
    /** Canonical module name. */
    name: string;

    /**
     * Enumerates exports of module.
     */
    enumerateExports(): ModuleExportDetails[];

    /** Loads the specified module. */
    static load(name: string): Module;

    private secret(): void;
}

/** Statics that live beside the class. */
declare namespace Module {
    /** Ensures initializers have run. */
    function ensureInitialized(name: string): void;
}

/**
 * Short-hand for \`new NativePointer(value)\`.
 */
declare function ptr(value: string | number): NativePointer;

/** Size of a pointer. */
declare const pointerSize: number;

interface ModuleExportDetails {
    /** Exported name. */
    name: string;
}

type Ignored = string;
`;

test('namespaces: the namespace itself, its constants and its functions', () => {
  const ix = buildHelpIndex(FIXTURE);
  assert.deepEqual(ix.Process, { kind: 'namespace', sigs: [], doc: 'Information about the current process.' });
  assert.deepEqual(ix['Process.id'], { kind: 'property', sigs: ['id: number'], doc: 'PID of the current process.' });
  assert.deepEqual(ix['Process.enumerateModules'], {
    kind: 'function',
    sigs: ['enumerateModules(filter?: string): Module[]'],
    doc: 'Enumerates modules loaded right now.\n\n@param filter Only modules matching this.',
  });
});

test('overloads are merged: every signature, the first non-empty doc', () => {
  const e = buildHelpIndex(FIXTURE)['Process.findModuleByAddress'];
  assert.deepEqual(e.sigs, ['findModuleByAddress(address: NativePointerValue): Module | null', 'findModuleByAddress(name: string): Module | null']);
  assert.equal(e.doc, 'Looks up a module by address.');
});

test('an undocumented member is still listed, with an empty doc', () => {
  assert.deepEqual(buildHelpIndex(FIXTURE)['Process.undocumented'], { kind: 'function', sigs: ['undocumented(): void'], doc: '' });
});

test('classes: instance members, static members, and a namespace of the same name are merged', () => {
  const ix = buildHelpIndex(FIXTURE);
  assert.equal(ix.Module.kind, 'class');
  assert.equal(ix.Module.doc, 'Statics that live beside the class.');
  assert.deepEqual(ix['Module.name'], { kind: 'property', sigs: ['name: string'], doc: 'Canonical module name.' });
  assert.deepEqual(ix['Module.enumerateExports'], { kind: 'method', sigs: ['enumerateExports(): ModuleExportDetails[]'], doc: 'Enumerates exports of module.' });
  assert.deepEqual(ix['Module.load'], { kind: 'static method', sigs: ['static load(name: string): Module'], doc: 'Loads the specified module.' });
  assert.equal(ix['Module.ensureInitialized'].kind, 'function');
  assert.equal('Module.secret' in ix, false); // private members are not help topics
});

test('top-level functions and constants; interfaces contribute their members; type aliases are skipped', () => {
  const ix = buildHelpIndex(FIXTURE);
  assert.deepEqual(ix.ptr, { kind: 'function', sigs: ['ptr(value: string | number): NativePointer'], doc: 'Short-hand for `new NativePointer(value)`.' });
  assert.deepEqual(ix.pointerSize, { kind: 'property', sigs: ['pointerSize: number'], doc: 'Size of a pointer.' });
  assert.equal(ix.ModuleExportDetails.kind, 'interface');
  assert.equal(ix['ModuleExportDetails.name'].doc, 'Exported name.');
  assert.equal('Ignored' in ix, false);
});

test('the real Frida definitions produce documented entries for the everyday APIs', () => {
  const dts = fs.readFileSync(path.join(__dirname, '..', 'node_modules', '@types', 'frida-gum', 'index.d.ts'), 'utf8');
  const ix = buildHelpIndex(dts);
  for (const key of ['Process', 'Process.id', 'Process.enumerateModules', 'Memory.scan', 'Interceptor.attach', 'NativePointer', 'NativePointer.readByteArray', 'ptr', 'hexdump', 'Module.enumerateExports']) {
    assert.ok(ix[key], 'missing ' + key);
    assert.ok(ix[key].sigs.length > 0 || ix[key].kind === 'namespace' || ix[key].kind === 'class', key + ' has no signature');
  }
  assert.match(ix['Process.enumerateModules'].doc, /modules/i);
  assert.match(ix['Interceptor.attach'].sigs[0], /^attach\(/);
  assert.ok(Object.keys(ix).length > 500, 'only ' + Object.keys(ix).length + ' entries');
  assert.doesNotThrow(() => JSON.stringify(ix));
});
