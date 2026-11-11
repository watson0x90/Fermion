// Bundles the renderer so it has no implicit cross-module require() dependency.
// Phase 1 keeps nodeIntegration on, so electron/frida/node builtins and the
// Monaco AMD loader stay as runtime externals (require() still works); the
// require-free end state arrives when the security flip lands (later tasks).
import * as esbuild from 'esbuild';

const externals = [
  'electron',
  '@electron/remote',
  'frida',
  'node-graphviz',
  'bindings',
  // node builtins used by code that moves to main later
  'fs', 'path', 'events', 'os', 'child_process',
  // Monaco's AMD loader is loaded at runtime (require under nodeIntegration);
  // it is not part of our bundle.
  '../node_modules/monaco-editor/min/vs/loader.js',
];

const ctx = {
  entryPoints: ['src/renderer.js'],
  bundle: true,
  outfile: 'src/renderer.bundle.js',
  format: 'iife',
  platform: 'node',        // Phase 1: nodeIntegration still on
  target: 'chrome128',
  external: externals,
  logLevel: 'info',
  sourcemap: 'inline',
  // jquery/xterm resolve from node_modules and get bundled in.
};

const watch = process.argv.includes('--watch');
if (watch) {
  const c = await esbuild.context(ctx);
  await c.watch();
  console.log('esbuild: watching…');
} else {
  await esbuild.build(ctx);
  console.log('esbuild: built src/renderer.bundle.js');
}
