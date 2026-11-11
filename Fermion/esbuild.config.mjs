// Two renderer bundles during the Phase 2 React migration:
//  - renderer.bundle.js  : the current vanilla renderer (live app) — stays until
//                          the Task 7 switchover.
//  - renderer.react.js   : the new React app (src/ui/main.tsx), browser platform,
//                          no node (the renderer is context-isolated). Built but
//                          not yet loaded by index.html; exercised by Vitest.
import * as esbuild from 'esbuild';

// The vanilla renderer still runs under the isolated model: node builtins /
// electron are already gone, but the Monaco AMD loader is a runtime <script>, so
// keep it external; same for the few remaining externals the old bundle marks.
const vanilla = {
  entryPoints: ['src/renderer.js'],
  bundle: true,
  outfile: 'src/renderer.bundle.js',
  format: 'iife',
  platform: 'node',
  target: 'chrome128',
  external: ['../node_modules/monaco-editor/min/vs/loader.js'],
  logLevel: 'info',
  sourcemap: 'inline',
};

const react = {
  entryPoints: ['src/ui/main.tsx'],
  bundle: true,
  outfile: 'src/renderer.react.js',
  format: 'iife',
  platform: 'browser',
  target: 'chrome128',
  jsx: 'automatic',
  // Monaco loads via the global AMD loader (<script> in index.html), not bundled.
  external: ['../node_modules/monaco-editor/min/vs/loader.js'],
  logLevel: 'info',
  sourcemap: 'inline',
};

const watch = process.argv.includes('--watch');
if (watch) {
  for (const cfg of [vanilla, react]) {
    const c = await esbuild.context(cfg);
    await c.watch();
  }
  console.log('esbuild: watching vanilla + react…');
} else {
  await Promise.all([esbuild.build(vanilla), esbuild.build(react)]);
  console.log('esbuild: built renderer.bundle.js + renderer.react.js');
}
