// Bundles the React renderer (src/ui/main.tsx) to src/renderer.bundle.js, loaded
// by pages/index.html. The renderer is context-isolated (no node); Monaco loads
// via the global AMD loader (<script> in index.html), not bundled.
import * as esbuild from 'esbuild';

const config = {
  entryPoints: ['src/ui/main.tsx'],
  bundle: true,
  outfile: 'src/renderer.bundle.js',
  format: 'iife',
  platform: 'browser',
  target: 'chrome128',
  jsx: 'automatic',
  external: ['../node_modules/monaco-editor/min/vs/loader.js'],
  logLevel: 'info',
  sourcemap: 'inline',
};

const watch = process.argv.includes('--watch');
if (watch) {
  const c = await esbuild.context(config);
  await c.watch();
  console.log('esbuild: watching…');
} else {
  await esbuild.build(config);
  console.log('esbuild: built src/renderer.bundle.js (React)');
}
