// Flat ESLint config for Fermion's renderer-side CommonJS modules and the
// Playwright/node test scripts. No bundler/compile step — this is the lint
// guardrail for the Tier 1 refactor. Baseline goal: runs clean on today's
// tree (warnings allowed, zero errors). Tightening rules is out of scope.
import js from '@eslint/js';
import globals from 'globals';

// Monaco theme objects are declared as file-level globals in
// src/lang/monaco-theme.js and read by setMonacoTheme(); treat them as globals
// so no-undef does not fire on the renderer side.
const monacoThemes = {
  Kuroir: 'readonly', idleFingers: 'readonly', Cobalt: 'readonly', Amy: 'readonly',
  MerbivoreSoft: 'readonly', VibrantInk: 'readonly', Katzenmilch: 'readonly',
  Monokai: 'readonly', SolarizedDark: 'readonly', SolarizedLight: 'readonly',
  BirdsOfParadise: 'readonly', Clouds: 'readonly', OceanicNext: 'readonly',
  NightOwl: 'readonly', Textmate: 'readonly', TomorrowNightBlue: 'readonly',
};

const projectGlobals = {
  // jQuery, Monaco, Split, and the shared cross-module handles live on window.
  $: 'writable', jQuery: 'writable', monaco: 'readonly', Split: 'readonly',
  MonacoCodeEditor: 'writable', FERMION_VER: 'writable', FRIDA_VER: 'writable',
  ...monacoThemes,
};

export default [
  {
    ignores: [
      'node_modules/**',
      'src/frameworks/**',
      'src/lang/**',
      'src/images/**',
      // Frida *agent* scripts that run inside the target process (Interceptor,
      // Stalker, ptr, send, … are the in-agent runtime, typed by
      // @types/frida-gum — not host renderer code).
      'src/tools/**',
      'out/**',
      '*-darwin-*/**',
      '*-win32-*/**',
      '*-linux-*/**',
    ],
  },
  js.configs.recommended,
  {
    files: ['src/**/*.js', 'scripts/**/*.js', 'core.js', '*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: {
        ...globals.browser,
        ...globals.node,
        ...projectGlobals,
      },
    },
    rules: {
      // The current tree predates linting; keep these as advisory so the
      // baseline is error-free. The refactor can tighten later.
      'no-unused-vars': 'warn',
      'no-undef': 'warn',
      'no-redeclare': 'warn',
      'no-empty': 'warn',
      'no-cond-assign': 'warn',
      'no-prototype-builtins': 'warn',
      'no-useless-escape': 'warn',
      'no-control-regex': 'warn',
    },
  },
];
