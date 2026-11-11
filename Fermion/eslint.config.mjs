// Flat ESLint config for Fermion. Three surfaces:
//  - renderer-side CommonJS modules + Playwright/node test scripts (browser+node),
//  - ESM build/config files (*.mjs),
//  - the React app (TS/TSX) under src/ui, linted with typescript-eslint.
// Baseline goal: zero errors; stylistic rules stay advisory (warn).
import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

// Monaco theme objects are declared as file-level globals in
// src/lang/monaco-theme.js and read on the renderer side.
const monacoThemes = {
  Kuroir: 'readonly', idleFingers: 'readonly', Cobalt: 'readonly', Amy: 'readonly',
  MerbivoreSoft: 'readonly', VibrantInk: 'readonly', Katzenmilch: 'readonly',
  Monokai: 'readonly', SolarizedDark: 'readonly', SolarizedLight: 'readonly',
  BirdsOfParadise: 'readonly', Clouds: 'readonly', OceanicNext: 'readonly',
  NightOwl: 'readonly', Textmate: 'readonly', TomorrowNightBlue: 'readonly',
};

const projectGlobals = {
  // jQuery, Monaco, and the shared cross-module handles live on window.
  $: 'writable', jQuery: 'writable', monaco: 'readonly',
  MonacoCodeEditor: 'writable', FERMION_VER: 'writable', FRIDA_VER: 'writable',
  ...monacoThemes,
};

const advisory = {
  'no-unused-vars': 'warn',
  'no-undef': 'warn',
  'no-redeclare': 'warn',
  'no-empty': 'warn',
  'no-cond-assign': 'warn',
  'no-prototype-builtins': 'warn',
  'no-useless-escape': 'warn',
  'no-control-regex': 'warn',
};

export default tseslint.config(
  {
    ignores: [
      'node_modules/**',
      'src/renderer.bundle.js',
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
  {
    // Build tooling / ESM config files (esbuild.config.mjs).
    files: ['**/*.mjs'],
    extends: [js.configs.recommended],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.node },
    },
  },
  {
    // Renderer-side CommonJS modules, main process, and test scripts.
    files: ['src/**/*.js', 'scripts/**/*.js', 'core.js', '*.js'],
    extends: [js.configs.recommended],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: {
        ...globals.browser,
        ...globals.node,
        ...projectGlobals,
      },
    },
    rules: advisory,
  },
  {
    // The React app (TS/TSX): typescript-eslint, non-type-aware (fast) baseline.
    files: ['src/ui/**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: { ...globals.browser },
    },
    rules: {
      ...advisory,
      // TS checks these; the core versions misfire on type syntax.
      'no-undef': 'off',
      'no-redeclare': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': 'warn',
    },
  },
);
