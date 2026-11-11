// Ambient declarations for Fermion's page globals, so the `// @ts-check`
// modules can reference them. These are provided at runtime by vendored
// scripts (Monaco AMD loader, split, the monaco-theme.js theme objects) and the
// renderer bootstrap — not by typed packages — so they are declared `any`.

declare const monaco: any;
declare const Split: any;

// Monaco theme objects published by src/lang/monaco-theme.js.
declare const Kuroir: any, idleFingers: any, Cobalt: any, Amy: any, MerbivoreSoft: any,
  VibrantInk: any, Katzenmilch: any, Monokai: any, SolarizedDark: any, SolarizedLight: any,
  BirdsOfParadise: any, Clouds: any, OceanicNext: any, NightOwl: any, Textmate: any,
  TomorrowNightBlue: any;

// Shared cross-module handles that live on window.
declare var FERMION_VER: string;
declare var FRIDA_VER: string;

interface Window {
  monaco?: any;
  FermionThemes?: Record<string, any>;
  MonacoCodeEditor?: any;
  FERMION_VER?: string;
  FRIDA_VER?: string;
  setMonacoTheme?: () => void;
  __fermion?: any;
  split?: any;
  module?: any;
  $?: any;
  jQuery?: any;
}
