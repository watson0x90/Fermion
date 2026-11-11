// @ts-check
// Preload: exposes the frida bridge as `window.fermion` to the renderer.
// Under contextIsolation (the Phase 1 end state) this uses contextBridge; during
// the interim where isolation is still off, contextBridge refuses, so we fall
// back to assigning the main-world window directly.
const { contextBridge, ipcRenderer } = require('electron');
const { buildApi } = require('./preload-api.js');

// Child windows receive their context (deviceId / pid) via additionalArguments
// (FERMION_ARG=<base64>); decode them here (was helper.js getExtraArgs, which
// read window.process — unavailable in an isolated renderer).
function readLaunchArgs() {
  const PREFIX = 'FERMION_ARG=';
  const out = [];
  for (let i = process.argv.length - 1; i >= 0; i--) {
    const a = process.argv[i];
    if (a.startsWith(PREFIX)) out.push(Buffer.from(a.slice(PREFIX.length), 'base64').toString('utf8'));
  }
  return out;
}

const api = buildApi(ipcRenderer);
api.launchArgs = readLaunchArgs();

try {
  contextBridge.exposeInMainWorld('fermion', api);
} catch {
  // contextIsolation disabled (interim) — contextBridge throws; expose directly.
  if (typeof window !== 'undefined') {
    window.fermion = api;
  }
}
