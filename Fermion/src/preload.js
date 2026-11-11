// Preload: exposes the frida bridge as `window.fermion` to the renderer.
// Under contextIsolation (the Phase 1 end state) this uses contextBridge; during
// the interim where isolation is still off, contextBridge refuses, so we fall
// back to assigning the main-world window directly.
const { contextBridge, ipcRenderer } = require('electron');
const { buildApi } = require('./preload-api.js');

const api = buildApi(ipcRenderer);

try {
  contextBridge.exposeInMainWorld('fermion', api);
} catch {
  // contextIsolation disabled (interim) — contextBridge throws; expose directly.
  if (typeof window !== 'undefined') {
    window.fermion = api;
  }
}
