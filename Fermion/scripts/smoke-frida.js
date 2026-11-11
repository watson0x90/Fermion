// Automated Frida-load smoke test (Task 3).
//
// Loads Frida the SAME way the app does: via `require('frida')` inside a
// renderer with nodeIntegration (the webPreferences from core.js). Frida 17
// is ESM-only, but Electron 45 embeds Node 24, whose require(esm) support
// loads Frida's synchronous ESM graph directly. (Dynamic import() does NOT
// work in a renderer: Chromium's module loader cannot resolve Frida's bare
// specifiers — proved during Task 3 — so require is the correct mechanism.)
//
//   Usage:  electron ./scripts/smoke-frida.js
//   Exit 0 + "SMOKE_OK ..."   -> Frida required and a core call succeeded
//   Exit 1 + "SMOKE_FAIL ..." -> Frida failed to load (regression)
//
// A zero-length device list is NOT a failure: reaching the Frida core at all
// proves the native binding loaded. Device availability is environmental.

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

app.whenReady().then(() => {
  const win = new BrowserWindow({
    show: false,
    webPreferences: {
      nodeIntegration: true,
      nodeIntegrationInWorker: true,
      contextIsolation: false
    }
  });

  ipcMain.on('smoke-result', (_event, r) => {
    if (r.ok) {
      console.log('SMOKE_OK frida-required electron=' + process.versions.electron +
        ' node=' + process.versions.node + ' devices=' + r.devices);
    } else {
      console.log('SMOKE_FAIL ' + r.message);
    }
    app.exit(r.ok ? 0 : 1);
  });

  win.loadFile(path.join(__dirname, 'smoke-frida.html'));
});

// Safety net: never hang CI.
setTimeout(() => { console.log('SMOKE_FAIL timeout'); app.exit(1); }, 30000);
