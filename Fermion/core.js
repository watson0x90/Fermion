// Modules to control application life and create native browser window
const {app, BrowserWindow} = require('electron');
const path = require('path');
const ipcMain = require('electron').ipcMain;
const { FridaService } = require('./src/frida-service.js');
const { createDispatch, wireServiceEvents } = require('./src/frida-ipc.js');
var bWin;

// All frida-node interaction runs here in the main process. The renderer drives
// it over the 'fermion:invoke' channel (guarded method dispatch) and receives
// message/log/detached events over 'fermion:event'.
const fridaService = new FridaService();
const fridaDispatch = createDispatch(fridaService);
ipcMain.handle('fermion:invoke', (_event, method, ...args) => fridaDispatch(method, ...args));
wireServiceEvents(fridaService, (kind, ...payload) => {
  if (bWin && !bWin.isDestroyed()) bWin.webContents.send('fermion:event', kind, ...payload);
});
app.commandLine.appendSwitch('disable-features', 'CrossOriginOpenerPolicy');
const remoteMain = require('@electron/remote/main');
remoteMain.initialize();
// Enable @electron/remote for every window created in the main process,
// including child windows the renderer opens (e.g. the Trace window). Doing it
// in the main process avoids the renderer calling
// remote.require('@electron/remote/main'), which no longer resolves under
// modern Electron (the remote server's module lookup fails).
app.on('browser-window-created', (_event, win) => {
  remoteMain.enable(win.webContents);
});

function createWindow() {
  // Create the browser window.
  bWin = new BrowserWindow({
    contextIsolation: false,
    width: 1024,
    minWidth: 1024,
    maxWidth: 3000,
    height: 930,
    minHeight: 930,
    frame: false,
    show: false,
    transparent: false,
    webPreferences: {
      nodeIntegration: true,
      nodeIntegrationInWorker: true,
      enableRemoteModule: true,
      contextIsolation: false,
      webviewTag: true,
      // The bridge exposes window.fermion. Additive here (isolation still off);
      // the security flip (contextIsolation:true, nodeIntegration:false) lands
      // in a later task.
      preload: path.join(__dirname, 'src', 'preload.js')
    }
  });
  
  // (remote is enabled for every window by the browser-window-created handler above)

  // and load the index.html of the app.
  bWin.loadFile(path.join(__dirname, '/pages/index.html'));

  // show the window only when the web page has been rendered
  bWin.once('ready-to-show', () => {
    // We still need a minor delay
    setTimeout(function () {
      bWin.show();
      bWin.focus();
    }, 500);
  });
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.whenReady().then(() => {
  createWindow()

  app.on('activate', function () {
    // On macOS it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit()
})

// IPC listeners
ipcMain.on('new-device', (event, message) => bWin.webContents.send('new-device', message));
ipcMain.on('attach-process', (event, message) => bWin.webContents.send('attach-process', message));
ipcMain.on('attach-process-shim', (event, message) => bWin.webContents.send('attach-process-shim', message));
ipcMain.on('start-process-shim', (event, message) => bWin.webContents.send('start-process-shim', message));
ipcMain.on('trace-data-recv', (event, message) => bWin.webContents.send('trace-data-recv', message));