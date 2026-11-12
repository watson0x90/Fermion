// Modules to control application life and create native browser window
const {app, BrowserWindow, ipcMain, dialog, shell} = require('electron');
const path = require('path');
const fs = require('fs');
const { FridaService } = require('./src/frida-service.js');
const { createDispatch, wireServiceEvents } = require('./src/frida-ipc.js');
const { buildWindowOptions } = require('./src/windows.js');
const { isAllowedPage, isSafeExternalUrl } = require('./src/ipc-guards.js');
const { createOutputWindowManager } = require('./src/output-window.js');
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

// -= Host services the isolated renderer needs over IPC =-

// Package versions (the renderer can't resolve node modules once isolated).
function packageVersion(moduleName) {
  let dir = path.dirname(require.resolve(moduleName));
  while (!fs.existsSync(path.join(dir, 'package.json'))) {
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error('package.json not found for ' + moduleName);
    dir = parent;
  }
  return require(path.join(dir, 'package.json')).version;
}
ipcMain.handle('fermion:versions', () => ({
  fermion: require('./package.json').version,
  frida: packageVersion('frida'),
}));

// Window controls (were @electron/remote.getCurrentWindow()).
ipcMain.handle('fermion:closeWindow', (e) => {
  const w = BrowserWindow.fromWebContents(e.sender);
  if (w) w.close();
});
ipcMain.handle('fermion:openDevTools', (e) => e.sender.openDevTools({ mode: 'detach' }));

// Open an http(s) link in the user's browser (validated; was renderer shell).
ipcMain.handle('fermion:openExternal', (_e, url) => {
  if (isSafeExternalUrl(url)) return shell.openExternal(url);
});

// File dialogs + I/O. Main owns the "current file" so the renderer never gets an
// arbitrary write-anywhere primitive: the overwrite path (saveCurrent) can only
// write the path a dialog previously returned to this app.
let currentFilePath = null;
ipcMain.handle('fermion:openFile', async () => {
  const r = await dialog.showOpenDialog({ properties: ['openFile'], title: 'Fermion Open File' });
  if (!r.filePaths || r.filePaths.length === 0) return null;
  currentFilePath = r.filePaths[0];
  const content = await fs.promises.readFile(currentFilePath, 'utf-8');
  return { path: currentFilePath, content };
});
ipcMain.handle('fermion:saveFile', async (_e, content, opts) => {
  const r = await dialog.showSaveDialog(opts || { title: 'Fermion Save File' });
  if (!r.filePath) return null;
  await fs.promises.writeFile(r.filePath, content);
  currentFilePath = r.filePath;
  return r.filePath;
});
ipcMain.handle('fermion:saveCurrent', async (_e, content) => {
  if (!currentFilePath) return null;
  await fs.promises.writeFile(currentFilePath, content);
  return currentFilePath;
});
ipcMain.handle('fermion:messageBox', async (_e, options) => dialog.showMessageBox(options));

// A remote origin must never inherit the bridge-privileged webPreferences, so
// block navigation away from local files and deny popups.
function hardenWindow(win) {
  win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('file://')) e.preventDefault(); });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
}

// Child-window creation (was remote.BrowserWindow + loadFile in the renderer).
ipcMain.handle('fermion:openWindow', (_e, page, dims) => {
  if (!isAllowedPage(page)) return null;  // no path traversal / arbitrary files
  const opts = buildWindowOptions(dims || {});
  opts.webPreferences.preload = path.join(__dirname, 'src', 'preload.js');
  const win = new BrowserWindow(opts);
  hardenWindow(win);
  win.loadFile(path.join(__dirname, 'pages', page));
  win.once('ready-to-show', () => setTimeout(() => { win.show(); win.focus(); }, 50));
  return win.id;
});

// Child windows relay their selections to the main window via these channels;
// the preload re-exposes them to the isolated renderer.
for (const ch of ['new-device', 'attach-process', 'attach-process-shim', 'start-process-shim']) {
  ipcMain.on(ch, (_e, message) => { if (bWin && !bWin.isDestroyed()) bWin.webContents.send(ch, message); });
}
app.commandLine.appendSwitch('disable-features', 'CrossOriginOpenerPolicy');

// Trace graph rendering runs in the main process (node-graphviz is a Node
// module the isolated renderer/trace window can't require); DOT -> SVG string.
const { graphviz } = require('node-graphviz');
ipcMain.handle('fermion:renderGraph', (_event, dot) => graphviz.dot(dot, 'svg'));

// Custom-title-bar window controls for the frameless window. Additive only:
// acts on the sender's own window; no change to the security model.
ipcMain.handle('fermion:win', (event, action, arg) => {
  const win = BrowserWindow.fromWebContents(event.sender);
  if (!win) return false;
  switch (action) {
    case 'minimize': win.minimize(); return true;
    case 'toggleMaximize': win.isMaximized() ? win.unmaximize() : win.maximize(); return win.isMaximized();
    case 'close': win.close(); return true;
    case 'isMaximized': return win.isMaximized();
    // Match the native window background to the active theme so areas exposed
    // during a live resize paint the theme color, not white.
    case 'setBackground': if (typeof arg === 'string' && /^#[0-9a-fA-F]{3,8}$/.test(arg)) win.setBackgroundColor(arg); return true;
    default: return false;
  }
});

// Detached Output window. Same secured webPreferences + preload as the main
// window; it loads one fixed page and only exchanges allow-listed relay
// messages with the main window (see src/output-window.js).
const outputWindows = createOutputWindowManager({
  BrowserWindow,
  getMainWindow: () => bWin,
  preload: path.join(__dirname, 'src', 'preload.js'),
  page: path.join(__dirname, 'pages', 'output.html'),
  harden: hardenWindow,
});
ipcMain.handle('fermion:output', (event, action) => {
  if (action === 'detach') return outputWindows.open(event.sender);
  if (action === 'dock') return outputWindows.close(event.sender);
  return false;
});
ipcMain.on('fermion:output-relay', (event, msg) => { outputWindows.relay(event.sender, msg); });

function createWindow() {
  // Create the browser window.
  bWin = new BrowserWindow({
    width: 1280,
    minWidth: 860,
    height: 860,
    minHeight: 600,
    frame: false,
    show: false,
    transparent: false,
    // Default to the Kuroir chrome; the renderer updates this per theme so a
    // live resize never flashes white in the exposed area.
    backgroundColor: '#e8e9e8',
    webPreferences: {
      // Secured renderer: no Node, isolated world. All host access is through
      // the preload bridge (window.fermion). sandbox:false lets the preload
      // require its local api module.
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
      preload: path.join(__dirname, 'src', 'preload.js')
    }
  });

  hardenWindow(bWin);

  // Notify the custom title bar when the maximize state changes (so its
  // maximize/restore glyph can follow).
  for (const ev of ['maximize', 'unmaximize']) {
    bWin.on(ev, () => { if (bWin && !bWin.isDestroyed()) bWin.webContents.send('fermion:win-state', bWin.isMaximized()); });
  }

  // The detached Output window must not outlive the main window.
  bWin.on('closed', () => outputWindows.closeAll());

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

// (Child-window relay listeners are registered near the top, next to the other
// IPC handlers.)