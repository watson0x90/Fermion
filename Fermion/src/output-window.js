// @ts-check
// Detached Output window (main process). The Output pane can be popped out of
// the main window into its own window; this owns that window's lifecycle and
// the relay channel that carries output lines to it and toolbar changes back.
//
// The main renderer stays the single source of output (it formats and routes
// Frida messages); the output window only mirrors what the main renderer sends
// it. Electron is injected so this is unit-testable without it.

// Message types each side may send. Anything else is dropped at the boundary.
const RELAY_TYPES = {
	toOutput: new Set(['snapshot', 'line', 'lines', 'clear', 'theme']),
	toMain: new Set(['ready', 'clear', 'filter', 'follow']),
};

function isRelayMessage(msg, direction) {
	const allowed = RELAY_TYPES[direction];
	if (!allowed) return false;
	if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return false;
	return typeof msg.t === 'string' && allowed.has(msg.t);
}

// Same secured webPreferences as every other Fermion window (no Node, isolated
// world, shared preload bridge). Unlike the fixed-size child dialogs this one is
// resizable — the point is to park it on a second monitor.
function buildOutputWindowOptions(preload) {
	return {
		width: 900,
		height: 620,
		minWidth: 420,
		minHeight: 240,
		frame: false,
		show: false,
		backgroundColor: '#e8e9e8',
		webPreferences: {
			nodeIntegration: false,
			contextIsolation: true,
			sandbox: false,
			preload,
		},
	};
}

function createOutputWindowManager({ BrowserWindow, getMainWindow, preload, page, harden }) {
	let win = null;

	const alive = (w) => !!w && !w.isDestroyed();
	const mainWindow = () => { const m = getMainWindow(); return alive(m) ? m : null; };
	const isMain = (sender) => { const m = mainWindow(); return !!m && sender === m.webContents; };
	const isOutput = (sender) => alive(win) && sender === win.webContents;
	const tellMain = (channel, payload) => { const m = mainWindow(); if (m) m.webContents.send(channel, payload); };

	return {
		isOpen() { return alive(win); },

		// Detach: only the main window may ask. Re-detaching focuses the window.
		open(sender) {
			if (!isMain(sender)) return false;
			if (alive(win)) {
				if (win.isMinimized()) win.restore();
				win.focus();
				// Re-tell the main window: a reloaded main renderer starts out
				// believing Output is docked.
				tellMain('fermion:output-state', true);
				return true;
			}
			const w = new BrowserWindow(buildOutputWindowOptions(preload));
			win = w;
			if (harden) harden(w);
			for (const ev of ['maximize', 'unmaximize']) {
				w.on(ev, () => { if (alive(w)) w.webContents.send('fermion:win-state', w.isMaximized()); });
			}
			w.on('closed', () => {
				// A stale window closing late must not report "docked" while a
				// newer output window is open.
				if (win !== w) return;
				win = null;
				tellMain('fermion:output-state', false);
			});
			w.once('ready-to-show', () => { if (alive(w)) { w.show(); w.focus(); } });
			w.loadFile(page);
			tellMain('fermion:output-state', true);
			return true;
		},

		// Dock: either window may ask; closing the window is what docks it.
		close(sender) {
			if (!alive(win)) return false;
			if (!isMain(sender) && !isOutput(sender)) return false;
			win.close();
			return true;
		},

		// Forward a message to the other window, by who sent it.
		relay(sender, msg) {
			if (!alive(win)) return false;
			if (isMain(sender)) {
				if (!isRelayMessage(msg, 'toOutput')) return false;
				win.webContents.send('fermion:output-relay', msg);
				return true;
			}
			if (isOutput(sender)) {
				if (!isRelayMessage(msg, 'toMain')) return false;
				tellMain('fermion:output-relay', msg);
				return true;
			}
			return false;
		},

		// The output window must not outlive the main window.
		closeAll() {
			// The window's `closed` handler clears the reference and tells main.
			if (alive(win)) win.destroy();
		},
	};
}

module.exports = { createOutputWindowManager, buildOutputWindowOptions, isRelayMessage };
