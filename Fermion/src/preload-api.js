// @ts-check
// Pure factory for the renderer-facing bridge api. preload.js wraps the real
// ipcRenderer with this and exposes it as `window.fermion`. Kept pure so it is
// unit-testable without Electron.
//
// Methods return promises (ipcRenderer.invoke → main-process frida-service).
// Events (message/log/detached) are demultiplexed from the single
// 'fermion:event' channel; each subscribe returns an unsubscribe fn.

function buildApi(ipcRenderer) {
	const invoke = (method, ...args) => ipcRenderer.invoke('fermion:invoke', method, ...args);

	const listeners = { message: new Set(), log: new Set(), detached: new Set() };
	let wired = false;
	function ensureWired() {
		if (wired) return;
		wired = true;
		ipcRenderer.on('fermion:event', (_event, kind, ...payload) => {
			const set = listeners[kind];
			if (set) for (const cb of set) cb(...payload);
		});
	}
	function on(kind, cb) {
		ensureWired();
		listeners[kind].add(cb);
		return () => listeners[kind].delete(cb);
	}

	// Subscribe to a plain relay channel (child windows -> main -> renderer).
	function onChannel(channel, cb) {
		const listener = (_event, msg) => cb(msg);
		ipcRenderer.on(channel, listener);
		return () => ipcRenderer.removeListener(channel, listener);
	}

	return {
		invoke,
		// Host services the isolated renderer needs over IPC.
		versions: () => ipcRenderer.invoke('fermion:versions'),
		closeWindow: () => ipcRenderer.invoke('fermion:closeWindow'),
		openDevTools: () => ipcRenderer.invoke('fermion:openDevTools'),
		openFile: () => ipcRenderer.invoke('fermion:openFile'),
		saveFile: (content, opts) => ipcRenderer.invoke('fermion:saveFile', content, opts),
		saveCurrentFile: (content) => ipcRenderer.invoke('fermion:saveCurrent', content),
		// Save something that is not the script (Output log, graph): it does not
		// become the file Ctrl-S writes to.
		exportFile: (content, opts) => ipcRenderer.invoke('fermion:saveFile', content, opts, 'export'),
		// Recent scripts (the list is kept by the main process).
		recentFiles: () => ipcRenderer.invoke('fermion:recentFiles'),
		openRecent: (filePath) => ipcRenderer.invoke('fermion:openRecent', filePath),
		messageBox: (options) => ipcRenderer.invoke('fermion:messageBox', options),
		openExternal: (url) => ipcRenderer.invoke('fermion:openExternal', url),
		openWindow: (page, dims) => ipcRenderer.invoke('fermion:openWindow', page, dims),
		renderGraph: (dot) => ipcRenderer.invoke('fermion:renderGraph', dot),
		// Custom-title-bar window controls (frameless main window).
		win: {
			minimize: () => ipcRenderer.invoke('fermion:win', 'minimize'),
			toggleMaximize: () => ipcRenderer.invoke('fermion:win', 'toggleMaximize'),
			close: () => ipcRenderer.invoke('fermion:win', 'close'),
			isMaximized: () => ipcRenderer.invoke('fermion:win', 'isMaximized'),
			setBackground: (color) => ipcRenderer.invoke('fermion:win', 'setBackground', color),
		},
		onMaximizeChange: (cb) => onChannel('fermion:win-state', cb),
		// Detached Output window: open/close it, and the relay that carries output
		// lines to it and its toolbar changes back to the main window.
		output: {
			detach: () => ipcRenderer.invoke('fermion:output', 'detach'),
			dock: () => ipcRenderer.invoke('fermion:output', 'dock'),
			send: (msg) => ipcRenderer.send('fermion:output-relay', msg),
			onRelay: (cb) => onChannel('fermion:output-relay', cb),
			onState: (cb) => onChannel('fermion:output-state', cb),
		},
		// Child windows -> main -> main window (relays).
		sendNewDevice: (msg) => ipcRenderer.send('new-device', msg),
		sendAttachProcess: (msg) => ipcRenderer.send('attach-process', msg),
		sendAttachProcessShim: (msg) => ipcRenderer.send('attach-process-shim', msg),
		sendStartProcessShim: (msg) => ipcRenderer.send('start-process-shim', msg),
		// Relay events from child windows.
		onNewDevice: (cb) => onChannel('new-device', cb),
		onAttachProcess: (cb) => onChannel('attach-process', cb),
		onAttachProcessShim: (cb) => onChannel('attach-process-shim', cb),
		onStartProcessShim: (cb) => onChannel('start-process-shim', cb),
		setDevice: (spec) => invoke('setDevice', spec),
		enumerateDevices: () => invoke('enumerateDevices'),
		enumerateProcesses: () => invoke('enumerateProcesses'),
		getDeviceInfo: () => invoke('getDeviceInfo'),
		attach: (pid) => invoke('attach', pid),
		spawn: (path, args) => invoke('spawn', path, args),
		resume: (pid) => invoke('resume', pid),
		loadScript: (src) => invoke('loadScript', src),
		reloadScript: (src) => invoke('reloadScript', src),
		detach: () => invoke('detach'),
		unload: () => invoke('unload'),
		getState: () => invoke('getState'),
		// REPL: evaluate one entry in the attached process.
		evaluate: (code) => invoke('evaluate', code),
		cancelEvaluate: () => invoke('cancelEvaluate'),
		// Inspector: read-only views of the attached process.
		inspect: {
			modules: () => invoke('inspectModules'),
			exports: (moduleName) => invoke('inspectExports', moduleName),
			imports: (moduleName) => invoke('inspectImports', moduleName),
			threads: () => invoke('inspectThreads'),
			backtrace: (threadId) => invoke('inspectBacktrace', threadId),
			ranges: (protection) => invoke('inspectRanges', protection),
			read: (address, size) => invoke('inspectRead', address, size),
			scan: (pattern, protection) => invoke('inspectScan', pattern, protection),
			follow: (threadId, scope) => invoke('inspectFollow', threadId, scope),
			unfollow: () => invoke('inspectUnfollow'),
		},
		onMessage: (cb) => on('message', cb),
		onLog: (cb) => on('log', cb),
		onDetached: (cb) => on('detached', cb),
	};
}

module.exports = { buildApi };
