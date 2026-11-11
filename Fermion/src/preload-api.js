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
		saveFileTo: (filePath, content) => ipcRenderer.invoke('fermion:saveFileTo', filePath, content),
		messageBox: (options) => ipcRenderer.invoke('fermion:messageBox', options),
		openWindow: (page, dims) => ipcRenderer.invoke('fermion:openWindow', page, dims),
		renderGraph: (dot) => ipcRenderer.invoke('fermion:renderGraph', dot),
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
		onMessage: (cb) => on('message', cb),
		onLog: (cb) => on('log', cb),
		onDetached: (cb) => on('detached', cb),
	};
}

module.exports = { buildApi };
