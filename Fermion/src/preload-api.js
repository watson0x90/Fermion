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

	return {
		invoke,
		setDevice: (spec) => invoke('setDevice', spec),
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
