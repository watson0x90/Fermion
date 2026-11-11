// The Frida seam: all frida-node interaction lives behind this EventEmitter.
// The UI calls its async methods and subscribes to its events; it never touches
// the DOM, the terminal, the trace window, or status text. This method+event
// surface is the future main<->renderer IPC contract (Tier 3) — keeping the UI
// talking to Frida only through here is the whole point of the split.
//
// Events:
//   'message' (message)        - a script.message record (send(), runtime error)
//   'log'     (level, text)    - a console.log/warn/error record (Frida routes
//                                these to Script.logHandler, NOT `message`)
//   'detached'(reason)         - the active session detached
//
// `frida` is required lazily (inside _getFrida) so the pure helpers below are
// requirable headless (unit tests) without an Electron/Frida runtime.
const { EventEmitter } = require('events');

// Pure: where does a formatted message go? SEND payloads are forwarded to the
// trace window only while trace mode is on; everything else goes to the
// terminal. Exported so the trace-routing decision is unit-tested.
function routeMessage(kind, traceMode) {
	return (traceMode && kind === 'SEND') ? 'trace' : 'terminal';
}

// Pure: classify a device spec. 'socket@HOST' selects a remote device named by
// HOST; anything else is a plain device id.
function parseDeviceSpec(spec) {
	if (typeof spec === 'string' && spec.startsWith('socket@')) {
		return { kind: 'socket', value: spec.split('@')[1] };
	}
	return { kind: 'id', value: spec };
}

class FridaService extends EventEmitter {
	constructor() {
		super();
		this._frida = null;
		this._deviceId = 'local';
		this._session = null;
		this._script = null;
		this._sessionPID = null;
		this._spawnDevice = null;
		// Unload the active script on process termination (the old inject/start
		// registered these per call; once is equivalent and avoids leaking a
		// listener per attach).
		const onSignal = () => { try { if (this._script) this._script.unload(); } catch { /* ignore */ } };
		process.on('SIGTERM', onSignal);
		process.on('SIGINT', onSignal);
	}

	_getFrida() {
		if (!this._frida) this._frida = require('frida');
		return this._frida;
	}

	get deviceId() { return this._deviceId; }
	get isAttached() { return this._session != null; }
	get hasScript() { return this._script != null; }
	get currentPid() { return this._sessionPID; }

	// Select a device, registering/unregistering remote socket devices as the
	// old `new-device` handler did. Returns the effective device id.
	async setDevice(spec) {
		const frida = this._getFrida();
		// Unregister a current remote socket if we are leaving one.
		if (this._deviceId.startsWith('socket@')) {
			const dm = await frida.getDeviceManager();
			dm.removeRemoteDevice(this._deviceId.split('@')[1]);
		}
		const parsed = parseDeviceSpec(spec);
		if (parsed.kind === 'socket') {
			const dm = await frida.getDeviceManager();
			const dev = await dm.addRemoteDevice(parsed.value);
			this._deviceId = dev.id;
		} else {
			this._deviceId = parsed.value;
		}
		return this._deviceId;
	}

	async enumerateProcesses() {
		const frida = this._getFrida();
		const device = await frida.getDevice(this._deviceId);
		return device.enumerateProcesses();
	}

	// Device name + system parameters for the "Device Info" readout. Returns a
	// structured result so the UI can reproduce the two distinct error messages
	// (acquire failure rejects; params failure is reported via paramsError).
	async getDeviceInfo() {
		const frida = this._getFrida();
		const dev = await frida.getDevice(this._deviceId);
		let params = null;
		let paramsError = null;
		try {
			params = await dev.querySystemParameters();
		} catch (e) {
			paramsError = e;
		}
		return { name: dev.name, params, paramsError };
	}

	async attach(pidOrName) {
		const frida = this._getFrida();
		const device = await frida.getDevice(this._deviceId);
		this._session = await device.attach(pidOrName);
		this._sessionPID = this._session.pid.toString();
		this._session.detached.connect((reason) => {
			this._session = null;
			this.emit('detached', reason);
		});
	}

	// Spawn (arg-splitting identical to the old start()) + attach. Returns the
	// spawned pid; call resume(pid) after the script is loaded.
	async spawn(path, args) {
		const frida = this._getFrida();
		const device = await frida.getDevice(this._deviceId);
		let procID;
		if (!args || 0 === args.length) {
			procID = await device.spawn(path);
		} else {
			const aBuildArgs = args.split(" ");
			aBuildArgs.unshift(path);
			procID = await device.spawn(aBuildArgs);
		}
		this._session = await device.attach(procID);
		this._sessionPID = this._session.pid.toString();
		this._session.detached.connect((reason) => {
			this._session = null;
			this.emit('detached', reason);
		});
		this._spawnDevice = device;
		return { pid: procID };
	}

	async resume(pid) {
		const device = this._spawnDevice || await this._getFrida().getDevice(this._deviceId);
		return device.resume(pid);
	}

	async loadScript(src) {
		this._script = await this._session.createScript(src);
		this._wireScript(this._script);
		await this._script.load();
	}

	async reloadScript(src) {
		if (this._script) {
			this._script.unload();
		}
		await this.loadScript(src);
	}

	async detach() {
		if (this._session) {
			this._session.detach();
			this._session = null;
		}
	}

	// Frida delivers console.log/warn/error to logHandler (it does NOT emit
	// `message` for log records), so surface both as distinct events.
	_wireScript(script) {
		script.message.connect((message) => this.emit('message', message));
		script.logHandler = (level, text) => this.emit('log', level, text);
	}
}

module.exports = { FridaService, routeMessage, parseDeviceSpec };
