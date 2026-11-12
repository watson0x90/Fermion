// @ts-check
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
const fs = require('fs');
const path = require('path');

// The REPL helper agent (runs inside the target; see the file's header).
const REPL_AGENT_PATH = path.join(__dirname, 'tools', 'repl-agent.js');
const MAX_EVAL_CHARS = 200000;

// Pure: where does a formatted message go? SEND payloads are forwarded to the
// trace window only while trace mode is on; everything else goes to the
// terminal. Exported so the trace-routing decision is unit-tested.
function routeMessage(kind, traceMode) {
	return (traceMode && kind === 'SEND') ? 'trace' : 'terminal';
}

// Frida model objects (Process, Device, parameters) are not own-enumerable, so
// they structured-clone to {} over IPC. Convert to a plain, JSON-safe object
// (drops binary like a process icon) before returning across the seam.
// BigInt (Frida 17 reports e.g. a process's ppid as one) is not JSON-serializable:
// it becomes a number when that is exact, otherwise a decimal string.
function toPlain(value) {
	try {
		return JSON.parse(JSON.stringify(value, (_k, v) => {
			if (typeof v !== 'bigint') return v;
			return (v <= BigInt(Number.MAX_SAFE_INTEGER) && v >= BigInt(Number.MIN_SAFE_INTEGER)) ? Number(v) : v.toString();
		}));
	} catch {
		return {};
	}
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
		// REPL agent: its own script in the session, separate from the user's.
		this._replScript = null;
		this._replLoading = null;
		this._replSession = null;
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

	// Plain snapshot of the getters, for the renderer over IPC.
	getState() {
		return {
			deviceId: this._deviceId,
			isAttached: this.isAttached,
			hasScript: this.hasScript,
			currentPid: this._sessionPID,
		};
	}

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

	async enumerateDevices() {
		const frida = this._getFrida();
		const devices = await frida.enumerateDevices();
		return devices.map((d) => ({ id: d.id, name: d.name, type: d.type }));
	}

	async enumerateProcesses() {
		const frida = this._getFrida();
		const device = await frida.getDevice(this._deviceId);
		// 'metadata' = user/ppid/path/argv/started without the icons ('full' adds
		// them; they are large, not cloneable, and never shown).
		const procs = await device.enumerateProcesses(/** @type {any} */ ({ scope: 'metadata' }));
		// Return IPC-serializable plain objects for the process view/tree.
		return procs.map((p) => {
			const params = Object.assign({}, p.parameters);
			delete params.icons;
			return { pid: p.pid, name: p.name, parameters: toPlain(params) };
		});
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
			params = toPlain(await dev.querySystemParameters());
		} catch (e) {
			// IPC-serializable: a string, not an Error object.
			paramsError = (e && e.message) ? e.message : String(e);
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

	// REPL: evaluate one entry in the attached process and return a printable
	// result ({ ok, type, text } or { ok:false, error, stack }). The code runs in
	// a dedicated agent script, so it works with or without a user script and is
	// untouched by script reloads; its console/send output joins the normal
	// message/log events.
	async evaluate(code) {
		if (typeof code !== 'string') throw new Error('evaluate: code must be a string');
		if (!code.trim()) throw new Error('evaluate: code is empty');
		if (code.length > MAX_EVAL_CHARS) throw new Error('evaluate: code is too long');
		if (!this._session) throw new Error('Not attached to a process');
		const script = await this._getReplScript();
		try {
			const result = toPlain(await script.exports.evaluate(code));
			if (result && typeof result.ok === 'boolean') return result;
			return { ok: false, error: 'The REPL agent returned no result', stack: '' };
		} catch (e) {
			// e.g. the target exited mid-call and the script was destroyed.
			return { ok: false, error: e && e.message ? e.message : String(e), stack: '' };
		}
	}

	// One agent per session; concurrent first calls share the same load.
	_getReplScript() {
		const session = this._session;
		if (this._replSession !== session) {
			this._replSession = session;
			this._replScript = null;
			this._replLoading = null;
		}
		if (this._replScript) return Promise.resolve(this._replScript);
		if (!this._replLoading) {
			const loading = (async () => {
				const script = await session.createScript(fs.readFileSync(REPL_AGENT_PATH, 'utf8'));
				this._wireScript(script);
				await script.load();
				if (this._replSession === session) this._replScript = script;
				return script;
			})();
			this._replLoading = loading;
			// A failed load must not be cached: the next entry retries.
			loading.catch(() => { if (this._replLoading === loading) this._replLoading = null; });
		}
		return this._replLoading;
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

module.exports = { FridaService, routeMessage, parseDeviceSpec, toPlain };
