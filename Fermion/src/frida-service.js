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

// Fermion's own helper agents (they run inside the target; see each file's
// header). Each is its own script in the session, separate from the user's.
const AGENT_PATHS = {
	repl: path.join(__dirname, 'tools', 'repl-agent.js'),
	inspector: path.join(__dirname, 'tools', 'inspector-agent.js'),
};
const MAX_EVAL_CHARS = 200000;

// ---- Inspector argument validation (the renderer is untrusted) ----
const MAX_READ_BYTES = 4096;
function checkModuleName(name) {
	if (typeof name !== 'string') throw new Error('module name must be a string');
	if (!name) throw new Error('module name is empty');
	if (name.length > 1024) throw new Error('module name is too long');
	return name;
}
function checkThreadId(id) {
	if (!Number.isSafeInteger(id) || id < 0) throw new Error('invalid thread id');
	return id;
}
function checkProtection(protection) {
	if (typeof protection !== 'string' || !/^[r-][w-][x-]$/.test(protection)) throw new Error('invalid protection (expected e.g. "r--" or "rw-")');
	return protection;
}
function checkAddress(address) {
	if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{1,16}$/.test(address)) throw new Error('invalid address (expected 0x… hex)');
	return address.toLowerCase();
}
function checkReadSize(size) {
	if (!Number.isSafeInteger(size) || size < 1 || size > MAX_READ_BYTES) throw new Error('invalid size (must be 1..' + MAX_READ_BYTES + ' bytes)');
	return size;
}
// A Frida scan pattern: space-separated hex bytes, `?` nibble wildcards allowed,
// with at least one concrete nibble (an all-wildcard pattern matches everything).
function checkPattern(pattern) {
	if (typeof pattern !== 'string') throw new Error('scan pattern must be a string');
	const p = pattern.trim().toLowerCase();
	if (!p) throw new Error('scan pattern is empty');
	if (p.length > 3 * 1024) throw new Error('scan pattern is too long');
	if (!/^[0-9a-f?]{2}( [0-9a-f?]{2})*$/.test(p)) throw new Error('invalid scan pattern (expected hex bytes like "4d 5a ?? 00")');
	if (!/[0-9a-f]/.test(p)) throw new Error('invalid scan pattern (needs at least one concrete byte)');
	return p;
}

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
		// Helper agents loaded into the current session (name -> Promise<Script>).
		this._agentSession = null;
		this._agents = new Map();
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
		const script = await this._getAgent('repl');
		try {
			const result = toPlain(await script.exports.evaluate(code));
			if (result && typeof result.ok === 'boolean') return result;
			return { ok: false, error: 'The REPL agent returned no result', stack: '' };
		} catch (e) {
			// e.g. the target exited mid-call and the script was destroyed.
			return { ok: false, error: e && e.message ? e.message : String(e), stack: '' };
		}
	}

	// One of each agent per session; concurrent first calls share the same load.
	_getAgent(name) {
		const session = this._session;
		if (!session) return Promise.reject(new Error('Not attached to a process'));
		if (this._agentSession !== session) {
			this._agentSession = session;
			this._agents = new Map();
		}
		const agents = this._agents;
		let loading = agents.get(name);
		if (!loading) {
			loading = (async () => {
				const script = await session.createScript(fs.readFileSync(AGENT_PATHS[name], 'utf8'));
				this._wireScript(script);
				await script.load();
				return script;
			})();
			agents.set(name, loading);
			// A failed load must not be cached: the next call retries.
			loading.catch(() => { if (agents.get(name) === loading) agents.delete(name); });
		}
		return loading;
	}

	// ---- Inspector: read-only views of the attached process ----
	// Each call goes to the inspector agent; arguments are validated here first.
	// An error raised in the target (unknown module, unreadable memory) rejects
	// with its message.
	async _inspect(method, ...args) {
		const script = await this._getAgent('inspector');
		return toPlain(await script.exports[method](...args));
	}
	async inspectModules() { return this._inspect('modules'); }
	async inspectExports(moduleName) { return this._inspect('exports', checkModuleName(moduleName)); }
	async inspectImports(moduleName) { return this._inspect('imports', checkModuleName(moduleName)); }
	async inspectThreads() { return this._inspect('threads'); }
	async inspectBacktrace(threadId) { return this._inspect('backtrace', checkThreadId(threadId)); }
	async inspectRanges(protection) { return this._inspect('ranges', checkProtection(protection)); }
	async inspectRead(address, size) { return this._inspect('read', checkAddress(address), checkReadSize(size)); }
	async inspectScan(pattern, protection) { return this._inspect('scan', checkPattern(pattern), checkProtection(protection)); }

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
