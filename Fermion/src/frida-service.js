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
	hooks: path.join(__dirname, 'tools', 'hooks-agent.js'),
};
const MAX_EVAL_CHARS = 200000;
const EVAL_TIMEOUT_MS = 20000;

// ---- Inspector argument validation (the renderer is untrusted) ----
const MAX_READ_BYTES = 4096;
const TIMED_OUT = Symbol('timed out');
const CANCELLED = Symbol('cancelled');
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
// ---- Hooks tab arguments ----
const HOOK_KINDS = ['exports', 'imports', 'symbols'];
const MAX_HOOK_QUERY = 256;
const MAX_HOOK_CODE = 65536;
const MAX_SYMBOLICATE = 64;
function checkHookId(id) {
	if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw new Error('invalid hook id');
	return id;
}
function checkHookKind(kind) {
	if (typeof kind !== 'string' || !HOOK_KINDS.includes(kind)) throw new Error('invalid search kind (expected exports, imports or symbols)');
	return kind;
}
function checkHookQuery(query) {
	if (typeof query !== 'string') throw new Error('search query must be a string');
	const q = query.trim();
	if (!q) throw new Error('search query is empty');
	if (q.length > MAX_HOOK_QUERY) throw new Error('search query is too long');
	return q;
}
function checkHookCode(code) {
	if (typeof code !== 'string' || !code.trim()) throw new Error('hook handler is empty');
	if (code.length > MAX_HOOK_CODE) throw new Error('hook handler is too long');
	return code;
}
// Where a hook goes: module + offset when it is inside a module (so it is
// found again after a restart), else an absolute address. Returns a fresh
// object holding only the known fields.
function checkHookSpec(spec) {
	if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw new Error('invalid hook');
	const out = { id: checkHookId(spec.id), module: '', offset: null, address: '', code: checkHookCode(spec.code), enabled: spec.enabled !== false, backtrace: spec.backtrace !== false };
	if (spec.module !== '' && spec.module !== undefined && spec.module !== null) {
		out.module = checkModuleName(spec.module);
		if (!Number.isSafeInteger(spec.offset) || spec.offset < 0) throw new Error('invalid hook offset');
		out.offset = spec.offset;
	}
	if (!out.module || (spec.address !== undefined && spec.address !== '' && spec.address !== null)) out.address = checkAddress(spec.address);
	return out;
}
function checkHookPatch(patch) {
	const out = {};
	if (patch && typeof patch === 'object' && !Array.isArray(patch)) {
		if (patch.code !== undefined) out.code = checkHookCode(patch.code);
		if (patch.backtrace !== undefined) out.backtrace = !!patch.backtrace;
	}
	if (!Object.keys(out).length) throw new Error('nothing to change in the hook');
	return out;
}
function checkAddresses(addresses) {
	if (!Array.isArray(addresses) || !addresses.length || addresses.length > MAX_SYMBOLICATE) throw new Error('addresses must be a list of 1..' + MAX_SYMBOLICATE);
	return addresses.map(checkAddress);
}

// What a follow covers: everything, everything but system libraries, or one
// module. Returns a fresh object holding only the two known fields.
const FOLLOW_MODES = ['all', 'app', 'module'];
function checkFollowScope(scope) {
	if (scope === undefined || scope === null) return { mode: 'all', module: '' };
	if (typeof scope !== 'object' || Array.isArray(scope)) throw new Error('invalid follow scope');
	const mode = scope.mode;
	if (typeof mode !== 'string' || !FOLLOW_MODES.includes(mode)) throw new Error('invalid follow scope (expected all, app or module)');
	return { mode, module: mode === 'module' ? checkModuleName(scope.module) : '' };
}
function checkProtection(protection) {
	if (typeof protection !== 'string' || !/^[r-][w-][x-]$/.test(protection)) throw new Error('invalid protection (expected e.g. "r--" or "rw-")');
	return protection;
}
function checkAddress(address) {
	if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{1,16}$/.test(address)) throw new Error('invalid address (expected 0x… hex)');
	return address.toLowerCase();
}
const MAX_INSTRUCTIONS = 200;
function checkInstructionCount(count) {
	if (count === undefined) return 60;
	if (!Number.isSafeInteger(count) || count < 1 || count > MAX_INSTRUCTIONS) throw new Error('invalid instruction count (must be 1..' + MAX_INSTRUCTIONS + ')');
	return count;
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
	// A pattern with fewer than two fully specified bytes matches a large part
	// of any process and would flood the target with matches.
	if (p.split(' ').filter((b) => /^[0-9a-f]{2}$/.test(b)).length < 2) throw new Error('invalid scan pattern (needs at least two concrete bytes)');
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
		this._evalTimeoutMs = EVAL_TIMEOUT_MS;
		// Entries being evaluated right now: a function per entry that cancels it.
		this._evalCancels = new Set();
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
		this._adoptSession(await device.attach(pidOrName));
	}

	// Make `session` the current one. Its `detached` signal only counts while it
	// is still current: a signal from a session we already left must not tear
	// down the one attached since.
	_adoptSession(session) {
		this._clearSession();
		this._session = session;
		this._sessionPID = session.pid.toString();
		session.detached.connect((reason) => {
			if (this._session !== session) return;
			this._clearSession();
			this.emit('detached', reason);
		});
	}

	// Forget everything that belonged to the session (it is gone, or going).
	_clearSession() {
		this._session = null;
		this._script = null;
		this._sessionPID = null;
		this._agentSession = null;
		this._agents = new Map();
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
		this._adoptSession(await device.attach(procID));
		this._spawnDevice = device;
		return { pid: procID };
	}

	async resume(pid) {
		const device = this._spawnDevice || await this._getFrida().getDevice(this._deviceId);
		return device.resume(pid);
	}

	async loadScript(src) {
		if (!this._session) throw new Error('Not attached to a process');
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
		let timer;
		let cancel;
		const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve(TIMED_OUT), this._evalTimeoutMs); });
		const cancelled = new Promise((resolve) => { cancel = () => resolve(CANCELLED); });
		this._evalCancels.add(cancel);
		try {
			const raw = await Promise.race([script.exports.evaluate(code), timeout, cancelled]);
			if (raw === TIMED_OUT || raw === CANCELLED) {
				// The entry is still running (or waiting on a promise that never
				// settles). Drop this agent so the prompt works again; the next
				// entry starts a fresh one. Unloading is best-effort and not
				// awaited: a spinning script may never answer.
				if (this._agents.get('repl')) this._agents.delete('repl');
				Promise.resolve().then(() => script.unload()).catch(() => {});
				const tail = ' The REPL was restarted, so its variables are gone. If the entry is a busy loop it may still be running in the target; detach to stop it.';
				return raw === CANCELLED
					? { ok: false, cancelled: true, error: 'Cancelled.' + tail, stack: '' }
					: { ok: false, error: 'Timed out after ' + Math.round(this._evalTimeoutMs / 1000) + ' s.' + tail, stack: '' };
			}
			const result = toPlain(raw);
			if (result && typeof result.ok === 'boolean') return result;
			return { ok: false, error: 'The REPL agent returned no result', stack: '' };
		} catch (e) {
			// e.g. the target exited mid-call and the script was destroyed.
			return { ok: false, error: e && e.message ? e.message : String(e), stack: '' };
		} finally {
			clearTimeout(timer);
			this._evalCancels.delete(cancel);
		}
	}

	// Stop waiting for the REPL entries that are running. Returns whether there
	// was anything to cancel.
	async cancelEvaluate() {
		if (!this._evalCancels.size) return false;
		for (const cancel of [...this._evalCancels]) cancel();
		return true;
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
		const loading = this._getAgent('inspector');
		const script = await loading;
		try {
			return toPlain(await script.exports[method](...args));
		} catch (e) {
			// The agent was replaced while this call was in flight (a follow
			// with a different scope, below): ask the new one, once.
			const current = this._session ? this._agents.get('inspector') : null;
			if (!current || current === loading) throw e;
			return toPlain(await (await current).exports[method](...args));
		}
	}

	// Unload a helper agent so the next call loads a fresh copy of it.
	async _dropAgent(name) {
		const loading = this._agents.get(name);
		this._agents.delete(name);
		if (!loading) return;
		try { await (await loading).unload(); } catch { /* already gone */ }
	}
	async inspectModules() { return this._inspect('modules'); }
	async inspectExports(moduleName) { return this._inspect('exports', checkModuleName(moduleName)); }
	async inspectImports(moduleName) { return this._inspect('imports', checkModuleName(moduleName)); }
	async inspectThreads() { return this._inspect('threads'); }
	async inspectBacktrace(threadId) { return this._inspect('backtrace', checkThreadId(threadId)); }
	async inspectRanges(protection) { return this._inspect('ranges', checkProtection(protection)); }
	async inspectRead(address, size) { return this._inspect('read', checkAddress(address), checkReadSize(size)); }
	async inspectDisassemble(address, count) { return this._inspect('disassemble', checkAddress(address), checkInstructionCount(count)); }
	async inspectScan(pattern, protection) { return this._inspect('scan', checkPattern(pattern), checkProtection(protection)); }
	// Follow one thread with Stalker and count the calls it makes; unfollow
	// stops and returns the counts. (Bounded in the agent: 15 s, one thread.)
	// The scope limits which modules Stalker goes into. Stalker cannot undo an
	// exclusion, so an agent that has excluded for another scope refuses with
	// FERMION_RESCOPE; it is then replaced by a fresh copy and asked again.
	async inspectFollow(threadId, scope) {
		const id = checkThreadId(threadId);
		const checked = checkFollowScope(scope);
		try {
			return await this._inspect('follow', id, checked);
		} catch (e) {
			if (!/FERMION_RESCOPE/.test(String(e && e.message))) throw e;
			await this._dropAgent('inspector');
			return this._inspect('follow', id, checked);
		}
	}
	async inspectUnfollow() { return this._inspect('unfollow'); }

	// ---- Hooks tab ----
	// Hooks live in their own agent script, so they survive reloads of the
	// user's script. A handler is JavaScript the operator wrote and runs in
	// the target, like a REPL entry; everything else is validated here.
	async _hooks(method, ...args) {
		const script = await this._getAgent('hooks');
		return toPlain(await script.exports[method](...args));
	}
	async hookSearch(kind, query) { return this._hooks('search', checkHookKind(kind), checkHookQuery(query)); }
	async hookAdd(spec) { return this._hooks('add', checkHookSpec(spec)); }
	async hookUpdate(id, patch) { return this._hooks('update', checkHookId(id), checkHookPatch(patch)); }
	async hookEnable(id, on) {
		if (typeof on !== 'boolean') throw new Error('enable must be true or false');
		return this._hooks('enable', checkHookId(id), on);
	}
	async hookRemove(id) { return this._hooks('remove', checkHookId(id)); }
	async hookSymbolicate(addresses) { return this._hooks('symbolicate', checkAddresses(addresses)); }

	// Unload the user's script (the helper agents stay). A no-op when none is loaded.
	async unload() {
		const script = this._script;
		this._script = null;
		if (script) await script.unload();
	}

	async detach() {
		const session = this._session;
		this._clearSession();
		if (session) session.detach();
	}

	// Frida delivers console.log/warn/error to logHandler (it does NOT emit
	// `message` for log records), so surface both as distinct events.
	_wireScript(script) {
		script.message.connect((message) => this.emit('message', message));
		script.logHandler = (level, text) => this.emit('log', level, text);
	}
}

module.exports = { FridaService, routeMessage, parseDeviceSpec, toPlain };
