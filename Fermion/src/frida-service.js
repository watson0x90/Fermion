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
const REPLACED_WAIT_MS = 5000; // how long to wait for the program a process replaced itself with
const MAX_CAUGHT_CHILDREN = 32; // children held suspended at once; more are let go
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
// ---- spawn arguments ----
const MAX_PATH_CHARS = 4096;
const MAX_ARGS_CHARS = 32768;
const MAX_ENV_VARS = 256;
const MAX_ENV_VALUE = 32767;
// Split a command line into arguments: spaces separate, and single or double
// quotes keep an argument with spaces together. Backslashes are ordinary
// characters, so Windows paths need no escaping.
function splitArgs(text) {
	const out = [];
	const s = typeof text === 'string' ? text : '';
	let current = '';
	let quote = '';
	let started = false;
	for (const ch of s) {
		if (quote) {
			if (ch === quote) quote = ''; else current += ch;
		} else if (ch === '"' || ch === "'") {
			quote = ch;
			started = true;
		} else if (ch === ' ' || ch === '\t') {
			if (started) { out.push(current); current = ''; started = false; }
		} else {
			current += ch;
			started = true;
		}
	}
	if (started) out.push(current);
	return out;
}
function checkSpawnPath(program) {
	if (typeof program !== 'string' || !program.trim()) throw new Error('spawn: the program path is empty');
	if (program.length > MAX_PATH_CHARS || program.includes('\0')) throw new Error('spawn: invalid program path');
	return program;
}
function checkSpawnArgs(args) {
	if (args === undefined || args === null) return '';
	if (typeof args !== 'string' || args.length > MAX_ARGS_CHARS || args.includes('\0')) throw new Error('spawn: invalid arguments');
	return args;
}
// { env, cwd }: variables added to (or replacing ones in) the environment the
// program would get anyway, and the directory it starts in. Returns a fresh
// object with only what was set.
function checkSpawnOptions(options) {
	/** @type {{ env?: { [name: string]: string }, cwd?: string, argv?: string[] }} */
	const out = {};
	if (options === undefined || options === null) return out;
	if (typeof options !== 'object' || Array.isArray(options)) throw new Error('invalid spawn options');
	if (options.env !== undefined && options.env !== null) {
		if (typeof options.env !== 'object' || Array.isArray(options.env)) throw new Error('spawn: the environment must be an object of NAME: value');
		const names = Object.keys(options.env);
		if (names.length > MAX_ENV_VARS) throw new Error('spawn: too many environment variables');
		/** @type {{ [name: string]: string }} */
		const env = {};
		for (const name of names) {
			if (!name || name.length > 256 || /[=\0]/.test(name)) throw new Error('spawn: invalid environment variable name');
			const value = options.env[name];
			if (typeof value !== 'string' || value.length > MAX_ENV_VALUE || value.includes('\0')) throw new Error('spawn: invalid value for environment variable ' + name);
			env[name] = value;
		}
		if (names.length) out.env = env;
	}
	if (options.cwd !== undefined && options.cwd !== null && options.cwd !== '') {
		if (typeof options.cwd !== 'string' || options.cwd.length > MAX_PATH_CHARS || options.cwd.includes('\0')) throw new Error('spawn: invalid working directory');
		out.cwd = options.cwd;
	}
	return out;
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
		// Catching child processes of the attached process (Frida child gating).
		this._childGating = false;
		this._gatedDevice = null;
		this._onChildAdded = null;
		this._caughtChildren = new Map(); // pid -> what was announced
		// While the session moves to a caught child, the parent's session is
		// kept: Frida lets a caught child run the moment its parent is detached
		// or its catching is switched off, and the child must stay suspended
		// until its script and hooks are in. { session, pid, childPid }.
		this._heldParent = null;
		// A process that replaces itself (exec: the usual way a new program
		// starts on Linux and macOS) keeps its pid, ends the session on it
		// with 'process-replaced' and, with catching on, is held and reported
		// as a child of itself. _replaced is the pid we are waiting to see
		// again { pid, timer }; _execEarly is such a report that arrived
		// before the session ended.
		this._replaced = null;
		this._execEarly = null;
		this._replacedWaitMs = REPLACED_WAIT_MS;
		// Turns the script as written into what is loaded (compiling it when
		// it imports packages). Set by main; absent, scripts load as written.
		this._prepareScript = null;
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
		this._setSession(session);
	}

	_setSession(session) {
		this._session = session;
		this._sessionPID = session.pid.toString();
		session.detached.connect((reason) => {
			// A parent we were holding went away by itself: nothing left to hold.
			if (this._heldParent && this._heldParent.session === session) { this._dropHeldParent(false); return; }
			if (this._session !== session) return;
			const device = this._gatedDevice;
			const follow = reason === 'process-replaced' && this._childGating && !!device;
			const pid = Number(this._sessionPID);
			const early = follow ? this._execEarly : null;
			if (follow) this._execEarly = null;
			this._clearSession();
			this.emit('detached', reason);
			if (follow) this._awaitReplacement(device, pid, early);
		});
	}

	// Forget everything that belonged to the session (it is gone, or going).
	_clearSession() {
		this._releaseChildren(this._session);
		this._session = null;
		this._script = null;
		this._sessionPID = null;
		this._agentSession = null;
		this._agents = new Map();
	}

	// Spawn suspended and attach. `args` is one command-line string (quotes
	// keep an argument with spaces together); `options` may add environment
	// variables and set the working directory. Returns the spawned pid; call
	// resume(pid) once the script and hooks are in place.
	async spawn(path, args, options) {
		const program = checkSpawnPath(path);
		const argv = splitArgs(checkSpawnArgs(args));
		const spawnOptions = checkSpawnOptions(options);
		if (argv.length) spawnOptions.argv = [program, ...argv];
		const frida = this._getFrida();
		const device = await frida.getDevice(this._deviceId);
		const procID = Object.keys(spawnOptions).length
			? await device.spawn(program, spawnOptions)
			: await device.spawn(program);
		this._adoptSession(await device.attach(procID));
		this._spawnDevice = device;
		return { pid: procID };
	}

	async resume(pid) {
		const device = this._spawnDevice || await this._getFrida().getDevice(this._deviceId);
		const result = await device.resume(pid);
		// The child we moved to is running now: its parent can be let go.
		if (this._heldParent && this._heldParent.childPid === pid) this._dropHeldParent(true);
		return result;
	}

	setScriptPreparer(fn) {
		this._prepareScript = typeof fn === 'function' ? fn : null;
	}

	async _prepared(src) {
		if (typeof src !== 'string') throw new Error('the script must be text');
		if (!this._prepareScript) return { code: src, compiled: false };
		return this._prepareScript(src);
	}

	// Returns { compiled }: whether the script was bundled with packages.
	async loadScript(src) {
		if (!this._session) throw new Error('Not attached to a process');
		const { code, compiled } = await this._prepared(src);
		if (!this._session) throw new Error('Not attached to a process'); // it ended while compiling
		this._script = await this._session.createScript(code);
		this._wireScript(this._script);
		await this._script.load();
		return { compiled: !!compiled };
	}

	async reloadScript(src) {
		if (!this._session) throw new Error('Not attached to a process');
		// Compile first: a script that does not compile leaves the one that is
		// running in place.
		const { code, compiled } = await this._prepared(src);
		if (!this._session) throw new Error('Not attached to a process');
		if (this._script) {
			this._script.unload();
		}
		this._script = await this._session.createScript(code);
		this._wireScript(this._script);
		await this._script.load();
		return { compiled: !!compiled };
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

	// ---- catching child processes ----
	// With catching on, a process started by the attached process is held
	// suspended and announced ('child' event) instead of running. It is then
	// either let go, or the session moves to it (resolveChild). A caught child
	// is never left frozen: switching catching off, detaching, or the session
	// ending lets every one of them run.
	async setChildGating(on) {
		if (typeof on !== 'boolean') throw new Error('child catching must be true or false');
		const session = this._session;
		if (!session) throw new Error('Not attached to a process');
		if (on === this._childGating) return on;
		if (!on) {
			await this._stopCatching(session);
			return false;
		}
		const device = await this._getFrida().getDevice(this._deviceId);
		const hadListener = !!this._onChildAdded;
		if (!hadListener) this._listenForChildren(device);
		try {
			await session.enableChildGating();
		} catch (e) {
			if (!hadListener) this._stopListening();
			throw e;
		}
		this._childGating = true;
		return true;
	}

	_listenForChildren(device) {
		const handler = (child) => this._childCaught(device, child);
		device.childAdded.connect(handler);
		this._gatedDevice = device;
		this._onChildAdded = handler;
	}

	_stopListening() {
		if (this._gatedDevice && this._onChildAdded) {
			try { this._gatedDevice.childAdded.disconnect(this._onChildAdded); } catch { /* already disconnected */ }
		}
		this._gatedDevice = null;
		this._onChildAdded = null;
	}

	_childCaught(device, child) {
		if (!child) return;
		const pid = child.pid;
		if (!Number.isSafeInteger(pid) || pid <= 0) return;
		const letGo = () => { Promise.resolve().then(() => device.resume(pid)).catch(() => {}); };
		if (child.origin === 'exec') {
			const info = this._childInfo(child);
			if (this._replaced && this._replaced.pid === pid) this._replacementArrived(info);
			else if (this._childGating && String(pid) === this._sessionPID) this._execEarly = info; // the session is about to end
			else letGo();
			return;
		}
		// A parent we are only holding on to during a move: its new children
		// are not ours any more, and must not be left suspended.
		if (this._heldParent && String(child.parentPid) === String(this._heldParent.pid)) { letGo(); return; }
		// Only children of the process this session is on are ours to hold.
		if (!this._childGating || String(child.parentPid) !== this._sessionPID) return;
		if (this._caughtChildren.size >= MAX_CAUGHT_CHILDREN) { letGo(); return; }
		const info = this._childInfo(child);
		this._caughtChildren.set(pid, info);
		this.emit('child', info);
	}

	_childInfo(child) {
		const argv = Array.isArray(child.argv)
			? child.argv.slice(0, 64).map((a) => String(a).slice(0, 1024))
			: [];
		return { pid: child.pid, parentPid: child.parentPid, path: typeof child.path === 'string' ? child.path.slice(0, 4096) : '', argv };
	}

	// The session's process replaced itself while catching was on: keep
	// listening, for a while, for the program it became.
	_awaitReplacement(device, pid, early) {
		this._listenForChildren(device);
		const timer = setTimeout(() => {
			this._replaced = null;
			if (!this._childGating && !this._heldParent) this._stopListening();
		}, this._replacedWaitMs);
		if (typeof timer.unref === 'function') timer.unref();
		this._replaced = { pid, timer };
		if (early) this._replacementArrived(early);
	}

	// It is held before its first instruction, like a caught child, and is
	// announced as one ('replaced'): resolveChild moves a new session to it.
	_replacementArrived(info) {
		clearTimeout(this._replaced.timer);
		this._replaced = null;
		const caught = { ...info, replaced: true };
		this._caughtChildren.set(info.pid, caught);
		this.emit('child', caught);
	}

	_forgetReplacement() {
		if (this._replaced) clearTimeout(this._replaced.timer);
		this._replaced = null;
		const early = this._execEarly;
		this._execEarly = null;
		if (early && this._gatedDevice) {
			const device = this._gatedDevice;
			Promise.resolve().then(() => device.resume(early.pid)).catch(() => {});
		}
	}

	// Let every caught child run. Returns the work, for callers that wait.
	_resumeCaught() {
		const device = this._gatedDevice;
		const pids = [...this._caughtChildren.keys()];
		this._caughtChildren = new Map();
		return device ? pids.map((pid) => Promise.resolve().then(() => device.resume(pid)).catch(() => {})) : [];
	}

	// Catching switched off for the current session (which carries on).
	_stopCatching(session) {
		const work = this._resumeCaught();
		if (this._childGating && session) work.push(Promise.resolve().then(() => session.disableChildGating()).catch(() => {}));
		this._childGating = false;
		if (!this._heldParent) this._stopListening();
		return Promise.all(work);
	}

	// Let go of the parent kept during a move. `leave` is false when it has
	// already gone by itself.
	_dropHeldParent(leave) {
		const held = this._heldParent;
		this._heldParent = null;
		if (!held) return;
		if (leave) {
			Promise.resolve().then(() => held.session.disableChildGating()).catch(() => {});
			try { held.session.detach(); } catch { /* already gone */ }
		}
		if (!this._childGating) this._stopListening();
	}

	// The session is over (or being replaced): nothing stays caught or held.
	_releaseChildren(session) {
		this._forgetReplacement();
		const work = this._resumeCaught();
		if (this._childGating && session) work.push(Promise.resolve().then(() => session.disableChildGating()).catch(() => {}));
		this._childGating = false;
		this._dropHeldParent(true); // letting the parent go also lets a child we were moving to run
		this._stopListening();
		return Promise.all(work);
	}

	// action 'resume': let the caught child run. action 'attach': move the
	// session to it. The child stays suspended; the caller loads the script
	// and hooks, then calls resume(pid), which also lets the parent go. Until
	// then the parent's session is kept, because leaving it would set the
	// child running.
	async resolveChild(pid, action) {
		if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error('invalid child pid');
		if (action !== 'attach' && action !== 'resume') throw new Error('the action must be attach or resume');
		const old = this._session;
		const device = this._gatedDevice;
		const caught = device ? this._caughtChildren.get(pid) : undefined;
		// A replacement is what the session's process became: there is no
		// session any more, and no parent to hold.
		const replacement = !old && !!caught && caught.replaced === true;
		if (!old && !replacement) throw new Error('Not attached to a process');
		if (!caught) throw new Error('No caught child with pid ' + pid);
		this._caughtChildren.delete(pid);
		if (action === 'resume') {
			if (replacement) this._stopListening();
			await device.resume(pid);
			return { pid, action };
		}
		let childSession;
		try {
			childSession = await device.attach(pid);
		} catch (e) {
			if (replacement) this._stopListening();
			await Promise.resolve().then(() => device.resume(pid)).catch(() => {});
			throw e;
		}
		if (replacement) {
			this._stopListening(); // catching is off until the caller switches it on again
			this._setSession(childSession);
			this._spawnDevice = device;
			return { pid, action };
		}
		// The session moves: the parent's other caught children run, the parent
		// is held (not detached) until the child is resumed, and no 'detached'
		// is announced, because the session did not end.
		this._resumeCaught();
		this._childGating = false; // the new session is not catching (yet)
		this._heldParent = { session: old, pid: Number(this._sessionPID), childPid: pid };
		this._script = null;
		this._agentSession = null;
		this._agents = new Map();
		this._setSession(childSession);
		this._spawnDevice = device; // resume(pid) goes to the same device
		return { pid, action };
	}

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

module.exports = { FridaService, routeMessage, parseDeviceSpec, toPlain, splitArgs };
