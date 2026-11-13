// @ts-check
// Main-process IPC glue for the Frida service: a guarded method dispatch (so the
// renderer can only invoke an explicit allow-list, never arbitrary properties)
// and event forwarding to a renderer window.

// Methods the renderer may invoke over 'fermion:invoke'. getState() is a plain
// snapshot of the service getters.
const INVOKE_METHODS = new Set([
	'setDevice',
	'enumerateDevices',
	'enumerateProcesses',
	'getDeviceInfo',
	'attach',
	'spawn',
	'resume',
	'loadScript',
	'reloadScript',
	'detach',
	'unload',
	'getState',
	// Phase 3 — REPL: run one entry in the attached process (same capability
	// as loadScript, which already runs arbitrary script there).
	'evaluate',
	// Roadmap — stop waiting for a running REPL entry (restarts the REPL agent).
	'cancelEvaluate',
	// Phase 3 — Inspector: read-only views of the attached process. Arguments
	// are validated in the service before they reach the target.
	'inspectModules',
	'inspectExports',
	'inspectImports',
	'inspectThreads',
	'inspectBacktrace',
	'inspectRanges',
	'inspectRead',
	'inspectScan',
	'inspectWrite',
	'inspectCoverStart',
	'inspectCoverStop',
	'inspectCoverSave',
	// Memory watch: who reads or writes some bytes of data (address and size
	// validated in the service; bounded in the agent).
	'inspectWatchStart',
	'inspectWatchHits',
	'inspectWatchStop',
	// Read-only: disassemble instructions at an address (validated, capped).
	'inspectDisassemble',
	// Roadmap — follow one thread with Stalker and count its calls.
	'inspectFollow',
	'inspectUnfollow',
	// Hooks tab — find functions and hook them from the UI. A hook's handler
	// is operator-written JavaScript run in the target (as with evaluate);
	// ids, kinds, sizes and addresses are validated in the service.
	'hookSearch',
	'hookAdd',
	'hookUpdate',
	'hookRemove',
	'hookEnable',
	'hookSymbolicate',
	// Catch child processes of the attached process, and decide what happens
	// to one: only pids main itself announced are accepted.
	'setChildGating',
	'resolveChild',
]);

function createDispatch(service) {
	return async function dispatch(method, ...args) {
		if (typeof method !== 'string' || !INVOKE_METHODS.has(method)) {
			throw new Error('unknown method: ' + method);
		}
		return service[method](...args);
	};
}

// Forward the service's events to a renderer via `send(kind, ...payload)`.
function wireServiceEvents(service, send) {
	service.on('message', (m) => send('message', m));
	service.on('log', (level, text) => send('log', level, text));
	service.on('detached', (reason) => send('detached', reason));
	service.on('child', (info) => send('child', info));
}

module.exports = { createDispatch, wireServiceEvents, INVOKE_METHODS };
