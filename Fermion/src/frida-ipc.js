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
}

module.exports = { createDispatch, wireServiceEvents, INVOKE_METHODS };
