// Limits the operator may adjust in Settings: for each, the lowest and highest
// value that is accepted and the default. Shared by the main process, which
// enforces them (a value from the window is brought into range here, whatever
// the window says), and by the window, which offers them.
const LIMITS = {
	replTimeoutSeconds: { min: 5, max: 600, default: 20 },          // an entry in the REPL is given this long
	recordMinutes: { min: 1, max: 60, default: 10 },                // coverage, a memory watch and heap tracking stop by themselves
	coverBlocks: { min: 100000, max: 5000000, default: 2000000 },   // distinct blocks a coverage recording holds
	watchHits: { min: 10000, max: 2000000, default: 200000 },       // accesses an exact memory watch counts
	heapLive: { min: 10000, max: 500000, default: 200000 },         // live blocks heap tracking records
	heapFreed: { min: 1000, max: 200000, default: 20000 },          // freed blocks heap tracking keeps, the newest
};

function defaultLimits() {
	const out = {};
	for (const key of Object.keys(LIMITS)) out[key] = LIMITS[key].default;
	return out;
}

// Any value -> valid limits. A limit that is missing gets its default; one that
// is given must be a number, and is rounded and brought into its range.
// Unknown names are dropped.
function checkLimits(limits) {
	if (limits === undefined || limits === null) return defaultLimits();
	if (typeof limits !== 'object' || Array.isArray(limits)) throw new Error('limits must be an object of numbers');
	const out = {};
	for (const key of Object.keys(LIMITS)) {
		const value = limits[key];
		const range = LIMITS[key];
		if (value === undefined || value === null) { out[key] = range.default; continue; }
		if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error('the limit ' + key + ' must be a number');
		out[key] = Math.min(range.max, Math.max(range.min, Math.round(value)));
	}
	return out;
}

module.exports = { LIMITS, defaultLimits, checkLimits };
