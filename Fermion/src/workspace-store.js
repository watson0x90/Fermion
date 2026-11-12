// @ts-check
// The operator's saved work: the Hooks tab's hooks and the address bookmarks,
// kept in one JSON file in userData and owned by the main process.
//
// The renderer asks to load and to save it. What it sends is not trusted (it
// displays output from instrumented targets), so every save is rebuilt here
// from known fields with bounded sizes, and what is on disk is validated the
// same way when read. Nothing else can be written through this.
const fs = require('fs');

const MAX_HOOKS = 200;
const MAX_BOOKMARKS = 500;
const MAX_CODE = 65536;
const MAX_NAME = 512;
const MAX_MODULE = 1024;
const MAX_NOTE = 2000;
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{1,16}$/;

const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');

// Where something is: inside a module (module + offset) or an absolute
// address. Null when it is neither.
function place(raw) {
	const module = str(raw.module, MAX_MODULE);
	const address = typeof raw.address === 'string' && ADDRESS.test(raw.address) ? raw.address.toLowerCase() : '';
	if (module) {
		if (!Number.isSafeInteger(raw.offset) || raw.offset < 0) return null;
		return { module, offset: raw.offset, address };
	}
	if (!address) return null;
	return { module: '', offset: null, address };
}

function cleanHook(raw) {
	if (!raw || typeof raw !== 'object' || typeof raw.id !== 'string' || !ID.test(raw.id)) return null;
	const at = place(raw);
	if (!at || typeof raw.code !== 'string' || !raw.code.trim() || raw.code.length > MAX_CODE) return null;
	return {
		id: raw.id,
		name: str(raw.name, MAX_NAME) || (at.module ? at.module + '!0x' + at.offset.toString(16) : at.address),
		...at,
		code: raw.code,
		enabled: raw.enabled !== false,
		backtrace: raw.backtrace !== false,
	};
}

function cleanBookmark(raw) {
	if (!raw || typeof raw !== 'object' || typeof raw.id !== 'string' || !ID.test(raw.id)) return null;
	const at = place(raw);
	if (!at) return null;
	return {
		id: raw.id,
		label: str(raw.label, 200) || (at.module ? at.module + '+0x' + at.offset.toString(16) : at.address),
		...at,
		view: raw.view === 'code' ? 'code' : 'memory',
		note: str(raw.note, MAX_NOTE),
	};
}

function cleanList(list, max, clean) {
	const out = [];
	const seen = new Set();
	if (!Array.isArray(list)) return out;
	for (const raw of list) {
		if (out.length >= max) break;
		const item = clean(raw);
		if (item && !seen.has(item.id)) { seen.add(item.id); out.push(item); }
	}
	return out;
}

// Anything -> { hooks, bookmarks } holding only valid entries.
function cleanWorkspace(raw) {
	const r = raw && typeof raw === 'object' ? raw : {};
	return {
		hooks: cleanList(r.hooks, MAX_HOOKS, cleanHook),
		bookmarks: cleanList(r.bookmarks, MAX_BOOKMARKS, cleanBookmark),
	};
}

/**
 * @param {string} file JSON file in userData
 * @param {{ readFileSync: Function, writeFileSync: Function, renameSync: Function }} [io]
 */
function createWorkspaceStore(file, io = fs) {
	return {
		load() {
			try {
				return cleanWorkspace(JSON.parse(io.readFileSync(file, 'utf8')));
			} catch {
				return cleanWorkspace(null); // nothing saved yet, or unreadable: start empty
			}
		},
		// Returns how much was kept, so the caller can tell if something was dropped.
		save(raw) {
			const data = cleanWorkspace(raw);
			// Written beside the file and moved over it, so a crash mid-write
			// cannot leave half a file.
			const tmp = file + '.tmp';
			io.writeFileSync(tmp, JSON.stringify({ version: 1, ...data }, null, 2));
			io.renameSync(tmp, file);
			return { hooks: data.hooks.length, bookmarks: data.bookmarks.length };
		},
	};
}

module.exports = { createWorkspaceStore, cleanWorkspace };
