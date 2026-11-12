// @ts-check
// Recently opened/saved script files, owned by the main process.
//
// The renderer may re-open one of these without a dialog (fermion:openRecent),
// so this list is what stands between it and reading arbitrary files: it only
// ever holds paths the user chose in an Open or Save dialog, and `has()` is an
// exact string match against them.
const fs = require('fs');
const path = require('path');

const MAX = 10;

class RecentFiles {
	/** @param {string} file JSON file the list is stored in (in userData) */
	constructor(file) {
		this._file = file;
		/** @type {string[]} */
		this._paths = [];
		try {
			const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
			if (Array.isArray(parsed)) {
				for (const p of parsed) {
					if (RecentFiles.valid(p) && !this._paths.includes(p) && this._paths.length < MAX) this._paths.push(p);
				}
			}
		} catch { /* no list yet, or unreadable: start empty */ }
	}

	static valid(p) {
		return typeof p === 'string' && p.length > 0 && p.length < 4096 && path.isAbsolute(p);
	}

	list() { return this._paths.slice(); }

	has(p) { return typeof p === 'string' && this._paths.includes(p); }

	add(p) {
		if (!RecentFiles.valid(p)) return;
		this._paths = [p, ...this._paths.filter((x) => x !== p)].slice(0, MAX);
		this._save();
	}

	remove(p) {
		this._paths = this._paths.filter((x) => x !== p);
		this._save();
	}

	_save() {
		try { fs.writeFileSync(this._file, JSON.stringify(this._paths, null, 2)); } catch { /* best effort */ }
	}
}

module.exports = { RecentFiles };
