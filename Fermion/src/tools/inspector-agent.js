// Fermion Inspector agent. Loaded as its own Frida script inside the attached
// process (like the REPL agent) and called over rpc by the Inspector panel.
// Everything here only READS the target: modules, exports/imports, threads,
// memory ranges, memory bytes, and pattern scans. Results are plain JSON —
// pointers are hex strings — and every list is capped so a huge target cannot
// flood the UI.

(function () {
	var MAX_SYMBOLS = 20000;   // exports / imports per module
	var MAX_RANGES = 20000;
	var MAX_READ = 4096;       // bytes per read
	var MAX_MATCHES = 500;     // scan results
	var SCAN_BUDGET_MS = 8000; // stop scanning after this long
	var SCAN_CHUNK = 16 * 1024 * 1024; // bytes scanned per step, so the limits are checked often
	var MAX_FRAMES = 64;

	function hex(p) { return p === null || p === undefined ? null : p.toString(); }

	function capped(list, max, map) {
		var out = [];
		for (var i = 0; i < list.length && out.length < max; i++) out.push(map(list[i]));
		return { items: out, total: list.length, truncated: list.length > max };
	}

	// "kernel32.dll+0x1a2b" for an address inside a module, else the bare address.
	function where(address) {
		try {
			var m = Process.findModuleByAddress(address);
			if (m) return m.name + '+0x' + address.sub(m.base).toString(16);
		} catch (e) { /* not in a module */ }
		return hex(address);
	}

	function moduleByName(name) {
		var m = Process.findModuleByName(name);
		if (!m) throw new Error('Module not found: ' + name);
		return m;
	}

	function findThread(id) {
		var threads = Process.enumerateThreads();
		for (var i = 0; i < threads.length; i++) if (threads[i].id === id) return threads[i];
		throw new Error('Thread not found: ' + id);
	}

	// A CpuContext exposes its registers through accessors (for-in sees none);
	// its JSON form lists them all.
	function registers(context) {
		var out = {};
		var plain;
		try { plain = JSON.parse(JSON.stringify(context)); } catch (e) { plain = null; }
		if (plain && typeof plain === 'object') {
			for (var k in plain) {
				var v = plain[k];
				if (v !== null && v !== undefined && typeof v !== 'object') out[k] = String(v);
			}
		}
		return out;
	}

	// "module!function" for an address with a known symbol, else ''.
	function symbolName(address) {
		try {
			var s = DebugSymbol.fromAddress(address);
			if (s && s.name) return (s.moduleName ? s.moduleName + '!' : '') + s.name;
		} catch (e) { /* no symbol */ }
		return '';
	}

	function bytesToHex(buffer) {
		var b = new Uint8Array(buffer);
		var s = '';
		for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
		return s;
	}

	rpc.exports = {
		modules: function () {
			return capped(Process.enumerateModules(), MAX_RANGES, function (m) {
				return { name: m.name, base: hex(m.base), size: m.size, path: m.path };
			});
		},

		exports: function (name) {
			return capped(moduleByName(name).enumerateExports(), MAX_SYMBOLS, function (e) {
				return { type: e.type, name: e.name, address: hex(e.address) };
			});
		},

		imports: function (name) {
			return capped(moduleByName(name).enumerateImports(), MAX_SYMBOLS, function (i) {
				return { type: i.type || '', name: i.name, module: i.module || '', address: hex(i.address) };
			});
		},

		threads: function () {
			return capped(Process.enumerateThreads(), MAX_RANGES, function (t) {
				var pc = t.context && t.context.pc;
				return {
					id: t.id,
					name: t.name || '',
					state: t.state,
					pc: hex(pc),
					where: pc ? where(pc) : '',
					registers: t.context ? registers(t.context) : {},
				};
			});
		},

		backtrace: function (id) {
			var t = findThread(id);
			var frames;
			try { frames = Thread.backtrace(t.context, Backtracer.ACCURATE); }
			catch (e) { frames = Thread.backtrace(t.context, Backtracer.FUZZY); }
			return capped(frames, MAX_FRAMES, function (address) {
				return { address: hex(address), where: where(address), symbol: symbolName(address) };
			});
		},

		ranges: function (protection) {
			return capped(Process.enumerateRanges(protection), MAX_RANGES, function (r) {
				return { base: hex(r.base), size: r.size, protection: r.protection, file: r.file ? r.file.path : '' };
			});
		},

		read: function (address, size) {
			var n = Math.max(1, Math.min(MAX_READ, size | 0));
			var p = ptr(address);
			// Only read inside a range Frida reports as readable, and never past
			// its end. Frida leaves guard pages out of its ranges; touching one
			// (e.g. below a thread's stack on Windows) would clear the guard and
			// crash the target later, so such an address is refused untouched.
			var range = Process.findRangeByAddress(p);
			if (!range || range.protection.charAt(0) !== 'r') throw new Error('Memory at ' + hex(p) + ' is not readable');
			var left = range.size - Number(p.sub(range.base).toString());
			if (left < n) n = Math.max(1, left);
			// If it faults anyway (the range changed under us), shrink so the
			// readable part is still shown.
			for (;;) {
				try {
					var buf = p.readByteArray(n);
					return { address: hex(p), size: n, requested: size, hex: bytesToHex(buf) };
				} catch (e) {
					if (n <= 16) throw new Error('Cannot read memory at ' + hex(p) + ': ' + e.message);
					n = n >> 1;
				}
			}
		},

		// Scans asynchronously, one chunk at a time, so neither a huge range nor
		// a pattern that matches everywhere can pin the target: matching stops
		// inside a chunk the moment the match cap is reached, and the time
		// budget is checked between chunks.
		scan: function (pattern, protection) {
			var started = Date.now();
			var matches = [];
			var ranges = Process.enumerateRanges(protection);
			var overlap = Math.max(0, pattern.split(' ').length - 1); // so a match across a chunk edge is found
			var scanned = 0;
			var stopped = '';

			function scanChunk(base, size) {
				return new Promise(function (resolve) {
					try {
						Memory.scan(base, size, pattern, {
							onMatch: function (address, len) {
								matches.push({ address: hex(address), size: len, where: where(address) });
								if (matches.length >= MAX_MATCHES) { stopped = 'limit'; return 'stop'; }
							},
							onError: function () { /* part of the chunk was unreadable */ },
							onComplete: function () { resolve(true); },
						});
					} catch (e) {
						resolve(false); // range vanished or became unreadable
					}
				});
			}

			function next(i, offset, ok) {
				if (stopped) return finish();
				if (i >= ranges.length) return finish();
				if (Date.now() - started > SCAN_BUDGET_MS) { stopped = 'time'; return finish(); }
				var r = ranges[i];
				if (offset >= r.size) { if (ok) scanned++; return next(i + 1, 0, true); }
				var len = Math.min(SCAN_CHUNK + overlap, r.size - offset);
				return scanChunk(r.base.add(offset), len).then(function (fine) {
					if (!fine) return next(i + 1, 0, true); // skip the rest of a faulting range
					return next(i, offset + SCAN_CHUNK, ok);
				});
			}

			function finish() {
				return { items: matches, total: matches.length, truncated: stopped !== '', stopped: stopped, rangesScanned: scanned, rangesTotal: ranges.length };
			}

			return Promise.resolve().then(function () { return next(0, 0, true); });
		},
	};
})();
