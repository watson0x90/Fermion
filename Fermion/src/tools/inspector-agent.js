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
			// Read as much of the page run as is readable: shrink on a fault so the
			// last bytes before an unmapped page are still shown.
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

		scan: function (pattern, protection) {
			var started = Date.now();
			var matches = [];
			var ranges = Process.enumerateRanges(protection);
			var scanned = 0;
			var stopped = '';
			for (var i = 0; i < ranges.length; i++) {
				if (matches.length >= MAX_MATCHES) { stopped = 'limit'; break; }
				if (Date.now() - started > SCAN_BUDGET_MS) { stopped = 'time'; break; }
				var r = ranges[i];
				var found;
				try { found = Memory.scanSync(r.base, r.size, pattern); }
				catch (e) { continue; } // range vanished or became unreadable
				scanned++;
				for (var j = 0; j < found.length && matches.length < MAX_MATCHES; j++) {
					matches.push({ address: hex(found[j].address), size: found[j].size, where: where(found[j].address) });
				}
			}
			return { items: matches, total: matches.length, truncated: stopped !== '', stopped: stopped, rangesScanned: scanned, rangesTotal: ranges.length };
		},
	};
})();
