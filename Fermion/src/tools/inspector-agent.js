// Fermion Inspector agent. Loaded as its own Frida script inside the attached
// process (like the REPL agent) and called over rpc by the Inspector panel.
// Everything here only observes the target: modules, exports/imports, threads,
// memory ranges, memory bytes, pattern scans, and following one thread with
// Stalker to count the calls it makes. Nothing writes to the target's memory. Results are plain JSON —
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
	var MAX_INSTRUCTIONS = 200;    // instructions per disassemble call
	var MAX_FOLLOW_MS = 15000;     // a follow stops by itself after this long
	var MAX_FOLLOW_TARGETS = 20000; // distinct functions counted
	var MAX_FOLLOW_ITEMS = 300;     // functions reported

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

	// ---- following a thread ----
	// One thread at a time. Stalker runs the thread through instrumented copies
	// of its code and reports how often each function was called; that is much
	// heavier than the other views, so it is bounded in time and size.
	var follow = null; // { threadId, scope, counts, calls, distinct, overflow, timer, endedBy }

	// A follow can be limited so Stalker does not go into some modules: calls
	// into them are still counted, what happens inside them is not. Stalker has
	// no way to un-exclude a range, so one loaded copy of this agent serves one
	// scope: asked for a different one, it throws FERMION_RESCOPE and the
	// service replaces it with a fresh copy.
	var MAX_FOLLOW_MODULES = 200; // modules reported in the per-module totals
	var excludedScope = '';   // '' until this agent has excluded anything
	var excludedBases = {};   // module base -> true

	function isSystemPath(path) {
		var p = String(path || '').replace(/\\/g, '/');
		return /^[a-z]:\/windows\//i.test(p)               // Windows: System32, SysWOW64, WinSxS
			|| /^\/(usr\/)?lib(32|64)?\//.test(p)          // Linux
			|| /^\/System\//.test(p) || /^\/usr\/lib\//.test(p) // macOS
			|| /^\/(system|apex|vendor)\//.test(p);        // Android
	}

	// -> { scope: { mode, module }, key, skip(module) }. Throws for a module
	// that is not loaded.
	function resolveScope(scope) {
		var mode = scope && scope.mode;
		if (mode === 'app') return { scope: { mode: 'app', module: '' }, key: 'app', skip: function (m) { return isSystemPath(m.path); } };
		if (mode === 'module') {
			var only = moduleByName(scope.module);
			var base = hex(only.base);
			return { scope: { mode: 'module', module: only.name }, key: 'module:' + base, skip: function (m) { return hex(m.base) !== base; } };
		}
		return { scope: { mode: 'all', module: '' }, key: '', skip: null };
	}

	// Exclude what the scope skips (once per module) and return how many
	// modules are excluded for it.
	function applyScope(resolved) {
		if (!resolved.skip) return 0;
		var modules = Process.enumerateModules();
		var n = 0;
		for (var i = 0; i < modules.length; i++) {
			var m = modules[i];
			if (!resolved.skip(m)) continue;
			n++;
			var base = hex(m.base);
			if (excludedBases[base]) continue;
			Stalker.exclude({ base: m.base, size: m.size });
			excludedBases[base] = true;
		}
		excludedScope = resolved.key;
		return n;
	}

	function stopStalking(endedBy) {
		if (!follow || follow.endedBy) return;
		follow.endedBy = endedBy;
		if (follow.timer !== null) { clearTimeout(follow.timer); follow.timer = null; }
		try { Stalker.unfollow(follow.threadId); } catch (e) { /* thread gone */ }
		try { Stalker.flush(); } catch (e) { /* nothing buffered */ }
		try { Stalker.garbageCollect(); } catch (e) { /* best effort */ }
	}

	function followResult() {
		if (!follow) return { following: false, threadId: null, calls: 0, total: 0, truncated: false, items: [], modules: [], scope: null, endedBy: 'none' };
		var keys = Object.keys(follow.counts);
		keys.sort(function (a, b) { return follow.counts[b] - follow.counts[a]; });
		var items = [];
		// Per-module totals cover every function counted; only the most-called
		// functions are listed (and symbolicated).
		var totals = {};
		var names = [];
		for (var i = 0; i < keys.length; i++) {
			var address = ptr(keys[i]);
			var count = follow.counts[keys[i]];
			var mod = '';
			try { var m = Process.findModuleByAddress(address); if (m) mod = m.name; } catch (e) { /* not in a module */ }
			if (!totals[mod]) { totals[mod] = { name: mod, calls: 0, functions: 0 }; names.push(mod); }
			totals[mod].calls += count;
			totals[mod].functions++;
			if (items.length < MAX_FOLLOW_ITEMS) items.push({ address: keys[i], name: symbolName(address) || where(address), module: mod, count: count });
		}
		names.sort(function (a, b) { return totals[b].calls - totals[a].calls; });
		var modules = [];
		for (var k = 0; k < names.length && modules.length < MAX_FOLLOW_MODULES; k++) modules.push(totals[names[k]]);
		return {
			following: false,
			threadId: follow.threadId,
			calls: follow.calls,
			total: keys.length,
			truncated: keys.length > MAX_FOLLOW_ITEMS || follow.overflow,
			items: items,
			modules: modules,
			scope: follow.scope,
			endedBy: follow.endedBy,
		};
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

		// scope: { mode: 'all' | 'app' | 'module', module } — see resolveScope.
		follow: function (id, scope) {
			if (follow && !follow.endedBy) throw new Error('Already following thread ' + follow.threadId + '. Stop that first.');
			if (id === Process.getCurrentThreadId()) throw new Error("That is Frida's own thread; it cannot be followed.");
			findThread(id); // throws for an unknown thread
			var resolved = resolveScope(scope); // throws for an unknown module
			if (excludedScope && excludedScope !== resolved.key) throw new Error('FERMION_RESCOPE');
			var excluded = applyScope(resolved);
			var state = { threadId: id, scope: resolved.scope, counts: {}, calls: 0, distinct: 0, overflow: false, timer: null, endedBy: '' };
			Stalker.follow(id, {
				events: { call: true },
				// A summary per time window: callee address -> number of calls.
				onCallSummary: function (summary) {
					for (var target in summary) {
						var n = summary[target];
						state.calls += n;
						if (state.counts[target] !== undefined) { state.counts[target] += n; continue; }
						if (state.distinct >= MAX_FOLLOW_TARGETS) { state.overflow = true; continue; }
						state.counts[target] = n;
						state.distinct++;
					}
				},
			});
			follow = state; // only once Stalker accepted the thread
			state.timer = setTimeout(function () { if (follow === state) stopStalking('limit'); }, MAX_FOLLOW_MS);
			return { following: true, threadId: id, maxSeconds: MAX_FOLLOW_MS / 1000, scope: resolved.scope, excluded: excluded };
		},

		// Stop (if still running) and return what was counted. The result of a
		// follow that ended at the time limit is kept until it is collected here.
		unfollow: function () {
			stopStalking('stop');
			var result = followResult();
			follow = null;
			return result;
		},

		// Disassemble forward from an address, inside the readable range it
		// is in. Direct calls and jumps carry the address they go to.
		disassemble: function (address, count) {
			var start = ptr(address);
			var range = Process.findRangeByAddress(start);
			if (!range || range.protection.charAt(0) !== 'r') throw new Error(address + ' is not in readable memory.');
			var end = range.base.add(range.size);
			var max = Math.min(count, MAX_INSTRUCTIONS);
			var items = [];
			var cursor = start;
			var stopped = '';
			while (items.length < max) {
				if (cursor.compare(end) >= 0) { stopped = 'end'; break; }
				var insn;
				try { insn = Instruction.parse(cursor); } catch (e) { stopped = 'undecodable'; break; }
				if (insn.next.compare(end) > 0) { stopped = 'end'; break; }
				var kind = '';
				try {
					var groups = insn.groups || [];
					if (groups.indexOf('call') >= 0) kind = 'call';
					else if (groups.indexOf('jump') >= 0) kind = 'jump';
					else if (groups.indexOf('ret') >= 0) kind = 'ret';
				} catch (e) { /* no group information for this architecture */ }
				var target = null;
				var targetName = '';
				var op = String(insn.opStr || '');
				if ((kind === 'call' || kind === 'jump') && /^#?0x[0-9a-f]+$/i.test(op)) {
					target = hex(ptr(op.replace('#', '')));
					// A call goes to a function: name it. A jump usually stays inside
					// the function it is in, where the function's name says nothing:
					// say where it lands instead.
					targetName = kind === 'call' ? (symbolName(ptr(target)) || where(ptr(target))) : where(ptr(target));
				}
				items.push({
					address: hex(cursor),
					size: insn.size,
					bytes: bytesToHex(cursor.readByteArray(insn.size)),
					text: insn.mnemonic + (op ? ' ' + op : ''),
					kind: kind,
					target: target,
					targetName: targetName,
				});
				cursor = insn.next;
			}
			return {
				address: hex(start),
				next: hex(cursor),
				stopped: stopped,
				where: where(start),
				symbol: symbolName(start),
				protection: range.protection,
				items: items,
			};
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
