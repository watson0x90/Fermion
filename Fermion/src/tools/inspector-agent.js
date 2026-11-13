// Fermion Inspector agent. Loaded as its own Frida script inside the attached
// process (like the REPL agent) and called over rpc by the Inspector panel.
// Everything here only observes the target: modules, exports/imports, threads,
// memory ranges, memory bytes, pattern scans, and following one thread with
// Stalker to count the calls it makes. Only `write` changes the target's
// memory; a memory watch changes a page's protection while it runs, and heap
// tracking hooks the allocator's functions while it runs. Results are plain JSON —
// pointers are hex strings — and every list is capped so a huge target cannot
// flood the UI.

(function () {
	var MAX_SYMBOLS = 20000;   // exports / imports per module
	var MAX_RANGES = 20000;
	var MAX_READ = 4096;       // bytes per read
	var MAX_WRITE = 4096;      // bytes per write
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

	// ---- recording coverage ----
	// Which basic blocks ran, on one thread or on all of them. Stalker reports
	// a block once, when it first compiles it for a thread, which is exactly
	// "this code was reached" and costs far less than an event per execution.
	// A recording is bounded in time and in blocks, and its result is kept
	// here until the next one starts: a summary, the drcov file (for
	// Lighthouse, Dragondance and the like) and a plain-text report.
	var MAX_COVER_MS = 600000;       // a recording stops by itself after 10 minutes
	var MAX_COVER_BLOCKS = 2000000;  // ... or after this many distinct blocks
	var COVER_POLL_MS = 500;         // how often new threads are picked up
	var COVER_SETTLE_MS = 150;       // Stalker hands over its last events a moment after unfollow
	var MAX_COVER_MODULES = 200;     // modules in the summary
	var MAX_TEXT_MODULES = 60;       // modules in the text report
	var MAX_TEXT_FUNCTIONS = 300;    // functions listed per module in the text report
	var MAX_COVER_SYMBOLS = 60000;   // blocks looked up by name for the text report
	var MAX_SYMBOL_MS = 6000;        // ... and how long that may take
	var cover = null;   // { all, threads, count, scope, blocks, n, overflow, timer, poll, endedBy, started, ended }
	var covered = null; // { summary, drcov, text } of the last recording

	function otherThreadIds() {
		var me = Process.getCurrentThreadId();
		var ids = [];
		var threads = Process.enumerateThreads();
		for (var i = 0; i < threads.length; i++) if (threads[i].id !== me) ids.push(threads[i].id);
		return ids;
	}

	// Returns true when Stalker took the thread.
	function coverThread(state, id) {
		if (state.threads[id]) return false;
		try {
			Stalker.follow(id, {
				events: { compile: true },
				onReceive: function (raw) {
					var list = Stalker.parse(raw, { annotate: false, stringify: false });
					for (var i = 0; i < list.length; i++) {
						var key = list[i][0].toString();
						if (state.blocks[key] !== undefined) continue;
						if (state.n >= MAX_COVER_BLOCKS) {
							// Stop from outside this callback: Stalker is delivering to it.
							if (!state.overflow) { state.overflow = true; setTimeout(function () { if (cover === state) stopCover('limit'); }, 0); }
							return;
						}
						state.blocks[key] = parseInt(list[i][1].sub(list[i][0]).toString(16), 16);
						state.n++;
					}
				},
			});
		} catch (e) {
			return false; // a thread that ended, or one Stalker cannot take
		}
		state.threads[id] = true;
		state.count++;
		return true;
	}

	function stopCover(endedBy) {
		if (!cover || cover.endedBy) return;
		cover.endedBy = endedBy;
		cover.ended = Date.now();
		if (cover.timer !== null) { clearTimeout(cover.timer); cover.timer = null; }
		if (cover.poll !== null) { clearInterval(cover.poll); cover.poll = null; }
		for (var id in cover.threads) {
			try { Stalker.unfollow(Number(id)); } catch (e) { /* thread gone */ }
		}
		try { Stalker.flush(); } catch (e) { /* nothing buffered */ }
	}

	function utf8(text) {
		var out = [];
		for (var i = 0; i < text.length; i++) {
			var c = text.charCodeAt(i);
			if (c >= 0xd800 && c < 0xdc00 && i + 1 < text.length) { c = 0x10000 + ((c - 0xd800) << 10) + (text.charCodeAt(++i) - 0xdc00); }
			if (c < 0x80) out.push(c);
			else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
			else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
			else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
		}
		return out;
	}

	function pad16(p) {
		var s = p.toString(16);
		while (s.length < 16) s = '0' + s;
		return '0x' + s;
	}

	function thousands(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ','); }

	// Sort the recorded blocks into modules. -> { used: [{ module, blocks: [{ off, size }], bytes }], unmapped, total, bytes }
	function coverByModule(state) {
		var modules = Process.enumerateModules().slice();
		modules.sort(function (a, b) { return a.base.compare(b.base); });
		var ends = [];
		for (var i = 0; i < modules.length; i++) ends.push(modules[i].base.add(modules[i].size));
		function find(p) {
			var lo = 0, hi = modules.length - 1;
			while (lo <= hi) {
				var mid = (lo + hi) >> 1;
				if (p.compare(modules[mid].base) < 0) hi = mid - 1;
				else if (p.compare(ends[mid]) >= 0) lo = mid + 1;
				else return mid;
			}
			return -1;
		}
		var slots = {};
		var used = [];
		var unmapped = 0, total = 0, bytes = 0;
		for (var key in state.blocks) {
			var p = ptr(key);
			var at = find(p);
			if (at < 0) { unmapped++; continue; } // code outside every module (JIT, shellcode)
			// A thread that was inside an excluded module when the recording
			// began runs on there until it returns: that code is out of scope.
			if (state.skip && state.skip(modules[at])) continue;
			var slot = slots[at];
			if (!slot) { slot = slots[at] = { module: modules[at], blocks: [], bytes: 0 }; used.push(slot); }
			var size = state.blocks[key];
			slot.blocks.push({ off: parseInt(p.sub(modules[at].base).toString(16), 16), size: size });
			slot.bytes += size;
			total++;
			bytes += size;
		}
		for (var u = 0; u < used.length; u++) used[u].blocks.sort(function (a, b) { return a.off - b.off; });
		used.sort(function (a, b) { return b.blocks.length - a.blocks.length || (a.module.name < b.module.name ? -1 : 1); });
		return { used: used, unmapped: unmapped, total: total, bytes: bytes };
	}

	// The drcov file: a text header naming the modules, then one 8-byte
	// record per block (offset in its module, size, module id).
	function coverDrcov(sorted) {
		var head = 'DRCOV VERSION: 2\nDRCOV FLAVOR: fermion\nModule Table: version 2, count ' + sorted.used.length + '\n'
			+ 'Columns: id, base, end, entry, checksum, timestamp, path\n';
		for (var i = 0; i < sorted.used.length; i++) {
			var m = sorted.used[i].module;
			head += ' ' + i + ', ' + pad16(m.base) + ', ' + pad16(m.base.add(m.size)) + ', 0x0000000000000000, 0x00000000, 0x00000000, ' + (m.path || m.name) + '\n';
		}
		head += 'BB Table: ' + sorted.total + ' bbs\n';
		var text = utf8(head);
		var out = new Uint8Array(text.length + sorted.total * 8);
		out.set(text, 0);
		var at = text.length;
		for (var k = 0; k < sorted.used.length; k++) {
			var blocks = sorted.used[k].blocks;
			for (var b = 0; b < blocks.length; b++) {
				var off = blocks[b].off, size = Math.min(blocks[b].size, 0xffff);
				out[at++] = off & 0xff; out[at++] = (off >>> 8) & 0xff; out[at++] = (off >>> 16) & 0xff; out[at++] = (off >>> 24) & 0xff;
				out[at++] = size & 0xff; out[at++] = (size >>> 8) & 0xff;
				out[at++] = k & 0xff; out[at++] = (k >>> 8) & 0xff;
			}
		}
		return out.buffer;
	}

	function scopeText(scope) {
		if (scope.mode === 'app') return 'everything except system libraries';
		if (scope.mode === 'module') return 'only ' + scope.module;
		return 'every module';
	}

	// A report meant to be read by a person or a language model: what ran,
	// by module and by function, in plain text with the units spelled out.
	function coverText(state, sorted, summary) {
		var started = Date.now();
		var looked = 0;
		var lines = [];
		var main = '';
		try { main = Process.enumerateModules()[0].name; } catch (e) { /* unknown */ }
		lines.push('# Code coverage recorded by Fermion (Frida)');
		lines.push('');
		lines.push('Process: ' + (main || 'unknown') + (Process.id ? ' (pid ' + Process.id + ')' : '') + (Process.platform ? ', ' + Process.platform + ' ' + (Process.arch || '') : ''));
		lines.push('Recorded: ' + summary.seconds + ' s on ' + summary.threads + ' thread' + (summary.threads === 1 ? '' : 's') + '; scope: ' + scopeText(state.scope)
			+ '; ended by: ' + (summary.endedBy === 'limit' ? 'the time or block limit' : 'the operator'));
		lines.push('Total: ' + thousands(sorted.total) + ' basic blocks (' + thousands(sorted.bytes) + ' bytes of code) in ' + sorted.used.length + ' module' + (sorted.used.length === 1 ? '' : 's')
			+ (sorted.unmapped ? '; ' + thousands(sorted.unmapped) + ' more blocks ran outside every module (generated code)' : ''));
		lines.push('');
		lines.push('How to read this: a basic block is a straight run of instructions with one entry and one exit. A block is listed if it ran at least once while recording; how many times is not recorded.');
		lines.push('Every offset is hexadecimal and relative to the base address of its module, so it can be looked up in a disassembler whatever address the module was loaded at.');
		lines.push('A function line reads: name, offset of its first block that ran, blocks that ran, bytes of code in those blocks. Code that is absent from this report did not run during the recording (or was outside the scope).');
		lines.push('Function names come from the symbols Frida can find. Where a module has no debug symbols, a block is named after the nearest exported symbol before it, so an exported name with far more blocks than such a function could hold is standing in for internal functions that have no name of their own. Trust the offsets over the names.');
		if (summary.overflow) lines.push('The recording hit the block limit: later code is missing.');
		lines.push('');
		lines.push('## Modules, most blocks first');
		lines.push('');
		lines.push('| module | blocks | bytes | path |');
		lines.push('| --- | ---: | ---: | --- |');
		for (var i = 0; i < sorted.used.length && i < MAX_TEXT_MODULES; i++) {
			var s = sorted.used[i];
			lines.push('| ' + s.module.name + ' | ' + s.blocks.length + ' | ' + s.bytes + ' | ' + (s.module.path || '') + ' |');
		}
		if (sorted.used.length > MAX_TEXT_MODULES) lines.push('(' + (sorted.used.length - MAX_TEXT_MODULES) + ' more modules with fewer blocks are not listed.)');
		lines.push('');
		lines.push('## Functions that ran, by module');
		for (var k = 0; k < sorted.used.length && k < MAX_TEXT_MODULES; k++) {
			var slot = sorted.used[k];
			var byName = {};
			var names = [];
			var unnamed = 0;
			var skipped = 0;
			for (var b = 0; b < slot.blocks.length; b++) {
				var block = slot.blocks[b];
				if (looked >= MAX_COVER_SYMBOLS || Date.now() - started > MAX_SYMBOL_MS) { skipped++; continue; }
				looked++;
				var name = '';
				try { var sym = DebugSymbol.fromAddress(slot.module.base.add(block.off)); if (sym && sym.name) name = sym.name; } catch (e) { /* no symbol */ }
				if (!name) { unnamed++; continue; }
				var f = byName[name];
				if (!f) { f = byName[name] = { name: name, off: block.off, blocks: 0, bytes: 0 }; names.push(name); }
				f.blocks++;
				f.bytes += block.size;
			}
			names.sort(function (a, c) { return byName[c].blocks - byName[a].blocks || byName[a].off - byName[c].off; });
			lines.push('');
			lines.push('### ' + slot.module.name + ': ' + slot.blocks.length + ' blocks in ' + names.length + ' named function' + (names.length === 1 ? '' : 's'));
			lines.push('');
			for (var n = 0; n < names.length && n < MAX_TEXT_FUNCTIONS; n++) {
				var fn = byName[names[n]];
				lines.push('- ' + fn.name + ' +0x' + fn.off.toString(16) + ': ' + fn.blocks + ' block' + (fn.blocks === 1 ? '' : 's') + ', ' + fn.bytes + ' bytes');
			}
			if (names.length > MAX_TEXT_FUNCTIONS) lines.push('(' + (names.length - MAX_TEXT_FUNCTIONS) + ' more functions with fewer blocks are not listed.)');
			if (unnamed) lines.push('(' + unnamed + ' blocks have no symbol name: this module has no debug symbols for them.)');
			if (skipped) lines.push('(' + skipped + ' blocks were not looked up by name, to keep this report quick to produce. The drcov file has them all.)');
		}
		lines.push('');
		return lines.join('\n');
	}

	function coverResult(state) {
		var sorted = coverByModule(state);
		var modules = [];
		for (var i = 0; i < sorted.used.length && i < MAX_COVER_MODULES; i++) {
			var s = sorted.used[i];
			modules.push({ name: s.module.name, path: s.module.path || '', blocks: s.blocks.length, bytes: s.bytes });
		}
		var drcov = coverDrcov(sorted);
		var summary = {
			recorded: true,
			threads: state.count,
			all: state.all,
			seconds: Math.round(((state.ended || Date.now()) - state.started) / 100) / 10,
			blocks: sorted.total,
			bytes: sorted.bytes,
			unmapped: sorted.unmapped,
			overflow: state.overflow,
			endedBy: state.endedBy,
			scope: state.scope,
			modules: modules,
			moduleCount: sorted.used.length,
			drcovBytes: drcov.byteLength,
		};
		return { summary: summary, drcov: drcov, text: coverText(state, sorted, summary) };
	}

	// ---- watching memory ----
	// Who reads or writes some bytes. Two ways, and one watch at a time:
	//
	// Exact (Windows; two aligned pieces of up to 8 bytes each): the processor's hardware
	// watchpoints, set on every thread. Each access raises a debug trap right
	// after the instruction that made it; all of them are counted, and nothing
	// about the memory changes.
	//
	// Sampled (anything else, up to a page's worth): the page holding the
	// bytes is trapped (MemoryAccessMonitor); the first access to it is
	// reported with the instruction it came from, and the trap is then gone.
	// So it is put back a moment later, again and again: accesses are sampled,
	// not all counted. The trap covers whole pages; an access to other bytes
	// of the page is counted apart.
	//
	// Either way a watch is bounded in time and in places.
	var MAX_WATCH = 4096;          // bytes watched
	var MAX_WATCH_MS = 600000;     // a watch ends by itself after 10 minutes
	var WATCH_REARM_MS = 5;        // the trap is put back this long after an access
	var WATCH_KEEP_MS = 250;       // ... and this often in any case
	var MAX_WATCH_PLACES = 500;    // distinct (operation, instruction) pairs kept
	var MAX_WATCH_ITEMS = 200;     // ... and reported
	var MAX_WATCH_FRAMES = 16;
	var MAX_WATCH_THREADS = 8;     // thread ids remembered per place
	var WATCH_THREADS_MS = 1000;   // exact: how often new threads are looked for, when their start cannot be hooked
	var MAX_WATCH_HITS = 200000;   // exact: a watch ends after this many accesses
	var WATCH_MODES = ['auto', 'exact', 'sampled'];
	var trapHandler = false;       // the exception handler is installed once
	var watch = null; // { base, end, size, protection, places, order, hits, near, overflow, timer, rearm, keep, endedBy, error, started, ended }

	function watching() { return !!watch && !watch.endedBy; }

	function pageOf(p) { return p.and(ptr(Process.pageSize - 1).not()); }

	// Does [p, p + n) touch a page that is trapped right now?
	function watchedPage(p, n) {
		if (!watching() || watch.mode !== 'sampled') return false;
		var first = pageOf(watch.base);
		var last = pageOf(watch.end.sub(1)).add(Process.pageSize);
		return p.add(n).compare(first) > 0 && p.compare(last) < 0;
	}

	function armWatch(state) {
		MemoryAccessMonitor.enable([{ base: state.base, size: state.size }], {
			onAccess: function (details) { onWatchAccess(state, details); },
		});
	}

	function stopWatch(endedBy) {
		if (!watching()) return;
		watch.endedBy = endedBy;
		watch.ended = Date.now();
		if (watch.timer !== null) { clearTimeout(watch.timer); watch.timer = null; }
		if (watch.rearm !== null) { clearTimeout(watch.rearm); watch.rearm = null; }
		if (watch.keep !== null) { clearInterval(watch.keep); watch.keep = null; }
		if (watch.birth !== null) { try { watch.birth.detach(); } catch (e) { /* already gone */ } watch.birth = null; }
		if (watch.mode === 'exact') disarmThreads(watch);
		else { try { MemoryAccessMonitor.disable(); } catch (e) { /* nothing armed */ } }
	}

	// ---- exact: hardware watchpoints ----
	// A watchpoint covers 1, 2, 4 or (64-bit) 8 bytes at an address aligned to
	// its size, and a thread has four. Each piece of the watch takes two: one
	// that fires on a write and one that fires on any access, because the
	// processor says which watchpoints fired but not what the access was.
	// -> the pieces, or a sentence saying why the bytes cannot be watched this way.
	function exactPieces(p, size) {
		if (Process.platform !== 'windows') return 'hardware watchpoints are used on Windows only';
		if (Process.arch !== 'x64' && Process.arch !== 'ia32') return 'hardware watchpoints are used on x86 processors only';
		var sizes = Process.arch === 'x64' ? [8, 4, 2, 1] : [4, 2, 1];
		var pieces = [];
		var at = p;
		var left = size;
		while (left > 0) {
			if (pieces.length === 2) return 'the bytes need more than two aligned pieces (two pieces of 1, 2, 4 or 8 bytes can be watched exactly)';
			var n = 1;
			for (var i = 0; i < sizes.length; i++) {
				if (sizes[i] <= left && at.and(ptr(sizes[i] - 1)).isNull()) { n = sizes[i]; break; }
			}
			pieces.push({ base: at, size: n });
			at = at.add(n);
			left -= n;
		}
		return pieces;
	}

	// Give one thread the watchpoints. A thread that will not take them (it is
	// ending, or is not ours to change) is left as it was.
	function armThread(state, thread) {
		var done = [];
		try {
			for (var i = 0; i < state.pieces.length; i++) {
				thread.setHardwareWatchpoint(2 * i, state.pieces[i].base, state.pieces[i].size, 'w');
				done.push(2 * i);
				thread.setHardwareWatchpoint(2 * i + 1, state.pieces[i].base, state.pieces[i].size, 'rw');
				done.push(2 * i + 1);
			}
		} catch (e) {
			for (var k = 0; k < done.length; k++) { try { thread.unsetHardwareWatchpoint(done[k]); } catch (e2) { /* gone */ } }
			return false;
		}
		state.armed[thread.id] = true;
		state.threadCount++;
		return true;
	}

	// Every thread but the one this agent runs on, which touches the target's
	// memory on the operator's behalf.
	function armThreads(state) {
		var me = Process.getCurrentThreadId();
		var threads = Process.enumerateThreads();
		for (var i = 0; i < threads.length; i++) {
			if (threads[i].id === me || state.armed[threads[i].id]) continue;
			armThread(state, threads[i]);
		}
	}

	// A new thread arms itself as it starts (every Windows thread begins in
	// RtlUserThreadStart), so not one of its accesses is missed. That function
	// never returns, so the listener must be the plain-function kind, which
	// only sees the entry: one with onEnter/onLeave traps the return too, and
	// a session with such a listener on a function that never returns hangs
	// when it detaches. -> the listener, or null where it cannot be hooked.
	function hookThreadStart(state) {
		try {
			var nt = Process.findModuleByName('ntdll.dll');
			var start = nt ? nt.findExportByName('RtlUserThreadStart') : null;
			if (!start) return null;
			return Interceptor.attach(start, function () {
				if (watch !== state || state.endedBy || state.armed[this.threadId]) return;
				var threads = Process.enumerateThreads();
				for (var i = 0; i < threads.length; i++) {
					if (threads[i].id === this.threadId) { armThread(state, threads[i]); return; }
				}
			});
		} catch (e) {
			return null;
		}
	}

	function disarmThreads(state) {
		var threads = Process.enumerateThreads();
		for (var i = 0; i < threads.length; i++) {
			if (!state.armed[threads[i].id]) continue;
			for (var k = 0; k < state.pieces.length * 2; k++) {
				try { threads[i].unsetHardwareWatchpoint(k); } catch (e) { /* thread gone */ }
			}
		}
		state.armed = {};
	}

	// The debug status register (DR6) in the thread context Windows hands an
	// exception handler: its low four bits say which watchpoints fired.
	function debugStatus(nativeContext) { return nativeContext.add(Process.pointerSize === 8 ? 0x68 : 0x14); }

	// Every debug trap in the process comes here while this agent is loaded.
	// One is taken only when a watch is running and the processor says one of
	// its watchpoints fired; anything else is passed on untouched.
	function onTrap(details) {
		var state = watch;
		if (!state || state.endedBy || state.mode !== 'exact' || details.type !== 'single-step') return false;
		var status;
		var fired;
		try { status = debugStatus(details.nativeContext); fired = status.readU32(); } catch (e) { return false; }
		var mine = fired & ((1 << (state.pieces.length * 2)) - 1);
		if (!mine) return false;
		try { status.writeU32((fired & ~0xf) >>> 0); } catch (e) { /* left as it is */ }
		var tid = Process.getCurrentThreadId();
		for (var i = 0; i < state.pieces.length; i++) {
			var wrote = (mine >> (2 * i)) & 1;
			var any = (mine >> (2 * i + 1)) & 1;
			if (!wrote && !any) continue;
			// The trap comes after the instruction: pc is the one that follows it.
			watchCount(state, wrote ? 'write' : 'read', details.context.pc, state.pieces[i].base, tid, details.context, true);
		}
		if (state.hits >= MAX_WATCH_HITS && !state.limitDue) {
			// Stop from outside this handler: it runs on the thread that trapped.
			state.limitDue = true;
			setTimeout(function () { if (watch === state) stopWatch('limit'); }, 0);
		}
		return true;
	}

	// Put the trap back. With `look`, first make sure the memory is still
	// there: Frida arms an unmapped page without complaint, and the watch
	// would go on seeing nothing. (Looking is only possible with the trap
	// off, and costs more than arming, so the quick re-arm after an access
	// does not.) A watch that cannot go on ends and says why.
	function rearmWatch(state, look) {
		if (watch !== state || state.endedBy) return;
		if (state.rearm !== null) { clearTimeout(state.rearm); state.rearm = null; }
		try { MemoryAccessMonitor.disable(); } catch (e) { /* nothing armed */ }
		if (look) {
			// Freed address space is no range at all, or (Windows) a range with no access.
			var range = Process.findRangeByAddress(state.base);
			if (!range || range.protection.charAt(0) !== 'r') {
				state.error = 'the memory is no longer mapped';
				stopWatch('lost');
				return;
			}
		}
		try {
			armWatch(state);
		} catch (e) {
			state.error = String(e && e.message ? e.message : e);
			stopWatch('lost');
		}
	}

	// Count one access. Runs on the thread that made it: only count here,
	// names are looked up when the result is asked for.
	function watchCount(state, op, from, address, threadId, context, inside) {
		if (inside) state.hits++; else state.near++;
		var key = op + '|' + from.toString();
		var place = state.places[key];
		if (!place) {
			if (state.order.length >= MAX_WATCH_PLACES) {
				state.overflow = true;
			} else {
				// Frida reuses the objects it hands a callback: keep pointers of our own.
				place = state.places[key] = { op: String(op), from: ptr(from.toString()), hits: 0, near: 0, last: null, threads: [], stack: null, named: null };
				state.order.push(key);
			}
		}
		if (place) {
			if (inside) { place.hits++; place.last = address.toString(); } else { place.near++; if (place.last === null) place.last = address.toString(); }
			if (place.threads.indexOf(threadId) < 0 && place.threads.length < MAX_WATCH_THREADS) place.threads.push(threadId);
			// The call stack of the first access on the bytes themselves.
			if (inside && place.stack === null && context) {
				try { place.stack = Thread.backtrace(context, Backtracer.ACCURATE); }
				catch (e) { try { place.stack = Thread.backtrace(context, Backtracer.FUZZY); } catch (e2) { place.stack = []; } }
			}
		}
	}

	// Sampled: runs on the thread that touched the page, before its instruction is retried.
	function onWatchAccess(state, details) {
		if (watch !== state || state.endedBy) return;
		var inside = details.address.compare(state.base) >= 0 && details.address.compare(state.end) < 0;
		watchCount(state, details.operation, details.from, details.address, details.threadId, details.context, inside);
		if (state.rearm === null) state.rearm = setTimeout(function () { state.rearm = null; rearmWatch(state, false); }, WATCH_REARM_MS);
	}

	function watchResult() {
		if (!watch) return { watching: false, endedBy: 'none', mode: '', address: null, size: 0, seconds: 0, hits: 0, near: 0, places: 0, truncated: false, error: '', items: [] };
		var state = watch;
		var keys = state.order.slice();
		keys.sort(function (a, b) { return state.places[b].hits - state.places[a].hits || state.places[b].near - state.places[a].near; });
		var items = [];
		for (var i = 0; i < keys.length && items.length < MAX_WATCH_ITEMS; i++) {
			var place = state.places[keys[i]];
			if (!place.named) place.named = { where: where(place.from), symbol: symbolName(place.from), frames: null };
			if (place.stack !== null && place.named.frames === null) {
				place.named.frames = [];
				for (var f = 0; f < place.stack.length && f < MAX_WATCH_FRAMES; f++) {
					place.named.frames.push({ address: hex(place.stack[f]), where: where(place.stack[f]), symbol: symbolName(place.stack[f]) });
				}
			}
			items.push({
				op: place.op, from: hex(place.from), where: place.named.where, symbol: place.named.symbol,
				hits: place.hits, near: place.near, last: place.last, threads: place.threads.slice(), frames: place.named.frames || [],
			});
		}
		return {
			watching: !state.endedBy,
			endedBy: state.endedBy,
			mode: state.mode,
			address: hex(state.base),
			size: state.size,
			seconds: Math.round(((state.ended || Date.now()) - state.started) / 100) / 10,
			hits: state.hits,
			near: state.near,
			places: keys.length,
			truncated: keys.length > MAX_WATCH_ITEMS || state.overflow,
			error: state.error,
			items: items,
		};
	}

	// ---- tracking the heap ----
	// Which blocks the program allocates and frees, each with the call stack
	// that did it, so that an address can be traced to the block it is (or
	// was) in. The allocator's functions are hooked while tracking runs. A
	// call stack per block is costly in a program that allocates a lot, so
	// tracking can be limited to a range of sizes: other blocks cost one
	// comparison. Everything is bounded: time, live blocks, freed blocks kept.
	var MAX_HEAP_MS = 600000;      // tracking ends by itself after 10 minutes
	var MAX_HEAP_LIVE = 200000;    // live blocks recorded; later ones are not
	var MAX_HEAP_FREED = 20000;    // freed blocks kept, the newest
	var MAX_HEAP_FRAMES = 12;
	var MAX_HEAP_SITES = 100;      // allocation places reported
	var HEAP_SITE_FRAMES = 3;      // callers that make up a place
	var MAX_HEAP_FOUND = 20;       // freed blocks reported for one address
	// Modules a block is allocated through, not by: the place that asked is
	// the first caller outside them.
	var ALLOCATOR_MODULE = /^(ntdll|kernel32|kernelbase|ucrtbase(d)?|msvcrt|vcruntime\d*d?|msvcp\d*d?|libc[.-]|libc\+\+|libstdc\+\+|libsystem_malloc|libsystem_c|libc\.so)/i;
	var heap = null; // { min, max, live, liveBytes, freed, freedNext, allocs, frees, overflow, listeners, depth, functions, timer, endedBy, started, ended, names }

	function heapTracking() { return !!heap && !heap.endedBy; }

	function num(p) { return Number(p.toString()); }

	function heapStack(context) {
		var frames;
		try { frames = Thread.backtrace(context, Backtracer.ACCURATE); }
		catch (e) { try { frames = Thread.backtrace(context, Backtracer.FUZZY); } catch (e2) { frames = []; } }
		return frames.length > MAX_HEAP_FRAMES ? frames.slice(0, MAX_HEAP_FRAMES) : frames;
	}

	// The allocator functions of this platform: [{ name, address, kind }].
	function heapFunctions() {
		var out = [];
		function add(name, kind, address) { if (address) out.push({ name: name, kind: kind, address: address }); }
		if (Process.platform === 'windows') {
			// Every Windows heap allocation (HeapAlloc, malloc, operator new) ends up here.
			var nt = Process.findModuleByName('ntdll.dll');
			if (nt) {
				add('RtlAllocateHeap', 'winalloc', nt.findExportByName('RtlAllocateHeap'));
				add('RtlReAllocateHeap', 'winrealloc', nt.findExportByName('RtlReAllocateHeap'));
				add('RtlFreeHeap', 'winfree', nt.findExportByName('RtlFreeHeap'));
			}
		} else {
			add('malloc', 'malloc', Module.findGlobalExportByName('malloc'));
			add('calloc', 'calloc', Module.findGlobalExportByName('calloc'));
			add('realloc', 'realloc', Module.findGlobalExportByName('realloc'));
			// Aligned blocks come from functions of their own (a C library has some of them).
			add('aligned_alloc', 'aligned', Module.findGlobalExportByName('aligned_alloc'));
			add('memalign', 'aligned', Module.findGlobalExportByName('memalign'));
			add('posix_memalign', 'posix_memalign', Module.findGlobalExportByName('posix_memalign'));
			add('free', 'free', Module.findGlobalExportByName('free'));
		}
		return out;
	}

	function heapWanted(state, size) { return size >= state.min && (state.max === 0 || size <= state.max); }

	function heapRecord(state, address, size, tid, stack) {
		var key = address.toString();
		var old = state.live.get(key);
		if (old) state.liveBytes -= old.size; // its free was not seen
		else if (state.live.size >= MAX_HEAP_LIVE) { state.overflow = true; return; }
		// Frida reuses the object it hands a callback: keep a pointer of our own.
		state.live.set(key, { a: ptr(key), size: size, tid: tid, t: Date.now(), stack: stack, site: null, freeTid: 0, freeT: 0, freeStack: null });
		state.liveBytes += size;
		state.allocs++;
	}

	function heapRelease(state, key, block, tid, stack) {
		state.live.delete(key);
		state.liveBytes -= block.size;
		state.frees++;
		block.freeTid = tid;
		block.freeT = Date.now();
		block.freeStack = stack;
		if (state.freed.length < MAX_HEAP_FREED) state.freed.push(block);
		else { state.freed[state.freedNext] = block; state.freedNext = (state.freedNext + 1) % MAX_HEAP_FREED; }
	}

	// The callbacks for one function. An allocator function called from inside
	// another one on the same thread (realloc getting its memory, the heap
	// growing itself) is not the program's doing: only the outermost counts.
	function heapListener(state, kind) {
		var allocates = kind !== 'free' && kind !== 'winfree';
		if (!allocates) {
			var at = kind === 'winfree' ? 2 : 0;
			return {
				onEnter: function (args) {
					if (heap !== state || state.endedBy || state.depth[this.threadId] > 0) return;
					var p = args[at];
					if (p.isNull()) return;
					var key = p.toString();
					var block = state.live.get(key);
					if (block) heapRelease(state, key, block, this.threadId, heapStack(this.context));
				},
			};
		}
		return {
			onEnter: function (args) {
				var tid = this.threadId;
				var d = state.depth[tid] = (state.depth[tid] || 0) + 1;
				this.outer = d === 1 && heap === state && !state.endedBy;
				this.stack = null;
				this.old = null;
				this.out = null;
				if (!this.outer) return;
				if (kind === 'winalloc') this.size = num(args[2]);
				else if (kind === 'malloc') this.size = num(args[0]);
				else if (kind === 'calloc') this.size = num(args[0]) * num(args[1]);
				else if (kind === 'aligned') this.size = num(args[1]);
				else if (kind === 'posix_memalign') { this.out = ptr(args[0].toString()); this.size = num(args[2]); }
				else if (kind === 'winrealloc') { this.old = args[2].isNull() ? null : args[2].toString(); this.size = num(args[3]); }
				else { this.old = args[0].isNull() ? null : args[0].toString(); this.size = num(args[1]); }
				this.wanted = heapWanted(state, this.size);
				var known = this.old !== null && state.live.has(this.old);
				if (this.wanted || known) this.stack = heapStack(this.context);
			},
			onLeave: function (ret) {
				var tid = this.threadId;
				if (state.depth[tid] > 0) state.depth[tid]--;
				if (!this.outer || heap !== state || state.endedBy) return;
				if (this.out !== null) {
					// posix_memalign: 0 means it worked, and the block is where its first argument points.
					if (!ret.isNull() || !this.wanted) return;
					var made;
					try { made = this.out.readPointer(); } catch (e) { return; }
					if (!made.isNull()) heapRecord(state, made, this.size, tid, this.stack || []);
					return;
				}
				if (ret.isNull()) return;
				if (this.old !== null) {
					var key = this.old;
					var block = state.live.get(key);
					if (block) {
						if (ret.toString() === key) { // resized where it is
							state.liveBytes += this.size - block.size;
							block.size = this.size;
							return;
						}
						heapRelease(state, key, block, tid, this.stack);
					} else if (ret.toString() === key) {
						return; // a block from before tracking began, resized where it is
					}
				}
				if (this.wanted) heapRecord(state, ret, this.size, tid, this.stack || []);
			},
		};
	}

	function stopHeap(endedBy) {
		if (!heapTracking()) return;
		heap.endedBy = endedBy;
		heap.ended = Date.now();
		if (heap.timer !== null) { clearTimeout(heap.timer); heap.timer = null; }
		for (var i = 0; i < heap.listeners.length; i++) {
			try { heap.listeners[i].detach(); } catch (e) { /* already gone */ }
		}
		heap.listeners = [];
		heap.depth = {};
	}

	function heapNamed(state, address) {
		var key = address.toString();
		var named = state.names.get(key);
		if (!named) { named = { address: key, where: where(address), symbol: symbolName(address) }; state.names.set(key, named); }
		return named;
	}

	function heapFrames(state, stack) {
		var out = [];
		for (var i = 0; stack && i < stack.length; i++) out.push(heapNamed(state, stack[i]));
		return out;
	}

	// The place a block was asked for: the first few callers outside the
	// allocator's own modules (one frame is not enough where every allocation
	// goes through the program's own malloc). The key is those addresses.
	function heapSite(state, block, modules) {
		if (block.site !== null) return block.site;
		var stack = block.stack || [];
		var site = stack.length ? stack[0].toString() : '';
		var picked = [];
		for (var i = 0; i < stack.length && picked.length < HEAP_SITE_FRAMES; i++) {
			if (picked.length) { picked.push(stack[i].toString()); continue; }
			var key = stack[i].toString();
			var inAllocator = state.allocatorFrame.get(key);
			if (inAllocator === undefined) {
				var m = null;
				try { m = modules.find(stack[i]); } catch (e) { /* not in a module */ }
				inAllocator = !!m && ALLOCATOR_MODULE.test(m.name);
				state.allocatorFrame.set(key, inAllocator);
			}
			if (!inAllocator) picked.push(key);
		}
		if (picked.length) site = picked.join('|');
		block.site = site;
		return site;
	}

	function heapStatus() {
		if (!heap) return { tracking: false, endedBy: 'none', seconds: 0, min: 0, max: 0, functions: [], allocs: 0, frees: 0, live: 0, liveBytes: 0, freedKept: 0, overflow: false, siteCount: 0, sites: [] };
		var state = heap;
		var modules = new ModuleMap();
		var totals = {};
		var keys = [];
		state.live.forEach(function (block) {
			var site = heapSite(state, block, modules);
			var t = totals[site];
			if (!t) { t = totals[site] = { blocks: 0, bytes: 0 }; keys.push(site); }
			t.blocks++;
			t.bytes += block.size;
		});
		keys.sort(function (a, b) { return totals[b].bytes - totals[a].bytes || totals[b].blocks - totals[a].blocks; });
		// The counts are taken now, with the places: looking names up below
		// can take a while, and the program goes on allocating meanwhile.
		var counts = { allocs: state.allocs, frees: state.frees, live: state.live.size, liveBytes: state.liveBytes, freedKept: state.freed.length, overflow: state.overflow };
		var sites = [];
		for (var i = 0; i < keys.length && sites.length < MAX_HEAP_SITES; i++) {
			var frames = [];
			var parts = keys[i] ? keys[i].split('|') : [];
			for (var f = 0; f < parts.length; f++) frames.push(heapNamed(state, ptr(parts[f])));
			sites.push({ frames: frames, blocks: totals[keys[i]].blocks, bytes: totals[keys[i]].bytes });
		}
		return {
			tracking: !state.endedBy,
			endedBy: state.endedBy,
			seconds: Math.round(((state.ended || Date.now()) - state.started) / 100) / 10,
			min: state.min,
			max: state.max,
			functions: state.functions,
			allocs: counts.allocs,
			frees: counts.frees,
			live: counts.live,
			liveBytes: counts.liveBytes,
			freedKept: counts.freedKept,
			overflow: counts.overflow,
			siteCount: keys.length,
			sites: sites,
		};
	}

	function heapBlock(state, block, p) {
		var seconds = function (t) { return Math.round((t - state.started) / 100) / 10; };
		return {
			address: hex(block.a),
			size: block.size,
			offset: num(p.sub(block.a)),
			thread: block.tid,
			at: seconds(block.t),
			frames: heapFrames(state, block.stack),
			freed: block.freeT ? { thread: block.freeTid, at: seconds(block.freeT), frames: heapFrames(state, block.freeStack) } : null,
		};
	}

	// ---- strings and references ----
	// The strings of a module, and what refers to an address: the two usual
	// ways into a program nothing is known about. Both only read the module's
	// memory, a megabyte at a time, and both are bounded in time and in how
	// much they return.
	var STR_CHUNK = 1 << 20;
	var STR_OVERLAP = 512;         // a string that starts near the end of a chunk is read into the next
	var MAX_STRINGS = 2000;        // strings returned
	var MAX_STRING_CHARS = 200;    // characters returned of one string
	var MAX_STRINGS_MS = 8000;
	var MAX_REFS = 200;            // references returned of each kind
	var MAX_REFS_MS = 10000;

	function printable(c) { return c >= 0x20 && c < 0x7f; }

	// query: { text, min }. -> { module, items: [{ address, where, kind, length, text }], total, truncated, scanned, timedOut }
	function moduleStrings(name, query) {
		var m = moduleByName(name);
		var min = query && query.min > 0 ? Math.floor(query.min) : 5;
		var needle = query && query.text ? String(query.text).toLowerCase() : '';
		var started = Date.now();
		var items = [];
		var total = 0, scanned = 0, timedOut = false;

		function found(address, kind, length, bytes, from, step) {
			var n = Math.min(length, MAX_STRING_CHARS);
			var text = '';
			for (var i = 0; i < n; i++) text += String.fromCharCode(bytes[from + i * step]);
			if (needle && text.toLowerCase().indexOf(needle) < 0) return;
			total++;
			if (items.length < MAX_STRINGS) items.push({ address: hex(address), where: where(address), kind: kind, length: length, text: text });
		}

		var ranges = m.enumerateRanges('r--');
		for (var r = 0; r < ranges.length && !timedOut; r++) {
			var range = ranges[r];
			if (range.protection.charAt(2) === 'x') continue; // code: its bytes spell things by accident
			// A run that reaches the end of a chunk is finished in the next one:
			// each chunk is read a little past its end, and runs only start inside it.
			var asciiOpen = false, wideOpen = false;
			for (var off = 0; off < range.size; off += STR_CHUNK) {
				var body = Math.min(STR_CHUNK, range.size - off);
				var n = Math.min(body + STR_OVERLAP, range.size - off);
				var bytes;
				try { bytes = new Uint8Array(range.base.add(off).readByteArray(n)); } catch (e) { asciiOpen = wideOpen = false; continue; }
				scanned += body;
				var i = 0;
				if (asciiOpen) { while (i < n && printable(bytes[i])) i++; } // the rest of a run already reported
				while (i < body) {
					if (!printable(bytes[i])) { i++; continue; }
					var start = i;
					while (i < n && printable(bytes[i])) i++;
					if (i - start >= min) found(range.base.add(off + start), 'ascii', i - start, bytes, start, 1);
				}
				asciiOpen = i >= body && body < n && printable(bytes[body - 1]) && printable(bytes[body]);
				// UTF-16, little endian, characters that are ASCII: a printable byte then a zero byte.
				var k = 0;
				if (wideOpen) { while (k + 1 < n && bytes[k + 1] === 0 && printable(bytes[k])) k += 2; }
				while (k + 1 < body + 1 && k < body) {
					if (!(bytes[k + 1] === 0 && printable(bytes[k]))) { k += 2; continue; }
					var ws = k;
					while (k + 1 < n && bytes[k + 1] === 0 && printable(bytes[k])) k += 2;
					if ((k - ws) / 2 >= min) found(range.base.add(off + ws), 'utf16', (k - ws) / 2, bytes, ws, 2);
				}
				wideOpen = k >= body && body + 1 < n && bytes[body + 1] === 0 && printable(bytes[body]) && body >= 2 && bytes[body - 1] === 0 && printable(bytes[body - 2]);
				if (Date.now() - started > MAX_STRINGS_MS) { timedOut = true; break; }
			}
		}
		// The two kinds are found in separate passes over each chunk: put them in address order.
		items.sort(function (x, y) { return parseInt(x.address, 16) - parseInt(y.address, 16); });
		return { module: m.name, items: items, total: total, truncated: total > items.length, scanned: scanned, timedOut: timedOut };
	}

	// An address as the bytes of a pointer in memory (little endian), for Memory.scan.
	function pointerPattern(p) {
		var digits = p.toString(16);
		while (digits.length < Process.pointerSize * 2) digits = '0' + digits;
		var out = [];
		for (var i = digits.length - 2; i >= 0; i -= 2) out.push(digits.substr(i, 2));
		return out.join(' ');
	}

	// The instruction that holds the four bytes at `at` as (the end of) its
	// operand, with `after` bytes of immediate following them, and that
	// really refers to `target`. Several starts before `at` can decode to an
	// instruction ending in the right place (the tail of `lea rdx, [rip+d]`
	// is also `adc eax, imm32`): only one that names the target, or reaches
	// it relative to the instruction pointer, is a reference.
	// -> the instruction, or null. (Short jumps inside a function, with a
	// one-byte distance, are not looked for.)
	function instructionHolding(at, after, target) {
		var end = at.add(4 + after);
		var named = '0x' + target.toString(16);
		var best = null;
		for (var back = 1; back <= 11; back++) {
			try {
				var insn = Instruction.parse(at.sub(back));
				if (insn.next.compare(end) !== 0) continue;
				var operands = String(insn.opStr || '').toLowerCase();
				// The longest that fits: the same bytes without their prefix decode too.
				if (operands.indexOf('rip') >= 0 || operands.indexOf(named) >= 0) best = insn;
			} catch (e) { /* not an instruction start */ }
		}
		return best;
	}

	// What refers to an address inside one module: pointers to it (in data and
	// in code), and x86 instructions that reach it relative to themselves
	// (calls, jumps, and on 64-bit every lea/mov of a global or a string).
	function moduleRefs(address, name) {
		var target = ptr(address);
		var m = name ? moduleByName(name) : Process.findModuleByAddress(target);
		if (!m) throw new Error(hex(target) + ' is not inside a module. Name the module to search.');
		var started = Date.now();
		var pointers = [], code = [];
		var truncated = false, timedOut = false, unconfirmed = 0;
		var ranges = m.enumerateRanges('r--');
		var pattern = pointerPattern(target);
		for (var r = 0; r < ranges.length; r++) {
			var hits;
			try { hits = Memory.scanSync(ranges[r].base, ranges[r].size, pattern); } catch (e) { continue; }
			var inCode = ranges[r].protection.charAt(2) === 'x';
			for (var h = 0; h < hits.length; h++) {
				// In code, the address is the operand of an instruction (32-bit
				// code names addresses outright): list the instruction.
				var holder = null;
				if (inCode) {
					var gaps = [0, 1, 2, 4];
					for (var g = 0; g < gaps.length && !holder; g++) holder = instructionHolding(hits[h].address, gaps[g] + Process.pointerSize - 4, target);
				}
				if (holder) {
					if (code.length >= MAX_REFS) { truncated = true; continue; }
					code.push({ address: hex(holder.address), where: where(holder.address), text: holder.mnemonic + (holder.opStr ? ' ' + holder.opStr : '') });
					continue;
				}
				if (pointers.length >= MAX_REFS) { truncated = true; break; }
				pointers.push({ address: hex(hits[h].address), where: where(hits[h].address) });
			}
		}
		var relative = Process.arch === 'x64' || Process.arch === 'ia32';
		var targetNumber = parseInt(target.toString(16), 16);
		for (var x = 0; relative && x < ranges.length && !timedOut; x++) {
			if (ranges[x].protection.charAt(2) !== 'x') continue;
			for (var off = 0; off < ranges[x].size; off += STR_CHUNK) {
				var n = Math.min(STR_CHUNK + 3, ranges[x].size - off);
				var bytes;
				try { bytes = new Uint8Array(ranges[x].base.add(off).readByteArray(n)); } catch (e) { continue; }
				var chunkBase = ranges[x].base.add(off);
				// A displacement d at index i refers to: chunk + i + 4 + (bytes of immediate after it) + d.
				var want = targetNumber - parseInt(chunkBase.toString(16), 16) - 4;
				for (var i = 0; i + 3 < n; i++) {
					var gap = want - i - (bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24));
					if (gap !== 0 && gap !== 1 && gap !== 2 && gap !== 4) continue;
					var insn = instructionHolding(chunkBase.add(i), gap, target);
					if (!insn) { unconfirmed++; continue; }
					if (code.length >= MAX_REFS) { truncated = true; continue; }
					code.push({ address: hex(insn.address), where: where(insn.address), text: insn.mnemonic + (insn.opStr ? ' ' + insn.opStr : '') });
				}
				if (Date.now() - started > MAX_REFS_MS) { timedOut = true; break; }
			}
		}
		return { address: hex(target), module: m.name, pointers: pointers, code: code, relative: relative, unconfirmed: unconfirmed, truncated: truncated, timedOut: timedOut };
	}

	// ---- asking Windows which block an address is in ----
	// Windows can list the entries of its heaps (HeapWalk): the blocks in use
	// and the free space between them. That answers for an address nothing
	// was recorded about: a block from before tracking began, or memory that
	// is free right now. It says nothing about who allocated or freed it.
	var MAX_WALK_MS = 3000;   // a walk gives up after this long
	var MAX_WALK_HEAPS = 256;
	var HEAP_ENTRY_BUSY = 4, HEAP_REGION = 1, HEAP_UNCOMMITTED = 2;
	var winHeap; // the four functions, null where they are not to be had; undefined until looked for

	function winHeapApi() {
		if (winHeap !== undefined) return winHeap;
		winHeap = null;
		if (Process.platform !== 'windows') return null;
		try {
			var k32 = Process.findModuleByName('kernel32.dll');
			if (!k32) return null;
			var abi = Process.pointerSize === 4 ? 'stdcall' : 'default';
			var get = function (name, ret, args) {
				var address = k32.findExportByName(name);
				if (!address) throw new Error(name + ' not found');
				return new NativeFunction(address, ret, args, abi);
			};
			winHeap = {
				heaps: get('GetProcessHeaps', 'uint32', ['uint32', 'pointer']),
				lock: get('HeapLock', 'int', ['pointer']),
				unlock: get('HeapUnlock', 'int', ['pointer']),
				walk: get('HeapWalk', 'int', ['pointer', 'pointer']),
			};
		} catch (e) {
			winHeap = null;
		}
		return winHeap;
	}

	// -> { state: 'live' | 'free' | 'none', address, size, offset, timedOut },
	// or null where the heaps cannot be walked (not Windows).
	function heapWalk(p) {
		var api = winHeapApi();
		if (!api) return null;
		var P = Process.pointerSize;
		var result = { state: 'none', address: null, size: 0, offset: 0, timedOut: false };
		var started = Date.now();
		var seen = 0;
		try {
			var list = Memory.alloc(P * MAX_WALK_HEAPS);
			var count = Math.min(api.heaps(MAX_WALK_HEAPS, list), MAX_WALK_HEAPS);
			for (var h = 0; h < count; h++) {
				var heapHandle = list.add(h * P).readPointer();
				// PROCESS_HEAP_ENTRY, zeroed: lpData, cbData (u32), cbOverhead (u8),
				// iRegionIndex (u8), wFlags (u16), then a union.
				var entry = Memory.alloc(P === 8 ? 40 : 28);
				if (!api.lock(heapHandle)) continue; // other threads wait for this heap meanwhile: be quick
				try {
					while (api.walk(heapHandle, entry)) {
						var flags = entry.add(P + 6).readU16();
						if (!(flags & (HEAP_REGION | HEAP_UNCOMMITTED))) {
							var data = entry.readPointer();
							var size = entry.add(P).readU32();
							if (p.compare(data) >= 0 && p.compare(data.add(size > 0 ? size : 1)) < 0) {
								result.state = (flags & HEAP_ENTRY_BUSY) ? 'live' : 'free';
								result.address = hex(data);
								result.size = size;
								result.offset = num(p.sub(data));
								return result;
							}
						}
						if ((++seen & 1023) === 0 && Date.now() - started > MAX_WALK_MS) { result.timedOut = true; return result; }
					}
				} catch (e) {
					// A damaged heap can fault under the walk: leave it and go on to the next.
				} finally {
					api.unlock(heapHandle);
				}
			}
		} catch (e) {
			// Nothing to report beyond "not found".
		}
		return result;
	}

	function heapHolds(block, p) {
		return p.compare(block.a) >= 0 && p.compare(block.a.add(block.size > 0 ? block.size : 1)) < 0;
	}

	rpc.exports = {
		strings: function (name, query) { return moduleStrings(name, query); },

		refs: function (address, name) { return moduleRefs(address, name); },

		// sizes: { min, max } in bytes; max 0 means no upper limit.
		heapStart: function (sizes) {
			if (heapTracking()) throw new Error('The heap is already being tracked. Stop that first.');
			var min = sizes && sizes.min > 0 ? Math.floor(sizes.min) : 0;
			var max = sizes && sizes.max > 0 ? Math.floor(sizes.max) : 0;
			if (max !== 0 && max < min) throw new Error('The largest size must not be below the smallest');
			var functions = heapFunctions();
			if (!functions.length) throw new Error('No allocator function was found in this process.');
			var state = {
				min: min, max: max, live: new Map(), liveBytes: 0, freed: [], freedNext: 0, allocs: 0, frees: 0, overflow: false,
				listeners: [], depth: {}, functions: [], timer: null, endedBy: '', started: Date.now(), ended: 0,
				names: new Map(), allocatorFrame: new Map(),
			};
			heap = state;
			try {
				for (var i = 0; i < functions.length; i++) {
					state.listeners.push(Interceptor.attach(functions[i].address, heapListener(state, functions[i].kind)));
					state.functions.push(functions[i].name);
				}
			} catch (e) {
				stopHeap('error');
				heap = null;
				throw new Error('Could not hook the allocator: ' + e.message);
			}
			state.timer = setTimeout(function () { if (heap === state) stopHeap('limit'); }, MAX_HEAP_MS);
			return { tracking: true, functions: state.functions, min: min, max: max, maxSeconds: MAX_HEAP_MS / 1000, maxLive: MAX_HEAP_LIVE, maxFreed: MAX_HEAP_FREED };
		},

		// Counts, and the places that hold the most live memory.
		heapStatus: function () { return heapStatus(); },

		heapStop: function () {
			stopHeap('stop');
			return heapStatus();
		},

		// The block an address is in now, and the freed blocks it was in
		// before (newest first), from what the last tracking recorded. For an
		// address not in a recorded live block, Windows is asked as well
		// (`system`): that works with nothing tracked at all.
		heapFind: function (address) {
			var p = ptr(address);
			if (!heap) {
				// Nothing recorded: on Windows the heaps themselves can still be asked.
				var asked = heapWalk(p);
				if (asked === null) throw new Error('Nothing has been tracked yet. Start tracking first.');
				return { address: hex(p), tracking: false, live: null, freed: [], freedTotal: 0, system: asked };
			}
			var state = heap;
			var live = null;
			state.live.forEach(function (block) { if (live === null && heapHolds(block, p)) live = block; });
			var found = [];
			var total = 0;
			var n = state.freed.length;
			for (var i = 0; i < n; i++) {
				// Newest first: the ring's next slot holds the oldest.
				var block = state.freed[(state.freedNext - 1 - i + 2 * n) % n];
				if (!heapHolds(block, p)) continue;
				total++;
				if (found.length < MAX_HEAP_FOUND) found.push(heapBlock(state, block, p));
			}
			// A block that was recorded and is live needs no second opinion.
			return { address: hex(p), tracking: !state.endedBy, live: live ? heapBlock(state, live, p) : null, freed: found, freedTotal: total, system: live ? null : heapWalk(p) };
		},

		// Watch `size` bytes at `address`: exactly where that is possible,
		// otherwise (or when mode is 'sampled') by trapping their page. Only
		// data that is mapped and readable: code is hooked instead, and a
		// thread's stack is refused.
		watchStart: function (address, size, mode) {
			if (mode === undefined || mode === null) mode = 'auto';
			if (WATCH_MODES.indexOf(mode) < 0) throw new Error('The watch mode must be auto, exact or sampled');
			if (watching()) throw new Error(hex(watch.base) + ' is already being watched. Stop that first.');
			if (typeof size !== 'number' || size !== Math.floor(size) || size < 1 || size > MAX_WATCH) throw new Error('A watch covers 1..' + MAX_WATCH + ' bytes');
			var p = ptr(address);
			var range = Process.findRangeByAddress(p);
			if (!range) throw new Error('Memory at ' + hex(p) + ' is not in mapped memory');
			var prot = range.protection;
			if (prot.charAt(0) !== 'r') throw new Error('Memory at ' + hex(p) + ' is not readable');
			if (prot.charAt(2) === 'x') throw new Error(hex(p) + ' is code. A watch is for data; hook the code instead.');
			if (range.size - Number(p.sub(range.base).toString()) < size) throw new Error('A watch of ' + size + ' bytes at ' + hex(p) + ' crosses the end of its range');
			// Never a thread's stack. The system uses it all the time, so a page
			// trap there breaks the thread; and handling a debug trap uses the
			// stack of the thread that trapped, so a hardware watchpoint there
			// fires again inside its own handling and takes the process down.
			var threads = Process.enumerateThreads();
			for (var i = 0; i < threads.length; i++) {
				var sp = threads[i].context && threads[i].context.sp;
				var stack = sp ? Process.findRangeByAddress(sp) : null;
				if (stack && p.compare(stack.base) >= 0 && p.compare(stack.base.add(stack.size)) < 0) {
					throw new Error(hex(p) + ' is on the stack of thread ' + threads[i].id + '. A stack cannot be watched safely.');
				}
			}
			var state = {
				mode: 'sampled', base: p, end: p.add(size), size: size, protection: prot, places: {}, order: [], hits: 0, near: 0, overflow: false,
				timer: null, rearm: null, keep: null, endedBy: '', error: '', started: Date.now(), ended: 0,
				pieces: [], armed: {}, threadCount: 0, limitDue: false, birth: null,
			};
			// Why the watch is sampled, when exact was possible in principle.
			var reason = '';
			var pieces = mode === 'sampled' ? 'the page trap was asked for' : exactPieces(p, size);
			if (typeof pieces !== 'string') {
				state.mode = 'exact';
				state.pieces = pieces;
				armThreads(state);
				if (!state.threadCount) {
					state.mode = 'sampled';
					pieces = 'No thread would take a hardware watchpoint';
				}
			}
			if (state.mode === 'sampled') {
				if (mode === 'exact') throw new Error('These bytes cannot be watched exactly: ' + pieces);
				if (mode === 'auto') reason = pieces;
				armWatch(state); // throws when the page cannot be trapped
				watch = state;
				state.keep = setInterval(function () { rearmWatch(state, true); }, WATCH_KEEP_MS);
			} else {
				if (!trapHandler) { Process.setExceptionHandler(onTrap); trapHandler = true; }
				watch = state;
				state.birth = hookThreadStart(state);
				if (state.birth === null) state.keep = setInterval(function () { if (watch === state && !state.endedBy) armThreads(state); }, WATCH_THREADS_MS);
			}
			state.timer = setTimeout(function () { if (watch === state) stopWatch('limit'); }, MAX_WATCH_MS);
			var pages = Number(pageOf(state.end.sub(1)).sub(pageOf(p)).toString()) / Process.pageSize + 1;
			return { watching: true, address: hex(p), size: size, mode: state.mode, reason: reason, threads: state.threadCount, pages: pages, pageSize: Process.pageSize, maxSeconds: MAX_WATCH_MS / 1000, protection: prot };
		},

		// What has been seen so far (or by the last watch, once it has ended).
		watchHits: function () { return watchResult(); },

		watchStop: function () {
			stopWatch('stop');
			return watchResult();
		},

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
			if (cover && !cover.endedBy) throw new Error('Coverage is being recorded. Stop that first.');
			if (id === Process.getCurrentThreadId()) throw new Error("That is Frida's own thread; it cannot be followed.");
			findThread(id); // throws for an unknown thread
			var resolved = resolveScope(scope); // throws for an unknown module
			if (excludedScope && excludedScope !== resolved.key) {
				// A fresh agent would end the watch without a word.
				if (watching()) throw new Error('A memory watch is running. Stop that first.');
				if (heapTracking()) throw new Error('Heap tracking is running. Stop that first.');
				throw new Error('FERMION_RESCOPE');
			}
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

		// threads: 'all' or one thread id; scope as for follow.
		coverStart: function (threads, scope) {
			if (follow && !follow.endedBy) throw new Error('Thread ' + follow.threadId + ' is being followed. Stop that first.');
			if (cover && !cover.endedBy) throw new Error('Coverage is already being recorded. Stop that first.');
			var all = threads === 'all';
			var ids;
			if (all) {
				ids = otherThreadIds();
			} else {
				if (threads === Process.getCurrentThreadId()) throw new Error("That is Frida's own thread; it cannot be followed.");
				findThread(threads); // throws for an unknown thread
				ids = [threads];
			}
			var resolved = resolveScope(scope); // throws for an unknown module
			if (excludedScope && excludedScope !== resolved.key) {
				// A fresh agent would end the watch without a word.
				if (watching()) throw new Error('A memory watch is running. Stop that first.');
				if (heapTracking()) throw new Error('Heap tracking is running. Stop that first.');
				throw new Error('FERMION_RESCOPE');
			}
			var excluded = applyScope(resolved);
			var state = { all: all, threads: {}, count: 0, scope: resolved.scope, skip: resolved.skip, blocks: {}, n: 0, overflow: false, timer: null, poll: null, endedBy: '', started: Date.now(), ended: 0 };
			for (var i = 0; i < ids.length; i++) coverThread(state, ids[i]);
			if (!state.count) throw new Error('No thread could be followed.');
			cover = state;
			covered = null;
			if (all) {
				state.poll = setInterval(function () {
					if (cover !== state || state.endedBy) return;
					var now = otherThreadIds();
					for (var k = 0; k < now.length; k++) coverThread(state, now[k]);
				}, COVER_POLL_MS);
			}
			state.timer = setTimeout(function () { if (cover === state) stopCover('limit'); }, MAX_COVER_MS);
			return { recording: true, threads: state.count, all: all, maxSeconds: MAX_COVER_MS / 1000, maxBlocks: MAX_COVER_BLOCKS, scope: resolved.scope, excluded: excluded };
		},

		// Stop (if still running) and return the summary. It is given again
		// until another recording starts.
		coverStop: function () {
			if (!cover) return covered ? covered.summary : { recorded: false };
			stopCover('stop');
			var state = cover;
			return new Promise(function (resolve) {
				setTimeout(function () {
					try { Stalker.garbageCollect(); } catch (e) { /* best effort */ }
					covered = coverResult(state);
					if (cover === state) cover = null;
					resolve(covered.summary);
				}, COVER_SETTLE_MS);
			});
		},

		// The last recording as a file: 'text' is the report, anything else the
		// drcov file (binary).
		coverData: function (format) {
			if (!covered) throw new Error('No coverage has been recorded.');
			return format === 'text' ? covered.text : covered.drcov;
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

		// Overwrite bytes. The write must lie inside one mapped, readable
		// range. What was there is read first and returned, so it can be put
		// back. Code goes through Memory.patchCode (which handles pages that
		// may not be writable and executable at once, and the instruction
		// cache); read-only data is made writable for the write only.
		write: function (address, bytesHex) {
			if (typeof bytesHex !== 'string' || !/^(?:[0-9a-fA-F]{2})+$/.test(bytesHex) || bytesHex.length > MAX_WRITE * 2) {
				throw new Error('The bytes to write must be 1..' + MAX_WRITE + ' hex bytes');
			}
			var n = bytesHex.length / 2;
			var bytes = [];
			for (var i = 0; i < n; i++) bytes.push(parseInt(bytesHex.substr(i * 2, 2), 16));
			var p = ptr(address);
			if (watchedPage(p, n)) throw new Error('Memory at ' + hex(p) + ' is being watched. Stop the watch to write it.');
			var range = Process.findRangeByAddress(p);
			if (!range) throw new Error('Memory at ' + hex(p) + ' is not in mapped memory');
			var prot = range.protection;
			if (prot.charAt(0) !== 'r') throw new Error('Memory at ' + hex(p) + ' is not readable');
			if (range.size - Number(p.sub(range.base).toString()) < n) throw new Error('A write of ' + n + ' bytes at ' + hex(p) + ' crosses the end of its range');
			var original;
			try {
				original = bytesToHex(p.readByteArray(n));
			} catch (e) {
				throw new Error('Cannot read memory at ' + hex(p) + ': ' + e.message);
			}
			try {
				if (prot.charAt(2) === 'x') {
					Memory.patchCode(p, n, function (code) { code.writeByteArray(bytes); });
				} else if (prot.charAt(1) === 'w') {
					p.writeByteArray(bytes);
				} else {
					if (!Memory.protect(p, n, 'rw-')) throw new Error('the memory could not be made writable');
					try { p.writeByteArray(bytes); } finally { Memory.protect(p, n, prot); }
				}
			} catch (e) {
				throw new Error('Cannot write memory at ' + hex(p) + ': ' + e.message);
			}
			return { address: hex(p), size: n, original: original, written: bytesHex.toLowerCase(), protection: prot };
		},

		ranges: function (protection) {
			return capped(Process.enumerateRanges(protection), MAX_RANGES, function (r) {
				return { base: hex(r.base), size: r.size, protection: r.protection, file: r.file ? r.file.path : '' };
			});
		},

		read: function (address, size) {
			var n = Math.max(1, Math.min(MAX_READ, size | 0));
			var p = ptr(address);
			// Reading a trapped page would spring the trap (and Frida hides such a page).
			if (watchedPage(p, n)) throw new Error('Memory at ' + hex(p) + ' is being watched. Stop the watch to read it.');
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
