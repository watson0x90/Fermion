// Fermion Hooks agent. Loaded as its own Frida script inside the attached
// process and driven over rpc by the Hooks tab: find functions, hook them with
// Interceptor, and report what the hooks log.
//
// A hook's handler is JavaScript the operator wrote:
//   ({ onEnter(log, args) { ... }, onLeave(log, retval) { ... } })
// `this` inside both is Frida's InvocationContext, so a value stored in
// onEnter is there in onLeave. What `log` is given becomes one line in the
// Hooks tab.
//
// Hits are not sent one message each: they are collected and sent in batches,
// and anything beyond the batch size is counted as dropped, so a function
// called a million times a second cannot flood the app.

(function () {
	var MAX_RESULTS = 500;      // functions returned by one search
	var MAX_HOOKS = 200;
	var MAX_TEXT = 2000;        // characters per logged line
	var MAX_FRAMES = 16;        // backtrace frames kept per hit
	var FLUSH_MS = 100;         // hits are sent this often
	var MAX_BATCH = 200;        // hits per batch; the rest are dropped (and counted)
	var MAX_SYMBOLICATE = 64;

	var hooks = {};             // id -> hook
	var hookCount = 0;
	var started = Date.now();
	var pending = [];
	var dropped = 0;
	var dirty = {};             // id -> true: its call count changed since the last flush
	var timer = null;
	var seq = 0;

	function hex(p) { return p.toString(); }

	function moduleOf(address) {
		try { return Process.findModuleByAddress(address); } catch (e) { return null; }
	}

	// One search result. The module + offset is what a hook is anchored to, so
	// it can be found again after the target restarts at another base address.
	function describeTarget(address, symbol) {
		var m = moduleOf(address);
		var name = symbol || '';
		if (!name) {
			try { var s = DebugSymbol.fromAddress(address); if (s && s.name) name = s.name; } catch (e) { /* no symbol */ }
		}
		var offset = m ? Number(address.sub(m.base).toString()) : null;
		if (!name) name = m ? '0x' + offset.toString(16) : hex(address);
		return {
			name: (m ? m.name + '!' : '') + name,
			module: m ? m.name : '',
			offset: offset,
			address: hex(address),
		};
	}

	function hasWildcard(s) { return /[*?]/.test(s); }
	// "open" finds anything containing it; a query with * or ? is taken as written.
	function glob(s) { return hasWildcard(s) ? s : '*' + s + '*'; }

	// "module!function" -> [module, function]; "function" -> ['', function].
	function splitQuery(query) {
		var i = query.indexOf('!');
		return i < 0 ? ['', query] : [query.slice(0, i), query.slice(i + 1)];
	}

	function collector() {
		var seen = {};
		var items = [];
		var total = 0;
		return {
			add: function (address, symbol) {
				var key = hex(address);
				if (seen[key]) return;
				seen[key] = true;
				total++;
				if (items.length < MAX_RESULTS) items.push(describeTarget(address, symbol));
			},
			result: function () { return { items: items, total: total, truncated: total > items.length }; },
		};
	}

	function symbolPart(name) {
		var i = name.lastIndexOf('!');
		return i < 0 ? name : name.slice(i + 1);
	}

	function searchResolver(type, query, out) {
		var parts = splitQuery(query);
		var mod = parts[0] ? glob(parts[0]) : '*';
		var fn = parts[1] ? glob(parts[1]) : '*';
		var matches = new ApiResolver('module').enumerateMatches(type + ':' + mod + '!' + fn + '/i');
		for (var i = 0; i < matches.length; i++) out.add(matches[i].address, symbolPart(matches[i].name));
	}

	function searchSymbols(query, out) {
		var parts = splitQuery(query);
		var want = parts[0].toLowerCase();
		var addresses = DebugSymbol.findFunctionsMatching(glob(parts[1] || '*'));
		for (var i = 0; i < addresses.length; i++) {
			if (want) {
				var m = moduleOf(addresses[i]);
				if (!m || m.name.toLowerCase().indexOf(want.replace(/[*?]/g, '')) < 0) continue;
			}
			out.add(addresses[i], '');
		}
	}

	// "0x7ff…" or "module!0x1a2b": one exact place, whatever kind was asked for.
	function exactAddress(query) {
		var parts = splitQuery(query);
		if (!/^0x[0-9a-f]+$/i.test(parts[1])) return null;
		if (!parts[0]) return ptr(parts[1]);
		var m = Process.findModuleByName(parts[0]);
		if (!m) throw new Error('Module not found: ' + parts[0]);
		return m.base.add(ptr(parts[1]));
	}

	// ---- reporting hits ----
	function flush() {
		timer = null;
		var counts = {};
		var any = pending.length > 0 || dropped > 0;
		for (var id in dirty) { if (hooks[id]) { counts[id] = hooks[id].calls; any = true; } }
		dirty = {};
		if (!any) return;
		var hits = pending;
		var lost = dropped;
		pending = [];
		dropped = 0;
		send({ fermionHooks: 'hits', hits: hits, dropped: lost, counts: counts });
	}
	function schedule() { if (timer === null) timer = setTimeout(flush, FLUSH_MS); }

	function textOf(value) {
		if (typeof value === 'string') return value;
		if (value === null || value === undefined) return String(value);
		if (typeof value === 'object') {
			// Pointers, Int64 and friends print as themselves; plain data as JSON.
			try {
				var proto = Object.getPrototypeOf(value);
				if (Array.isArray(value) || proto === Object.prototype || proto === null) {
					var s = JSON.stringify(value);
					if (s !== undefined && s !== '{}') return s;
				}
			} catch (e) { /* fall through */ }
		}
		try { return String(value); } catch (e) { return '[unprintable]'; }
	}

	function record(hook, phase, ctx, values, isError) {
		if (pending.length >= MAX_BATCH) { dropped++; schedule(); return; }
		var text = '';
		for (var i = 0; i < values.length; i++) text += (i ? ' ' : '') + textOf(values[i]);
		if (text.length > MAX_TEXT) text = text.slice(0, MAX_TEXT) + '…';
		var hit = {
			seq: ++seq,
			id: hook.id,
			t: Date.now() - started,
			tid: ctx.threadId,
			depth: ctx.depth,
			phase: phase,
			text: text,
		};
		if (isError) hit.error = true;
		// Where the call came from: taken once per call, on entry, and only when
		// something is logged.
		if (hook.backtrace && phase === 'enter' && !ctx.__fermionTraced) {
			ctx.__fermionTraced = true;
			try {
				var frames = Thread.backtrace(ctx.context, Backtracer.ACCURATE);
				var bt = [];
				for (var k = 0; k < frames.length && bt.length < MAX_FRAMES; k++) bt.push(hex(frames[k]));
				hit.bt = bt;
			} catch (e) { /* no backtrace for this call */ }
		}
		pending.push(hit);
		schedule();
	}

	// ---- handlers ----
	function compile(code) {
		var handler;
		try {
			handler = (0, eval)('(' + code + '\n)');
		} catch (e) {
			throw new Error('The handler does not compile: ' + e.message);
		}
		if (typeof handler === 'function') handler = { onEnter: handler };
		if (!handler || typeof handler !== 'object') throw new Error('The handler must be ({ onEnter(log, args) {…}, onLeave(log, retval) {…} })');
		var onEnter = handler.onEnter;
		var onLeave = handler.onLeave;
		if (onEnter !== undefined && typeof onEnter !== 'function') throw new Error('onEnter must be a function');
		if (onLeave !== undefined && typeof onLeave !== 'function') throw new Error('onLeave must be a function');
		if (!onEnter && !onLeave) throw new Error('The handler needs an onEnter or an onLeave function');
		return { onEnter: onEnter || null, onLeave: onLeave || null };
	}

	function run(hook, phase, ctx, fn, arg) {
		var log = function () { record(hook, phase, ctx, arguments, false); };
		try {
			fn.call(ctx, log, arg);
		} catch (e) {
			record(hook, phase, ctx, [(phase === 'enter' ? 'onEnter' : 'onLeave') + ' threw: ' + (e && e.message ? e.message : e)], true);
		}
	}

	function attach(hook) {
		hook.listener = Interceptor.attach(hook.target, {
			onEnter: function (args) {
				hook.calls++;
				dirty[hook.id] = true;
				schedule();
				if (hook.handler.onEnter) run(hook, 'enter', this, hook.handler.onEnter, args);
			},
			onLeave: function (retval) {
				if (hook.handler.onLeave) run(hook, 'leave', this, hook.handler.onLeave, retval);
			},
		});
	}

	function detach(hook) {
		if (!hook.listener) return;
		try { hook.listener.detach(); } catch (e) { /* already gone */ }
		hook.listener = null;
	}

	function resolveTarget(spec) {
		if (spec.module) {
			var m = Process.findModuleByName(spec.module);
			if (!m) throw new Error('Module not loaded: ' + spec.module);
			return m.base.add(spec.offset);
		}
		return ptr(spec.address);
	}

	function get(id) {
		var hook = hooks[id];
		if (!hook) throw new Error('No such hook: ' + id);
		return hook;
	}

	function state(hook) {
		return { id: hook.id, address: hex(hook.target), enabled: hook.listener !== null, calls: hook.calls };
	}

	rpc.exports = {
		// kind: 'exports' | 'imports' | 'symbols'. The query is "function" or
		// "module!function"; * and ? are wildcards, and without one the text is
		// looked for anywhere in the name. For imports the module is the one
		// doing the importing.
		search: function (kind, query) {
			var out = collector();
			var exact = exactAddress(query);
			if (exact) {
				out.add(exact, '');
			} else if (kind === 'symbols') {
				searchSymbols(query, out);
			} else {
				searchResolver(kind === 'imports' ? 'imports' : 'exports', query, out);
			}
			return out.result();
		},

		// spec: { id, module, offset, address, code, enabled, backtrace }.
		// With a module the hook goes at module base + offset; otherwise at the
		// address. Adding an id that exists replaces that hook.
		add: function (spec) {
			var handler = compile(spec.code);
			var target = resolveTarget(spec);
			var old = hooks[spec.id];
			if (!old && hookCount >= MAX_HOOKS) throw new Error('Too many hooks (the limit is ' + MAX_HOOKS + ').');
			if (old) detach(old); else hookCount++;
			var hook = { id: spec.id, target: target, handler: handler, backtrace: spec.backtrace !== false, listener: null, calls: 0 };
			hooks[spec.id] = hook;
			if (spec.enabled !== false) {
				try {
					attach(hook);
				} catch (e) {
					delete hooks[spec.id];
					hookCount--;
					throw new Error('Could not hook ' + hex(target) + ': ' + e.message);
				}
			}
			return state(hook);
		},

		// patch: { code?, backtrace? }. The new handler is used from the next call.
		update: function (id, patch) {
			var hook = get(id);
			if (patch.code !== undefined) hook.handler = compile(patch.code);
			if (patch.backtrace !== undefined) hook.backtrace = !!patch.backtrace;
			return state(hook);
		},

		enable: function (id, on) {
			var hook = get(id);
			if (on && !hook.listener) attach(hook);
			if (!on) detach(hook);
			return state(hook);
		},

		remove: function (id) {
			var hook = hooks[id];
			if (!hook) return false;
			detach(hook);
			delete hooks[id];
			hookCount--;
			return true;
		},

		symbolicate: function (addresses) {
			var out = [];
			for (var i = 0; i < addresses.length && out.length < MAX_SYMBOLICATE; i++) {
				var address = ptr(addresses[i]);
				var name = '';
				try { var s = DebugSymbol.fromAddress(address); if (s && s.name) name = (s.moduleName ? s.moduleName + '!' : '') + s.name; } catch (e) { /* no symbol */ }
				var m = moduleOf(address);
				out.push({ address: hex(address), name: name, where: m ? m.name + '+0x' + address.sub(m.base).toString(16) : hex(address) });
			}
			return out;
		},
	};
})();
