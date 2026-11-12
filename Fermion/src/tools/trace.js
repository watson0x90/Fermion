// Fermion Graph tracer. Loaded in place of the user's script while the Graph
// tab is tracing: it hooks one exported function and, each time that function
// runs, follows the thread with Stalker and sends the calls made inside it as
// a Graphviz DOT graph.
//
// The Graph panel prepends `var FERMION_TRACE = { module, symbol };`.
// Messages (all via send()):
//   { fermionTrace: 'ready', address, target }          hooked, waiting for a call
//   { fermionTrace: 'error', message }                  could not hook
//   { fermionTrace: 'dot', dot, calls, edges, truncated }   one traced call

(function () {
	var MAX_EVENTS = 20000;      // call events kept per traced call
	var MAX_EDGES = 400;         // distinct edges drawn (a bigger graph is unreadable)
	var MIN_INTERVAL_MS = 750;   // a hot function is sampled, not traced every time

	var cfg = typeof FERMION_TRACE === 'object' && FERMION_TRACE ? FERMION_TRACE : {};
	var moduleName = String(cfg.module || '');
	var symbol = String(cfg.symbol || '');
	var targetName = (moduleName ? moduleName + '!' : '') + symbol;

	function fail(message) { send({ fermionTrace: 'error', message: message }); }

	// ---- resolve the function (Frida 17: exports are looked up on a Module) ----
	if (!symbol) return fail('No symbol given to trace.');
	var target = null;
	if (moduleName) {
		var mod = Process.findModuleByName(moduleName);
		if (!mod) return fail('Module not found: ' + moduleName);
		target = mod.findExportByName(symbol);
	} else {
		target = Module.findGlobalExportByName(symbol);
	}
	if (!target) return fail('Export not found: ' + targetName);

	var modMap = new ModuleMap();
	var labels = {}; // address -> node label (symbol lookups are slow; do each once)

	// A DOT string literal: escape what would end or corrupt it. Names come from
	// the target's own symbols, so they are not trusted to be well-formed.
	function quote(text) {
		return '"' + String(text).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[\r\n]+/g, ' ') + '"';
	}

	// A node is a function: "module!symbol", so call sites inside one function
	// share a node and the traced function connects to what it calls. An
	// address with no symbol information is shown as the bare address.
	function nodeOf(address) {
		var key = address.toString();
		if (labels[key]) return labels[key];
		var name = '';
		try {
			var m = modMap.find(address);
			var s = DebugSymbol.fromAddress(address);
			if (s && s.name) name = (m && m.name ? m.name + '!' : '') + s.name;
		} catch (e) { /* no symbol information */ }
		var node = quote(name || key);
		labels[key] = node;
		return node;
	}

	// Is this call site part of the program? Calls made from Frida's own modules,
	// or from code outside every module (Frida's trampolines and JavaScript
	// runtime live there), are tracing machinery, not the traced function.
	function fromProgram(address) {
		try {
			var m = modMap.find(address);
			return !!m && m.name.toLowerCase().indexOf('frida') === -1;
		} catch (e) { return false; }
	}

	function buildDot(events) {
		var order = [];   // distinct edges, in first-seen order
		var counts = {};
		var last = null;
		var first = null; // the function the first call was made from
		var truncated = false;
		for (var i = 0; i < events.length; i++) {
			var from = events[i][1];
			var to = events[i][2];
			if (!fromProgram(from)) continue;
			var a = nodeOf(from);
			var b = nodeOf(to);
			if (first === null) first = a;
			var key = a + ' -> ' + b;
			if (counts[key]) { counts[key]++; continue; }
			if (order.length >= MAX_EDGES) { truncated = true; continue; }
			counts[key] = 1;
			order.push(key);
			last = b;
		}
		if (!order.length) return null;
		var lines = [
			'digraph Trace {',
			'    rankdir=LR; nodesep=0.12; ranksep=0.3;',
			'    node [fontname="Helvetica", fontsize=10, style=filled, fillcolor="#f4f5f2", color="#9a9c95", shape=box, height=0.26, margin="0.07,0.03"];',
			'    edge [fontname="Helvetica", fontsize=8, color="#6c6e68", arrowsize=0.6];',
			'',
		];
		for (var j = 0; j < order.length; j++) {
			var n = counts[order[j]];
			lines.push('    ' + order[j] + (n > 1 ? ' [label="×' + n + '"]' : '') + ';');
		}
		// The hooked function may only jump to its real body (an export that
		// forwards to another module): link it to where the calls begin.
		if (first !== nodeOf(target)) lines.push('    ' + nodeOf(target) + ' -> ' + first + ' [style=dashed];');
		lines.push('');
		lines.push('    ' + nodeOf(target) + ' [fillcolor="#cfe8c8", color="#3f6e3f", penwidth=2];');
		if (last && last !== nodeOf(target)) lines.push('    ' + last + ' [fillcolor="#f3d0cb", color="#c23b2b", penwidth=2];');
		lines.push('}');
		return { dot: lines.join('\n'), edges: order.length, truncated: truncated };
	}

	// ---- hook and stalk ----
	var depth = {};        // thread id -> nesting depth of the traced function
	var events = [];
	var total = 0;
	var tracingTid = null;
	var lastSent = -MIN_INTERVAL_MS;

	Interceptor.attach(target, {
		onEnter: function () {
			var tid = Process.getCurrentThreadId();
			depth[tid] = (depth[tid] || 0) + 1;
			if (depth[tid] !== 1 || tracingTid !== null) return;   // nested, or another thread is being traced
			if (Date.now() - lastSent < MIN_INTERVAL_MS) return;   // sampled out
			tracingTid = tid;
			events = [];
			total = 0;
			Stalker.follow(tid, {
				events: { call: true, ret: false },
				onReceive: function (raw) {
					var parsed = Stalker.parse(raw);
					total += parsed.length;
					for (var i = 0; i < parsed.length && events.length < MAX_EVENTS; i++) events.push(parsed[i]);
				},
			});
		},
		onLeave: function () {
			var tid = Process.getCurrentThreadId();
			depth[tid] = Math.max(0, (depth[tid] || 1) - 1);
			if (depth[tid] !== 0 || tracingTid !== tid) return;
			Stalker.flush();
			Stalker.unfollow(tid);
			Stalker.garbageCollect();
			tracingTid = null;
			var graph = buildDot(events);
			var calls = total;
			events = [];
			if (!graph) return;
			lastSent = Date.now();
			send({
				fermionTrace: 'dot',
				dot: graph.dot,
				calls: calls,
				edges: graph.edges,
				truncated: graph.truncated || calls > MAX_EVENTS,
			});
		},
	});

	send({ fermionTrace: 'ready', address: target.toString(), target: targetName });
})();
