// Fermion REPL agent. Loaded as its own Frida script inside the attached
// process (separate from the user's script, so it survives script reloads and
// works before any script is loaded). The REPL panel calls
// rpc.exports.evaluate(code); the code runs with indirect eval, so `var` and
// global assignments persist from one entry to the next.
//
// The result is always a plain object the host can show as text:
//   { ok: true,  type, text }      the value, printed. Objects, arrays and
//                                  pointers also carry `tree`, the value as a
//                                  bounded tree for the REPL's expandable view
//   { ok: false, error, stack }    it threw (or the promise rejected)

(function () {
	var MAX_TEXT = 64 * 1024;

	function typeName(v) {
		if (v === null) return 'null';
		var t = typeof v;
		if (t !== 'object') return t;
		var ctor = v.constructor && v.constructor.name;
		return ctor && ctor !== 'Object' ? ctor : 'object';
	}

	// Frida's own value types (NativePointer, Int64, UInt64, ...) print best as
	// their toString(); plain objects and arrays as JSON.
	function isPlain(v) {
		if (Array.isArray(v)) return true;
		var proto = Object.getPrototypeOf(v);
		return proto === null || proto === Object.prototype;
	}

	var MAX_DEPTH = 12;     // nesting printed before giving up with […]
	var MAX_NODES = 20000;  // objects/arrays visited per result

	// Turn a value into something JSON.stringify can print. Only the objects on
	// the current path count as circular (an object reached twice by different
	// routes is printed twice). Class instances print their own properties.
	function toPlain(value) {
		var path = [];
		var nodes = 0;
		function walk(v) {
			var t = typeof v;
			if (t === 'bigint') return v.toString() + 'n';
			if (t === 'undefined') return 'undefined';
			if (t === 'function') return '[Function]';
			if (t === 'symbol') return v.toString();
			if (v === null || t !== 'object') return v;
			if (path.indexOf(v) !== -1) return '[Circular]';
			if (path.length >= MAX_DEPTH || ++nodes > MAX_NODES) return '[…]';
			if (!isPlain(v)) {
				if (typeof v.toJSON === 'function') {
					var viaJson;
					try { viaJson = v.toJSON(); } catch (e) { return '[Thrown: ' + e.message + ']'; }
					if (viaJson !== v) return walk(viaJson);
				} else {
					var s = String(v);
					if (s !== '[object Object]') return s; // NativePointer, Int64, Error, …
				}
			}
			path.push(v);
			var out;
			if (Array.isArray(v)) {
				out = [];
				for (var i = 0; i < v.length; i++) out.push(walk(v[i]));
			} else {
				out = {};
				var keys = Object.keys(v);
				for (var k = 0; k < keys.length; k++) {
					var child;
					try { child = v[keys[k]]; } catch (e) { out[keys[k]] = '[Thrown: ' + e.message + ']'; continue; }
					out[keys[k]] = walk(child);
				}
			}
			path.pop();
			return out;
		}
		return walk(value);
	}

	function toJson(value) {
		return JSON.stringify(toPlain(value), null, 2);
	}

	function describe(v) {
		var t = typeof v;
		if (v === null || t === 'undefined' || t === 'number' || t === 'boolean') return String(v);
		if (t === 'bigint') return v.toString() + 'n';
		if (t === 'string') return JSON.stringify(v);
		if (t === 'symbol' || t === 'function') return v.toString();
		if (!isPlain(v)) {
			// ArrayBuffer has no useful toString; show it as a hex dump when we can.
			if (typeof ArrayBuffer !== 'undefined' && v instanceof ArrayBuffer && typeof hexdump === 'function') {
				return hexdump(v, { length: Math.min(v.byteLength, 256) });
			}
			var s = String(v);
			if (s !== '[object Object]') return s;
		}
		try {
			var j = toJson(v);
			return typeof j === 'string' ? j : String(v);
		} catch (e) {
			return String(v);
		}
	}

	// ---- the value as a tree ----
	// { t, v } for a leaf: str, num, bool, null, undef, fn, ptr (a NativePointer),
	// other (anything else that prints as itself), cut (a branch not followed).
	// { t: 'obj' | 'arr', label, n, kids: [{ k, v }], more } for a container: n is
	// how many children it has, kids the first of them, more the number left out.
	var TREE_DEPTH = 6;       // containers nested inside the result
	var TREE_CONTAINERS = 400; // containers walked per result
	var TREE_CHILDREN = 100;  // children listed per container
	var TREE_TEXT = 2000;     // characters per string

	function isPointer(v) {
		return typeof NativePointer !== 'undefined' && v instanceof NativePointer;
	}

	function buildTree(value) {
		var path = [];
		var containers = 0;
		function walk(v) {
			var t = typeof v;
			if (v === null) return { t: 'null', v: 'null' };
			if (t === 'string') return { t: 'str', v: v.length > TREE_TEXT ? v.slice(0, TREE_TEXT) + '…' : v };
			if (t === 'number') return { t: 'num', v: String(v) };
			if (t === 'boolean') return { t: 'bool', v: String(v) };
			if (t === 'undefined') return { t: 'undef', v: 'undefined' };
			if (t === 'bigint') return { t: 'num', v: v.toString() + 'n' };
			if (t === 'symbol') return { t: 'other', v: v.toString() };
			if (t === 'function') return { t: 'fn', v: (v.name || 'anonymous') + '()' };
			if (isPointer(v)) return { t: 'ptr', v: String(v) };
			if (!isPlain(v)) {
				if (typeof v.toJSON === 'function') {
					var viaJson;
					try { viaJson = v.toJSON(); } catch (e) { return { t: 'other', v: '[Thrown: ' + e.message + ']' }; }
					if (viaJson !== v) return walk(viaJson);
				} else {
					var s = String(v);
					if (s !== '[object Object]') return { t: 'other', v: s.length > TREE_TEXT ? s.slice(0, TREE_TEXT) + '…' : s };
				}
			}
			if (path.indexOf(v) !== -1) return { t: 'cut', v: '[Circular]' };
			if (path.length >= TREE_DEPTH || containers >= TREE_CONTAINERS) return { t: 'cut', v: '…' };
			containers++;
			path.push(v);
			var isArray = Array.isArray(v);
			var keys = isArray ? null : Object.keys(v);
			var total = isArray ? v.length : keys.length;
			var node = isArray ? { t: 'arr', n: total, kids: [] } : { t: 'obj', label: typeName(v) === 'object' ? 'Object' : typeName(v), n: total, kids: [] };
			var shown = Math.min(total, TREE_CHILDREN);
			for (var i = 0; i < shown; i++) {
				var key = isArray ? i : keys[i];
				var child;
				try { child = walk(v[key]); } catch (e) { child = { t: 'other', v: '[Thrown: ' + e.message + ']' }; }
				node.kids.push({ k: String(key), v: child });
			}
			if (total > shown) node.more = total - shown;
			path.pop();
			return node;
		}
		return walk(value);
	}

	function clip(text) {
		if (text.length <= MAX_TEXT) return text;
		return text.slice(0, MAX_TEXT) + '\n… (truncated, ' + text.length + ' characters in total)';
	}

	function ok(v) {
		var result = { ok: true, type: typeName(v), text: clip(describe(v)) };
		if (v !== null && typeof v === 'object') {
			try {
				var tree = buildTree(v);
				if (tree.t === 'obj' || tree.t === 'arr' || tree.t === 'ptr') result.tree = tree;
			} catch (e) { /* the text alone is the result */ }
		}
		return result;
	}
	function fail(e) {
		var isErr = e !== null && typeof e === 'object' && typeof e.message === 'string';
		return {
			ok: false,
			error: isErr ? (e.name ? e.name + ': ' : '') + e.message : String(e),
			stack: isErr && typeof e.stack === 'string' ? e.stack : '',
		};
	}

	// ---- tab completion and `help` ----
	// The REPL panel reaches these through evaluate(), as `__fermion.complete(…)`
	// etc. They only look names up: a dotted chain of identifiers is resolved by
	// property access (no calls, no indexing), so completing or asking for help
	// never runs the user's functions.
	var GLOBAL = (0, eval)('this');
	var IDENT = /^[A-Za-z_$][\w$]*$/;
	var IDENT_CHAIN = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/;
	var MAX_ITEMS = 200;
	var MAX_MEMBERS = 500;
	var OBJECT_NOISE = Object.getOwnPropertyNames(Object.prototype);
	var FUNCTION_NOISE = Object.getOwnPropertyNames(Function.prototype).concat(['prototype', 'length', 'name', 'arguments', 'caller']);

	function resolve(chain) {
		if (typeof chain !== 'string' || !IDENT_CHAIN.test(chain)) return { ok: false };
		var parts = chain.split('.');
		var cur;
		try {
			cur = (0, eval)(parts[0]); // a bare identifier: reads a global, runs nothing
			for (var i = 1; i < parts.length; i++) {
				if (cur === null || cur === undefined) return { ok: false };
				cur = cur[parts[i]];
			}
		} catch (e) {
			return { ok: false };
		}
		return { ok: true, value: cur };
	}

	// Own and inherited property names that are valid identifiers, de-duplicated.
	function memberNames(value) {
		var out = [];
		var seen = {};
		var o = Object(value);
		for (var depth = 0; o && depth < 32; depth++) {
			var names;
			try { names = Object.getOwnPropertyNames(o); } catch (e) { break; }
			for (var i = 0; i < names.length; i++) {
				var n = names[i];
				if (!IDENT.test(n) || seen['$' + n]) continue;
				seen['$' + n] = true;
				out.push(n);
			}
			o = Object.getPrototypeOf(o);
		}
		return out.sort();
	}

	function read(obj, name) {
		try { return { ok: true, value: obj[name] }; } catch (e) { return { ok: false }; }
	}

	function without(names, noise) {
		return names.filter(function (n) { return noise.indexOf(n) === -1; });
	}

	function complete(text) {
		var none = { from: String(text).length, items: [], truncated: false };
		text = String(text);
		var tail = /[\w$.]*$/.exec(text)[0];
		if (!tail || tail.charAt(0) === '.' || /^[0-9]/.test(tail)) return none;
		var dot = tail.lastIndexOf('.');
		var base = dot < 0 ? '' : tail.slice(0, dot);
		var partial = tail.slice(dot + 1);
		var holder;
		var names;
		if (base === '') {
			if (!partial) return none;
			holder = GLOBAL;
			names = without(memberNames(GLOBAL), ['__fermion']);
		} else {
			var r = resolve(base);
			if (!r.ok || r.value === null || r.value === undefined) return none;
			holder = r.value;
			names = memberNames(holder);
			// Object.prototype members (toString, hasOwnProperty, …) only when typed for.
			if (!partial) names = without(names, OBJECT_NOISE);
		}
		var matching = names.filter(function (n) { return n.indexOf(partial) === 0; });
		var items = matching.slice(0, MAX_ITEMS).map(function (n) {
			var v = read(holder, n);
			return { name: n, kind: v.ok && typeof v.value === 'function' ? 'function' : 'property' };
		});
		return { from: text.length - partial.length, items: items, truncated: matching.length > MAX_ITEMS };
	}

	function memberList(holder, noise) {
		return without(memberNames(holder), noise).slice(0, MAX_MEMBERS).map(function (n) {
			var v = read(holder, n);
			if (v.ok && typeof v.value === 'function') return { name: n, kind: 'function', arity: v.value.length };
			return { name: n, kind: 'property', type: v.ok ? typeName(v.value) : 'unknown' };
		});
	}

	// What a dotted name refers to, for `help <name>`.
	function inspect(name) {
		var r = resolve(name);
		if (!r.ok || r.value === undefined) return { found: false, name: String(name) };
		var v = r.value;
		var t = typeof v;
		var out = { found: true, name: name, type: t === 'function' ? 'function' : typeName(v) };
		if (t === 'function') {
			out.arity = v.length;
			out.members = memberList(v, OBJECT_NOISE.concat(FUNCTION_NOISE));
			// A class: also what its instances offer.
			if (v.prototype && typeof v.prototype === 'object') out.instanceMembers = memberList(v.prototype, OBJECT_NOISE);
		} else if (v !== null && t === 'object') {
			out.members = memberList(v, OBJECT_NOISE);
		} else {
			var text = describe(v);
			out.value = text.length > 200 ? text.slice(0, 200) + '…' : text;
		}
		return out;
	}

	function globals() {
		return without(memberNames(GLOBAL), ['__fermion']);
	}

	Object.defineProperty(GLOBAL, '__fermion', {
		value: { complete: complete, inspect: inspect, globals: globals },
		enumerable: false,
		configurable: true,
		writable: false,
	});

	rpc.exports = {
		evaluate: function (code) {
			var value;
			try {
				value = (0, eval)(code); // indirect: global scope, state persists
			} catch (e) {
				return fail(e);
			}
			if (value !== null && typeof value === 'object' && typeof value.then === 'function') {
				return value.then(ok, fail);
			}
			return ok(value);
		},
	};
})();
