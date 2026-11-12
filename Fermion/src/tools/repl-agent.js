// Fermion REPL agent. Loaded as its own Frida script inside the attached
// process (separate from the user's script, so it survives script reloads and
// works before any script is loaded). The REPL panel calls
// rpc.exports.evaluate(code); the code runs with indirect eval, so `var` and
// global assignments persist from one entry to the next.
//
// The result is always a plain object the host can show as text:
//   { ok: true,  type, text }      the value, printed
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

	function clip(text) {
		if (text.length <= MAX_TEXT) return text;
		return text.slice(0, MAX_TEXT) + '\n… (truncated, ' + text.length + ' characters in total)';
	}

	function ok(v) { return { ok: true, type: typeName(v), text: clip(describe(v)) }; }
	function fail(e) {
		var isErr = e !== null && typeof e === 'object' && typeof e.message === 'string';
		return {
			ok: false,
			error: isErr ? (e.name ? e.name + ': ' : '') + e.message : String(e),
			stack: isErr && typeof e.stack === 'string' ? e.stack : '',
		};
	}

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
