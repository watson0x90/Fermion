// Model for the Docs window: the REPL help index (src/frida-help.json, built
// from the Frida type definitions) grouped into top-level topics with their
// members. Pure; loaded as a classic <script> by pages/docs.html and required
// by the unit tests.
(function (root) {
	function buildDocsModel(index) {
		if (!index || typeof index !== 'object') return [];
		var topics = {};
		var keys = Object.keys(index);
		for (var i = 0; i < keys.length; i++) {
			var key = keys[i];
			var dot = key.indexOf('.');
			var top = dot < 0 ? key : key.slice(0, dot);
			if (!topics[top]) topics[top] = { name: top, kind: '', sigs: [], doc: '', members: [] };
			var e = index[key] || {};
			var entry = { kind: String(e.kind || ''), sigs: Array.isArray(e.sigs) ? e.sigs.map(String) : [], doc: String(e.doc || '') };
			if (dot < 0) {
				topics[top].kind = entry.kind;
				topics[top].sigs = entry.sigs;
				topics[top].doc = entry.doc;
			} else {
				topics[top].members.push({ name: key.slice(dot + 1), kind: entry.kind, sigs: entry.sigs, doc: entry.doc });
			}
		}
		var byName = function (a, b) { return a.name.localeCompare(b.name); };
		return Object.keys(topics).map(function (k) {
			topics[k].members.sort(byName);
			return topics[k];
		}).sort(byName);
	}

	// Topics whose name, or any member's name, contains the text.
	function filterTopics(topics, text) {
		var needle = String(text || '').trim().toLowerCase();
		if (!needle) return topics;
		return topics.filter(function (t) {
			if (t.name.toLowerCase().indexOf(needle) !== -1) return true;
			for (var i = 0; i < t.members.length; i++) if (t.members[i].name.toLowerCase().indexOf(needle) !== -1) return true;
			return false;
		});
	}

	// Join the hard-wrapped lines of a doc comment into paragraphs. Blank lines,
	// @tag lines, list items and indented (code) lines keep their line breaks.
	function reflow(doc) {
		var lines = String(doc || '').split(/\r?\n/);
		var out = [];
		for (var i = 0; i < lines.length; i++) {
			var line = lines[i];
			var prev = out.length ? out[out.length - 1] : null;
			var own = line.trim() === '' || /^\s*(@|[-*] |\d+\. )/.test(line) || /^\s{2,}/.test(line);
			var prevOpen = prev !== null && prev.trim() !== '' && !/^\s{2,}/.test(prev);
			if (!own && prevOpen) out[out.length - 1] = prev + ' ' + line.trim();
			else out.push(line);
		}
		return out.join('\n');
	}

	var api = { buildDocsModel: buildDocsModel, filterTopics: filterTopics, reflow: reflow };
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.FermionDocs = api;
})(typeof window !== 'undefined' ? window : globalThis);
