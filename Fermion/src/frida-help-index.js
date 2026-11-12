// @ts-check
// Builds the lookup table behind the REPL's `help <name>` from the Frida type
// definitions (@types/frida-gum/index.d.ts). Those definitions carry the
// official doc comment and signature of every API, so the help text is Frida's
// own documentation rather than something written here.
//
// Build-time only (needs `typescript`); see scripts/gen-frida-help.js. The
// result maps a dotted name to { kind, sigs, doc }:
//   "Process"                  { kind: 'namespace', sigs: [], doc }
//   "Process.enumerateModules" { kind: 'function',  sigs: ['enumerateModules(): Module[]'], doc }
//   "NativePointer.add"        { kind: 'method',    sigs: [...], doc }
const ts = require('typescript');

const MAX_SIGS = 6;

function buildHelpIndex(dtsText) {
	const sf = ts.createSourceFile('frida-gum.d.ts', dtsText, ts.ScriptTarget.Latest, true);
	/** @type {Record<string, { kind: string, sigs: string[], doc: string }>} */
	const index = Object.create(null);

	const oneLine = (text) => text.replace(/\s+/g, ' ').trim();

	// The doc comment as plain text, with its @param/@returns lines kept.
	function docOf(node) {
		const blocks = /** @type {any} */ (node).jsDoc;
		if (!blocks || !blocks.length) return '';
		const block = blocks[blocks.length - 1];
		const parts = [];
		const main = ts.getTextOfJSDocComment(block.comment);
		if (main) parts.push(main.trim());
		const tags = [];
		for (const tag of block.tags || []) {
			const text = ts.getTextOfJSDocComment(tag.comment) || '';
			const name = /** @type {any} */ (tag).name ? /** @type {any} */ (tag).name.getText(sf) + ' ' : '';
			tags.push(('@' + tag.tagName.getText(sf) + ' ' + name + oneLine(text)).trim());
		}
		if (tags.length) parts.push(tags.join('\n'));
		return parts.join('\n\n');
	}

	function add(key, kind, sig, doc) {
		const prev = index[key];
		if (!prev) {
			index[key] = { kind, sigs: sig ? [sig] : [], doc };
			return;
		}
		// Overloads and merged declarations: keep every signature, the first doc.
		if (sig && prev.sigs.indexOf(sig) === -1 && prev.sigs.length < MAX_SIGS) prev.sigs.push(sig);
		if (!prev.doc && doc) prev.doc = doc;
		// A class or interface outranks the namespace that carries its statics.
		if (kind === 'class' || (kind === 'interface' && prev.kind === 'namespace')) prev.kind = kind;
	}

	const typeParams = (node) => (node.typeParameters && node.typeParameters.length ? '<' + node.typeParameters.map((t) => t.getText(sf)).join(', ') + '>' : '');
	const params = (node) => '(' + node.parameters.map((p) => oneLine(p.getText(sf))).join(', ') + ')';
	const returns = (node) => (node.type ? ': ' + oneLine(node.type.getText(sf)) : '');
	const callSig = (name, node) => name + typeParams(node) + params(node) + returns(node);
	const propSig = (name, node) => name + (node.questionToken ? '?' : '') + (node.type ? ': ' + oneLine(node.type.getText(sf)) : '');

	const isHidden = (node) => (ts.getCombinedModifierFlags(node) & (ts.ModifierFlags.Private | ts.ModifierFlags.Protected)) !== 0;
	const isStatic = (node) => (ts.getCombinedModifierFlags(node) & ts.ModifierFlags.Static) !== 0;
	const nameOf = (node) => (node.name && (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name)) ? node.name.text : null);

	// Members of a class or interface.
	function members(prefix, list) {
		for (const m of list) {
			if (isHidden(m)) continue;
			const name = nameOf(m);
			if (!name) continue;
			const key = prefix + '.' + name;
			if (ts.isMethodDeclaration(m) || ts.isMethodSignature(m)) {
				const stat = isStatic(m);
				add(key, stat ? 'static method' : 'method', (stat ? 'static ' : '') + callSig(name, m), docOf(m));
			} else if (ts.isPropertyDeclaration(m) || ts.isPropertySignature(m)) {
				add(key, 'property', (isStatic(m) ? 'static ' : '') + propSig(name, m), docOf(m));
			} else if (ts.isGetAccessorDeclaration(m)) {
				add(key, 'property', propSig(name, m), docOf(m));
			}
		}
	}

	function statement(node, prefix) {
		const at = (name) => (prefix ? prefix + '.' + name : name);
		if (ts.isModuleDeclaration(node)) {
			const name = nameOf(node);
			if (!name) return;
			add(at(name), 'namespace', '', docOf(node));
			let body = node.body;
			while (body && ts.isModuleDeclaration(body)) body = body.body; // namespace A.B { }
			if (body && ts.isModuleBlock(body)) for (const s of body.statements) statement(s, at(name));
		} else if (ts.isFunctionDeclaration(node)) {
			const name = nameOf(node);
			if (name) add(at(name), 'function', callSig(name, node), docOf(node));
		} else if (ts.isVariableStatement(node)) {
			const doc = docOf(node);
			for (const d of node.declarationList.declarations) {
				if (ts.isIdentifier(d.name)) add(at(d.name.text), 'property', propSig(d.name.text, d), doc);
			}
		} else if (ts.isClassDeclaration(node)) {
			const name = nameOf(node);
			if (!name) return;
			add(at(name), 'class', '', docOf(node));
			for (const m of node.members) {
				if (ts.isConstructorDeclaration(m) && !isHidden(m)) add(at(name), 'class', 'new ' + name + params(m), docOf(m));
			}
			members(at(name), node.members);
		} else if (ts.isInterfaceDeclaration(node)) {
			const name = nameOf(node);
			if (!name) return;
			add(at(name), 'interface', '', docOf(node));
			members(at(name), node.members);
		} else if (ts.isEnumDeclaration(node)) {
			const name = nameOf(node);
			if (!name) return;
			add(at(name), 'enum', node.members.map((m) => m.name.getText(sf)).join(' | '), docOf(node));
		}
		// Type aliases describe shapes, not things you can type at the prompt.
	}

	for (const s of sf.statements) statement(s, '');
	return Object.assign({}, index);
}

module.exports = { buildHelpIndex };
