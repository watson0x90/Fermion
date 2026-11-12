// @ts-check
// npm packages for scripts, owned by the main process.
//
// Packages live in one folder in userData (a small npm project: package.json
// + node_modules). A script that imports one is compiled here, with Frida's
// own compiler, into a single bundle before it is loaded into the target.
//
// What the renderer may ask for is narrow: search the registry, install or
// remove a package by name, list what is installed. The folder is fixed, a
// package name must match npm's naming rules before anything runs, and install
// scripts are never run on this machine. The code of an installed package
// runs only inside instrumented processes, like any Frida script.
const fs = require('fs');
const path = require('path');

const NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const VERSION = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/; // an exact version or a tag: no ranges
const MAX_NAME = 214;
const MAX_QUERY = 100;
const MAX_SOURCE = 2 * 1024 * 1024;
const SEARCH_LIMIT = 30;
const INSTALL_TIMEOUT_MS = 180000;
const ENTRY = 'script.js'; // what the compiled script is called in stack traces
const ENTRY_TS = 'script.ts'; // the same, for a TypeScript script

// "name" or "name@version" -> { name, version, spec }. Throws for anything else.
function parseSpec(spec) {
	if (typeof spec !== 'string') throw new Error('package name must be a string');
	const s = spec.trim();
	const at = s.lastIndexOf('@');
	const name = at > 0 ? s.slice(0, at) : s;
	const version = at > 0 ? s.slice(at + 1) : '';
	if (!name || name.length > MAX_NAME || !NAME.test(name)) throw new Error('Not a valid npm package name: ' + s.slice(0, 80));
	if (at > 0 && !VERSION.test(version)) throw new Error('Not a valid package version: ' + version.slice(0, 80));
	return { name, version, spec: version ? name + '@' + version : name };
}

// Does the script need compiling? Only when it imports or exports something
// (at the start of a line, so the word inside a string or comment line does
// not count). Everything else is loaded exactly as written, as before.
function needsCompile(source) {
	return typeof source === 'string'
		&& /^[ \t]*(?:import\s*(?:[\w*${}\s,]+\s*from\s*)?['"][^'"\n]+['"]|export\s+(?:default|const|let|var|function|class|\{|\*))/m.test(source);
}

function formatDiagnostics(batches) {
	const lines = [];
	for (const batch of batches) {
		for (const d of Array.isArray(batch) ? batch : [batch]) {
			if (!d || typeof d !== 'object') continue;
			const file = d.file && typeof d.file === 'object' ? d.file : null;
			// The compiler counts lines from 0; editors count from 1.
			const where = file ? `${String(file.path)}:${Number(file.line) + 1}:${Number(file.character) + 1}: ` : '';
			lines.push(where + String(d.text ?? 'error').slice(0, 500));
			if (lines.length >= 20) return lines;
		}
	}
	return lines;
}

/**
 * @param {{
 *   dir: string,
 *   getFrida: () => any,
 *   spawn: Function,
 *   platform?: string,
 * }} deps
 */
function createPackages({ dir, getFrida, spawn, platform = process.platform }) {
	const manifestPath = path.join(dir, 'package.json');
	let busy = Promise.resolve(); // one install/remove at a time

	function ensureProject() {
		fs.mkdirSync(dir, { recursive: true });
		if (!fs.existsSync(manifestPath)) {
			fs.writeFileSync(manifestPath, JSON.stringify({ name: 'fermion-scripts', version: '1.0.0', private: true, type: 'module', dependencies: {} }, null, 2));
		}
	}

	function readManifest() {
		try {
			const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
			return m && typeof m === 'object' ? m : {};
		} catch {
			return {};
		}
	}

	function packageDir(name) { return path.join(dir, 'node_modules', ...name.split('/')); }

	function installedInfo(name) {
		try {
			const p = JSON.parse(fs.readFileSync(path.join(packageDir(name), 'package.json'), 'utf8'));
			return { name, version: String(p.version ?? '').slice(0, 64), description: String(p.description ?? '').slice(0, 300) };
		} catch {
			return null;
		}
	}

	// The packages the operator asked for (not what they pulled in).
	function list() {
		const deps = readManifest().dependencies;
		const out = [];
		if (deps && typeof deps === 'object') {
			for (const name of Object.keys(deps)) {
				if (!NAME.test(name)) continue;
				const info = installedInfo(name);
				if (info) out.push(info);
			}
		}
		return out.sort((a, b) => a.name.localeCompare(b.name));
	}

	async function search(query) {
		if (typeof query !== 'string' || !query.trim()) throw new Error('search query is empty');
		const q = query.trim();
		if (q.length > MAX_QUERY) throw new Error('search query is too long');
		const frida = getFrida();
		const manager = new frida.PackageManager();
		const found = await manager.search(q, { limit: SEARCH_LIMIT });
		const items = [];
		for (const p of found.packages ?? []) {
			const name = String(p.name ?? '');
			if (!NAME.test(name) || name.length > MAX_NAME) continue; // only names that could be installed
			items.push({ name, version: String(p.version ?? '').slice(0, 64), description: String(p.description ?? '').slice(0, 300) });
		}
		return { items, total: Number(found.total) || items.length };
	}

	// npm, with install scripts off. The only variable part of the command is
	// the spec, which parseSpec has already limited to [a-z0-9@/._+-].
	function npmInstall(spec) {
		return new Promise((resolve, reject) => {
			const args = ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--no-progress', '--save', spec];
			// On Windows npm is a .cmd file, which can only be run through the shell.
			const child = platform === 'win32'
				? spawn('npm ' + args.join(' '), { cwd: dir, shell: true, windowsHide: true })
				: spawn('npm', args, { cwd: dir, shell: false });
			let output = '';
			const keep = (d) => { if (output.length < 8000) output += String(d); };
			child.stdout?.on('data', keep);
			child.stderr?.on('data', keep);
			const timer = setTimeout(() => { try { child.kill(); } catch { /* gone */ } reject(new Error('npm took too long and was stopped')); }, INSTALL_TIMEOUT_MS);
			child.on('error', (e) => { clearTimeout(timer); reject(new Error(e && e.code === 'ENOENT' ? 'npm was not found on this machine' : 'npm could not be started: ' + (e && e.message))); });
			child.on('close', (code) => {
				clearTimeout(timer);
				if (code === 0) { resolve(undefined); return; }
				const text = output.replace(/\s+/g, ' ').trim();
				reject(new Error(/not recognized|not found|ENOENT/i.test(text) && !/E404/.test(text)
					? 'npm was not found on this machine'
					: 'npm failed (exit ' + code + '): ' + text.slice(-400)));
			});
		});
	}

	async function installNow(spec) {
		const { name, spec: clean } = parseSpec(spec);
		ensureProject();
		let via = 'frida';
		let fridaError = '';
		try {
			const frida = getFrida();
			const manager = new frida.PackageManager();
			await manager.install({ projectRoot: dir, specs: [clean] });
			if (!installedInfo(name)) throw new Error('nothing was installed');
		} catch (e) {
			// Frida's installer fails on some platforms: fall back to npm.
			fridaError = String(e && e.message ? e.message : e);
			via = 'npm';
			try {
				await npmInstall(clean);
			} catch (npmError) {
				throw new Error(`Could not install ${clean}. ${npmError.message}. (Frida's own installer said: ${fridaError.slice(0, 200)})`);
			}
		}
		const info = installedInfo(name);
		if (!info) throw new Error('The package was not found after installing ' + clean);
		// Make sure it is recorded as asked-for, whichever installer ran.
		const manifest = readManifest();
		if (!manifest.dependencies || typeof manifest.dependencies !== 'object') manifest.dependencies = {};
		if (!manifest.dependencies[name]) {
			manifest.dependencies[name] = info.version || '*';
			fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
		}
		return { ...info, via };
	}

	function removeNow(name) {
		const { name: clean } = parseSpec(name);
		const manifest = readManifest();
		if (!manifest.dependencies || !Object.prototype.hasOwnProperty.call(manifest.dependencies, clean)) throw new Error(clean + ' is not installed');
		delete manifest.dependencies[clean];
		fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
		// The name passed NAME, so this path cannot leave node_modules.
		fs.rmSync(packageDir(clean), { recursive: true, force: true });
		return true;
	}

	const queued = (fn) => (...args) => {
		const run = busy.then(() => fn(...args));
		busy = run.catch(() => {});
		return run;
	};

	// Bundle a script with the packages it imports. A TypeScript script is
	// turned into JavaScript on the way, and its types are checked against
	// Frida's definitions. Throws with the compiler's messages when it does
	// not compile.
	async function compile(source, options) {
		const typescript = !!(options && options.typescript);
		if (typeof source !== 'string') throw new Error('the script must be text');
		if (source.length > MAX_SOURCE) throw new Error('the script is too long to compile');
		ensureProject();
		const entry = path.join(dir, typescript ? ENTRY_TS : ENTRY);
		// Only one of the two is the script: the other would be picked up by
		// the type check, or resolved by an import of './script'.
		try { fs.rmSync(path.join(dir, typescript ? ENTRY : ENTRY_TS), { force: true }); } catch { /* not there */ }
		fs.writeFileSync(entry, source);
		const frida = getFrida();
		const compiler = new frida.Compiler();
		const batches = [];
		const onDiagnostics = (d) => batches.push(d);
		compiler.diagnostics.connect(onDiagnostics);
		try {
			return await compiler.build(entry, { projectRoot: dir, typeCheck: typescript ? 'full' : 'none', sourceMaps: 'included' });
		} catch (e) {
			const lines = formatDiagnostics(batches);
			const missing = lines.map((l) => /Could not resolve "([^"]+)"/.exec(l)).filter(Boolean).map((m) => m[1]);
			const hint = missing.length ? '\nInstall ' + [...new Set(missing)].join(', ') + ' from Packages in the Editor toolbar.' : '';
			throw new Error('The script did not compile:\n' + (lines.length ? lines.join('\n') : String(e && e.message ? e.message : e)) + hint);
		} finally {
			try { compiler.diagnostics.disconnect(onDiagnostics); } catch { /* already gone */ }
		}
	}

	return { search, list, install: queued(installNow), remove: queued(removeNow), compile, dir };
}

// The four operations the window can ask for. Installing is confirmed by the
// operator in a dialog that main shows itself, so a window showing output from
// a target cannot install anything on its own.
/**
 * @param {{ packages: ReturnType<typeof createPackages>, confirm: (spec: string) => Promise<boolean> }} deps
 */
function createPackageHandlers({ packages, confirm }) {
	return {
		search: (query) => packages.search(query),
		list: () => packages.list(),
		remove: (name) => packages.remove(name),
		async install(spec) {
			const { spec: clean } = parseSpec(spec); // refused here, before the operator is asked
			if (!(await confirm(clean))) return { cancelled: true };
			return packages.install(clean);
		},
	};
}

// What the service does to a script before loading it: compile it when it
// imports something, otherwise leave it exactly as written.
function createScriptPreparer(packages) {
	return async (source, options) => {
		if (options && options.typescript) return { code: await packages.compile(source, { typescript: true }), compiled: true, typescript: true };
		return needsCompile(source)
			? { code: await packages.compile(source), compiled: true }
			: { code: source, compiled: false };
	};
}

module.exports = { createPackages, createPackageHandlers, createScriptPreparer, parseSpec, needsCompile, formatDiagnostics };
