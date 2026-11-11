// @ts-check
// Monaco editor setup, theme/wrap handling, and the startup version banner —
// moved out of pages/index.html's inline scripts. initEditor() resolves the
// Fermion/Frida versions synchronously (so the editor banner art can embed
// FERMION_VER), prints the banner through the injected logger, then kicks off
// the async Monaco AMD load and creates the editor.
//
// Path note: this is a real src/ module (__dirname = src/), and
// src/../node_modules resolves to Fermion/node_modules, so the Monaco loader
// paths below are unchanged from when this lived in pages/. The frida-gum def
// is fetched via XHR (resolved against the document, i.e. pages/), so it keeps
// the '../node_modules/...' form.
const path = require('path');

// XHR loader for the in-editor frida-gum .d.ts (internal to this module now).
function LocalLoadLang(url, method) {
	var request = new XMLHttpRequest();
	return new Promise(function (resolve, reject) {
		request.onreadystatechange = function () {
			if (request.readyState !== 4) return;
			if (request.status >= 200 && request.status < 300) {
				resolve(request);
			} else {
				reject({
					status: request.status,
					statusText: request.statusText
				});
			}
		};
		request.open(method || 'GET', url, true);
		request.send();
	});
}

function setMonacoTheme() {
	// monaco is a window property (the AMD loader sets it); the theme objects
	// are classic-script globals published by monaco-theme.js. A module's scope
	// chain sees neither by bare name, so bind them explicitly.
	const monaco = window.monaco;
	const {
		idleFingers, Cobalt, MerbivoreSoft, Katzenmilch, Monokai,
		SolarizedDark, SolarizedLight, BirdsOfParadise, Clouds, Kuroir,
		NightOwl, Textmate, Amy, OceanicNext, TomorrowNightBlue, VibrantInk,
	} = window.FermionThemes || {};
	var theme = /** @type {HTMLSelectElement} */ (document.getElementById("MonacoThemeSelect")).value;
	var refCodeContainer = document.getElementById("Container");
	if (theme == "idleFingers") {
		monaco.editor.defineTheme("idleFingers", idleFingers);
		monaco.editor.setTheme("idleFingers");
	} else if (theme == "Cobalt") {
		monaco.editor.defineTheme("Cobalt", Cobalt);
		monaco.editor.setTheme("Cobalt");
	} else if (theme == "MerbivoreSoft") {
		monaco.editor.defineTheme("MerbivoreSoft", MerbivoreSoft);
		monaco.editor.setTheme("MerbivoreSoft");
	} else if (theme == "Katzenmilch") {
		monaco.editor.defineTheme("Katzenmilch", Katzenmilch);
		monaco.editor.setTheme("Katzenmilch");
	} else if (theme == "Monokai") {
		monaco.editor.defineTheme("Monokai", Monokai);
		monaco.editor.setTheme("Monokai");
	} else if (theme == "Solarized-Dark") {
		monaco.editor.defineTheme("SolarizedDark", SolarizedDark);
		monaco.editor.setTheme("SolarizedDark");
	} else if (theme == "Solarized-Light") {
		monaco.editor.defineTheme("SolarizedLight", SolarizedLight);
		monaco.editor.setTheme("SolarizedLight");
	} else if (theme == "Birds-Of-Paradise") {
		monaco.editor.defineTheme("BirdsOfParadise", BirdsOfParadise);
		monaco.editor.setTheme("BirdsOfParadise");
	} else if (theme == "Clouds") {
		monaco.editor.defineTheme("Clouds", Clouds);
		monaco.editor.setTheme("Clouds");
	} else if (theme == "Kuroir") {
		monaco.editor.defineTheme("Kuroir", Kuroir);
		monaco.editor.setTheme("Kuroir");
	} else if (theme == "NightOwl") {
		monaco.editor.defineTheme("NightOwl", NightOwl);
		monaco.editor.setTheme("NightOwl");
	} else if (theme == "Textmate") {
		monaco.editor.defineTheme("Textmate", Textmate);
		monaco.editor.setTheme("Textmate");
	} else if (theme == "VSCode") {
		monaco.editor.setTheme("vs");
	} else if (theme == "VSCode-Dark") {
		monaco.editor.setTheme("vs-dark");
	} else if (theme == "VSCode-HighContrast") {
		monaco.editor.setTheme("hc-black");
	} else if (theme == "Amy") {
		monaco.editor.defineTheme("Amy", Amy);
		monaco.editor.setTheme("Amy");
	} else if (theme == "Oceanic Next") {
		monaco.editor.defineTheme("Oceanic-Next", OceanicNext);
		monaco.editor.setTheme("Oceanic-Next");
	} else if (theme == "Tomorrow Night Blue") {
		monaco.editor.defineTheme("Tomorrow-Night-Blue", TomorrowNightBlue);
		monaco.editor.setTheme("Tomorrow-Night-Blue");
	} else if (theme == "Vibrant Ink") {
		monaco.editor.defineTheme("Vibrant-Ink", VibrantInk);
		monaco.editor.setTheme("Vibrant-Ink");
	}
}

// Toggle Monaco word-wrap from the #FermionMonacoWrap checkbox.
function toggleWrap() {
	// Toggle the current state
	var wrapState = document.getElementById("FermionMonacoWrap");
	var checkbox = /** @type {HTMLInputElement} */ (wrapState.children[0]);
	if (checkbox.checked == false) {
		window.MonacoCodeEditor.updateOptions({ wordWrap: "on" });
		checkbox.checked = true;
	} else {
		window.MonacoCodeEditor.updateOptions({ wordWrap: "off" });
		checkbox.checked = false;
	}
}

// Resolve a package's version without assuming its internal file layout. Frida
// 17's entry point is build/src/frida.js and its "exports" map blocks
// require('frida/package.json'), so walk up from the resolved entry until the
// package.json is found.
function packageVersion(moduleName) {
	const { dirname, join } = require("path");
	const nodeFs = require("fs");
	let dir = dirname(require.resolve(moduleName));
	while (!nodeFs.existsSync(join(dir, "package.json"))) {
		const parent = dirname(dir);
		if (parent === dir) throw new Error("package.json not found for " + moduleName);
		dir = parent;
	}
	return require(join(dir, "package.json")).version;
}

// Create the Monaco editor and print the startup banner. deps.log is the
// terminal logger (appendFridaLog). Versions are resolved and the banner is
// printed synchronously; the editor itself mounts when the async AMD load
// completes.
function initEditor(deps) {
	// Resolve versions first so the editor banner art can embed FERMION_VER and
	// the startup banner lines are correct.
	window.FRIDA_VER = packageVersion("frida");
	window.FERMION_VER = require('../package.json').version;

	// Print release versions to the terminal (startup banner).
	deps.log("[+] Fermion v" + window.FERMION_VER + " -> Frida v" + window.FRIDA_VER);
	deps.log("    |_ https://github.com/frida/frida/releases/tag/" + window.FRIDA_VER);

	const amdLoader = require('../node_modules/monaco-editor/min/vs/loader.js');
	const amdRequire = amdLoader.require;
	const amdDefine = amdLoader.require.define;
	function uriFromPath(_path) {
		var pathName = path.resolve(_path).replace(/\\/g, '/');
		if (pathName.length > 0 && pathName.charAt(0) !== '/') {
			pathName = '/' + pathName;
		}
		return encodeURI('file://' + pathName);
	}
	amdRequire.config({
		baseUrl: uriFromPath(path.join(__dirname, '../node_modules/monaco-editor/min'))
	});
	// workaround monaco-css not understanding the environment
	self.module = undefined;
	amdRequire(['vs/editor/editor.main'], function () {
		// Bind page globals explicitly (see setMonacoTheme note above).
		const monaco = window.monaco;
		const { Kuroir } = window.FermionThemes || {};
		monaco.languages.typescript.javascriptDefaults.setDiagnosticsOptions({
			noSemanticValidation: true,
			noSyntaxValidation: true
		});

		monaco.languages.typescript.typescriptDefaults.setCompilerOptions({
			target: monaco.languages.typescript.ScriptTarget.Latest,
			allowNonTsExtensions: true,
			moduleResolution: monaco.languages.typescript.ModuleResolutionKind.NodeJs
		});

		// Load custom Frida Lang TypeScript defs
		var fridaDefFile = '../node_modules/@types/frida-gum/index.d.ts'
		LocalLoadLang(fridaDefFile).then(function (data) {
			monaco.languages.typescript.typescriptDefaults.addExtraLib(data.responseText, uriFromPath(fridaDefFile));
		});

		// Load monaco theme
		monaco.editor.defineTheme("Kuroir", Kuroir);
		monaco.editor.setTheme("Kuroir");

		var editor = monaco.editor.create(document.getElementById('container'), {
			value: [
				'//                                                            ',
				'//   █████▒▓█████  ██▀███   ███▄ ▄███▓ ██▓ ▒█████   ███▄    █ ',
				'// ▓██   ▒ ▓█   ▀ ▓██ ▒ ██▒▓██▒▀█▀ ██▒▓██▒▒██▒  ██▒ ██ ▀█   █ ',
				'// ▒████ ░ ▒███   ▓██ ░▄█ ▒▓██    ▓██░▒██▒▒██░  ██▒▓██  ▀█ ██▒',
				'// ░▓█▒  ░ ▒▓█  ▄ ▒██▀▀█▄  ▒██    ▒██ ░██░▒██   ██░▓██▒  ▐▌██▒',
				'// ░▒█░    ░▒████▒░██▓ ▒██▒▒██▒   ░██▒░██░░ ████▓▒░▒██░   ▓██░',
				'//  ▒ ░    ░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░   ░  ░░▓  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ',
				'//  ░       ░ ░  ░  ░▒ ░ ▒░░  ░      ░ ▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░',
				'//  ░ ░       ░     ░░    v' + window.FERMION_VER + '  ░    ▒ ░░ ░ ░ ▒  ░ ~b33f  ░ ',
				'//            ░  ░   ░            ░    ░      ░ ░           ░ ',
				'//',
				'//   -= Editor =-',
				'//',
				'// + The text editor is a fully featured monaco-editor',
				'//   |-> Linting, IntelliSense, Shortcuts (press F1)',
				'//   |-> https://microsoft.github.io/monaco-editor/',
				'//',
				'// + I am trapping Ctrl-s / Ctrl-o in JS so you can save',
				'//   and open files without clicking on the menu',
				'//',
				'// + I am trapping Ctrl-t in JS so you can reload the',
				'//   current script in the attached target',
				'//',
				'//   -= Frida =-',
				'//',
				'// + To send output to the text area you have to use "send(...)"',
				'//   |-> Not this: console.log("Hello from Frida!")',
				'//   |-> But this: send("Hello from Frida!")'
			].join('\n'),
			language: 'typescript',
			scrollBeyondLastLine: false,
			automaticLayout: true
		});

		// Store the editor reff as a global var
		window.MonacoCodeEditor = editor;
	});
}

module.exports = { initEditor, setMonacoTheme, toggleWrap };
