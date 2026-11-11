// @ts-check
// One factory for Fermion's child windows (device, proc, instrument, about,
// docs, trace), replacing six near-identical `new BrowserWindow` blocks.
//
// Path note: this is a real src/ module, so __dirname is src/. The child-window
// HTML lives in pages/, so build the page path as '../pages/<page>'. (The
// renderer entry script resolves __dirname to the HTML dir and uses just the
// bare filename; a module must not copy that.)
//
// @electron/remote is acquired lazily inside openWindow so buildWindowOptions
// stays requirable headless (unit test) without an Electron runtime.
const path = require('path');
const { wrapExtraArgs } = require('./helper.js');

// Pure: the BrowserWindow options shared by every child window today.
// additionalArguments is included only when extraArgs is non-empty (matches
// instrument.html / docs.html, which pass none).
function buildWindowOptions({ width, height, extraArgs }) {
	const webPreferences = {
		nodeIntegration: true,
		nodeIntegrationInWorker: true,
		enableRemoteModule: true,
		contextIsolation: false,
		webviewTag: true,
	};
	if (extraArgs && extraArgs.length) {
		webPreferences.additionalArguments = wrapExtraArgs(extraArgs);
	}
	return {
		contextIsolation: false,
		width,
		height,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences,
	};
}

// Resolve a child-window HTML file. This module is in src/, but the HTML lives
// in pages/, so climb out of src/ into pages/ — do NOT copy renderer.js's
// path.join(__dirname, page) (its __dirname is the HTML dir; a module's is src/).
function pagePath(page) {
	return path.join(__dirname, '..', 'pages', page);
}

// Create, load, and show a child window. @electron/remote is enabled for new
// windows by the main process (browser-window-created handler in core.js), so
// no per-window enabling is needed here.
function openWindow(page, opts) {
	const { BrowserWindow } = require('@electron/remote');
	let win = new BrowserWindow(buildWindowOptions(opts));
	win.loadFile(pagePath(page));
	win.once('ready-to-show', () => {
		setTimeout(function () {
			win.show();
			win.focus();
		}, 50);
	});
	win.on('close', function () { win = null; });
	return win;
}

module.exports = { buildWindowOptions, openWindow, pagePath };
