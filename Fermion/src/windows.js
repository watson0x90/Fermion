// @ts-check
// Child-window options + page-path helper, used by the main process
// (core.js fermion:openWindow) to create the device/proc/instrument/trace/etc.
// windows. The main process owns window creation now (the isolated renderer
// can't), so this module no longer opens windows itself.
//
// Path note: this is a real src/ module, so __dirname is src/. The child-window
// HTML lives in pages/, so build the page path as '../pages/<page>'.
const path = require('path');
const { wrapExtraArgs } = require('./helper.js');

// Pure: the BrowserWindow options shared by every child window today.
// additionalArguments is included only when extraArgs is non-empty (matches
// instrument.html / docs.html, which pass none).
function buildWindowOptions({ width, height, extraArgs }) {
	// Secured child windows: no Node, isolated world (host access via the
	// preload bridge, which the caller attaches). Launch args are passed through
	// additionalArguments and read by the preload.
	const webPreferences = {
		nodeIntegration: false,
		contextIsolation: true,
		sandbox: false,
		webviewTag: true,
	};
	if (extraArgs && extraArgs.length) {
		webPreferences.additionalArguments = wrapExtraArgs(extraArgs);
	}
	return {
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


module.exports = { buildWindowOptions, pagePath };
