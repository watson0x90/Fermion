const { createTerminal } = require('../src/terminal.js');
const { formatMessage } = require('../src/output-model.js');
const { readSettings, writeSettings } = require('../src/settings.js');
const { createLayout } = require('../src/layout.js');
const { initEditor, setMonacoTheme, toggleWrap } = require('../src/editor.js');
// Inline index.html handlers (onchange="setMonacoTheme()", onclick="exitFermion()")
// resolve against window; the renderer is bundled (IIFE) so top-level functions
// are no longer implicit globals — expose the ones HTML references.
window.setMonacoTheme = setMonacoTheme;
window.exitFermion = () => exitFermion();

// Overwrite default node.js prop to get Jquery working
window.$ = window.jQuery = require('jquery');

// -= Output terminal =-
// Replaces the old <textarea>. The #FridaOut host is parsed above this script,
// so it exists now; creating the terminal here means the startup banner
// (printed from index.html after this script) lands in it.
let fermionTerminal = null;
(function () {
	const host = document.getElementById('FridaOut');
	if (host) {
		fermionTerminal = createTerminal(host);
		window.__fermion = { terminal: fermionTerminal, handleScriptMessage };
		window.addEventListener('resize', function () { if (fermionTerminal) fermionTerminal.fit(); });
		setTimeout(function () { if (fermionTerminal) fermionTerminal.fit(); }, 300);
	}
})();

// Globals
//////////////////////////////////////////////////

var currentFilePath = null;

// All frida-node interaction runs in the MAIN process; the renderer drives it
// through the preload bridge (window.fermion) and keeps a small local state
// mirror for synchronous UI guards (the bridge is async-only). Events
// (message/log/detached) are subscribed below, after traceSender exists.
const fapi = window.fermion;
let fstate = { deviceId: 'local', isAttached: false, hasScript: false, currentPid: null };
function refreshState() { return fapi.getState().then((s) => { fstate = s; return s; }); }

// Pure trace routing (was frida-service.routeMessage): a SEND payload goes to
// the trace window only while trace mode is on, otherwise to the terminal.
function routeMessage(kind, mode) { return (mode && kind === 'SEND') ? 'trace' : 'terminal'; }

// UI-side flag: while on, SEND payloads route to the trace window (see
// onServiceMessage). Tied to the loaded script (reset on user-script load +
// detach; set once the tracer is live).
let traceMode = false;

// Enhanced Frida Output variables
let originalSplit = null;
// Layout controller (src/layout.js), built in the DOMContentLoaded handler
// once the DOM + split instance exist. Owns the live isVertical state.
let layout = null;

// Instrument
//////////////////////////////////////////////////

// -= Inject (UI orchestration over the service) =-
// Matches the old inject(): attach -> publish PID to the trace window ->
// create+load the editor's script. Status text ("[+] Injecting => …") is
// logged by the caller, as before.
function injectVia(pid) {
	fapi.attach(pid)
		.then(() => refreshState())
		.then((s) => {
			traceSender.postMessage(s.currentPid);
			return fapi.loadScript(window.MonacoCodeEditor.getValue());
		})
		.then(() => { fstate.hasScript = true; traceMode = false; })  // user script loaded -> terminal routing
		.catch(e => { appendFridaLog(e); });
}

// -= Start (UI orchestration over the service) =-
// Matches the old start(): spawn+attach -> publish PID -> "[+] Injecting" ->
// load script -> resume -> "[+] Process start success".
function startVia(ProcPath, ProcArgs) {
	let spawnedPid;
	fapi.spawn(ProcPath, ProcArgs)
		.then(({ pid }) => { spawnedPid = pid; return refreshState(); })
		.then((s) => {
			traceSender.postMessage(s.currentPid);
			appendFridaLog('[+] Injecting => PID: ' + spawnedPid + ', Name: ' + ProcPath);
			return fapi.loadScript(window.MonacoCodeEditor.getValue()).then(() => fapi.resume(spawnedPid));
		})
		.then(() => { fstate.hasScript = true; traceMode = false; appendFridaLog('[+] Process start success'); })
		.catch(e => { appendFridaLog(e); });
}

// -= Detach =-

document.getElementById("FridaDetach").onclick = function () {
	if (fstate.isAttached) {
		appendFridaLog('[+] Detaching..');
		fapi.detach();
		fstate.isAttached = false;
		traceSender.postMessage(null);
	} else {
		appendFridaLog('[!] Not currently attached..');
	}
}

// -= Reload Script =-

document.getElementById("FridaReload").onclick = function () {
	if (fstate.isAttached) {
		if (fstate.hasScript) {
			fapi.reloadScript(window.MonacoCodeEditor.getValue())
				.then(() => { traceMode = false; appendFridaLog('[+] Script reloaded..'); })
				.catch(e => { appendFridaLog(e); });
		} else {
			appendFridaLog('[!] Not currently attached..');
		}
	} else {
		appendFridaLog('[!] Not currently attached..');
	}
}

// -= Shim for process list attach =-

function handleAttachProcess(message) {
	if (!fstate.isAttached) {
		appendFridaLog('[?] Attempting process attach..');
		fapi.enumerateProcesses().then(data => {
			// Search active processes
			var resultArray = [];
			data.find(function (element) {
				if (element.pid == message) {
					resultArray.push(element);
				}
			})

			// Do we have a single match?
			if (resultArray.length == 0) {
				appendFridaLog('[!] Process not found..');
				return;
			} else if (resultArray.length > 1) {
				appendFridaLog('[!] Ambiguous process match..');
				for (var i = 0; i < resultArray.length; i++) {
					appendFridaLog('PID: ' + resultArray[i].pid + ', Name: ' + resultArray[i].name);
				}
				return;
			} else {
				appendFridaLog('[+] Injecting => PID: ' + resultArray[0].pid + ', Name: ' + resultArray[0].name);
				injectVia(resultArray[0].pid);
			}
		}).catch((err) => {
			appendFridaLog(`[!] Error: ${err.message}`);
		});

	} else {
		appendFridaLog('[!] Already attached to a process..');
	}
}
fapi.onAttachProcess(handleAttachProcess);

// -= Shim for attach invocation =-

fapi.onAttachProcessShim(async (message) => {
	if (!fstate.isAttached) {
		appendFridaLog('[?] Attempting process attach..');
		fapi.enumerateProcesses().then(data => {
			// What are we searching for?
			var ProcName = message[0];
			var ProcId = message[1];
			var queryProc;
			if ((!ProcId || 0 === ProcId.length) && (!ProcName || 0 === ProcName.length)) {
				appendFridaLog('[!] Process parameters not provided..');
				return;
			} else if (ProcId.length > 0 && ProcName.length > 0) {
				queryProc = ProcId;
			} else {
				if (!ProcId || 0 === ProcId.length) {
					queryProc = ProcName;
				} else {
					queryProc = ProcId;
				}
			}

			// Search active processes
			var resultArray = [];
			data.find(function (element) {
				if (element.name.includes(queryProc) || element.pid == queryProc) {
					resultArray.push(element);
				}
			})

			// Do we have a single match?
			if (resultArray.length == 0) {
				appendFridaLog('[!] Process not found..');
				return;
			} else if (resultArray.length > 1) {
				appendFridaLog('[!] Ambiguous process match..');
				for (var i = 0; i < resultArray.length; i++) {
					appendFridaLog('PID: ' + resultArray[i].pid + ', Name: ' + resultArray[i].name);
				}
				return;
			} else {
				appendFridaLog('[+] Injecting => PID: ' + resultArray[0].pid + ', Name: ' + resultArray[0].name);
				injectVia(resultArray[0].pid);
			}
		}).catch((err) => {
			appendFridaLog(`[!] Error: ${err.message}`);
		});

	} else {
		appendFridaLog('[!] Already attached to a process..');
	}
});

// -= Shim for start invocation =-

fapi.onStartProcessShim(async (message) => {
	if (!fstate.isAttached) {
		appendFridaLog('[?] Attempting process start..');
		var ProcPath = message[0];
		var ProcAgrs = message[1];
		if (!ProcPath || 0 === ProcPath.length) {
			appendFridaLog('[!] Process parameters not provided..');
			return;
		} else {
			startVia(ProcPath, ProcAgrs);
		}
	} else {
		appendFridaLog('[!] Already attached to a process..');
	}
});

// Pages
//////////////////////////////////////////////////

// -= Device Selector =-

document.getElementById("setDevice").onclick = function () {
	fapi.openWindow('device.html', { width: 420, height: 615, extraArgs: [fstate.deviceId] });
}

fapi.onNewDevice(async (message) => {
	const id = await fapi.setDevice(message);
	fstate.deviceId = id;
});

// -= Process Listing =-

document.getElementById("FridaProc").onclick = function () {
	fapi.openWindow('proc.html', { width: 570, height: 600, extraArgs: [fstate.deviceId] });
}

// -= Instrument Manager =-

document.getElementById("FridaAttach").onclick = function () {
	fapi.openWindow('instrument.html', { width: 420, height: 595 });
}

// -= About =-

document.getElementById("FermionAbout").onclick = function () {
	fapi.openWindow('about.html', { width: 460, height: 270, extraArgs: [fstate.deviceId] });
}

// -= JS API Docs =-

document.getElementById("FermionDocs").onclick = function () {
	fapi.openWindow('docs.html', { width: 800, height: 800 });
}

// -= Trace =-

let TraceWin = null;
document.getElementById("FermionTools").onclick = function () {
	// The trace window expects a PID string; use "null" when not attached.
	const pidArg = (fstate.currentPid == null || fstate.currentPid.length == 0)
		? "null" : fstate.currentPid;
	// @electron/remote is enabled for this window by the main process
	// (browser-window-created handler in core.js).
	TraceWin = fapi.openWindow('trace.html', { width: 425, height: 615, extraArgs: [pidArg] });
}

// Create IPC sender
const traceSender = new BroadcastChannel('trace-data-send');

// Trace is a UI-side mode layered on the service (the service stays
// trace-ignorant). Entering trace reloads the active script with the Graphviz
// tracer and flips traceMode so SEND payloads route to the trace window; STOP
// reloads the editor's script and clears the flag.
traceSender.onmessage = function (message) {
	if (message.data == "STOP") {
		// Reloading the editor script clears traceMode (reload's .then), so the
		// tracer's trailing output during the reload gap still routes to the
		// trace window until the user script is live.
		appendFridaLog('\n[+] Graphviz tracer will be unloaded..');
		appendFridaLog('    |_ Reloading script in Monaco editor\n');
		document.getElementById("FridaReload").click();
	} else {
		if (fstate.isAttached) {
			if (fstate.hasScript) {
				fapi.reloadScript(message.data)
					.then(() => {
						// Flip to trace routing only once the tracer is live, so a
						// send() during the reload gap still goes to the terminal.
						traceMode = true;
						appendFridaLog('\n[+] Current script unloaded..');
						appendFridaLog('    |_ Graphviz tracer loaded\n');
					})
					.catch(e => { appendFridaLog(e); });
			} else {
				appendFridaLog('[!] Not currently attached..');
			}
		} else {
			appendFridaLog('[!] Not currently attached..');
		}
	}
}

// -= Service event wiring =-
// message -> terminal, unless trace mode forwards a SEND payload to the trace
// window (routeMessage). log -> terminal via handleScriptMessage. detached ->
// clear the trace window PID and print the exit reason.
function onServiceMessage(message) {
	const { kind, text } = formatMessage(message);
	if (routeMessage(kind, traceMode) === 'trace') {
		appendFridaLog("[>] Received Graphviz trace data");
		traceSender.postMessage(message.payload);
	} else if (fermionTerminal) {
		fermionTerminal.write(kind, text);
	}
}
fapi.onMessage(onServiceMessage);
fapi.onLog((level, text) => handleScriptMessage({ type: 'log', level, payload: text }));
fapi.onDetached((reason) => {
	traceMode = false;  // no active script -> routing resets (fixes trace->detach->re-attach misroute)
	fstate.isAttached = false;
	traceSender.postMessage(null);
	appendFridaLog(`[+] Exit Reason: ${reason}`);
});
// Prime the local state mirror from the main-process service.
refreshState();
// Sync view of the service state for the Playwright suite (bridge is async),
// plus a test-surface attach trigger (the isolated renderer has no ipcRenderer,
// so tests can't send the 'attach-process' relay directly).
if (window.__fermion) {
	window.__fermion.service = {
		get isAttached() { return fstate.isAttached; },
		get hasScript() { return fstate.hasScript; },
		get currentPid() { return fstate.currentPid; },
		get deviceId() { return fstate.deviceId; },
	};
	window.__fermion.triggerAttach = (pid) => handleAttachProcess(pid);
}

// Logging
//////////////////////////////////////////////////

// Maps a Frida message/log record to a typed terminal line (console.log->LOG,
// warn->WARN, error-level log / throw->ERR, send->SEND, unknown->STATUS) and
// writes it to the terminal. Used for the service's `log` events and by the
// test harness (window.__fermion.handleScriptMessage). The service's `message`
// events go through onServiceMessage, which adds trace-mode routing.
function handleScriptMessage(message) {
	const { kind, text } = formatMessage(message);
	if (fermionTerminal) fermionTerminal.write(kind, text);
}

// Status/meta output goes to the terminal as the STATUS kind. The terminal
// owns its own scrollback cap and follow-tail behavior (replacing the old
// textarea trim + overlay-search).
function appendFridaLog(data) {
	if (fermionTerminal) fermionTerminal.write('STATUS', data);
}

// Monaco editor setup, theme switching, and the version banner now live in
// src/editor.js (setMonacoTheme is imported above and re-exposed on window).

// UI Handler
//////////////////////////////////////////////////

function exitFermion() {
	fapi.closeWindow();
}

document.getElementById("FermionDevTools").onclick = function () {
	fapi.openDevTools();
}

document.getElementById("FermionOpen").onclick = function () {
	fapi.openFile().then(result => {
		if (!result) return;
		appendFridaLog("[+] File opened..");
		appendFridaLog("    |-> Path: " + result.path);
		window.MonacoCodeEditor.setValue(result.content);
		// Set global filepath on success
		currentFilePath = result.path;
	}).catch(err => {
		appendFridaLog("[!] Error opening file: " + err)
	})
}

document.getElementById("FermionSave").onclick = function () {
	const content = window.MonacoCodeEditor.getValue();
	fapi.saveFile(content, { title: "Fermion Save File" }).then(savedPath => {
		if (!savedPath) return;
		appendFridaLog("[+] File saved..");
		appendFridaLog("    |-> Path: " + savedPath);
		// Set global filepath on success
		currentFilePath = savedPath;
	}).catch(err => {
		appendFridaLog("[!] Error saving file: " + err)
	})
}

document.getElementById("getDeviceDetail").onclick = function () {
	appendFridaLog("\n[>] Device --> " + fstate.deviceId);
	fapi.getDeviceInfo().then(({ name, params, paramsError }) => {
		appendFridaLog("    |_ Device Name : " + name);
		if (paramsError) {
			appendFridaLog("[!] Failed to enumerate device properties: " + paramsError + "\n");
			return;
		}
		const result = params;
		if (result.hasOwnProperty("os")) {
			if (result.os.hasOwnProperty("name")) {
				appendFridaLog("    |_ Platform    : " + result.os.name);
			}
			if (result.os.hasOwnProperty("version")) {
				appendFridaLog("    |_ Version     : " + result.os.version);
			}
		}
		if (result.hasOwnProperty("arch")) {
			appendFridaLog("    |_ Arch        : " + result.arch);
		}
		if (result.hasOwnProperty("access")) {
			appendFridaLog("    |_ Access      : " + result.access);
		}
		if (result.hasOwnProperty("name")) {
			appendFridaLog("    |_ Host Name   : " + result.name + "\n");
		}
	}).catch(err => {
		appendFridaLog("[!] Failed to acquire device context: " + err + "\n");
	});
}

document.getElementById("FermionMonacoWrap").onclick = function () {
	toggleWrap();
}

// Trap keybinds
//////////////////////////////////////////////////

document.addEventListener("keydown", function (e) {
	if ((window.navigator.platform.match("Mac") ? e.metaKey : e.ctrlKey) && e.keyCode == 83) {
		e.preventDefault();

		// Do we currently have a known file path?
		if (currentFilePath == null) {
			// Trigger the save function
			document.getElementById("FermionSave").click();
		} else {
			// Overwrite known file
			fapi.messageBox({
				type: "warning",
				buttons: ["Yes", "No"],
				defaultId: 1,
				title: "Save File",
				message: "Overwrite existing file?",
				detail: currentFilePath,
				cancelId: 1,
			}).then(result => {
				if (result.response == 0) {
					const content = window.MonacoCodeEditor.getValue();
					fapi.saveFileTo(currentFilePath, content).then(() => {
						appendFridaLog("[+] File saved..");
						appendFridaLog("    |-> Path: " + currentFilePath);
					}).catch(err => {
						appendFridaLog("[!] Error saving file: " + err);
						appendFridaLog("    |-> Path: " + currentFilePath);
					})
				}
			})
		}
	}
}, false);

document.addEventListener("keydown", function (e) {
	if ((window.navigator.platform.match("Mac") ? e.metaKey : e.ctrlKey) && e.keyCode == 79) {
		e.preventDefault();
		// Trigger the save function
		document.getElementById("FermionOpen").click();
	}
}, false);

document.addEventListener("keydown", function (e) {
	if ((window.navigator.platform.match("Mac") ? e.metaKey : e.ctrlKey) && e.keyCode == 84) {
		e.preventDefault();
		// Trigger script reload
		document.getElementById("FridaReload").click();
	}
}, false);

document.getElementById('clear-output').title = "Clear output (Alt+C)";
// Add keyboard shortcut for clearing output panel
document.addEventListener("keydown", function (e) {
	// Clear Output with Alt+C
	if (e.altKey && e.keyCode == 67) {
		e.preventDefault();
		clearOutputArea();
	}
}, false);

//////////////////////////////////////////////////
// Frida Output Enhancement Functions
//////////////////////////////////////////////////

// Store DOM references
const copyButton = document.getElementById('copy-output');
const decreaseFontButton = document.getElementById('decrease-font');
const increaseFontButton = document.getElementById('increase-font');
const regexSearch = document.getElementById('regex-search');
const searchButton = document.getElementById('search-button');
const toggleLayoutButton = document.getElementById('toggle-layout');
const clearOutputButton = document.getElementById('clear-output');
const saveOutputButton = document.getElementById('save-output');


// Initialize features when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
	// Monaco editor setup + startup version banner (src/editor.js). Must run
	// AFTER split-1.6.4.js and monaco-theme.js have loaded (editor.js sets
	// self.module = undefined for the Monaco AMD loader, which would corrupt
	// split's UMD load if run during parse). DOMContentLoaded is after both.
	// The Monaco AMD load is async, so the editor still mounts a moment later.
	initEditor({ log: appendFridaLog });

	// Build the layout controller first — loadSettings() may call
	// layout.toggleLayout() to restore a saved horizontal layout.
	layout = createLayout({
		getTerminal: () => fermionTerminal,
		getEditor: () => window.MonacoCodeEditor,
		onChange: saveSettings,
	});

	// Make sure window.split is available before storing it
	setTimeout(() => {
		if (window.split) {
			originalSplit = window.split;
		}
	}, 500);

	// Load saved settings from localStorage
	loadSettings();

	// Add event listeners
	addEventListeners();

	// Initialize the layout button icon
	layout.initLayoutButton();

	// Initial UI adjustment
	setTimeout(() => layout.adjustUIForSidebar(), 100);

	// Initialize Monaco editor with custom theme
	setTimeout(addMonacoSettingsListeners, 1500);

	// Wire the terminal toolbar (search, level filters, follow-tail).
	wireTerminalToolbar();
});

// Wire the output terminal's toolbar controls to the terminal controller.
function wireTerminalToolbar() {
	const t = fermionTerminal;
	if (!t) return;

	const searchInput = document.getElementById('regex-search');
	if (searchInput) {
		const runNext = () => { if (searchInput.value) t.searchNext(searchInput.value); };
		const searchBtn = document.getElementById('search-button');
		if (searchBtn) searchBtn.addEventListener('click', runNext);
		searchInput.addEventListener('keydown', (e) => {
			if (e.key === 'Enter') {
				e.preventDefault();
				if (searchInput.value) (e.shiftKey ? t.searchPrev : t.searchNext)(searchInput.value);
			} else if (e.key === 'Escape') {
				e.preventDefault();
				searchInput.value = '';
				t.clearSearch();
			}
		});
		const clearBtn = document.getElementById('clear-search');
		if (clearBtn) clearBtn.addEventListener('click', () => { searchInput.value = ''; t.clearSearch(); });
	}

	// Level filter chips (LOG/WARN/ERR/SEND/STATUS) — all start visible (.on).
	document.querySelectorAll('.flt-chip').forEach((chip) => {
		chip.addEventListener('click', () => {
			const on = chip.classList.toggle('on');
			t.setFilter(chip.getAttribute('data-kind'), on);
		});
	});

	// Follow-tail toggle (on by default).
	const followBtn = document.getElementById('term-follow');
	if (followBtn) followBtn.addEventListener('click', () => {
		t.setFollow(followBtn.classList.toggle('on'));
	});
}

// Add event listeners to UI elements
function addEventListeners() {
	// Copy button functionality
	copyButton.addEventListener('click', copyOutputToClipboard);

	// Font size controls
	decreaseFontButton.addEventListener('click', decreaseFontSize);
	increaseFontButton.addEventListener('click', increaseFontSize);

	// Layout toggle
	toggleLayoutButton.addEventListener('click', () => layout.toggleLayout());

	// Output clear / save
	clearOutputButton.addEventListener('click', clearOutputArea);
	saveOutputButton.addEventListener('click', saveOutputArea);

	// Sidebar state changes and window resize
	window.addEventListener('resize', () => layout.adjustUIForSidebar());

	// Add a listener for possible sidebar toggle events
	document.addEventListener('click', function (event) {
		// Check if click might be related to sidebar toggle
		if (event.target.closest('nav') || event.target.closest('.navbar-menu')) {
			// Wait a moment for DOM to update
			setTimeout(() => layout.adjustUIForSidebar(), 100);
		}
	});
}

// Copy output to clipboard
function copyOutputToClipboard() {
	const text = fermionTerminal ? fermionTerminal.copySelectionOrAll() : '';
	if (navigator.clipboard && navigator.clipboard.writeText) {
		navigator.clipboard.writeText(text);
	}
	showNotification('Copied to clipboard!');
}

// Show notification
function showNotification(message) {
	// Remove any existing notifications
	const existingNotification = document.querySelector('.notification');
	if (existingNotification) {
		existingNotification.remove();
	}

	// Create notification element
	const notification = document.createElement('div');
	notification.className = 'notification';
	notification.textContent = message;
	document.body.appendChild(notification);

	// Remove after 2 seconds
	setTimeout(() => {
		if (notification.parentNode) {
			notification.parentNode.removeChild(notification);
		}
	}, 2000);
}

// Decrease terminal font size
function decreaseFontSize() {
	if (!fermionTerminal) return;
	fermionTerminal.setFontSize(Math.max(8, fermionTerminal.getFontSize() - 1));
}

// Increase terminal font size
function increaseFontSize() {
	if (!fermionTerminal) return;
	fermionTerminal.setFontSize(Math.min(28, fermionTerminal.getFontSize() + 1));
}


// Save settings to localStorage
function saveSettings() {
	// Get the current Monaco theme
	const themeSelect = document.getElementById("MonacoThemeSelect");
	const currentTheme = themeSelect ? themeSelect.value : "Kuroir"; // Default if not found

	// Get the current wrap state
	const wrapToggle = document.getElementById("FermionMonacoWrap");
	const isWrapEnabled = wrapToggle && wrapToggle.children[0] ?
		wrapToggle.children[0].checked : false;

	const settings = {
		isVertical: layout ? layout.isVertical() : true,
		// Monaco Editor settings
		monacoTheme: currentTheme,
		monacoWrap: isWrapEnabled
	};

	writeSettings(settings);
}

// Function to clear the output area
function clearOutputArea() {
	if (fermionTerminal) fermionTerminal.clear();
	showNotification('Output cleared');
}


// Function to save the output area content to a file
function saveOutputArea() {
	// Get the content from the terminal buffer
	const content = fermionTerminal ? fermionTerminal.getText() : '';

	// If content is empty, show notification and return
	if (!content.trim()) {
		showNotification('Nothing to save');
		return;
	}

	// Show save dialog (write happens in main via the bridge)
	fapi.saveFile(content, {
		title: "Save Frida Output",
		defaultPath: "frida-output.txt",
		filters: [
			{ name: 'Text Files', extensions: ['txt'] },
			{ name: 'Log Files', extensions: ['log'] },
			{ name: 'All Files', extensions: ['*'] }
		]
	}).then(savedPath => {
		if (savedPath) {
			showNotification('Output saved successfully');
			appendFridaLog("[+] Output saved..");
			appendFridaLog("    |-> Path: " + savedPath);
		}
	}).catch(err => {
		appendFridaLog("[!] Error saving output: " + err);
	});
}

// Load settings from localStorage
function loadSettings() {
	const settings = readSettings();
	if (settings) {
		{
			// Apply layout direction. The app starts vertical (isVertical = true)
			// and toggleLayout() both flips isVertical and rebuilds the split, so
			// restore a saved HORIZONTAL layout by calling toggleLayout() once.
			// (Previously this also did `isVertical = settings.isVertical`, which
			// cancelled out the flip inside toggleLayout and then re-saved the
			// preference as vertical, so horizontal was never restored.)
			if (settings.hasOwnProperty('isVertical') && settings.isVertical === false
				&& typeof window.split !== 'undefined') {
				setTimeout(function () {
					layout.toggleLayout();
				}, 500);
			}

			// Apply Monaco Editor theme
			if (settings.monacoTheme) {
				// Wait for Monaco editor to be fully initialized
				setTimeout(function () {
					const themeSelect = document.getElementById("MonacoThemeSelect");
					if (themeSelect) {
						// Set the dropdown value
						themeSelect.value = settings.monacoTheme;
						// Apply the theme
						setMonacoTheme();
					}
				}, 1000); // Allow time for Monaco to initialize
			}

			// Apply Monaco Editor wrap setting
			if (settings.hasOwnProperty('monacoWrap')) {
				setTimeout(function () {
					const wrapToggle = document.getElementById("FermionMonacoWrap");
					if (wrapToggle && wrapToggle.children[0]) {
						// Set the checkbox state
						wrapToggle.children[0].checked = settings.monacoWrap;

						// Apply the wrap setting to Monaco
						if (window.MonacoCodeEditor) {
							window.MonacoCodeEditor.updateOptions({
								wordWrap: settings.monacoWrap ? "on" : "off"
							});
						}
					}
				}, 1000); // Allow time for Monaco to initialize
			}
		}
	}
}

// Prevent default actions for F5 and Ctrl+R
// This is to prevent the default refresh behavior of the browser
document.addEventListener("keydown", function (e) {
	// Prevent F5 key
	if (e.key === 'F5' || e.keyCode === 116) {
		e.preventDefault();
		// For Debug purposes
		//appendFridaLog('[i] Refresh prevented (F5)');
		return false;
	}

	// Prevent Ctrl+R
	if ((window.navigator.platform.match("Mac") ? e.metaKey : e.ctrlKey) && (e.key === 'r' || e.keyCode === 82)) {
		e.preventDefault();
		// For Debug purposes
		//appendFridaLog('[i] Refresh prevented (Ctrl+R)');
		return false;
	}
}, false);

// Add event listeners to save settings when Monaco editor settings change
function addMonacoSettingsListeners() {
	// Theme change listener
	const themeSelect = document.getElementById("MonacoThemeSelect");
	if (themeSelect) {
		themeSelect.addEventListener('change', function () {
			// The setMonacoTheme function is already called by the onchange attribute,
			// so we just need to save the settings
			setTimeout(saveSettings, 100);
		});
	}

	// Wrap toggle listener - add this only if the existing onclick doesn't save settings
	const wrapToggle = document.getElementById("FermionMonacoWrap");
	if (wrapToggle) {
		wrapToggle.addEventListener('click', function () {
			// The existing onclick handler toggles the wrap state,
			// we just need to save the settings afterward
			setTimeout(saveSettings, 100);
		});
	}
}
