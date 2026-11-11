const electron = require('electron');
const path = require('path');
const ipc = require('electron').ipcRenderer;
const remote = require('@electron/remote');
const BrowserWindow = remote.BrowserWindow;
const dialog = remote.dialog;
var fs = require('fs');
const frida = require('frida');
const { wrapExtraArgs } = require('../src/helper.js');
const { createTerminal } = require('../src/terminal.js');
const { formatMessage } = require('../src/output-model.js');
const { readSettings, writeSettings } = require('../src/settings.js');
const { createLayout } = require('../src/layout.js');

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

var MonacoCodeEditor;
var currentFilePath = null;
let script = null;
var session = null;
var sessionPID = null;
var deviceId = 'local';

// Enhanced Frida Output variables
let originalSplit = null;
// Layout controller (src/layout.js), built in the DOMContentLoaded handler
// once the DOM + split instance exist. Owns the live isVertical state.
let layout = null;

// Instrument
//////////////////////////////////////////////////

// -= Inject =-
async function inject(AttachTo) {
	// Exit on process termination
	process.on('SIGTERM', stop);
	process.on('SIGINT', stop);

	// Attach and load script
	device = await frida.getDevice(deviceId);
	session = await device.attach(AttachTo);
	sessionPID = session.pid.toString();
	traceSender.postMessage(sessionPID);
	session.detached.connect(onDetached);
	script = await session.createScript(MonacoCodeEditor.getValue());

	// For performance we can't update the text area all the time
	// it will lock the UI on big volumes of data. Instead we append
	// to an array using a mutex and every X ms we flush the array
	// to the text area
	wireScript(script);
	await script.load();
}

// -= Start =-
async function start(Path, Args) {
	// Exit on process termination
	process.on('SIGTERM', stop);
	process.on('SIGINT', stop);

	// Attach and load script
	device = await frida.getDevice(deviceId);
	if (!Args || 0 === Args.length) {
		procID = await device.spawn(Path);
	} else {
		var aBuildArgs = Args.split(" ");
		aBuildArgs.unshift(Path)
		procID = await device.spawn(aBuildArgs);
	}
	session = await device.attach(procID);
	sessionPID = session.pid.toString();
	traceSender.postMessage(sessionPID);
	session.detached.connect(onDetached);
	script = await session.createScript(MonacoCodeEditor.getValue());

	// For performance we can't update the text area all the time
	// it will lock the UI on big volumes of data. Instead we append
	// to an array using a mutex and every X ms we flush the array
	// to the text area
	wireScript(script);

	appendFridaLog('[+] Injecting => PID: ' + procID + ', Name: ' + Path);
	await script.load();

	device.resume(procID);
	appendFridaLog('[+] Process start success');
}

// -= On Terminate =-
function stop() {
	script.unload();
}

function onDetached(reason) {
	if (session != null) {
		session = null;
		traceSender.postMessage(null);
	}
	appendFridaLog(`[+] Exit Reason: ${reason}`);
}

// -= Detach =-

document.getElementById("FridaDetach").onclick = function () {
	if (session != null) {
		appendFridaLog('[+] Detaching..');
		session.detach();
		session = null;
		traceSender.postMessage(null);
	} else {
		appendFridaLog('[!] Not currently attached..');
	}
}

// -= Reload Script =-

document.getElementById("FridaReload").onclick = async function () {
	if (session != null) {
		if (script != null) {
			script.unload();
			script = await session.createScript(MonacoCodeEditor.getValue());
			wireScript(script);
			appendFridaLog('[+] Script reloaded..');
			await script.load();
		} else {
			appendFridaLog('[!] Not currently attached..');
		}
	} else {
		appendFridaLog('[!] Not currently attached..');
	}
}

// -= Proc Listing =-
async function getProcList() {
	let currentDevice = await frida.getDevice(deviceId);
	let Applications = await currentDevice.enumerateProcesses();
	return Applications;
}

// -= Shim for process list attach =-

ipc.on('attach-process', async (event, message) => {
	if (session == null) {
		appendFridaLog('[?] Attempting process attach..');
		getProcList().then(data => {
			// Search active processes
			var resultArray = [];
			data.find(function (element) {
				var Result = [];
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
				inject(resultArray[0].pid).catch(e => {
					appendFridaLog(e);
				});
			}
		}).catch((err) => {
			appendFridaLog(`[!] Error: ${err.message}`);
		});

	} else {
		appendFridaLog('[!] Already attached to a process..');
	}
});

// -= Shim for attach invocation =-

ipc.on('attach-process-shim', async (event, message) => {
	if (session == null) {
		appendFridaLog('[?] Attempting process attach..');
		getProcList().then(data => {
			// What are we searching for?
			var ProcName = message[0];
			var ProcId = message[1];
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
				var Result = [];
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
				inject(resultArray[0].pid).catch(e => {
					appendFridaLog(e);
				});
			}
		}).catch((err) => {
			appendFridaLog(`[!] Error: ${err.message}`);
		});

	} else {
		appendFridaLog('[!] Already attached to a process..');
	}
});

// -= Shim for start invocation =-

ipc.on('start-process-shim', async (event, message) => {
	if (session == null) {
		appendFridaLog('[?] Attempting process start..');
		var ProcPath = message[0];
		var ProcAgrs = message[1];
		if (!ProcPath || 0 === ProcPath.length) {
			appendFridaLog('[!] Process parameters not provided..');
			return;
		} else {
			start(ProcPath, ProcAgrs).catch(e => {
				appendFridaLog(e);
				return;
			});
		}
	} else {
		appendFridaLog('[!] Already attached to a process..');
	}
});

// -= Shim for trace invocation =-

async function trace(scriptBody) {
	if (session != null) {
		if (script != null) {
			script.unload();
			script = await session.createScript(scriptBody);
			wireScript(script, function (payload) {
				appendFridaLog("[>] Received Graphviz trace data");
				// Forward the DOT payload to the trace window (not printed here).
				traceSender.postMessage(payload);
			});
			appendFridaLog('\n[+] Current script unloaded..');
			appendFridaLog('    |_ Graphviz tracer loaded\n');
			await script.load();
		} else {
			appendFridaLog('[!] Not currently attached..');
		}
	} else {
		appendFridaLog('[!] Not currently attached..');
	}
}

// Pages
//////////////////////////////////////////////////

// -= Device Selector =-

document.getElementById("setDevice").onclick = function () {
	const modalPath = path.join(__dirname, 'device.html');
	let ProcWin = new BrowserWindow({
		contextIsolation: false,
		width: 420,
		height: 615,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true,
			additionalArguments: wrapExtraArgs([deviceId])
		}
	})

	ProcWin.loadFile(modalPath);
	ProcWin.once('ready-to-show', () => {
		setTimeout(function () {
			ProcWin.show();
			ProcWin.focus();
		}, 50);
	});
	ProcWin.on('close', function () { ProcWin = null })
}

ipc.on('new-device', async (event, message) => {
	// Do we need to unregister a current remote socket?
	if (deviceId.startsWith("socket@")) {
		var dm = await frida.getDeviceManager();
		dm.removeRemoteDevice(deviceId.split('@')[1]);
	}

	// Do we need to register a new remote socket?
	if (message.startsWith("socket@")) {
		var dm = await frida.getDeviceManager();
		var devID = await dm.addRemoteDevice(message.split('@')[1]);
		deviceId = devID.id;
	} else {
		deviceId = message;
	}
});

// -= Process Listing =-

document.getElementById("FridaProc").onclick = function () {
	const modalPath = path.join(__dirname, 'proc.html');
	let ProcWin = new BrowserWindow({
		contextIsolation: false,
		width: 570,
		height: 600,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true,
			additionalArguments: wrapExtraArgs([deviceId])
		}
	})

	ProcWin.loadFile(modalPath);
	ProcWin.once('ready-to-show', () => {
		setTimeout(function () {
			ProcWin.show();
			ProcWin.focus();
		}, 50);
	});
	ProcWin.on('close', function () { ProcWin = null })
}

// -= Instrument Manager =-

document.getElementById("FridaAttach").onclick = function () {
	const modalPath = path.join(__dirname, 'instrument.html');
	let ProcWin = new BrowserWindow({
		contextIsolation: false,
		width: 420,
		height: 595,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true
		}
	})

	ProcWin.loadFile(modalPath);
	ProcWin.once('ready-to-show', () => {
		setTimeout(function () {
			ProcWin.show();
			ProcWin.focus();
		}, 50);
	});
	ProcWin.on('close', function () { ProcWin = null })
}

// -= About =-

document.getElementById("FermionAbout").onclick = function () {
	const modalPath = path.join(__dirname, 'about.html');
	let ProcWin = new BrowserWindow({
		contextIsolation: false,
		width: 460,
		height: 270,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true,
			additionalArguments: wrapExtraArgs([deviceId])
		}
	})

	ProcWin.loadFile(modalPath);
	ProcWin.once('ready-to-show', () => {
		setTimeout(function () {
			ProcWin.show();
			ProcWin.focus();
		}, 50);
	});
	ProcWin.on('close', function () { ProcWin = null })
}

// -= JS API Docs =-

document.getElementById("FermionDocs").onclick = function () {
	const modalPath = path.join(__dirname, 'docs.html');
	let ProcWin = new BrowserWindow({
		contextIsolation: false,
		width: 800,
		height: 800,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true
		}
	})

	ProcWin.loadFile(modalPath);
	ProcWin.once('ready-to-show', () => {
		setTimeout(function () {
			ProcWin.show();
			ProcWin.focus();
		}, 50);
	});
	ProcWin.on('close', function () { ProcWin = null })
}

// -= Trace =-

let TraceWin = null;
document.getElementById("FermionTools").onclick = function () {
	const modalPath = path.join(__dirname, 'trace.html');
	if (sessionPID == null || sessionPID.length == 0) {
		sessionPID = "null";
	}
	TraceWin = new BrowserWindow({
		contextIsolation: false,
		width: 425,
		height: 615,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true,
			additionalArguments: wrapExtraArgs([sessionPID])
		}
	})

	// @electron/remote is enabled for this window by the main process
	// (browser-window-created handler in core.js).

	TraceWin.loadFile(modalPath);
	TraceWin.once('ready-to-show', () => {
		setTimeout(function () {
			TraceWin.show();
			TraceWin.focus();
		}, 50);
	});
	TraceWin.on('close', function () { TraceWin = null })
}

// Create IPC sender
const traceSender = new BroadcastChannel('trace-data-send');

// Invoke trace shim
traceSender.onmessage = function (message) {
	if (message.data == "STOP") {
		appendFridaLog('\n[+] Graphviz tracer will be unloaded..');
		appendFridaLog('    |_ Reloading script in Monaco editor\n');
		document.getElementById("FridaReload").click();
	} else {
		trace(message.data);
	}
}

// Logging
//////////////////////////////////////////////////

// Shared handler for every Frida script.message. Maps the message to a typed
// line (console.log->LOG, warn->WARN, error-level log / throw->ERR, send->SEND,
// unknown->STATUS) and writes it to the terminal. The `send` branch is
// parameterized: when `onSend` is given (the trace site) the raw payload is
// forwarded instead of printed.
function handleScriptMessage(message, onSend) {
	const { kind, text } = formatMessage(message);
	if (kind === 'SEND' && typeof onSend === 'function') {
		onSend(message.payload);
		return;
	}
	if (fermionTerminal) fermionTerminal.write(kind, text);
}

// Wire a freshly created Frida script to the terminal. send() and runtime
// errors arrive via the `message` signal; but Frida delivers console.log/warn/
// error to `logHandler` (it does NOT emit `message` for log records), so route
// both through handleScriptMessage. `onSend` (trace) is forwarded to message.
function wireScript(script, onSend) {
	script.message.connect(message => handleScriptMessage(message, onSend));
	script.logHandler = (level, text) => handleScriptMessage({ type: 'log', level, payload: text });
}

// Status/meta output goes to the terminal as the STATUS kind. The terminal
// owns its own scrollback cap and follow-tail behavior (replacing the old
// textarea trim + overlay-search).
function appendFridaLog(data) {
	if (fermionTerminal) fermionTerminal.write('STATUS', data);
}

// Monaco Editor
//////////////////////////////////////////////////

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
};

function setMonacoTheme() {
	var theme = document.getElementById("MonacoThemeSelect").value;
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

// UI Handler
//////////////////////////////////////////////////

function exitFermion() {
	var CurrWnd = remote.getCurrentWindow();
	CurrWnd.close();
}

document.getElementById("FermionDevTools").onclick = function () {
	var CurrWnd = remote.getCurrentWindow();
	CurrWnd.webContents.openDevTools({ mode: 'detach' });
}

document.getElementById("FermionOpen").onclick = function () {
	dialog.showOpenDialog(
		{
			properties: ['openFile'],
			title: "Fermion Open File",
		}
	).then(result => {
		if (result.filePaths.length == 0) {
			return;
		} else {
			fs.readFile(result.filePaths[0], 'utf-8', (err, data) => {
				if (err) {
					appendFridaLog("[!] Error opening file: " + err.message);
					return;
				} else {
					appendFridaLog("[+] File opened..");
					appendFridaLog("    |-> Path: " + result.filePaths[0]);
				}
				MonacoCodeEditor.setValue(data);
				// Set global filepath on success
				currentFilePath = result.filePaths[0];
			});
		}
	}).catch(err => {
		appendFridaLog("[!] Error opening file: " + err)
	})
}

document.getElementById("FermionSave").onclick = function () {
	dialog.showSaveDialog(
		{
			title: "Fermion Save File",
		}
	).then(result => {
		if (result.filePath) {
			content = MonacoCodeEditor.getValue();
			fs.writeFile(result.filePath, content, (err) => {
				if (err) {
					appendFridaLog("[!] Error saving file: " + err.message)
					return;
				} else {
					appendFridaLog("[+] File saved..");
					appendFridaLog("    |-> Path: " + result.filePath);
				}
				// Set global filepath on success
				currentFilePath = result.filePath;
			});
		}
	}).catch(err => {
		appendFridaLog("[!] Error saving file: " + err)
	})
}

document.getElementById("getDeviceDetail").onclick = function () {
	appendFridaLog("\n[>] Device --> " + deviceId);
	frida.getDevice(deviceId).then(dev => {
		appendFridaLog("    |_ Device Name : " + dev.name);
		dev.querySystemParameters().then(result => {
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
			appendFridaLog("[!] Failed to enumerate device properties: " + err + "\n");
		});
	}).catch(err => {
		appendFridaLog("[!] Failed to acquire device context: " + err + "\n");
	});
}

document.getElementById("FermionMonacoWrap").onclick = function () {
	// Toggle the current state
	var wrapState = document.getElementById("FermionMonacoWrap");
	if (wrapState.children[0].checked == false) {
		MonacoCodeEditor.updateOptions({ wordWrap: "on" });
		wrapState.children[0].checked = true;
	} else {
		MonacoCodeEditor.updateOptions({ wordWrap: "off" });
		wrapState.children[0].checked = false;
	}
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
			dialog.showMessageBox(
				{
					type: "warning",
					buttons: ["Yes", "No"],
					defaultId: 1,
					title: "Save File",
					message: "Overwrite existing file?",
					detail: currentFilePath,
					cancelId: 1,
				}
			).then(result => {
				if (result.response == 0) {
					content = MonacoCodeEditor.getValue();
					fs.writeFile(currentFilePath, content, (err) => {
						if (err) {
							appendFridaLog("[!] Error saving file: " + err.message);
							appendFridaLog("    |-> Path: " + currentFilePath);
						} else {
							appendFridaLog("[+] File saved..");
							appendFridaLog("    |-> Path: " + currentFilePath);
						}
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
	// Build the layout controller first — loadSettings() may call
	// layout.toggleLayout() to restore a saved horizontal layout.
	layout = createLayout({
		getTerminal: () => fermionTerminal,
		getEditor: () => MonacoCodeEditor,
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

	// Show save dialog
	dialog.showSaveDialog(
		{
			title: "Save Frida Output",
			defaultPath: "frida-output.txt",
			filters: [
				{ name: 'Text Files', extensions: ['txt'] },
				{ name: 'Log Files', extensions: ['log'] },
				{ name: 'All Files', extensions: ['*'] }
			]
		}
	).then(result => {
		if (result.filePath) {
			// Write the content to the file
			fs.writeFile(result.filePath, content, (err) => {
				if (err) {
					appendFridaLog("[!] Error saving output: " + err.message);
					return;
				} else {
					showNotification('Output saved successfully');
					appendFridaLog("[+] Output saved..");
					appendFridaLog("    |-> Path: " + result.filePath);
				}
			});
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
						if (MonacoCodeEditor) {
							MonacoCodeEditor.updateOptions({
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
