const electron = require('electron');
const path = require('path');
const ipc = require('electron').ipcRenderer;
var MutexPromise = require('mutex-promise');
const remote = require('@electron/remote');
const BrowserWindow = remote.BrowserWindow;
const dialog = remote.dialog;
var fs = require('fs');
const frida = require('frida');
const { wrapExtraArgs } = require('../src/helper.js');

// Overwrite default node.js prop to get Jquery working
window.$ = window.jQuery = require('jquery');

// Globals
//////////////////////////////////////////////////

var MonacoCodeEditor;
var currentFilePath = null;
let script = null;
var session = null;
var sessionPID = null;
let logMutex = new MutexPromise('48011b2b9a930ee19e26320e5adbffa2e309663c');
let RunningLog = [];
var deviceId = 'local';

// Enhanced Frida Output variables
let currentFontSize = 0.8; // em units
let isVertical = true;
let searchRegex = null;
let bgColor = '#423636';
let textColor = '#ffffff';
let highlightColor = '#ffff00';
let highlightTextColor = '#000000';
let originalSplit = null;

// Add these new search-related variables
let matchPositions = [];
let currentMatchIndex = -1;
let totalMatches = 0;
let currentMatchColor = '#FFD300';
let currentMatchTextColor = '#000000';

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
	script.message.connect(message => {
		if (message.type == "send") {
			ChangeLogExclusive(logMutex, 'Append', message.payload);
		} else {
			ChangeLogExclusive(logMutex, 'Append', "[!] Runtime error: " + message.stack);
		}
		setTimeout(function () {
			if (RunningLog.length > 0) {
				ChangeLogExclusive(logMutex, 'Write', null);
			}
		}, 500);
	});
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
	script.message.connect(message => {
		if (message.type == "send") {
			ChangeLogExclusive(logMutex, 'Append', message.payload);
		} else {
			ChangeLogExclusive(logMutex, 'Append', "[!] Runtime error: " + message.stack);
		}
		setTimeout(function () {
			if (RunningLog.length > 0) {
				ChangeLogExclusive(logMutex, 'Write', null);
			}
		}, 500);
	});

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
			script.message.connect(message => {
				if (message.type == "send") {
					ChangeLogExclusive(logMutex, 'Append', message.payload);
				} else {
					ChangeLogExclusive(logMutex, 'Append', "[!] Runtime error: " + message.stack);
				}
				setTimeout(function () {
					if (RunningLog.length > 0) {
						ChangeLogExclusive(logMutex, 'Write', null);
					}
				}, 500);
			});
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
			script.message.connect(message => {
				if (message.type == "send") {
					ChangeLogExclusive(logMutex, 'Append', "[>] Received Graphviz trace data");
					// Send it back to trace window
					traceSender.postMessage(message.payload);
				} else {
					ChangeLogExclusive(logMutex, 'Append', "[!] Runtime error: " + message.stack);
				}
				setTimeout(function () {
					if (RunningLog.length > 0) {
						ChangeLogExclusive(logMutex, 'Write', null);
					}
				}, 500);
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
	const modalPath = path.join('file://', __dirname, 'device.html');
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

	ProcWin.loadURL(modalPath);
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
	const modalPath = path.join('file://', __dirname, 'proc.html');
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

	ProcWin.loadURL(modalPath);
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
	const modalPath = path.join('file://', __dirname, 'instrument.html');
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

	ProcWin.loadURL(modalPath);
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
	const modalPath = path.join('file://', __dirname, 'about.html');
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

	ProcWin.loadURL(modalPath);
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
	const modalPath = path.join('file://', __dirname, 'docs.html');
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

	ProcWin.loadURL(modalPath);
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
	const modalPath = path.join('file://', __dirname, 'trace.html');
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

	// Node 14+ patch, jesus node devs, just leave us alone with remote already..
	require("@electron/remote").require("@electron/remote/main").enable(TraceWin.webContents);

	TraceWin.loadURL(modalPath);
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

function appendFridaLog(data) {
	var FridaOut = document.getElementById('FridaOut');
	FridaOut.value += (data + "\n");

	// DIY garbage collection
	// |-> If the textarea grows too large it locks up the app
	var aFridaOut = FridaOut.value.split("\n");
	var iMaxLen = 5000; // max line count in textarea
	if (aFridaOut.length > iMaxLen) {
		var iRemCount = aFridaOut.length - iMaxLen;
		aFridaOut.splice(0, iRemCount);
		FridaOut.value = aFridaOut.join("\n");
	}

	FridaOut.scrollTop = FridaOut.scrollHeight;

	// If search is active, update highlights
	if (searchRegex) {
		performSearch();
	}
}

function ChangeLogExclusive(mutex, locktype, data) {
	return mutex.promise()
		.then(function (mutex) {
			mutex.lock();
			if (locktype == "Append") {
				RunningLog.push(data);
			} else if (locktype == "Write") {
				appendFridaLog(RunningLog.join("\n"));
				RunningLog = [];
			}
		})
		.then(function (res) {
			mutex.unlock();
			return res;
		})
		.catch(function (e) {
			mutex.unlock();
			throw e;
		});
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

//////////////////////////////////////////////////
// Frida Output Enhancement Functions
//////////////////////////////////////////////////

// Store DOM references
const fridaOut = document.getElementById('FridaOut');
const copyButton = document.getElementById('copy-output');
const decreaseFontButton = document.getElementById('decrease-font');
const increaseFontButton = document.getElementById('increase-font');
const regexSearch = document.getElementById('regex-search');
const searchButton = document.getElementById('search-button');
const toggleLayoutButton = document.getElementById('toggle-layout');
const colorSettingsButton = document.getElementById('color-settings');
const colorModal = document.getElementById('color-modal');
const closeModalBtn = document.querySelector('.close-modal');
const applyColorsButton = document.getElementById('apply-colors');
const resetColorsButton = document.getElementById('reset-colors');
const bgColorPicker = document.getElementById('background-color');
const bgColorHex = document.getElementById('background-color-hex');
const textColorPicker = document.getElementById('text-color');
const textColorHex = document.getElementById('text-color-hex');
const highlightColorPicker = document.getElementById('highlight-color');
const highlightColorHex = document.getElementById('highlight-color-hex');
const highlightOverlay = document.getElementById('highlight-overlay');
const currentMatchColorPicker = document.getElementById('current-match-color');
const currentMatchColorHex = document.getElementById('current-match-color-hex');
const clearOutputButton = document.getElementById('clear-output');
const saveOutputButton = document.getElementById('save-output');


// Initialize features when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
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
	initLayoutButton();

	// Initial UI adjustment
	setTimeout(adjustUIForSidebar, 100);

	// Initialize Monaco editor with custom theme
	setTimeout(addMonacoSettingsListeners, 1500);

	// Initialize search functionality with new features
	setTimeout(() => {
		initSearchFunctionality();
		addSearchNavButtons();
		addSearchKeyboardShortcuts();
		addSearchStyles();
	}, 500);
});

// Add event listeners to UI elements
function addEventListeners() {
	// Copy button functionality
	copyButton.addEventListener('click', copyOutputToClipboard);

	// Font size controls
	decreaseFontButton.addEventListener('click', decreaseFontSize);
	increaseFontButton.addEventListener('click', increaseFontSize);

	// Search functionality
	searchButton.addEventListener('click', performSearch);
	regexSearch.addEventListener('keypress', function (e) {
		if (e.key === 'Enter') {
			if (searchRegex) {
				navigateToNextMatch();
			} else {
				performSearch();
			}
		}
	});

	regexSearch.addEventListener('input', function () {
		if (this.value.trim() === '') {
			clearSearch();
		}
	});

	// Layout toggle
	toggleLayoutButton.addEventListener('click', toggleLayout);

	// Color settings
	colorSettingsButton.addEventListener('click', function () {
		colorModal.style.display = 'block';
	});

	closeModalBtn.addEventListener('click', function () {
		colorModal.style.display = 'none';
	});

	clearOutputButton.addEventListener('click', clearOutputArea);

	saveOutputButton.addEventListener('click', saveOutputArea);


	window.addEventListener('click', function (event) {
		if (event.target === colorModal) {
			colorModal.style.display = 'none';
		}
	});

	currentMatchColorPicker.addEventListener('input', function () {
		currentMatchColorHex.value = this.value;
	});

	currentMatchColorHex.addEventListener('input', function () {
		if (/^#[0-9A-F]{6}$/i.test(this.value)) {
			currentMatchColorPicker.value = this.value;
		}
	});

	// Link color pickers with hex inputs
	bgColorPicker.addEventListener('input', function () {
		bgColorHex.value = this.value;
	});

	bgColorHex.addEventListener('input', function () {
		if (/^#[0-9A-F]{6}$/i.test(this.value)) {
			bgColorPicker.value = this.value;
		}
	});

	textColorPicker.addEventListener('input', function () {
		textColorHex.value = this.value;
	});

	textColorHex.addEventListener('input', function () {
		if (/^#[0-9A-F]{6}$/i.test(this.value)) {
			textColorPicker.value = this.value;
		}
	});

	highlightColorPicker.addEventListener('input', function () {
		highlightColorHex.value = this.value;
	});

	highlightColorHex.addEventListener('input', function () {
		if (/^#[0-9A-F]{6}$/i.test(this.value)) {
			highlightColorPicker.value = this.value;
		}
	});


	// Apply and reset buttons
	applyColorsButton.addEventListener('click', applyColors);
	resetColorsButton.addEventListener('click', resetColors);

	// Sync scrolling between textarea and highlight overlay
	fridaOut.addEventListener('scroll', function () {
		highlightOverlay.scrollTop = fridaOut.scrollTop;
		highlightOverlay.scrollLeft = fridaOut.scrollLeft;
	});

	// Handle textarea input and content changes for highlighting
	fridaOut.addEventListener('input', function () {
		// If search is active, update highlights
		if (searchRegex) {
			performSearch();
		}
	});

	// Monitor textarea size changes to adjust highlight overlay
	new ResizeObserver(() => {
		if (searchRegex) {
			performSearch();
		}
	}).observe(fridaOut);

	// Add event listeners for sidebar state changes and window resize
	window.addEventListener('resize', adjustUIForSidebar);

	// Add a listener for possible sidebar toggle events
	document.addEventListener('click', function (event) {
		// Check if click might be related to sidebar toggle
		if (event.target.closest('nav') || event.target.closest('.navbar-menu')) {
			// Wait a moment for DOM to update
			setTimeout(adjustUIForSidebar, 100);
		}
	});
}

// Function to add navigation buttons to the toolbar
function addSearchNavButtons() {
	// First check if buttons already exist
	if (document.getElementById('prev-match') || document.getElementById('next-match')) {
		return;
	}

	const searchContainer = document.querySelector('.search-container');

	// Create navigation buttons
	const navContainer = document.createElement('div');
	navContainer.className = 'search-nav-buttons';
	navContainer.style.display = 'none'; // Hidden by default

	const prevButton = document.createElement('button');
	prevButton.id = 'prev-match';
	prevButton.className = 'toolbar-button';
	prevButton.title = 'Previous match (Shift+Enter)';
	prevButton.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"></polyline></svg>`;

	const nextButton = document.createElement('button');
	nextButton.id = 'next-match';
	nextButton.className = 'toolbar-button';
	nextButton.title = 'Next match (Enter)';
	nextButton.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>`;

	navContainer.appendChild(prevButton);
	navContainer.appendChild(nextButton);

	// Insert before the search button
	const searchButton = document.getElementById('search-button');
	searchContainer.insertBefore(navContainer, searchButton);

	// Add event listeners
	prevButton.addEventListener('click', navigateToPreviousMatch);
	nextButton.addEventListener('click', navigateToNextMatch);
}

// Function to navigate to the previous match
function navigateToPreviousMatch() {
	if (matchPositions.length === 0) return;

	currentMatchIndex = (currentMatchIndex <= 0) ? matchPositions.length - 1 : currentMatchIndex - 1;
	highlightCurrentMatch();
	scrollToCurrentMatch();
	updateMatchCounter();
}

// Function to navigate to the next match
function navigateToNextMatch() {
	if (matchPositions.length === 0) return;

	currentMatchIndex = (currentMatchIndex >= matchPositions.length - 1) ? 0 : currentMatchIndex + 1;
	highlightCurrentMatch();
	scrollToCurrentMatch();
	updateMatchCounter();
}

// Function to scroll the textarea to show the current match
function scrollToCurrentMatch() {
	if (currentMatchIndex < 0 || matchPositions.length === 0) return;

	const fridaOut = document.getElementById('FridaOut');
	const match = matchPositions[currentMatchIndex];

	// Calculate position in the textarea
	const textBeforeMatch = fridaOut.value.substring(0, match.start);
	const lines = textBeforeMatch.split('\n');

	// Create a temporary element to measure text dimensions
	const temp = document.createElement('div');
	temp.style.position = 'absolute';
	temp.style.visibility = 'hidden';
	temp.style.whiteSpace = 'pre';
	temp.style.font = window.getComputedStyle(fridaOut).font;
	document.body.appendChild(temp);

	// Calculate the line height
	temp.textContent = 'M';
	const lineHeight = temp.offsetHeight;

	// Calculate approximate scroll position
	const lineNumber = lines.length - 1;
	const approximateScrollTop = lineNumber * lineHeight;

	// Remove the temporary element
	document.body.removeChild(temp);

	// Scroll to position, with some offset to center it in the view
	const viewportHeight = fridaOut.clientHeight;
	fridaOut.scrollTop = approximateScrollTop - (viewportHeight / 2) + lineHeight;
}

// Function to update the UI counter showing current match position
function updateMatchCounter() {
	// Update or create the match counter
	let counter = document.querySelector('.match-indicator');

	if (!counter) {
		counter = document.createElement('div');
		counter.className = 'match-indicator';
		document.querySelector('.textarea-container').appendChild(counter);
	}

	if (matchPositions.length > 0) {
		counter.textContent = `${currentMatchIndex + 1} of ${matchPositions.length} matches`;
		counter.style.display = 'block';

		// Show navigation buttons
		const navButtons = document.querySelector('.search-nav-buttons');
		if (navButtons) {
			navButtons.style.display = 'flex';
		}
	} else {
		counter.style.display = 'none';

		// Hide navigation buttons
		const navButtons = document.querySelector('.search-nav-buttons');
		if (navButtons) {
			navButtons.style.display = 'none';
		}
	}
}

// Copy output to clipboard
function copyOutputToClipboard() {
	fridaOut.select();
	document.execCommand('copy');
	window.getSelection().removeAllRanges();

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

// Decrease font size
function decreaseFontSize() {
	if (currentFontSize > 0.5) {
		currentFontSize -= 0.1;
		currentFontSize = Math.round(currentFontSize * 10) / 10; // Round to 1 decimal place
		fridaOut.style.fontSize = currentFontSize + 'em';
		highlightOverlay.style.fontSize = currentFontSize + 'em';
		saveSettings();

		// Reapply search highlighting if active
		if (searchRegex) {
			performSearch();
		}
	}
}

// Increase font size
function increaseFontSize() {
	if (currentFontSize < 2.0) {
		currentFontSize += 0.1;
		currentFontSize = Math.round(currentFontSize * 10) / 10; // Round to 1 decimal place
		fridaOut.style.fontSize = currentFontSize + 'em';
		highlightOverlay.style.fontSize = currentFontSize + 'em';
		saveSettings();

		// Reapply search highlighting if active
		if (searchRegex) {
			performSearch();
		}
	}
}

// Improved synchronization function for textarea and overlay
function syncOverlayDimensions() {
	if (!highlightOverlay || !fridaOut) return;

	// Get computed dimensions from the textarea
	const computedStyle = window.getComputedStyle(fridaOut);

	// Apply exact dimensions and properties to the overlay
	highlightOverlay.style.width = computedStyle.width;
	highlightOverlay.style.height = computedStyle.height;
	highlightOverlay.style.padding = computedStyle.padding;
	highlightOverlay.style.boxSizing = computedStyle.boxSizing;
	highlightOverlay.style.fontFamily = computedStyle.fontFamily;
	highlightOverlay.style.fontSize = computedStyle.fontSize;
	highlightOverlay.style.lineHeight = computedStyle.lineHeight;
	highlightOverlay.style.letterSpacing = computedStyle.letterSpacing;
	highlightOverlay.style.wordSpacing = computedStyle.wordSpacing;
	highlightOverlay.style.textAlign = computedStyle.textAlign;
	highlightOverlay.style.whiteSpace = 'pre-wrap'; // This matches textarea behavior

	// Sync scroll position
	highlightOverlay.scrollTop = fridaOut.scrollTop;
	highlightOverlay.scrollLeft = fridaOut.scrollLeft;
}

// Updated CSS to apply to the highlight overlay
function updateOverlayStyles() {
	const style = document.createElement('style');
	style.textContent = `
	  .highlight-overlay {
		position: absolute;
		top: 0;
		left: 0;
		width: 100%;
		height: 100%;
		pointer-events: none;
		color: transparent;
		overflow: auto;
		font-family: monospace;
		font-size: 0.8em;
		line-height: 1.7em;
		padding: 8px;
		box-sizing: border-box;
		border: 1px solid transparent;
		z-index: 5;
		white-space: pre-wrap; /* Match textarea behavior */
	  }
  
	  .highlight-match {
		background-color: var(--highlight-bg, #ffff00);
		color: var(--highlight-text, #000000) !important;
		padding: 0;
		border-radius: 2px;
		display: inline;
	  }
	`;
	document.head.appendChild(style);
}

// Enhanced function to adjust UI based on sidebar state
function adjustUIForSidebar() {
	// Get the actual width of the container
	const containerWidth = document.getElementById('split-1').offsetWidth;

	// Adjust search container width based on available space
	const searchContainer = document.querySelector('.search-container');
	if (searchContainer) {
		// Make search container narrower if space is limited
		if (containerWidth < 300) {
			searchContainer.style.maxWidth = '100px';
			searchContainer.style.minWidth = '60px';
		} else {
			searchContainer.style.maxWidth = '220px'; // Updated to accommodate navigation buttons
			searchContainer.style.minWidth = '80px';
		}
	}

	// Update overlay dimensions after sidebar changes
	syncOverlayDimensions();

	// If search is active, reapply highlights
	if (searchRegex) {
		performSearch();
	}
}

// Initialize the search-related functionality
function initSearchFunctionality() {
	// Update overlay styles
	updateOverlayStyles();

	// Set clear button event
	document.getElementById('clear-search').addEventListener('click', clearSearch);

	// Handle input changes for search box
	document.getElementById('regex-search').addEventListener('input', function () {
		if (this.value.trim() === '') {
			clearSearch();
		}
	});

	// Handle search button clicks
	document.getElementById('search-button').addEventListener('click', performSearch);

	// Handle Enter key in search box
	document.getElementById('regex-search').addEventListener('keypress', function (e) {
		if (e.key === 'Enter') {
			if (searchRegex) {
				navigateToNextMatch();
			} else {
				performSearch();
			}
		}
	});

	// Sync scrolling between textarea and highlight overlay
	document.getElementById('FridaOut').addEventListener('scroll', function () {
		document.getElementById('highlight-overlay').scrollTop = this.scrollTop;
		document.getElementById('highlight-overlay').scrollLeft = this.scrollLeft;
	});
}

// Add keyboard shortcuts for search
function addSearchKeyboardShortcuts() {
	// Global Ctrl+F to focus search box
	document.addEventListener('keydown', function (e) {
		// Check if this is Ctrl+F (or Cmd+F on Mac)
		if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
			// Don't intercept if user is typing in Monaco editor (it has its own search)
			const activeElement = document.activeElement;
			const isInMonacoEditor = activeElement &&
				(activeElement.closest('.monaco-editor') ||
					document.querySelector('.monaco-editor').contains(activeElement));

			if (!isInMonacoEditor) {
				e.preventDefault();
				// Focus the search box
				const searchInput = document.getElementById('regex-search');
				searchInput.focus();
				searchInput.select();
			}
		}
	});

	// Search box keyboard navigation
	const searchInput = document.getElementById('regex-search');
	searchInput.addEventListener('keydown', function (e) {
		if (e.key === 'Enter') {
			// Shift+Enter to go to previous match
			if (e.shiftKey) {
				e.preventDefault();
				navigateToPreviousMatch();
			}
			// Enter to go to next match
			else {
				e.preventDefault();
				// If we have an active search, navigate to next match
				if (searchRegex) {
					navigateToNextMatch();
				}
				// Otherwise, perform search
				else {
					performSearch();
				}
			}
		}
		// Escape to clear search
		else if (e.key === 'Escape') {
			e.preventDefault();
			clearSearch();
		}
	});

	// Textarea Esc key to clear search
	document.getElementById('FridaOut').addEventListener('keydown', function (e) {
		if (e.key === 'Escape' && searchRegex) {
			e.preventDefault();
			clearSearch();
		}
	});
}

// Add search styles
function addSearchStyles() {
	const styleEl = document.createElement('style');
	styleEl.textContent = `
	  .highlight-match.current-match {
		background-color: var(--current-match-bg, ${currentMatchColor}) !important;
		color: var(--current-match-text, ${currentMatchTextColor}) !important;
	  }
	  
	  .search-nav-buttons {
		display: flex;
		align-items: center;
		margin-right: 5px;
	  }
	`;
	document.head.appendChild(styleEl);

	// Set initial CSS variables
	document.documentElement.style.setProperty('--current-match-bg', currentMatchColor);
	document.documentElement.style.setProperty('--current-match-text', currentMatchTextColor);
}

// Perform search
function performSearch() {
	const searchTerm = document.getElementById('regex-search').value.trim();

	if (searchTerm === '') {
		searchRegex = null;
		clearSearch();
		return;
	}

	try {
		// Create a new regex object
		searchRegex = new RegExp(searchTerm, 'gi');
		highlightMatches();
	} catch (error) {
		showNotification('Invalid regular expression: ' + error.message);
		searchRegex = null;
		clearHighlights();
	}
}

// Function to clear the search
function clearSearch() {
	const searchInput = document.getElementById('regex-search');
	searchInput.value = '';
	searchRegex = null;
	matchPositions = [];
	currentMatchIndex = -1;
	totalMatches = 0;
	clearHighlights();

	// Hide match indicator
	const matchIndicator = document.querySelector('.match-indicator');
	if (matchIndicator) {
		matchIndicator.style.display = 'none';
	}

	// Hide navigation buttons
	const navButtons = document.querySelector('.search-nav-buttons');
	if (navButtons) {
		navButtons.style.display = 'none';
	}
}

// Clear highlights
function clearHighlights() {
	highlightOverlay.innerHTML = '';

	// Remove match indicator if present
	const matchIndicator = document.querySelector('.match-indicator');
	if (matchIndicator) {
		matchIndicator.parentNode.removeChild(matchIndicator);
	}
}

// Enhanced highlight function
function highlightMatches() {
	if (!searchRegex) return;

	// Clear previous highlights
	highlightOverlay.innerHTML = '';

	// Get the current text
	const content = fridaOut.value;
	if (!content) return;

	// Reset match tracking
	matchPositions = [];
	totalMatches = 0;

	// Ensure overlay dimensions match textarea exactly
	syncOverlayDimensions();

	// Create a fresh regex for the actual processing
	const processRegex = new RegExp(searchRegex.source, 'gi');

	// Transform content to HTML with highlights
	let htmlContent = '';
	let lastIndex = 0;
	let match;

	while ((match = processRegex.exec(content)) !== null) {
		// Add text before the match
		htmlContent += content.substring(lastIndex, match.index);

		// Store match position
		matchPositions.push({
			start: match.index,
			end: processRegex.lastIndex,
			text: match[0]
		});

		// Add the highlighted match with a data attribute for the match index
		htmlContent += `<span class="highlight-match" data-match-index="${matchPositions.length - 1}">${match[0]}</span>`;

		lastIndex = processRegex.lastIndex;
		totalMatches++;

		// Prevent infinite loops for zero-length matches
		if (match.index === processRegex.lastIndex) {
			processRegex.lastIndex++;
		}
	}

	// Add remaining text after the last match
	if (lastIndex < content.length) {
		htmlContent += content.substring(lastIndex);
	}

	// Replace newlines with <br> tags for proper display
	htmlContent = htmlContent.replace(/\n/g, '<br>');

	// Set the HTML content
	highlightOverlay.innerHTML = htmlContent;

	// If we have matches, set the current match to the first one
	if (matchPositions.length > 0) {
		// Default to first match if we don't have a current match index
		if (currentMatchIndex < 0 || currentMatchIndex >= matchPositions.length) {
			currentMatchIndex = 0;
		}

		// Highlight the current match
		highlightCurrentMatch();

		// Show match counter
		updateMatchCounter();

		// Scroll to the current match
		scrollToCurrentMatch();
	} else {
		// No matches found
		currentMatchIndex = -1;
		showNotification('No matches found');

		// Hide navigation buttons
		const navButtons = document.querySelector('.search-nav-buttons');
		if (navButtons) {
			navButtons.style.display = 'none';
		}
	}
}

// Function to highlight the current match
function highlightCurrentMatch() {
	// Remove any existing current-match classes
	const allMatches = highlightOverlay.querySelectorAll('.highlight-match');
	allMatches.forEach(match => {
		match.style.backgroundColor = highlightColor;
		match.style.color = highlightTextColor;
	});

	// Apply current match highlighting
	if (currentMatchIndex >= 0 && currentMatchIndex < matchPositions.length) {
		const currentMatch = highlightOverlay.querySelector(`.highlight-match[data-match-index="${currentMatchIndex}"]`);
		if (currentMatch) {
			currentMatch.style.backgroundColor = currentMatchColor;
			currentMatch.style.color = currentMatchTextColor;
		}
	}
}

const verticalIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
  <line x1="12" y1="3" x2="12" y2="21"></line>
</svg>`;

const horizontalIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
  <line x1="3" y1="12" x2="21" y2="12"></line>
</svg>`;

// Toggle layout direction
function toggleLayout() {
	// Toggle the layout state
	isVertical = !isVertical;

	// Ensure split instance exists
	if (typeof window.split !== 'undefined') {
		// Get elements we'll need to manipulate
		const split0 = document.getElementById('split-0');
		const split1 = document.getElementById('split-1');
		const container = document.getElementById('container');
		const fridaOutContainer = document.querySelector('.textarea-container');
		const splitContainer = document.querySelector('.split');

		// Force visibility of the output area during transition
		fridaOut.style.display = 'block';

		// Destroy existing split
		window.split.destroy();

		// Remove all inline styles that might interfere
		split0.removeAttribute('style');
		split1.removeAttribute('style');

		// Apply basic required styles
		split0.style.overflow = 'hidden';
		split1.style.overflow = 'hidden';
		container.style.width = '100%';
		container.style.height = '100%';

		// Update container classes
		if (isVertical) {
			splitContainer.classList.remove('horizontal');
		} else {
			splitContainer.classList.add('horizontal');
		}

		// Create new split with a delay to ensure DOM updates
		setTimeout(() => {
			window.split = Split(['#split-0', '#split-1'], {
				direction: isVertical ? 'vertical' : 'horizontal',
				sizes: isVertical ? [63, 37] : [50, 50],
				minSize: 100,
				gutterSize: 8,
				onDragEnd: function () {
					window.dispatchEvent(new Event('resize'));
					if (MonacoCodeEditor) {
						MonacoCodeEditor.layout();
					}
				}
			});

			// Force output container to take full width/height
			fridaOutContainer.style.width = '100%';
			fridaOutContainer.style.height = '100%';
			fridaOut.style.width = '100%';
			fridaOut.style.height = '100%';

			// Force Monaco editor layout update
			if (MonacoCodeEditor) {
				MonacoCodeEditor.layout();
			}

			// Update layout button icon
			updateLayoutButtonIcon();

			// Sync overlay dimensions
			syncOverlayDimensions();
		}, 50);

		// Save settings
		saveSettings();
	}
}

// Function to update the layout button icon based on current state
function updateLayoutButtonIcon() {
	const toggleButton = document.getElementById('toggle-layout');

	// Note: We've swapped the logic here - show what layout we're CURRENTLY in
	// (not what we'll switch to next)
	toggleButton.innerHTML = isVertical ? verticalIcon : horizontalIcon;
	toggleButton.title = isVertical ? "Switch to horizontal layout" : "Switch to vertical layout";
}

function initLayoutButton() {
	// Set the initial icon based on the current layout
	updateLayoutButtonIcon();
}

// Apply colors
function applyColors() {
	bgColor = bgColorPicker.value;
	textColor = textColorPicker.value;
	highlightColor = highlightColorPicker.value;
	highlightTextColor = getContrastColor(highlightColor);
	currentMatchColor = currentMatchColorPicker.value;
	currentMatchTextColor = getContrastColor(currentMatchColor);

	// Apply colors to textarea
	fridaOut.style.backgroundColor = bgColor;
	fridaOut.style.color = textColor;

	// Set CSS variables for highlight colors
	document.documentElement.style.setProperty('--highlight-bg', highlightColor);
	document.documentElement.style.setProperty('--highlight-text', highlightTextColor);
	document.documentElement.style.setProperty('--current-match-bg', currentMatchColor);
	document.documentElement.style.setProperty('--current-match-text', currentMatchTextColor);

	// Close modal
	colorModal.style.display = 'none';

	// Save settings
	saveSettings();

	// Reapply highlighting if active
	if (searchRegex) {
		performSearch();
	}
}

// Reset colors to defaults
function resetColors() {
	// Default colors
	bgColor = '#423636';
	textColor = '#ffffff';
	highlightColor = '#ffff00';
	highlightTextColor = '#000000';
	currentMatchColor = '#FFD300';
	currentMatchTextColor = '#000000';

	// Update color pickers and hex inputs
	bgColorPicker.value = bgColor;
	bgColorHex.value = bgColor;
	textColorPicker.value = textColor;
	textColorHex.value = textColor;
	highlightColorPicker.value = highlightColor;
	highlightColorHex.value = highlightColor;
	currentMatchColorPicker.value = currentMatchColor;
	currentMatchColorHex.value = currentMatchColor;

	// Apply colors
	fridaOut.style.backgroundColor = bgColor;
	fridaOut.style.color = textColor;

	// Set CSS variables
	document.documentElement.style.setProperty('--highlight-bg', highlightColor);
	document.documentElement.style.setProperty('--highlight-text', highlightTextColor);
	document.documentElement.style.setProperty('--current-match-bg', currentMatchColor);
	document.documentElement.style.setProperty('--current-match-text', currentMatchTextColor);

	// Close modal
	colorModal.style.display = 'none';

	// Save settings
	saveSettings();

	// Reapply highlighting if active
	if (searchRegex) {
		performSearch();
	}
}

// Get contrast color (black or white) based on background color
function getContrastColor(hexColor) {
	// Convert hex to RGB
	const r = parseInt(hexColor.substr(1, 2), 16);
	const g = parseInt(hexColor.substr(3, 2), 16);
	const b = parseInt(hexColor.substr(5, 2), 16);

	// Calculate luminance - standard formula for perceived brightness
	const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;

	// Return black for light colors, white for dark
	return luminance > 0.5 ? '#000000' : '#ffffff';
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
		fontSize: currentFontSize,
		bgColor: bgColor,
		textColor: textColor,
		highlightColor: highlightColor,
		currentMatchColor: currentMatchColor,
		isVertical: isVertical,
		// Add Monaco Editor settings
		monacoTheme: currentTheme,
		monacoWrap: isWrapEnabled
	};

	localStorage.setItem('fermion_output_settings', JSON.stringify(settings));
}

// Function to clear the output area
function clearOutputArea() {
	// Get the textarea
	const fridaOut = document.getElementById('FridaOut');

	// Clear the textarea content
	fridaOut.value = '';

	// Clear highlights if search is active
	clearHighlights();

	// Reset search-related variables
	searchRegex = null;
	matchPositions = [];
	currentMatchIndex = -1;
	totalMatches = 0;

	// Hide match indicator
	const matchIndicator = document.querySelector('.match-indicator');
	if (matchIndicator) {
		matchIndicator.style.display = 'none';
	}

	// Hide navigation buttons
	const navButtons = document.querySelector('.search-nav-buttons');
	if (navButtons) {
		navButtons.style.display = 'none';
	}

	// Show notification
	showNotification('Output cleared');
}


// Function to save the output area content to a file
function saveOutputArea() {
	// Get the content from the textarea
	const fridaOut = document.getElementById('FridaOut');
	const content = fridaOut.value;

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
	const savedSettings = localStorage.getItem('fermion_output_settings');
	if (savedSettings) {
		try {
			const settings = JSON.parse(savedSettings);

			// Apply font size
			if (settings.fontSize && !isNaN(settings.fontSize)) {
				currentFontSize = settings.fontSize;
				fridaOut.style.fontSize = currentFontSize + 'em';
				highlightOverlay.style.fontSize = currentFontSize + 'em';
			}

			// Apply colors
			if (settings.bgColor) {
				bgColor = settings.bgColor;
				bgColorPicker.value = bgColor;
				bgColorHex.value = bgColor;
				fridaOut.style.backgroundColor = bgColor;
			}

			if (settings.textColor) {
				textColor = settings.textColor;
				textColorPicker.value = textColor;
				textColorHex.value = textColor;
				fridaOut.style.color = textColor;
			}

			if (settings.highlightColor) {
				highlightColor = settings.highlightColor;
				highlightColorPicker.value = highlightColor;
				highlightColorHex.value = highlightColor;
				highlightTextColor = getContrastColor(highlightColor);
			}

			if (settings.currentMatchColor) {
				currentMatchColor = settings.currentMatchColor;
				currentMatchColorPicker.value = currentMatchColor;
				currentMatchColorHex.value = currentMatchColor;
				currentMatchTextColor = getContrastColor(currentMatchColor);
			}

			// Set CSS variables
			document.documentElement.style.setProperty('--highlight-bg', highlightColor);
			document.documentElement.style.setProperty('--highlight-text', highlightTextColor);
			document.documentElement.style.setProperty('--current-match-bg', currentMatchColor);
			document.documentElement.style.setProperty('--current-match-text', currentMatchTextColor);

			// Apply layout direction
			if (settings.hasOwnProperty('isVertical')) {
				isVertical = settings.isVertical;

				// If not vertical, toggle the layout after a short delay
				if (!isVertical && typeof window.split !== 'undefined') {
					setTimeout(function () {
						toggleLayout();
					}, 500);
				}
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
		} catch (error) {
			console.error('Error loading settings:', error);
		}
	}
}

// Initialize on load
window.addEventListener('load', function () {
	// Make sure highlighting overlay has the correct initial font size
	highlightOverlay.style.fontSize = currentFontSize + 'em';

	// Add the color modal to the document body if it's not already there
	if (!document.getElementById('color-modal')) {
		const modalHTML = document.getElementById('color-modal');
		document.body.appendChild(modalHTML);
	}
});

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
