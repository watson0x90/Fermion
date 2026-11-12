// @ts-check
// Main-process file handlers behind the renderer's Open / Save / Recent.
//
// The main process owns "the current script file" and the recent-files list,
// so the renderer never gets a read-anywhere or write-anywhere primitive:
//   - it can write the current file only after a dialog chose it,
//   - it can re-open a file only if that file is on the recent list, which
//     holds nothing but paths chosen in an Open or Save dialog.
// Electron's dialog and fs are injected so this is unit-testable.

function createFileHandlers({ dialog, fs, recent }) {
	let currentFilePath = null;

	const text = (content) => {
		if (typeof content !== 'string') throw new Error('Only text can be saved');
		return content;
	};

	return {
		_fs: fs,

		async openFile() {
			const r = await dialog.showOpenDialog({ properties: ['openFile'], title: 'Fermion Open File' });
			if (!r.filePaths || r.filePaths.length === 0) return null;
			const chosen = r.filePaths[0];
			const content = await fs.promises.readFile(chosen, 'utf-8');
			currentFilePath = chosen;
			recent.add(chosen);
			return { path: chosen, content };
		},

		// purpose 'export' = saving something other than the script (the Output
		// log, a graph): written where the user chose, but it must not become the
		// file that Ctrl-S overwrites, nor a "recent script".
		async saveFile(content, opts, purpose) {
			text(content);
			const r = await dialog.showSaveDialog(opts || { title: 'Fermion Save File' });
			if (!r.filePath) return null;
			await fs.promises.writeFile(r.filePath, content);
			if (purpose !== 'export') {
				currentFilePath = r.filePath;
				recent.add(r.filePath);
			}
			return r.filePath;
		},

		async saveCurrent(content) {
			text(content);
			if (!currentFilePath) return null;
			await fs.promises.writeFile(currentFilePath, content);
			return currentFilePath;
		},

		async recentFiles() {
			return recent.list();
		},

		async openRecent(filePath) {
			if (!recent.has(filePath)) throw new Error('Not a recent file');
			let content;
			try {
				content = await fs.promises.readFile(filePath, 'utf-8');
			} catch (e) {
				recent.remove(filePath);
				throw new Error(e && e.code === 'ENOENT' ? 'That file no longer exists' : 'That file could not be read: ' + (e && e.message ? e.message : e));
			}
			currentFilePath = filePath;
			recent.add(filePath);
			return { path: filePath, content };
		},
	};
}

module.exports = { createFileHandlers };
