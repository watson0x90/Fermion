// @ts-check
// Saving a coverage recording. The recording lives in the main process (see
// FridaService.inspectCoverStop); the window only asks for it to be saved, and
// says in which form. Main shows the dialog and writes the file, so the
// window never chooses the path or supplies the bytes.

const FORMATS = {
	drcov: { ext: 'drcov', title: 'Save coverage (drcov)', filter: { name: 'drcov coverage', extensions: ['drcov'] } },
	text: { ext: 'md', title: 'Save coverage report', filter: { name: 'Text report', extensions: ['md', 'txt'] } },
};

// A file name from the program's name: letters, digits, dot, dash and
// underscore only, so nothing the target calls itself can steer the path.
function suggestedName(program, ext) {
	const base = String(program || '').replace(/\.[A-Za-z0-9]{1,5}$/, '').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^[._]+/, '').slice(0, 60);
	return (base || 'coverage') + '-coverage.' + ext;
}

/**
 * @param {{ dialog: { showSaveDialog: Function }, fs: { promises: { writeFile: Function } }, getWindow?: () => any }} deps
 * @returns {(file: { format: string, data: Buffer | string, program?: string }) => Promise<string | null>}
 */
function createCoverageSaver({ dialog, fs, getWindow }) {
	return async ({ format, data, program }) => {
		const kind = FORMATS[format];
		if (!kind) throw new Error('unknown coverage format');
		const options = { title: kind.title, defaultPath: suggestedName(program, kind.ext), filters: [kind.filter, { name: 'All files', extensions: ['*'] }] };
		const win = getWindow ? getWindow() : null;
		const r = win ? await dialog.showSaveDialog(win, options) : await dialog.showSaveDialog(options);
		if (!r || !r.filePath) return null; // cancelled
		await fs.promises.writeFile(r.filePath, data);
		return r.filePath;
	};
}

module.exports = { createCoverageSaver, suggestedName };
