// @ts-check
// Pure guards for the main-process IPC boundary: the renderer is untrusted
// (it displays instrumentation output from the target), so validate everything
// that crosses into the main process.

// The only HTML files the renderer may ask main to open as a (bridge-privileged)
// child window. Prevents path traversal / loading arbitrary local files.
const ALLOWED_PAGES = new Set([
	'device.html', 'proc.html', 'instrument.html', 'trace.html', 'svg.html', 'about.html', 'docs.html',
]);

function isAllowedPage(page) {
	return typeof page === 'string' && ALLOWED_PAGES.has(page);
}

// Only http(s) links may be opened in the external browser.
function isSafeExternalUrl(url) {
	if (typeof url !== 'string') return false;
	try {
		const u = new URL(url);
		return u.protocol === 'http:' || u.protocol === 'https:';
	} catch {
		return false;
	}
}

module.exports = { isAllowedPage, isSafeExternalUrl, ALLOWED_PAGES };
