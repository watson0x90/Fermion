// Theme for the small dialog windows (About, Docs). The main window derives
// the theme tokens (see ui/theme/themeEngine.ts) and stores them in
// localStorage; these pages read them and set the same CSS custom properties,
// so a dialog opens in the colours the app is using and follows a change made
// while it is open.
//
// Loaded as a classic <script> in the page, and required by the unit tests.
(function (root) {
	var STORAGE_KEY = 'fermion.themeTokens';
	// Values are colours or a logo filter. Anything that could carry a url or
	// another declaration is refused: localStorage is writable by any page.
	var VALUE = /^[#\w\s.,%()-]+$/;

	function okValue(v) {
		return typeof v === 'string' && v.length <= 80 && VALUE.test(v) && !/url|expression|;/i.test(v);
	}

	function applyTokens(el, tokens) {
		if (!tokens || typeof tokens !== 'object' || Array.isArray(tokens)) return 0;
		var n = 0;
		for (var k in tokens) {
			if (!Object.prototype.hasOwnProperty.call(tokens, k)) continue;
			var isToken = /^--[a-z][a-z-]*$/.test(k) || k === 'color-scheme';
			if (!isToken || !okValue(tokens[k])) continue;
			if (k === 'color-scheme' && tokens[k] !== 'dark' && tokens[k] !== 'light') continue;
			el.style.setProperty(k, tokens[k]);
			n++;
		}
		return n;
	}

	function readTokens(storage) {
		try {
			var parsed = JSON.parse(storage.getItem(STORAGE_KEY));
			return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
		} catch (e) {
			return null;
		}
	}

	function start(win) {
		var apply = function () {
			var tokens = readTokens(win.localStorage);
			applyTokens(win.document.documentElement, tokens);
			// Match the native window background too (shown while resizing/loading).
			try { if (tokens && tokens['--bg'] && win.fermion && win.fermion.win) win.fermion.win.setBackground(tokens['--bg']); } catch (e) { /* not in Electron */ }
		};
		apply();
		win.addEventListener('storage', function (e) { if (e.key === STORAGE_KEY) apply(); });
	}

	var api = { applyTokens: applyTokens, readTokens: readTokens, start: start, STORAGE_KEY: STORAGE_KEY };
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else { root.FermionDialogTheme = api; start(root); }
})(typeof window !== 'undefined' ? window : globalThis);
