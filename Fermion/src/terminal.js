// xterm.js output terminal for Fermion. Wraps xterm + fit + search addons and
// an OutputBuffer (see output-model.js). Renders faithful, color-by-level Frida
// output; the DOM renderer is used (no webgl) so the rendered rows stay
// readable/testable.

const { Terminal } = require('@xterm/xterm');
const { FitAddon } = require('@xterm/addon-fit');
const { SearchAddon } = require('@xterm/addon-search');
const { OutputBuffer, KINDS, stripAnsi } = require('./output-model');

// Visual contract (design spec). Truecolor SGR per kind; LOG uses the default
// foreground. A line that carries its own ANSI is written untouched. The palette
// and the xterm theme are theme-aware — setTheme() (driven by the app theme
// engine) swaps them so the output matches the active Monaco/app theme.
const RESET = '\x1b[0m';
const DEFAULT_PALETTE = { WARN: '#e3b341', ERR: '#f85149', SEND: '#39c5cf', STATUS: '#6e7681' };
const DEFAULT_THEME = {
  background: '#0d1117',
  foreground: '#c9d1d9',
  cursor: '#0d1117', // hide the cursor block (output-only)
  selectionBackground: '#30425f'
};
const SCROLLBACK = 5000;

function hasAnsi(text) {
  return /\x1b\[/.test(text);
}
function hexToSgr(hex) {
  const h = String(hex || '').replace('#', '');
  if (h.length < 6) return '';
  const r = parseInt(h.slice(0, 2), 16), g = parseInt(h.slice(2, 4), 16), b = parseInt(h.slice(4, 6), 16);
  return `\x1b[38;2;${r};${g};${b}m`;
}

// Create and mount a terminal into `container`. Returns a controller.
function createTerminal(container) {
  const buffer = new OutputBuffer(SCROLLBACK);
  const active = new Set(KINDS); // all kinds visible by default
  let follow = true;
  // Mutable per-kind SGR colors (hex -> SGR), swapped by setTheme().
  const sgr = {};
  for (const [k, hex] of Object.entries(DEFAULT_PALETTE)) sgr[k] = hexToSgr(hex);

  function colorize(kind, text) {
    if (hasAnsi(text)) return text;
    const c = sgr[kind];
    return c ? c + text + RESET : text;
  }
  function toTermText(kind, text) {
    return colorize(kind, String(text)).replace(/\r?\n/g, '\r\n') + '\r\n';
  }

  const term = new Terminal({
    convertEol: false,
    scrollback: SCROLLBACK,
    fontSize: 13,
    fontFamily: '"IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
    cursorStyle: 'bar',
    cursorBlink: false,
    disableStdin: true,
    theme: DEFAULT_THEME
  });
  const fitAddon = new FitAddon();
  const searchAddon = new SearchAddon();
  term.loadAddon(fitAddon);
  term.loadAddon(searchAddon);
  term.open(container);
  try { fitAddon.fit(); } catch (_) {}

  function renderFiltered() {
    term.reset();
    for (const e of buffer.filtered(active)) term.write(toTermText(e.kind, e.text));
    if (follow) term.scrollToBottom();
  }

  const controller = {
    // Append a line: always buffered; rendered now only if its kind is visible.
    write(kind, text) {
      const k = KINDS.includes(kind) ? kind : 'STATUS';
      buffer.append({ kind: k, text: String(text) });
      if (active.has(k)) {
        term.write(toTermText(k, text));
        if (follow) term.scrollToBottom();
      }
    },
    setFilter(kind, on) {
      if (!KINDS.includes(kind)) return;
      if (on) active.add(kind); else active.delete(kind);
      renderFiltered();
    },
    isFilterOn(kind) { return active.has(kind); },
    clear() { buffer.clear(); term.reset(); },
    getText() { return buffer.entries().map((e) => stripAnsi(e.text)).join('\n'); },
    // Re-theme the terminal to match the active app theme. `theme` is an xterm
    // ITheme (background/foreground/cursor/selectionBackground); `kindColors`
    // maps WARN/ERR/SEND/STATUS to hex. Existing output is re-colorized.
    setTheme(theme, kindColors) {
      if (theme) term.options.theme = theme;
      if (kindColors) for (const [k, hex] of Object.entries(kindColors)) { if (hex) sgr[k] = hexToSgr(hex); }
      renderFiltered();
    },
    setFollow(on) { follow = !!on; if (follow) term.scrollToBottom(); },
    setFontSize(px) { term.options.fontSize = px; try { fitAddon.fit(); } catch (_) {} },
    getFontSize() { return term.options.fontSize; },
    fit() { try { fitAddon.fit(); } catch (_) {} },
    searchNext(regexStr) {
      // An invalid regex from the toolbar must fail gracefully, not throw.
      try { return searchAddon.findNext(regexStr, { regex: true, caseSensitive: false }); }
      catch (_) { return false; }
    },
    searchPrev(regexStr) {
      try { return searchAddon.findPrevious(regexStr, { regex: true, caseSensitive: false }); }
      catch (_) { return false; }
    },
    clearSearch() { try { searchAddon.clearDecorations(); } catch (_) {} },
    copySelectionOrAll() {
      const sel = term.getSelection();
      return sel && sel.length ? sel : controller.getText();
    },
    // Tear down the xterm instance (React unmount).
    dispose() { try { term.dispose(); } catch (_) {} },
    _term: term
  };

  return controller;
}

module.exports = { createTerminal };
