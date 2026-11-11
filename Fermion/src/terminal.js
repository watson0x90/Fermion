// xterm.js output terminal for Fermion. Wraps xterm + fit + search addons and
// an OutputBuffer (see output-model.js). Renders faithful, color-by-level Frida
// output; the DOM renderer is used (no webgl) so the rendered rows stay
// readable/testable.

const { Terminal } = require('@xterm/xterm');
const { FitAddon } = require('@xterm/addon-fit');
const { SearchAddon } = require('@xterm/addon-search');
const { OutputBuffer, KINDS, stripAnsi } = require('./output-model');

// Visual contract (design spec). Truecolor SGR per kind; LOG uses the default
// foreground. A line that carries its own ANSI is written untouched.
const RESET = '\x1b[0m';
const COLOR = {
  WARN: '\x1b[38;2;227;179;65m',   // #e3b341
  ERR: '\x1b[38;2;248;81;73m',     // #f85149
  SEND: '\x1b[38;2;57;197;207m',   // #39c5cf
  STATUS: '\x1b[38;2;110;118;129m' // #6e7681
};
const THEME = {
  background: '#0d1117',
  foreground: '#c9d1d9',
  cursor: '#0d1117', // hide the cursor block (output-only)
  selectionBackground: '#30425f'
};
const SCROLLBACK = 5000;

function hasAnsi(text) {
  return /\x1b\[/.test(text);
}
function colorize(kind, text) {
  if (hasAnsi(text)) return text;
  const c = COLOR[kind];
  return c ? c + text + RESET : text;
}
function toTermText(kind, text) {
  return colorize(kind, String(text)).replace(/\r?\n/g, '\r\n') + '\r\n';
}

// Create and mount a terminal into `container`. Returns a controller.
function createTerminal(container) {
  const buffer = new OutputBuffer(SCROLLBACK);
  const active = new Set(KINDS); // all kinds visible by default
  let follow = true;

  const term = new Terminal({
    convertEol: false,
    scrollback: SCROLLBACK,
    fontSize: 13,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
    cursorStyle: 'bar',
    cursorBlink: false,
    disableStdin: true,
    theme: THEME
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
    _term: term
  };

  return controller;
}

module.exports = { createTerminal };
