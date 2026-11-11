// Pure output model for Fermion's terminal pane: no DOM, no xterm — just the
// mapping from a Frida script message to a typed output line, and a capped
// buffer of those lines. Unit-tested in output-model.test.js.

const KINDS = ['LOG', 'WARN', 'ERR', 'SEND', 'STATUS'];

// Strip ANSI CSI escape sequences (color codes, cursor moves) so saved/copied
// output is plain text rather than literal "\x1b[..m" codes.
function stripAnsi(text) {
  // eslint-disable-next-line no-control-regex
  return String(text).replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '');
}

// Map a Frida `script.message` to { kind, text }.
//
// Frida delivers:
//   send(x)                      -> { type:'send', payload:x }
//   console.log/info/debug(x)    -> { type:'log', level:'info',    payload:'<string>' }
//   console.warn(x)              -> { type:'log', level:'warning', payload:'<string>' }
//   console.error(x)             -> { type:'log', level:'error',   payload:'<string>' }
//   uncaught throw               -> { type:'error', stack, description, ... }
// Anything else is shown verbatim as STATUS rather than guessed at.
function formatMessage(message) {
  if (!message || typeof message !== 'object') {
    return { kind: 'STATUS', text: String(message) };
  }

  switch (message.type) {
    case 'send': {
      const payload = message.payload;
      const text = typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2);
      return { kind: 'SEND', text };
    }
    case 'log': {
      const kind = message.level === 'warning' ? 'WARN'
        : message.level === 'error' ? 'ERR'
        : 'LOG';
      return { kind, text: String(message.payload) };
    }
    case 'error':
      return { kind: 'ERR', text: message.stack || message.description || String(message) };
    default:
      return { kind: 'STATUS', text: JSON.stringify(message) };
  }
}

// A ring-ish buffer of { kind, text } lines, capped to avoid unbounded growth
// under high-volume hooks (replaces the old 5000-line textarea trim).
class OutputBuffer {
  constructor(cap = 5000) {
    this.cap = cap;
    this._lines = [];
  }

  get size() {
    return this._lines.length;
  }

  append(entry) {
    this._lines.push(entry);
    if (this._lines.length > this.cap) {
      this._lines.splice(0, this._lines.length - this.cap);
    }
    return entry;
  }

  entries() {
    return this._lines;
  }

  filtered(activeKinds) {
    return this._lines.filter((e) => activeKinds.has(e.kind));
  }

  clear() {
    this._lines = [];
  }
}

module.exports = { formatMessage, OutputBuffer, KINDS, stripAnsi };
