// @ts-check
// localStorage persistence primitives for Fermion's output/editor settings.
// Only the persistence mechanism lives here; collecting current state from the
// DOM and applying restored state are owned by the modules that own those
// concerns (layout.js, editor.js) and orchestrated by the renderer bootstrap.
const STORAGE_KEY = 'fermion_output_settings';

// Pure: parse a stored settings blob. Returns null for null/empty/invalid
// input and never throws, so callers can skip their own try/catch.
function parseSettings(raw) {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function readSettings() {
  return parseSettings(localStorage.getItem(STORAGE_KEY));
}

function writeSettings(settings) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
}

module.exports = { STORAGE_KEY, parseSettings, readSettings, writeSettings };
