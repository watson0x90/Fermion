import { render, screen, fireEvent, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import session from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui, { uiActions } from '../store/uiSlice';
import prefs, { prefsActions } from '../store/prefsSlice';
import { themeMeta } from '../theme/themeEngine';
const themeIsDark = (name: string) => themeMeta(name).dark;
import { DEFAULT_PREFS } from '../prefs';
import * as fonts from '../fonts';
import '../../lang/monaco-theme.js'; // load the real theme set
import { Settings } from './Settings';

function renderSettings(section?: string) {
  localStorage.clear();
  const store = configureStore({ reducer: { session, output, ui, prefs } });
  store.dispatch(uiActions.toggleSettings(true));
  render(<Provider store={store}><Settings /></Provider>);
  if (section) fireEvent.click(screen.getByTestId('settings-tab-' + section));
  return store;
}
const go = (section: string) => fireEvent.click(screen.getByTestId('settings-tab-' + section));

beforeEach(() => {
  // This computer "has" Consolas and Menlo; Georgia is there but not fixed-width.
  vi.spyOn(fonts, 'installedFonts').mockReturnValue(['Consolas', 'Menlo']);
  vi.spyOn(fonts, 'fontState').mockImplementation((name: string) => (name === 'Georgia' ? 'proportional' : ['Consolas', 'Menlo', fonts.BUILT_IN_FONT, fonts.SYSTEM_FONT].includes(name) ? 'installed' : 'missing'));
});
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

test('Settings is a dialog with a list of sections; arrow keys move between them', () => {
  renderSettings('appearance');
  const dialog = screen.getByRole('dialog', { name: 'Settings' });
  expect(dialog).toHaveAttribute('aria-modal', 'true');
  expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual(['Appearance', 'Editor', 'Output', 'Inspector', 'Session', 'Limits']);
  expect(screen.getByTestId('settings-tab-appearance')).toHaveAttribute('aria-selected', 'true');
  fireEvent.keyDown(screen.getByTestId('settings-tab-appearance'), { key: 'ArrowDown' });
  expect(screen.getByTestId('settings-tab-editor')).toHaveAttribute('aria-selected', 'true');
  expect(screen.getByTestId('settings-tab-editor')).toHaveFocus();
  expect(screen.getByTestId('settings-pane-editor')).toBeInTheDocument();
  fireEvent.keyDown(screen.getByTestId('settings-tab-editor'), { key: 'End' });
  expect(screen.getByTestId('settings-pane-limits')).toBeInTheDocument();
  fireEvent.keyDown(screen.getByTestId('settings-tab-limits'), { key: 'ArrowDown' }); // wraps
  expect(screen.getByTestId('settings-pane-appearance')).toBeInTheDocument();
});

test('themes are shown as cards, dark and light apart; the current one is marked; choosing one applies it', () => {
  const store = renderSettings('appearance');
  expect(screen.getByTestId('theme-Kuroir')).toHaveClass('sel');
  expect(screen.getByTestId('theme-Kuroir')).toHaveAttribute('aria-pressed', 'true');
  expect(screen.getByText(/original Fermion/)).toBeInTheDocument();
  expect(screen.getByRole('group', { name: 'Dark color themes' })).toContainElement(screen.getByTestId('theme-Monokai'));
  expect(screen.getByRole('group', { name: 'Light color themes' })).toContainElement(screen.getByTestId('theme-Kuroir'));
  fireEvent.click(screen.getByTestId('theme-Monokai'));
  expect(store.getState().ui.theme).toBe('Monokai');
});

test('the scrim, the close button and Escape each close Settings; closed, it renders nothing', () => {
  for (const close of [
    () => fireEvent.click(screen.getByTestId('settings-scrim')),
    () => fireEvent.click(screen.getByTestId('settings-close')),
    () => fireEvent.keyDown(screen.getByTestId('settings'), { key: 'Escape' }),
  ]) {
    const store = renderSettings();
    close();
    expect(store.getState().ui.settingsOpen).toBe(false);
    expect(screen.queryByTestId('settings')).toBeNull();
  }
});

test('Tab stays inside the dialog', () => {
  renderSettings('session');
  const stops = [...screen.getByTestId('settings').querySelectorAll<HTMLElement>('button, select, input')].filter((el) => !(el as HTMLButtonElement).disabled && el.tabIndex >= 0);
  const first = stops[0]; const last = stops[stops.length - 1];
  last.focus();
  fireEvent.keyDown(last, { key: 'Tab' });
  expect(first).toHaveFocus();
  fireEvent.keyDown(first, { key: 'Tab', shiftKey: true });
  expect(last).toHaveFocus();
});

test('font size: plus and minus step by one and stop at the limits; the arrow keys, Page keys, Home and End work', () => {
  const store = renderSettings('editor');
  const size = () => store.getState().prefs.editorFontSize;
  const field = screen.getByTestId('pref-editor-font');
  expect(field).toHaveValue('14');
  expect(field).toHaveAttribute('role', 'spinbutton');
  expect(field).toHaveAttribute('aria-valuenow', '14');
  fireEvent.click(screen.getByTestId('pref-editor-font-plus'));
  fireEvent.click(screen.getByTestId('pref-editor-font-plus'));
  expect(size()).toBe(16);
  fireEvent.click(screen.getByTestId('pref-editor-font-minus'));
  expect(size()).toBe(15);
  expect(field).toHaveValue('15');
  fireEvent.keyDown(field, { key: 'ArrowUp' });
  fireEvent.keyDown(field, { key: 'PageUp' });
  expect(size()).toBe(18);
  fireEvent.keyDown(field, { key: 'ArrowDown' });
  fireEvent.keyDown(field, { key: 'PageDown' });
  expect(size()).toBe(15);
  fireEvent.keyDown(field, { key: 'End' });
  expect(size()).toBe(24);
  expect(screen.getByTestId('pref-editor-font-plus')).toBeDisabled();
  fireEvent.keyDown(field, { key: 'ArrowUp' });
  expect(size()).toBe(24);
  fireEvent.keyDown(field, { key: 'Home' });
  expect(size()).toBe(9);
  expect(screen.getByTestId('pref-editor-font-minus')).toBeDisabled();
});

test('font size: holding plus keeps stepping, and letting go stops it without one step more', () => {
  vi.useFakeTimers();
  const store = renderSettings('output');
  const plus = screen.getByTestId('pref-output-font-plus');
  fireEvent.pointerDown(plus);
  act(() => { vi.advanceTimersByTime(399); });
  expect(store.getState().prefs.outputFontSize).toBe(13); // not yet: a click is not a hold
  act(() => { vi.advanceTimersByTime(1 + 60 * 3); });
  expect(store.getState().prefs.outputFontSize).toBe(16);
  fireEvent.pointerUp(plus);
  fireEvent.click(plus); // the click that ends the hold
  act(() => { vi.advanceTimersByTime(1000); });
  expect(store.getState().prefs.outputFontSize).toBe(16);
  fireEvent.click(plus); // a plain click afterwards steps again
  expect(store.getState().prefs.outputFontSize).toBe(17);
});

test('font size typed: a number in range applies while typing; out of range is brought in on leaving; not a number changes nothing', () => {
  const store = renderSettings('editor');
  const field = screen.getByTestId('pref-editor-font');
  fireEvent.change(field, { target: { value: '1' } }); // on the way to 12: not yet a size
  expect(store.getState().prefs.editorFontSize).toBe(14);
  expect(field).toHaveValue('1');
  fireEvent.change(field, { target: { value: '12' } });
  expect(store.getState().prefs.editorFontSize).toBe(12);
  fireEvent.change(field, { target: { value: '300' } });
  expect(store.getState().prefs.editorFontSize).toBe(12);
  fireEvent.blur(field);
  expect(store.getState().prefs.editorFontSize).toBe(24);
  expect(field).toHaveValue('24');
  fireEvent.change(field, { target: { value: '2' } });
  fireEvent.keyDown(field, { key: 'Enter' });
  expect(store.getState().prefs.editorFontSize).toBe(9);
  for (const junk of ['', 'big', '1e']) {
    fireEvent.change(field, { target: { value: junk } });
    fireEvent.blur(field);
    expect(store.getState().prefs.editorFontSize).toBe(9);
    expect(field).toHaveValue('9');
  }
  // Escape while typing drops what was typed, and does not close Settings.
  fireEvent.change(field, { target: { value: '77' } });
  fireEvent.keyDown(field, { key: 'Escape' });
  expect(field).toHaveValue('9');
  expect(store.getState().ui.settingsOpen).toBe(true);
});

test('font: the list offers the built-in font, the installed ones and the system font; choosing one applies it and the preview shows it', () => {
  const store = renderSettings('editor');
  const pick = screen.getByTestId('pref-editor-family') as HTMLSelectElement;
  expect([...pick.options].map((o) => o.textContent)).toEqual(['IBM Plex Mono (built in)', 'Consolas', 'Menlo', 'System monospace', 'Another installed font…']);
  expect(pick).toHaveValue('IBM Plex Mono');
  fireEvent.change(pick, { target: { value: 'Consolas' } });
  expect(store.getState().prefs.editorFontFamily).toBe('Consolas');
  expect(screen.getByTestId('preview-editor').style.fontFamily).toMatch(/^"?Consolas"?, /);
  expect(screen.queryByTestId('pref-editor-family-custom')).toBeNull();
});

test('font: another family can be typed; one that is not installed or not fixed-width is said so, and unsafe characters are dropped', () => {
  const store = renderSettings('output');
  const pick = screen.getByTestId('pref-output-family');
  fireEvent.change(pick, { target: { value: (pick as HTMLSelectElement).options[4].value } });
  expect(store.getState().prefs.outputFontFamily).toBe('IBM Plex Mono'); // nothing is chosen until a name is given
  const name = screen.getByTestId('pref-output-family-custom');
  fireEvent.change(name, { target: { value: 'Berkeley Mono"; }' } });
  fireEvent.keyDown(name, { key: 'Enter' });
  expect(store.getState().prefs.outputFontFamily).toBe('Berkeley Mono');
  expect(name).toHaveValue('Berkeley Mono');
  expect(screen.getByTestId('pref-output-family-missing')).toHaveTextContent('Berkeley Mono is not installed on this computer. IBM Plex Mono is used instead.');
  fireEvent.change(name, { target: { value: 'Georgia' } });
  fireEvent.blur(name);
  expect(screen.getByTestId('pref-output-family-proportional')).toHaveTextContent('Georgia is not a fixed-width font');
  expect(screen.queryByTestId('pref-output-family-missing')).toBeNull();
  fireEvent.change(name, { target: { value: '   ' } });
  fireEvent.blur(name);
  expect(store.getState().prefs.outputFontFamily).toBe('Georgia'); // an empty name is not a choice
  // A typed family is still shown as typed when Settings is opened again.
  act(() => { store.dispatch(uiActions.toggleSettings(false)); });
  act(() => { store.dispatch(uiActions.toggleSettings(true)); });
  expect(screen.getByTestId('pref-output-family-custom')).toHaveValue('Georgia');
});

test('every preference shows its value and changes the store; Settings reopens on the section it was left on', () => {
  const store = renderSettings('editor');
  expect(screen.getByTestId('pref-editor-minimap')).toBeChecked();
  expect(screen.getByTestId('pref-editor-numbers')).toBeChecked();
  expect(screen.getByTestId('pref-editor-tab-4')).toHaveAttribute('aria-checked', 'true');
  fireEvent.click(screen.getByTestId('pref-editor-minimap'));
  fireEvent.click(screen.getByTestId('pref-editor-wrap'));
  fireEvent.click(screen.getByTestId('pref-editor-numbers'));
  fireEvent.click(screen.getByTestId('pref-editor-spacing-relaxed'));
  fireEvent.click(screen.getByTestId('pref-editor-tab-2'));
  fireEvent.click(screen.getByTestId('pref-editor-whitespace-all'));
  fireEvent.keyDown(screen.getByTestId('pref-editor-cursor-line'), { key: 'ArrowRight' }); // arrows choose, like radio buttons
  expect(screen.getByTestId('pref-editor-cursor-block')).toHaveFocus();
  expect(screen.queryByTestId('preview-editor')!.querySelector('.ln')).toBeNull(); // the preview follows: no line numbers
  go('output');
  fireEvent.click(screen.getByTestId('pref-output-spacing-normal'));
  fireEvent.click(screen.getByTestId('pref-output-cursor-underline'));
  go('inspector');
  expect(screen.getByTestId('pref-cover-scope')).toHaveValue('app');
  fireEvent.change(screen.getByTestId('pref-cover-scope'), { target: { value: 'all' } });
  fireEvent.change(screen.getByTestId('pref-follow-scope'), { target: { value: 'app' } });
  fireEvent.change(screen.getByTestId('pref-watch-mode'), { target: { value: 'sampled' } });
  fireEvent.change(screen.getByTestId('pref-auto-refresh'), { target: { value: '5' } });
  go('session');
  fireEvent.click(screen.getByLabelText('Catch child processes when Fermion starts')); // the name is the checkbox's label
  go('appearance');
  fireEvent.change(screen.getByTestId('pref-data-font'), { target: { value: 'Menlo' } });
  expect(store.getState().prefs).toEqual({
    ...DEFAULT_PREFS,
    dataFontFamily: 'Menlo',
    editorFontFamily: 'IBM Plex Mono', editorFontSize: 14, editorLineSpacing: 'relaxed', editorLineNumbers: false, editorMinimap: false, editorWordWrap: true,
    editorTabSize: 2, editorWhitespace: 'all', editorCursor: 'block',
    outputFontFamily: 'IBM Plex Mono', outputFontSize: 13, outputLineSpacing: 'normal', outputCursor: 'underline',
    coverScope: 'all', followScope: 'app', watchMode: 'sampled', autoRefreshSeconds: 5, catchChildren: true,
  });
  go('inspector');
  act(() => { store.dispatch(uiActions.toggleSettings(false)); });
  act(() => { store.dispatch(uiActions.toggleSettings(true)); });
  expect(screen.getByTestId('settings-pane-inspector')).toBeInTheDocument();
});

test('a changed setting is marked, and so is its section; the mark puts that one setting back', () => {
  const store = renderSettings('editor');
  expect(screen.queryByTestId('pref-editor-wrap-changed')).toBeNull();
  expect(screen.queryByTestId('settings-tab-editor-changed')).toBeNull();
  fireEvent.click(screen.getByTestId('pref-editor-wrap'));
  fireEvent.click(screen.getByTestId('pref-editor-font-plus'));
  expect(screen.getByTestId('settings-tab-editor-changed')).toBeInTheDocument();
  expect(screen.queryByTestId('settings-tab-output-changed')).toBeNull();
  fireEvent.click(screen.getByTestId('pref-editor-wrap-changed'));
  expect(store.getState().prefs.editorWordWrap).toBe(false);
  expect(store.getState().prefs.editorFontSize).toBe(15);
  expect(screen.queryByTestId('pref-editor-wrap-changed')).toBeNull();
});

test('reset: a section alone, or everything; either can be undone for a few seconds', () => {
  vi.useFakeTimers();
  const store = renderSettings('editor');
  expect(screen.getByTestId('pref-reset')).toBeDisabled();
  expect(screen.getByTestId('pref-reset-section')).toBeDisabled();
  fireEvent.click(screen.getByTestId('pref-editor-font-plus'));
  go('output');
  expect(screen.getByTestId('pref-reset-section')).toBeDisabled(); // nothing in Output differs
  expect(screen.getByTestId('pref-reset-section')).toHaveTextContent('Reset output');
  fireEvent.click(screen.getByTestId('pref-output-font-plus'));
  fireEvent.click(screen.getByTestId('pref-reset-section'));
  expect(store.getState().prefs).toEqual({ ...DEFAULT_PREFS, editorFontSize: 15 }); // the editor's is untouched
  fireEvent.click(screen.getByTestId('pref-undo'));
  expect(store.getState().prefs).toEqual({ ...DEFAULT_PREFS, editorFontSize: 15, outputFontSize: 14 });
  expect(screen.queryByTestId('pref-undo')).toBeNull();
  fireEvent.click(screen.getByTestId('pref-reset'));
  expect(store.getState().prefs).toEqual(DEFAULT_PREFS);
  expect(screen.getByTestId('pref-reset')).toBeDisabled();
  expect(screen.getByTestId('pref-undo-note')).toHaveTextContent('Settings reset.');
  act(() => { vi.advanceTimersByTime(8100); });
  expect(screen.queryByTestId('pref-undo')).toBeNull(); // the offer does not stay
  expect(store.getState().prefs).toEqual(DEFAULT_PREFS);
});

test('resetting does not change the color theme', () => {
  const store = renderSettings('appearance');
  fireEvent.click(screen.getByTestId('theme-Monokai'));
  fireEvent.change(screen.getByTestId('pref-data-font'), { target: { value: 'Consolas' } });
  fireEvent.click(screen.getByTestId('pref-reset'));
  expect(store.getState().prefs.dataFontFamily).toBe('IBM Plex Mono');
  expect(store.getState().ui.theme).toBe('Monokai');
});

test('themes: the arrow keys move from card to card, across dark and light, choosing as they go', () => {
  const store = renderSettings('appearance');
  const cards = [...document.querySelectorAll<HTMLElement>('.themeopt')];
  const at = cards.findIndex((c) => c.dataset.testid === 'theme-Kuroir');
  cards[at].focus();
  fireEvent.keyDown(cards[at], { key: 'ArrowRight' });
  expect(cards[at + 1]).toHaveFocus();
  expect('theme-' + store.getState().ui.theme).toBe(cards[at + 1].dataset.testid);
  fireEvent.keyDown(cards[at + 1], { key: 'ArrowLeft' });
  fireEvent.keyDown(cards[at], { key: 'ArrowLeft' }); // from the first light theme to the last dark one
  expect(cards[at - 1]).toHaveFocus();
  expect(themeIsDark(store.getState().ui.theme)).toBe(true);
  fireEvent.keyDown(cards[at - 1], { key: 'Escape' });
  expect(store.getState().ui.settingsOpen).toBe(false);
});

test('Inspector text size is a choice of four, and belongs to the Inspector section', () => {
  const store = renderSettings('inspector');
  expect(screen.getByTestId('pref-inspector-size-normal')).toHaveAttribute('aria-checked', 'true');
  fireEvent.click(screen.getByTestId('pref-inspector-size-larger'));
  expect(store.getState().prefs.inspectorTextSize).toBe('larger');
  expect(screen.getByTestId('settings-tab-inspector-changed')).toBeInTheDocument();
  fireEvent.click(screen.getByTestId('pref-reset-section'));
  expect(store.getState().prefs.inspectorTextSize).toBe('normal');
});

test('limits: times are stepped inside their range, sizes are chosen from a few; a stored size that is not one of them is still shown', () => {
  const store = renderSettings('limits');
  expect(screen.getByTestId('pref-limit-repl')).toHaveValue('20');
  expect(screen.getByTestId('pref-limit-record')).toHaveValue('10');
  fireEvent.change(screen.getByTestId('pref-limit-repl'), { target: { value: '9999' } });
  fireEvent.blur(screen.getByTestId('pref-limit-repl'));
  expect(store.getState().prefs.limitReplSeconds).toBe(600);
  fireEvent.keyDown(screen.getByTestId('pref-limit-record'), { key: 'Home' });
  expect(store.getState().prefs.limitRecordMinutes).toBe(1);
  expect(screen.getByTestId('pref-limit-record-minus')).toBeDisabled();
  const cover = screen.getByTestId('pref-limit-cover') as HTMLSelectElement;
  expect([...cover.options].map((o) => o.textContent)).toEqual(['500,000', '1 million', '2 million', '5 million']);
  fireEvent.change(cover, { target: { value: '5000000' } });
  fireEvent.change(screen.getByTestId('pref-limit-watch'), { target: { value: '50000' } });
  fireEvent.change(screen.getByTestId('pref-limit-heap-live'), { target: { value: '500000' } });
  fireEvent.change(screen.getByTestId('pref-limit-heap-freed'), { target: { value: '5000' } });
  expect(store.getState().prefs).toMatchObject({ limitCoverBlocks: 5000000, limitWatchHits: 50000, limitHeapLive: 500000, limitHeapFreed: 5000 });
  act(() => { store.dispatch(prefsActions.changed({ limitHeapFreed: 12345 })); });
  expect(screen.getByTestId('pref-limit-heap-freed')).toHaveValue('12345');
  fireEvent.click(screen.getByTestId('pref-reset-section'));
  expect(store.getState().prefs).toEqual(DEFAULT_PREFS);
});
