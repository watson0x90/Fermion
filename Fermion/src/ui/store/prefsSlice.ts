import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { useSelector } from 'react-redux';
import { Prefs, DEFAULT_PREFS, cleanPrefs, loadPrefs } from '../prefs';

// The operator's preferences (see ../prefs). Loaded from the window's storage
// when the app starts; Layout saves them and applies them whenever they change.
const slice = createSlice({
  name: 'prefs',
  initialState: loadPrefs(),
  reducers: {
    // Change some preferences. Whatever is passed is checked like stored values are.
    changed(state, action: PayloadAction<Partial<Prefs>>) {
      return cleanPrefs({ ...state, ...action.payload });
    },
    reset() {
      return { ...DEFAULT_PREFS };
    },
  },
});

export const prefsActions = slice.actions;
export default slice.reducer;

// The preferences, or the defaults in a store that has none (some tests).
export const usePrefs = (): Prefs => useSelector((s: { prefs?: Prefs }) => s.prefs ?? DEFAULT_PREFS);
