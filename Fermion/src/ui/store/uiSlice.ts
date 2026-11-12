import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { loadSavedTheme } from '../theme/themeEngine';

export type ToolboxTab = 'editor' | 'repl' | 'hooks' | 'graph' | 'tree' | 'inspector';

// "Show this address": which Inspector view, and a counter so asking for the
// same address twice is still a new request.
export type AddressView = 'memory' | 'code';
export interface AddressRequest { view: AddressView; address: string; n: number; }

export interface UiState {
  activeTab: ToolboxTab;
  theme: string;       // active Monaco/app theme (drives the whole shell)
  railOpen: boolean;   // activity rail expanded (icons + labels)
  settingsOpen: boolean;
  outputDetached: boolean; // Output pane lives in its own window
  filePath: string | null; // the script file in the editor (null = never saved)
  dirty: boolean;          // the editor has changes that are not saved
  addressRequest: AddressRequest | null; // an address to open in the Inspector
}

const initialState: UiState = {
  activeTab: 'editor',
  theme: loadSavedTheme(),
  railOpen: false,
  settingsOpen: false,
  outputDetached: false,
  filePath: null,
  dirty: false,
  addressRequest: null,
};

const uiSlice = createSlice({
  name: 'ui',
  initialState,
  reducers: {
    setActiveTab(state, action: PayloadAction<ToolboxTab>) {
      state.activeTab = action.payload;
    },
    setTheme(state, action: PayloadAction<string>) {
      state.theme = action.payload;
    },
    toggleRail(state, action: PayloadAction<boolean | undefined>) {
      state.railOpen = action.payload ?? !state.railOpen;
    },
    toggleSettings(state, action: PayloadAction<boolean | undefined>) {
      state.settingsOpen = action.payload ?? !state.settingsOpen;
    },
    // Open an address in the Inspector's Memory or Disassembly view.
    openAddress(state, action: PayloadAction<{ view: AddressView; address: string }>) {
      state.activeTab = 'inspector';
      state.addressRequest = { ...action.payload, n: (state.addressRequest?.n ?? 0) + 1 };
    },
    setOutputDetached(state, action: PayloadAction<boolean>) {
      state.outputDetached = action.payload;
    },
    edited(state) {
      state.dirty = true;
    },
    fileOpened(state, action: PayloadAction<string>) {
      state.filePath = action.payload;
      state.dirty = false;
    },
    fileSaved(state, action: PayloadAction<string>) {
      state.filePath = action.payload;
      state.dirty = false;
    },
  },
});

export const uiActions = uiSlice.actions;
export default uiSlice.reducer;
