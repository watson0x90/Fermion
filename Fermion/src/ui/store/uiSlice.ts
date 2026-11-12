import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { loadSavedTheme } from '../theme/themeEngine';

export type ToolboxTab = 'editor' | 'repl' | 'hooks' | 'graph' | 'tree' | 'inspector';

export interface UiState {
  activeTab: ToolboxTab;
  theme: string;       // active Monaco/app theme (drives the whole shell)
  railOpen: boolean;   // activity rail expanded (icons + labels)
  settingsOpen: boolean;
  outputDetached: boolean; // Output pane lives in its own window
  filePath: string | null; // the script file in the editor (null = never saved)
  dirty: boolean;          // the editor has changes that are not saved
}

const initialState: UiState = {
  activeTab: 'editor',
  theme: loadSavedTheme(),
  railOpen: false,
  settingsOpen: false,
  outputDetached: false,
  filePath: null,
  dirty: false,
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
