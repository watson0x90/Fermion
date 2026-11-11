import { createSlice, PayloadAction } from '@reduxjs/toolkit';

export type ToolboxTab = 'editor' | 'repl' | 'graph' | 'tree' | 'inspector';

export interface UiState {
  activeTab: ToolboxTab;
  vertical: boolean; // output/editor split orientation (persisted)
}

const initialState: UiState = {
  activeTab: 'editor',
  vertical: true,
};

const uiSlice = createSlice({
  name: 'ui',
  initialState,
  reducers: {
    setActiveTab(state, action: PayloadAction<ToolboxTab>) {
      state.activeTab = action.payload;
    },
    setVertical(state, action: PayloadAction<boolean>) {
      state.vertical = action.payload;
    },
  },
});

export const uiActions = uiSlice.actions;
export default uiSlice.reducer;
