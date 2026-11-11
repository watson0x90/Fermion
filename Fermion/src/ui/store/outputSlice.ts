import { createSlice, PayloadAction } from '@reduxjs/toolkit';

// Output kinds. (SEND is renamed to MSG in Task 4 across the UI.)
export const KINDS = ['LOG', 'WARN', 'ERR', 'SEND', 'STATUS'] as const;
export type Kind = (typeof KINDS)[number];

export interface OutputState {
  // Which kinds are visible (filter chips). The actual stream is written to
  // xterm imperatively (not held in Redux) to avoid re-rendering on volume.
  filters: Record<string, boolean>;
  follow: boolean;
  count: number;
}

const initialState: OutputState = {
  filters: Object.fromEntries(KINDS.map((k) => [k, true])),
  follow: true,
  count: 0,
};

const outputSlice = createSlice({
  name: 'output',
  initialState,
  reducers: {
    toggleFilter(state, action: PayloadAction<string>) {
      state.filters[action.payload] = !state.filters[action.payload];
    },
    setFollow(state, action: PayloadAction<boolean>) {
      state.follow = action.payload;
    },
    counted(state) {
      state.count += 1;
    },
    clear(state) {
      state.count = 0;
    },
  },
});

export const outputActions = outputSlice.actions;
export default outputSlice.reducer;
