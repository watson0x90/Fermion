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
    // Set (not toggle) one kind — used when another window reports its change.
    setFilter(state, action: PayloadAction<{ kind: string; on: boolean }>) {
      const { kind, on } = action.payload;
      if (kind in state.filters) state.filters[kind] = !!on;
    },
    // Adopt the toolbar state of another window (detached Output snapshot).
    hydrate(state, action: PayloadAction<{ filters?: Record<string, boolean>; follow?: boolean }>) {
      const { filters, follow } = action.payload;
      if (filters) for (const k of KINDS) { if (typeof filters[k] === 'boolean') state.filters[k] = filters[k]; }
      if (typeof follow === 'boolean') state.follow = follow;
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
