import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { Bookmark } from './bookmarksSlice';

// Hooks and bookmarks are kept as one set per program. The set in use lives
// in the hooks and bookmarks slices; this holds its name ('' is the general
// set, used before any program has been attached to) and the sets of the
// other programs, as they are saved.
export interface SavedHook {
  id: string; name: string; module: string; offset: number | null; address: string;
  code: string; enabled: boolean; backtrace: boolean;
}
export interface SavedSet { name: string; hooks: SavedHook[]; bookmarks: Bookmark[]; }
export interface SetsState { active: string; others: SavedSet[]; }

const initialState: SetsState = { active: '', others: [] };

const setsSlice = createSlice({
  name: 'sets',
  initialState,
  reducers: {
    replaced(_state, action: PayloadAction<SetsState>) {
      return action.payload;
    },
  },
});

export const setsActions = setsSlice.actions;
export default setsSlice.reducer;
