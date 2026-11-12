import { createSlice, PayloadAction } from '@reduxjs/toolkit';

// A saved place in a target: inside a module it is module + offset, so it is
// found again when the module loads somewhere else; outside one it is the
// address. `view` is how it opens.
export interface Bookmark {
  id: string;
  label: string;
  module: string;
  offset: number | null;
  address: string; // where it was when bookmarked
  view: 'memory' | 'code';
  note: string;
}

export const MAX_BOOKMARKS = 500;

export interface BookmarksState { items: Bookmark[]; }
const initialState: BookmarksState = { items: [] };

let counter = 0;
export function newBookmarkId(): string {
  counter++;
  return 'bm-' + Date.now().toString(36) + '-' + counter.toString(36);
}

// The same place? (As for hooks: module + offset inside a module.)
export function samePlace(a: { module: string; offset: number | null; address: string }, b: { module: string; offset: number | null; address: string }): boolean {
  if (a.module || b.module) return a.module.toLowerCase() === b.module.toLowerCase() && a.offset === b.offset;
  return a.address.toLowerCase() === b.address.toLowerCase();
}

const bookmarksSlice = createSlice({
  name: 'bookmarks',
  initialState,
  reducers: {
    loaded(state, action: PayloadAction<Bookmark[]>) {
      state.items = action.payload.slice(0, MAX_BOOKMARKS);
    },
    added(state, action: PayloadAction<Bookmark>) {
      if (state.items.length >= MAX_BOOKMARKS || state.items.some((b) => samePlace(b, action.payload))) return;
      state.items.push(action.payload);
    },
    changed(state, action: PayloadAction<{ id: string } & Partial<Pick<Bookmark, 'label' | 'note' | 'view'>>>) {
      const item = state.items.find((b) => b.id === action.payload.id);
      if (!item) return;
      const { label, note, view } = action.payload;
      if (label !== undefined) item.label = label.slice(0, 200);
      if (note !== undefined) item.note = note.slice(0, 2000);
      if (view !== undefined) item.view = view;
    },
    removed(state, action: PayloadAction<string>) {
      state.items = state.items.filter((b) => b.id !== action.payload);
    },
  },
});

export const bookmarksActions = bookmarksSlice.actions;
export default bookmarksSlice.reducer;
