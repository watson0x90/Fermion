import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { Hook, Hit, HitBatch, HookStatus } from '../hooking/model';

export const MAX_HITS = 2000; // hits kept for display; older ones fall off

export interface HooksState {
  hooks: Hook[];
  selected: string | null;
  hits: Hit[];        // oldest first
  dropped: number;    // hits the agent or the cap above discarded
  nextSeq: number;    // hits are renumbered here: the agent restarts its own count per session
  echo: boolean;      // also print hits in the Output pane
}

const initialState: HooksState = { hooks: [], selected: null, hits: [], dropped: 0, nextSeq: 1, echo: true };

const hooksSlice = createSlice({
  name: 'hooks',
  initialState,
  reducers: {
    added(state, action: PayloadAction<Hook>) {
      state.hooks.push(action.payload);
      if (state.selected === null) state.selected = action.payload.id;
    },
    removed(state, action: PayloadAction<string>) {
      const id = action.payload;
      const at = state.hooks.findIndex((h) => h.id === id);
      if (at < 0) return;
      state.hooks.splice(at, 1);
      state.hits = state.hits.filter((h) => h.id !== id);
      if (state.selected === id) state.selected = state.hooks[Math.min(at, state.hooks.length - 1)]?.id ?? null;
    },
    patched(state, action: PayloadAction<{ id: string } & Partial<Hook>>) {
      const hook = state.hooks.find((h) => h.id === action.payload.id);
      if (hook) Object.assign(hook, action.payload);
    },
    selected(state, action: PayloadAction<string | null>) {
      state.selected = action.payload;
    },
    batchReceived(state, action: PayloadAction<HitBatch>) {
      const { hits, dropped, counts } = action.payload;
      for (const hook of state.hooks) if (counts[hook.id] !== undefined) hook.calls = counts[hook.id];
      const known = new Set(state.hooks.map((h) => h.id));
      for (const hit of hits) if (known.has(hit.id)) state.hits.push({ ...hit, seq: state.nextSeq++ });
      state.dropped += dropped;
      if (state.hits.length > MAX_HITS) state.hits.splice(0, state.hits.length - MAX_HITS);
    },
    hitsCleared(state) {
      state.hits = [];
      state.dropped = 0;
    },
    // The session ended: nothing is hooked any more. The hooks themselves are
    // kept, to be placed again in the next session.
    sessionEnded(state) {
      for (const hook of state.hooks) {
        const status: HookStatus = hook.enabled ? 'waiting' : 'off';
        hook.status = status;
        hook.error = '';
      }
    },
    echoSet(state, action: PayloadAction<boolean>) {
      state.echo = action.payload;
    },
  },
});

export const hooksActions = hooksSlice.actions;
export default hooksSlice.reducer;
