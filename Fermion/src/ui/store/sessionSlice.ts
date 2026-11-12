import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { SessionTarget, ChildInfo } from '../session/launch';

export interface SessionState {
  deviceId: string;
  isAttached: boolean;
  hasScript: boolean;
  currentPid: string | null;
  traceMode: boolean;
  target: SessionTarget | null;  // what the current (or last) session is on, so it can be started again
  ended: string | null;          // why the last session ended; null while attached or before any
  suspendedPid: number | null;   // a spawned process that is waiting for Resume
  childGating: boolean;          // the operator wants child processes caught
  children: ChildInfo[];         // caught children waiting for a decision, oldest first
}

const initialState: SessionState = {
  deviceId: 'local',
  isAttached: false,
  hasScript: false,
  currentPid: null,
  traceMode: false,
  target: null,
  ended: null,
  suspendedPid: null,
  childGating: false,
  children: [],
};

const sessionSlice = createSlice({
  name: 'session',
  initialState,
  reducers: {
    // Sync from window.fermion.getState().
    syncState(state, action: PayloadAction<Partial<SessionState>>) {
      Object.assign(state, action.payload);
    },
    attached(state, action: PayloadAction<string | null>) {
      state.isAttached = true;
      state.currentPid = action.payload;
    },
    // A session started on this target (attach or spawn).
    sessionStarted(state, action: PayloadAction<SessionTarget>) {
      state.target = action.payload;
      state.ended = null;
    },
    suspendedSet(state, action: PayloadAction<number | null>) {
      state.suspendedPid = action.payload;
    },
    childGatingSet(state, action: PayloadAction<boolean>) {
      state.childGating = action.payload;
      if (!action.payload) state.children = []; // main lets them run
    },
    childCaught(state, action: PayloadAction<ChildInfo>) {
      if (!state.children.some((c) => c.pid === action.payload.pid)) state.children.push(action.payload);
    },
    childResolved(state, action: PayloadAction<number>) {
      state.children = state.children.filter((c) => c.pid !== action.payload);
    },
    childrenCleared(state) {
      state.children = [];
    },
    endedDismissed(state) {
      state.ended = null;
    },
    // The session is over. With a reason (Frida's, or 'user'), and a known
    // target, the end is kept so the sidebar can offer to start it again.
    detached(state, action: PayloadAction<string | undefined>) {
      if (state.isAttached && state.target) state.ended = action.payload ?? 'unknown';
      state.suspendedPid = null;
      state.children = []; // main lets caught children run when the session ends
      state.isAttached = false;
      state.hasScript = false; // the session's script is gone — Reload must disable
      state.currentPid = null;
      state.traceMode = false; // routing resets on detach
    },
    scriptLoaded(state) {
      state.hasScript = true;
      state.traceMode = false; // user script live -> terminal routing
    },
    setDevice(state, action: PayloadAction<string>) {
      state.deviceId = action.payload;
    },
    setTraceMode(state, action: PayloadAction<boolean>) {
      state.traceMode = action.payload;
    },
  },
});

export const sessionActions = sessionSlice.actions;
export default sessionSlice.reducer;
