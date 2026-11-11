import { createSlice, PayloadAction } from '@reduxjs/toolkit';

export interface SessionState {
  deviceId: string;
  isAttached: boolean;
  hasScript: boolean;
  currentPid: string | null;
  traceMode: boolean;
}

const initialState: SessionState = {
  deviceId: 'local',
  isAttached: false,
  hasScript: false,
  currentPid: null,
  traceMode: false,
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
    detached(state) {
      state.isAttached = false;
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
