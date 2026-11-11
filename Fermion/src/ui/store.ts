import { configureStore } from '@reduxjs/toolkit';
import { useDispatch, useSelector } from 'react-redux';

// Slices are added in Task 2 (session/output/ui). A placeholder reducer keeps
// configureStore valid until then.
export const store = configureStore({
  reducer: {
    _placeholder: (state: null = null) => state,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector = useSelector.withTypes<RootState>();
