import { configureStore } from '@reduxjs/toolkit';
import { useDispatch, useSelector } from 'react-redux';
import session from './store/sessionSlice';
import output from './store/outputSlice';
import ui from './store/uiSlice';
import hooks from './store/hooksSlice';
import bookmarks from './store/bookmarksSlice';
import sets from './store/setsSlice';

export const store = configureStore({
  reducer: { session, output, ui, hooks, bookmarks, sets },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector = useSelector.withTypes<RootState>();
