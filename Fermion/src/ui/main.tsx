import { createRoot } from 'react-dom/client';
import { Provider } from 'react-redux';
import { store } from './store';
import { initBridge } from './bridge';
import { exposeTestSurface } from './testSurface';
import { App } from './App';

// Subscribe the window.fermion bridge to the store at startup (before any attach).
initBridge(store);
exposeTestSurface(store);

const rootEl = document.getElementById('root');
if (rootEl) {
  createRoot(rootEl).render(
    <Provider store={store}>
      <App />
    </Provider>,
  );
}
