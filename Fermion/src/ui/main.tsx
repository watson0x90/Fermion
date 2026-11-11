import { createRoot } from 'react-dom/client';
import { Provider } from 'react-redux';
import { store } from './store';
import { App } from './App';

const rootEl = document.getElementById('root');
if (rootEl) {
  createRoot(rootEl).render(
    <Provider store={store}>
      <App />
    </Provider>,
  );
}
