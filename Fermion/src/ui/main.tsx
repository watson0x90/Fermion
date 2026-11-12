import { createRoot } from 'react-dom/client';
import { Provider } from 'react-redux';
import './styles/fonts.css';
import { store } from './store';
import { initBridge } from './bridge';
import { exposeTestSurface } from './testSurface';
import { initOutputHost, initOutputClient } from './outputDetach';
import { App } from './App';
import { OutputWindow } from './components/OutputWindow';

const rootEl = document.getElementById('root');
// One bundle serves two pages: index.html (the IDE) and output.html (the
// detached Output window, marked data-view="output").
const isOutputWindow = rootEl?.dataset.view === 'output';

if (isOutputWindow) {
  // Mirror only: no Frida bridge here — lines arrive from the main window.
  initOutputClient(store);
} else {
  // Subscribe the window.fermion bridge to the store at startup (before any attach).
  initBridge(store);
  initOutputHost(store);
  exposeTestSurface(store);
}

if (rootEl) {
  createRoot(rootEl).render(
    <Provider store={store}>
      {isOutputWindow ? <OutputWindow /> : <App />}
    </Provider>,
  );
}
