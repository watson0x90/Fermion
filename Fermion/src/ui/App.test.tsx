import { render, screen } from '@testing-library/react';
import { Provider } from 'react-redux';
import { store } from './store';
import { App } from './App';

test('App renders the root marker', () => {
  render(
    <Provider store={store}>
      <App />
    </Provider>,
  );
  expect(screen.getByTestId('app-root')).toBeInTheDocument();
});
