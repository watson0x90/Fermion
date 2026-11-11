import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';
import session from '../store/sessionSlice';
import output from '../store/outputSlice';
import ui from '../store/uiSlice';
import { GraphPanel } from './GraphPanel';
import * as bridge from '../bridge';

function makeStore() {
  return configureStore({ reducer: { session, output, ui } });
}

/* eslint-disable @typescript-eslint/no-explicit-any */
let calls: any[];
beforeEach(() => {
  calls = [];
  (window as any).MonacoCodeEditor = { getValue: () => 'USERSCRIPT' };
  (window as any).fermion = {
    reloadScript: async (s: string) => { calls.push(['reload', s]); },
    renderGraph: async (dot: string) => `<svg data-dot="${dot}">graph</svg>`,
  };
  (globalThis as any).fetch = vi.fn(async () => ({ text: async () => 'TRACE_BODY' }));
});

test('Trace reloads with the tracer + sets traceMode; STOP reloads the editor script', async () => {
  const store = makeStore();
  store.dispatch({ type: 'session/attached', payload: '1' });
  render(<Provider store={store}><GraphPanel /></Provider>);

  fireEvent.change(screen.getByLabelText('module'), { target: { value: 'k32.dll' } });
  fireEvent.change(screen.getByLabelText('symbol'), { target: { value: 'open' } });
  fireEvent.click(screen.getByText('Trace'));
  await waitFor(() => expect(store.getState().session.traceMode).toBe(true));
  expect(calls[0][1]).toContain('TRACE_BODY');

  fireEvent.click(screen.getByText('STOP'));
  await waitFor(() => expect(store.getState().session.traceMode).toBe(false));
  expect(calls[1][1]).toBe('USERSCRIPT'); // STOP reloads the editor script
});

test('a DOT payload via the trace sink renders to SVG in the panel', async () => {
  let sink: ((p: unknown) => void) | null = null;
  const spy = vi.spyOn(bridge, 'setTraceSink').mockImplementation((fn: any) => { sink = fn; });
  render(<Provider store={makeStore()}><GraphPanel /></Provider>);
  expect(sink).toBeTypeOf('function');
  sink!('digraph{a->b}');
  await waitFor(() => {
    expect(screen.getByTestId('graph-svg').innerHTML).toContain('<svg');
  });
  spy.mockRestore();
});
