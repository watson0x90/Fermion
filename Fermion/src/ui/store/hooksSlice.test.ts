import reducer, { hooksActions, MAX_HITS } from './hooksSlice';
import { hookFromTarget, Hit } from '../hooking/model';

const T1 = { name: 'k!CreateFileW', module: 'k', offset: 16, address: '0x10' };
const T2 = { name: 'k!ReadFile', module: 'k', offset: 32, address: '0x20' };
const hit = (id: string, text: string): Hit => ({ seq: 99, id, t: 5, tid: 1, depth: 0, phase: 'enter', text, error: false, bt: null });

function two() {
  let s = reducer(undefined, hooksActions.added(hookFromTarget(T1, 'a')));
  s = reducer(s, hooksActions.added(hookFromTarget(T2, 'b')));
  return s;
}

test('the first hook added is selected; later ones do not steal the selection', () => {
  const s = two();
  expect(s.hooks.map((h) => h.id)).toEqual(['a', 'b']);
  expect(s.selected).toBe('a');
});

test('a batch updates call counts and appends hits, renumbered in arrival order', () => {
  let s = two();
  s = reducer(s, hooksActions.batchReceived({ hits: [hit('a', 'one'), hit('b', 'two')], dropped: 3, counts: { a: 7, zzz: 1 } }));
  s = reducer(s, hooksActions.batchReceived({ hits: [hit('a', 'three')], dropped: 1, counts: { b: 2 } }));
  expect(s.hooks.map((h) => h.calls)).toEqual([7, 2]);
  expect(s.hits.map((h) => [h.seq, h.text])).toEqual([[1, 'one'], [2, 'two'], [3, 'three']]);
  expect(s.dropped).toBe(4);
});

test('hits for a hook that is not ours are ignored', () => {
  let s = two();
  s = reducer(s, hooksActions.batchReceived({ hits: [hit('ghost', 'x')], dropped: 0, counts: {} }));
  expect(s.hits).toEqual([]);
});

test('only the newest hits are kept', () => {
  let s = two();
  const many = Array.from({ length: 500 }, (_, i) => hit('a', 'n' + i));
  for (let i = 0; i < 5; i++) s = reducer(s, hooksActions.batchReceived({ hits: many, dropped: 0, counts: {} }));
  expect(s.hits.length).toBe(MAX_HITS);
  expect(s.hits[s.hits.length - 1].seq).toBe(2500);
  expect(s.hits[0].seq).toBe(501);
});

test('removing a hook removes its hits and moves the selection to a neighbour', () => {
  let s = two();
  s = reducer(s, hooksActions.batchReceived({ hits: [hit('a', 'one'), hit('b', 'two')], dropped: 0, counts: {} }));
  s = reducer(s, hooksActions.removed('a'));
  expect(s.hooks.map((h) => h.id)).toEqual(['b']);
  expect(s.selected).toBe('b');
  expect(s.hits.map((h) => h.text)).toEqual(['two']);
  s = reducer(s, hooksActions.removed('b'));
  expect(s.selected).toBeNull();
  s = reducer(s, hooksActions.removed('never-existed'));
  expect(s.hooks).toEqual([]);
});

test('patched changes one hook; clearing hits resets the dropped count', () => {
  let s = two();
  s = reducer(s, hooksActions.patched({ id: 'b', status: 'error', error: 'Module not loaded: k' }));
  expect(s.hooks[1]).toMatchObject({ status: 'error', error: 'Module not loaded: k' });
  expect(s.hooks[0].status).toBe('waiting');
  s = reducer(s, hooksActions.batchReceived({ hits: [hit('a', 'x')], dropped: 9, counts: {} }));
  s = reducer(s, hooksActions.hitsCleared());
  expect(s.hits).toEqual([]);
  expect(s.dropped).toBe(0);
});

test('when the session ends the hooks stay, waiting to be placed again; switched-off ones stay off', () => {
  let s = two();
  s = reducer(s, hooksActions.patched({ id: 'a', status: 'on', calls: 5 }));
  s = reducer(s, hooksActions.patched({ id: 'b', status: 'error', error: 'boom', enabled: false }));
  s = reducer(s, hooksActions.sessionEnded());
  expect(s.hooks.map((h) => [h.status, h.error])).toEqual([['waiting', ''], ['off', '']]);
  expect(s.hooks[0].calls).toBe(5);
});
