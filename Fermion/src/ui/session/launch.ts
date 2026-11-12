// Starting and re-establishing sessions: what a session is on (so it can be
// started again), how a launch's environment is written, and how a session's
// end is described.

export interface SpawnConfig {
  path: string;
  args: string;       // one command line; quotes keep an argument together
  env: string;        // NAME=value, one per line
  cwd: string;
  suspended: boolean; // leave the process suspended after the script and hooks are in
}

export type SessionTarget =
  | { kind: 'attach'; pid: number; name: string }
  | ({ kind: 'spawn' } & SpawnConfig);

export interface Proc { pid: number; name: string; }

// "NAME=value" lines -> { NAME: value }. Blank lines and lines starting with #
// are skipped. Only the first = separates, so a value may contain more.
export function parseEnv(text: string): { env: Record<string, string>; error: string } {
  const env: Record<string, string> = {};
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    const at = line.indexOf('=');
    const name = at < 0 ? '' : line.slice(0, at).trim();
    if (!name) return { env: {}, error: `Line ${i + 1} is not NAME=value: ${line.slice(0, 60)}` };
    env[name] = line.slice(at + 1);
  }
  return { env, error: '' };
}

export function envCount(text: string): number {
  return Object.keys(parseEnv(text).env).length;
}

// Which running process is "the same program again"? The same pid still under
// the same name wins; otherwise the only process of that name. More than one
// of that name is the operator's choice, not ours.
export function pickReattach(procs: Proc[], target: { pid: number; name: string }): { pid: number | null; message: string } {
  const same = procs.find((p) => p.pid === target.pid && (!target.name || p.name === target.name));
  if (same) return { pid: same.pid, message: '' };
  if (!target.name) return { pid: null, message: `Process ${target.pid} is no longer running.` };
  const named = procs.filter((p) => p.name === target.name);
  if (named.length === 1) return { pid: named[0].pid, message: '' };
  if (!named.length) return { pid: null, message: `${target.name} is not running.` };
  return { pid: null, message: `${named.length} processes are named ${target.name}: pick one in the Process list.` };
}

const ENDED: Record<string, string> = {
  user: 'You detached.',
  'application-requested': 'The session was closed.',
  'process-terminated': 'The process exited.',
  'process-replaced': 'The process replaced itself with another program.',
  'connection-terminated': 'The connection to the device was lost.',
  'device-lost': 'The device was disconnected.',
};

export function endedText(reason: string): string {
  return ENDED[reason] ?? `The session ended (${reason}).`;
}

export function targetLabel(target: SessionTarget): string {
  if (target.kind === 'attach') return target.name ? `${target.name} (pid ${target.pid})` : `pid ${target.pid}`;
  return target.path.split(/[\\/]/).pop() || target.path;
}
