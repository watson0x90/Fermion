// The REPL's `help` command and the pieces of Tab completion that are pure.
//
// Help text comes from two places: the documentation index generated at build
// time from the Frida type definitions (src/frida-help.json — signatures and
// doc comments), and a live look at the value in the target (which members
// really exist in this Frida). Either alone still produces useful help.

export interface HelpEntry { kind: string; sigs: string[]; doc: string; }
export type HelpIndex = Record<string, HelpEntry>;

export interface Member { name: string; kind: 'function' | 'property'; arity?: number; type?: string; }
// What __fermion.inspect(name) reports from the target.
export interface Inspection {
  found: boolean;
  name: string;
  type?: string;
  arity?: number;
  value?: string;
  members?: Member[];
  instanceMembers?: Member[];
}

const DOCS_URL = 'https://frida.re/docs/javascript-api/';

// `help`, `help <topic>`, `?<topic>` or `help(<topic>)`. Null for ordinary code.
export function parseHelpCommand(entry: string): { topic: string } | null {
  const s = entry.trim();
  if (s === 'help' || s === '?') return { topic: '' };
  let m = /^help\s*\(\s*(.*?)\s*\)\s*;?$/.exec(s);
  if (m) return { topic: m[1] };
  m = /^help\s+(.+)$/.exec(s);
  if (m) return { topic: m[1].trim() };
  m = /^\?\s*(\S.*)$/.exec(s);
  if (m) return { topic: m[1].trim() };
  return null;
}

export function commonPrefix(names: string[]): string {
  if (!names.length) return '';
  let prefix = names[0];
  for (const n of names) {
    let i = 0;
    while (i < prefix.length && i < n.length && prefix[i] === n[i]) i++;
    prefix = prefix.slice(0, i);
    if (!prefix) break;
  }
  return prefix;
}

const firstLine = (doc: string) => (doc || '').split('\n')[0].trim();

// One row per member: its documented signature (or what the runtime reports
// when it is not in the definitions) and the first line of its documentation.
function memberRows(owner: string, members: Member[], index: HelpIndex): string[] {
  const rows = members.map((m) => {
    const entry = index[`${owner}.${m.name}`];
    const sig = entry?.sigs[0]?.replace(/^static /, '')
      ?? (m.kind === 'function' ? `${m.name}(${m.arity ? `…${m.arity} arg${m.arity === 1 ? '' : 's'}` : ''})` : `${m.name}${m.type ? ': ' + m.type : ''}`);
    return { sig, doc: firstLine(entry?.doc ?? '') };
  });
  // Signature, then its one-line description indented beneath: this reads
  // cleanly in a narrow pane, where aligned columns would wrap.
  return rows.flatMap((r) => (r.doc ? [`  ${r.sig}`, `      ${r.doc}`] : [`  ${r.sig}`]));
}

function memberSections(owner: string, members: Member[] | undefined, index: HelpIndex, labels: { props: string; fns: string }): string[] {
  const out: string[] = [];
  const props = (members ?? []).filter((m) => m.kind === 'property');
  const fns = (members ?? []).filter((m) => m.kind === 'function');
  if (props.length) out.push('', labels.props, ...memberRows(owner, props, index));
  if (fns.length) out.push('', labels.fns, ...memberRows(owner, fns, index));
  return out;
}

export function formatHelp(topic: string, info: Inspection, index: HelpIndex): string {
  const entry = index[topic];
  if (!info.found && !entry) {
    return `No help for “${topic}”.\nIt is not a name in the attached process and is not in the Frida documentation.\nPress Tab while typing to see the names that exist, or type help for an overview.`;
  }

  const lines: string[] = [];
  const kind = entry?.kind ?? (info.type === 'function' ? 'function' : info.type ?? 'value');
  lines.push(`${topic} — ${kind}`);
  if (entry?.sigs.length) lines.push(...entry.sigs.map((s) => '  ' + s));
  if (entry?.doc) lines.push('', entry.doc);

  if (!info.found) {
    lines.push('', 'This is documented, but it is not a value you can use by that name here'
      + (kind === 'method' || kind === 'property' ? ' — it belongs to instances of ' + topic.split('.').slice(0, -1).join('.') + '.' : '.'));
    return lines.join('\n');
  }

  if (info.value !== undefined) lines.push('', 'Current value: ' + info.value);

  const hasMembers = (info.members?.length ?? 0) > 0 || (info.instanceMembers?.length ?? 0) > 0;
  if (info.instanceMembers?.length) {
    lines.push(...memberSections(topic, info.members, index, { props: 'Static properties', fns: 'Static functions' }));
    lines.push('', 'Instances', ...memberRows(topic, info.instanceMembers, index));
  } else {
    lines.push(...memberSections(topic, info.members, index, { props: 'Properties', fns: 'Functions' }));
  }
  if (hasMembers) lines.push('', `More on one of these: help ${topic}.<name>`);
  if (entry && !topic.includes('.')) lines.push(`Frida API reference: ${DOCS_URL}`);
  return lines.join('\n');
}

// `help` on its own.
export function formatOverview(globals: string[], index: HelpIndex): string {
  const live = new Set(globals);
  const apis = Object.keys(index)
    .filter((k) => !k.includes('.') && live.has(k) && index[k].kind !== 'interface' && index[k].kind !== 'enum')
    .sort((a, b) => a.localeCompare(b));
  const lines = [
    'Fermion REPL',
    '  help <name>    documentation, e.g. help Process',
    '                 or help Process.enumerateModules',
    '  Tab            complete the name being typed',
    '  Enter          run the entry',
    '  Shift+Enter    new line',
    '  ↑ / ↓          earlier / later entries',
    '',
    'Entries run in the attached process. Variables declared with var stay available.',
  ];
  if (apis.length) lines.push('', 'Frida APIs available here:', '  ' + apis.join(', '));
  lines.push('', `Frida API reference: ${DOCS_URL}`);
  return lines.join('\n');
}

// ---- the documentation index, loaded on first use ----
let indexPromise: Promise<HelpIndex> | null = null;
export function loadHelpIndex(): Promise<HelpIndex> {
  if (!indexPromise) {
    indexPromise = fetch('../src/frida-help.json')
      .then((r) => (r.ok ? r.json() : {}))
      .catch(() => ({})) // no index (not built): help falls back to the live value
      .then((ix) => (ix && typeof ix === 'object' ? ix as HelpIndex : {}));
  }
  return indexPromise;
}
export function resetHelpIndexForTests() { indexPromise = null; }
