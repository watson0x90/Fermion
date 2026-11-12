// One cohesive line-icon set (1.7px stroke, rounded, currentColor) used across
// the whole shell — replaces the ad-hoc Unicode glyphs. Each icon is drawn in a
// 24x24 viewBox; size via the `size` prop or font-size/`em`.

export type IconName =
  | 'mark' | 'session' | 'graph' | 'tree' | 'inspect' | 'docs' | 'info' | 'gear'
  | 'hook' | 'refresh' | 'play' | 'reload' | 'stop' | 'follow' | 'clear' | 'save' | 'floppy'
  | 'search' | 'wrap' | 'expand' | 'popout' | 'dock' | 'chevron' | 'plus' | 'folder' | 'clock' | 'saveas' | 'tick' | 'min' | 'max' | 'unmax' | 'close';

const P: Record<IconName, React.ReactNode> = {
  mark: (<><circle cx="12" cy="12" r="3.2" fill="currentColor" stroke="none" /><ellipse cx="12" cy="12" rx="10" ry="4.3" /><ellipse cx="12" cy="12" rx="10" ry="4.3" transform="rotate(60 12 12)" /><ellipse cx="12" cy="12" rx="10" ry="4.3" transform="rotate(120 12 12)" /></>),
  session: (<><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9l3 3-3 3M13 15h4" /></>),
  graph: (<><circle cx="6" cy="6" r="2.4" /><circle cx="18" cy="9" r="2.4" /><circle cx="9" cy="18" r="2.4" /><path d="M8 7.5l7.6 1M8.5 16l-1-6M11 17l5.2-6" /></>),
  hook: (<><path d="M12 3v9a4 4 0 11-8 0v-1" /><path d="M4 8l0 3 3 0" opacity=".55" /><circle cx="12" cy="3" r="1.2" /><path d="M16 8h5M16 12h5M16 16h3" opacity=".55" /></>),
  tree: (<><rect x="9" y="3" width="6" height="5" rx="1" /><rect x="3" y="16" width="6" height="5" rx="1" /><rect x="15" y="16" width="6" height="5" rx="1" /><path d="M12 8v4M6 16v-2h12v2" /></>),
  inspect: (<><circle cx="11" cy="11" r="7" /><path d="M11 8v6M8 11h6" opacity=".55" /><path d="M16.5 16.5L21 21" /></>),
  docs: (<><path d="M6 3h8l4 4v14H6z" /><path d="M14 3v4h4M9 12h6M9 16h6" /></>),
  info: (<><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></>),
  gear: (<><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M22 12h-3M5 12H2M18.4 5.6l-2 2M7.6 16.4l-2 2M18.4 18.4l-2-2M7.6 7.6l-2-2" /></>),
  refresh: (<path d="M20 11a8 8 0 10-.9 4.6M20 5v6h-6" />),
  play: (<path d="M7 5l12 7-12 7z" fill="currentColor" stroke="none" />),
  reload: (<path d="M3 12a9 9 0 019-9 9 9 0 018 5M21 4v4h-4M21 12a9 9 0 01-9 9 9 9 0 01-8-5M3 20v-4h4" />),
  stop: (<rect x="6" y="6" width="12" height="12" rx="2" fill="currentColor" stroke="none" />),
  follow: (<path d="M12 4v12M7 11l5 5 5-5M5 20h14" />),
  clear: (<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13" />),
  save: (<path d="M12 3v11M8 10l4 4 4-4M5 20h14" />),
  floppy: (<><path d="M5 4h11l3 3v12a1 1 0 01-1 1H6a1 1 0 01-1-1z" /><path d="M8 4v5h7V4M8 20v-6h8v6" /></>),
  search: (<><circle cx="11" cy="11" r="7" /><path d="M16.5 16.5L21 21" /></>),
  wrap: (<path d="M4 6h16M4 12h12a3 3 0 110 6h-3m0 0l2-2m-2 2l2 2M4 18h5" />),
  expand: (<path d="M4 6h16M4 12h16M4 18h16" />),
  popout: (<path d="M14 4h6v6M20 4l-8 8M18 14v4a2 2 0 01-2 2H6a2 2 0 01-2-2V8a2 2 0 012-2h4" />),
  dock: (<path d="M20 4l-8 8M12 6v6h6M18 14v4a2 2 0 01-2 2H6a2 2 0 01-2-2V8a2 2 0 012-2h4" />),
  folder: (<path d="M3 7a2 2 0 012-2h4l2 2.5h8a2 2 0 012 2V18a2 2 0 01-2 2H5a2 2 0 01-2-2z" />),
  clock: (<><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3.5 2" /></>),
  saveas: (<><path d="M5 4h9l3 3v5M5 4v16h7M8 4v5h6V4" /><path d="M18 14v7M14.5 17.5h7" /></>),
  plus: (<path d="M12 5v14M5 12h14" />),
  chevron: (<path d="M9 6l6 6-6 6" />),
  tick: (<path d="M5 12l5 5 9-10" />),
  min: (<path d="M5 12h14" />),
  max: (<rect x="5" y="5" width="14" height="14" rx="1.5" />),
  unmax: (<><rect x="7" y="7" width="12" height="12" rx="1.5" /><path d="M5 15V6a1 1 0 011-1h9" /></>),
  close: (<path d="M6 6l12 12M18 6L6 18" />),
};

export function Icon({ name, size = '1em', className }: { name: IconName; size?: number | string; className?: string }) {
  return (
    <svg
      data-icon={name}
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {P[name]}
    </svg>
  );
}
