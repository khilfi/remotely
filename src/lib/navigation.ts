// UX-08: the page registry and where every page id and page shortcut leads. The sidebar shows three groups (Machines,
// Remote, Overview) with Vault and Settings at the bottom, and Ctrl+1 to Ctrl+9 follow the sidebar's order (Settings
// keeps Ctrl+,). A page added once the digits ran out (FD-09's Toolbox) has none: it opens from the palette, its rows'
// links and the sidebar. PageHeader takes each page's title from here, so a title always matches the sidebar.
//
// Pages that became part of another page keep their id, so links, notifications and the palette still reach them:
// Snapshots (QL-14) is a view of Virtual machines, Image tools the Templates page's Disk images tab, the Map a Dashboard
// tab and Known hosts a Vault tab. A 0.5.0 shortcut that no page uses now still opens what it opened (Ctrl+0 the map,
// Ctrl+; Disk images, Ctrl+. Schedules); the others now open the page in that place of the sidebar. Tested in
// navigation.test.ts.

export type PageId =
  | "vms"
  | "templates"
  | "schedules"
  | "sessions"
  | "terminal"
  | "containers"
  | "toolbox"
  | "dashboard"
  | "activity"
  | "vault"
  | "settings";

export type NavGroupId = "machines" | "remote" | "overview";

export interface PageInfo {
  id: PageId;
  /** The sidebar's name, and the page header's title. */
  label: string;
  /** Its sidebar group; null for Vault and Settings, at the bottom. */
  group: NavGroupId | null;
  /** None once the digits are taken: such a page opens from the palette and from links. */
  shortcut?: string;
}

export const NAV_GROUPS: readonly { id: NavGroupId; label: string }[] = [
  { id: "machines", label: "Machines" },
  { id: "remote", label: "Remote" },
  { id: "overview", label: "Overview" },
];

/** Every page, in sidebar order. */
export const PAGES: readonly PageInfo[] = [
  { id: "vms", label: "Virtual machines", group: "machines", shortcut: "Ctrl+1" },
  { id: "templates", label: "Templates", group: "machines", shortcut: "Ctrl+2" },
  { id: "schedules", label: "Schedules", group: "machines", shortcut: "Ctrl+3" },
  { id: "sessions", label: "Sessions", group: "remote", shortcut: "Ctrl+4" },
  { id: "terminal", label: "Terminal", group: "remote", shortcut: "Ctrl+5" },
  { id: "containers", label: "Containers", group: "remote", shortcut: "Ctrl+6" },
  // FD-09: no digit is free; it opens from Ctrl+K and from session and VM rows.
  { id: "toolbox", label: "Toolbox", group: "remote" },
  { id: "dashboard", label: "Dashboard", group: "overview", shortcut: "Ctrl+7" },
  { id: "activity", label: "Activity", group: "overview", shortcut: "Ctrl+8" },
  { id: "vault", label: "Vault", group: null, shortcut: "Ctrl+9" },
  { id: "settings", label: "Settings", group: null, shortcut: "Ctrl+," },
];

/** The tabs pages gained in 0.6.0, by their home page. */
export type TemplatesHomeTab = "disks";
export type DashboardTab = "metrics" | "map";
export type VaultTab = "secrets" | "knownHosts";

/** Pages that are now a tab or view of another page, with their 0.5.0 shortcut when no page has taken it since. */
export const MOVED_PAGES = {
  snapshots: { label: "Snapshots", home: "vms", tab: "snapshots" },
  images: { label: "Disk images", home: "templates", tab: "disks", shortcut: "Ctrl+;" },
  map: { label: "Map", home: "dashboard", tab: "map", shortcut: "Ctrl+0" },
  knownHosts: { label: "Known hosts", home: "vault", tab: "knownHosts" },
} as const satisfies Record<string, { label: string; home: PageId; tab: string; shortcut?: string }>;
export type MovedPage = keyof typeof MOVED_PAGES;

/** 0.5.0 shortcuts that no page uses now, still opening their page. */
export const OLD_SHORTCUTS: Readonly<Record<string, PageId>> = { "Ctrl+.": "schedules" };

/** A page, and the tab or view to show on it. */
export type NavTarget = { page: PageId; tab?: string } | null;

const own = (table: object, key: string) => Object.prototype.hasOwnProperty.call(table, key);

/** The page's sidebar name. */
export function pageLabel(id: PageId): string {
  return PAGES.find((p) => p.id === id)?.label ?? id;
}

/** The sidebar's groups in order, each with its pages, then the bottom pages (group null). */
export function sidebarGroups(): { group: { id: NavGroupId; label: string } | null; pages: PageInfo[] }[] {
  return [
    ...NAV_GROUPS.map((group) => ({ group, pages: PAGES.filter((p) => p.group === group.id) })),
    { group: null, pages: PAGES.filter((p) => p.group === null) },
  ];
}

/** What Ctrl+<key> opens: a page (on a tab, for a moved one), or nothing. */
export function shortcutTarget(key: string): NavTarget {
  const shortcut = `Ctrl+${key}`;
  const page = PAGES.find((p) => p.shortcut !== undefined && p.shortcut === shortcut);
  if (page) return { page: page.id };
  const moved = (Object.keys(MOVED_PAGES) as MovedPage[]).find((m) => movedShortcut(m) === shortcut);
  if (moved) return { page: MOVED_PAGES[moved].home, tab: MOVED_PAGES[moved].tab };
  return own(OLD_SHORTCUTS, shortcut) ? { page: OLD_SHORTCUTS[shortcut] } : null;
}

/** What a page id from a link, the palette or an older version opens. */
export function navTarget(id: string): NavTarget {
  const page = PAGES.find((p) => p.id === id);
  if (page) return { page: page.id };
  if (!own(MOVED_PAGES, id)) return null;
  const moved = MOVED_PAGES[id as MovedPage];
  return { page: moved.home, tab: moved.tab };
}

function movedShortcut(m: MovedPage): string | undefined {
  const entry = MOVED_PAGES[m];
  return "shortcut" in entry ? entry.shortcut : undefined;
}

/** The moved pages the palette and the shortcut sheet list, named with their home ("Dashboard › Map"). */
export function movedPageEntries(): { id: MovedPage; label: string; shortcut?: string }[] {
  return (Object.keys(MOVED_PAGES) as MovedPage[])
    .filter((m) => m !== "snapshots")
    .map((m) => ({
      id: m,
      label: `${pageLabel(MOVED_PAGES[m].home)} › ${MOVED_PAGES[m].label}`,
      shortcut: movedShortcut(m),
    }));
}

/** The keys App's shortcut handler looks at (Ctrl plus one of them). */
export const SHORTCUT_KEYS = /^[0-9,.;]$/;
