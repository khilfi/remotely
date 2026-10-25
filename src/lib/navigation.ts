// FD-01 page shortcuts (Ctrl+1 to Ctrl+9, Ctrl+0 for the map since 0.5.0, Ctrl+,) follow each page's own shortcut,
// not its place in the sidebar, so a page leaving the sidebar doesn't renumber the others. QL-14: Snapshots moved into
// the Virtual machines page; its old page id and shortcut (Ctrl+3) open the snapshot view there until another page
// takes the slot (Containers, Q6).

export interface ShortcutPage {
  id: string;
  shortcut: string;
}

/** Pages from before 0.4.0 that are now part of another page, with the shortcut they had. */
export const MOVED_PAGES = { snapshots: { shortcut: "Ctrl+3" } } as const;
export type MovedPage = keyof typeof MOVED_PAGES;

export type NavTarget = { page: string } | { moved: MovedPage } | null;

/** What Ctrl+<key> opens: a page, a moved page, or nothing. */
export function shortcutTarget(key: string, pages: ShortcutPage[]): NavTarget {
  const shortcut = `Ctrl+${key}`;
  const page = pages.find((p) => p.shortcut === shortcut);
  if (page) return { page: page.id };
  const moved = (Object.keys(MOVED_PAGES) as MovedPage[]).find((m) => MOVED_PAGES[m].shortcut === shortcut);
  return moved ? { moved } : null;
}

/** What a page id from the palette or an older link opens. */
export function navTarget(id: string, pages: ShortcutPage[]): NavTarget {
  if (pages.some((p) => p.id === id)) return { page: id };
  const moved = (Object.keys(MOVED_PAGES) as MovedPage[]).find((m) => m === id);
  return moved ? { moved } : null;
}
