// QL-24: every keyboard shortcut in Remotely, for the shortcut sheet (Ctrl+/, ShortcutSheet.tsx). The page shortcuts
// come from the page registry (lib/navigation.ts: the sidebar's pages in order, then the tabs that were pages), so a
// new page's shortcut is listed without an edit here; the rest are the keys each part of the app handles. A part that
// adds a key adds it to its group below. Tested in shortcuts.test.ts.

import { movedPageEntries, PAGES } from "./navigation.ts";

/** The page shortcuts for the sheet: the sidebar's pages in order, then the tabs that were pages and kept theirs. */
export function pageShortcuts(): { label: string; shortcut: string }[] {
  return [
    ...PAGES.map((p) => ({ label: p.label, shortcut: p.shortcut })),
    ...movedPageEntries().flatMap((m) => (m.shortcut ? [{ label: m.label, shortcut: m.shortcut }] : [])),
  ];
}

export interface Shortcut {
  /** Keys as shown: "Ctrl+K", "Ctrl+Shift+G", "Up / Down". */
  keys: string;
  what: string;
}

export interface ShortcutGroup {
  title: string;
  shortcuts: Shortcut[];
}

/** QL-24 itself: the sheet, outside a terminal and inside one (where Ctrl+/ belongs to the shell). */
export const SHEET_KEYS = "Ctrl+/";
export const SHEET_KEYS_IN_TERMINAL = "Ctrl+Shift+/";

/** Whether a key press opens the sheet: Ctrl+/ outside a terminal, Ctrl+Shift+/ (Ctrl+?) anywhere. */
export function opensShortcutSheet(
  press: { key: string; code?: string; ctrlKey: boolean; shiftKey: boolean; altKey: boolean; metaKey: boolean },
  inTerminal: boolean,
): boolean {
  if (!press.ctrlKey || press.altKey || press.metaKey) return false;
  const slash = press.key === "/" || press.key === "?" || press.code === "Slash";
  if (!slash) return false;
  return press.shiftKey || !inTerminal;
}

const ANYWHERE: ShortcutGroup = {
  title: "Anywhere",
  shortcuts: [
    { keys: "Ctrl+K", what: "Command palette: search VMs, sessions, containers, templates, commands and settings" },
    { keys: SHEET_KEYS, what: "This list of shortcuts" },
    { keys: "Esc", what: "Close the dialog, menu or panel in front" },
  ],
};

const PALETTE: ShortcutGroup = {
  title: "Command palette",
  shortcuts: [
    { keys: "Up / Down", what: "Move between results" },
    { keys: "Enter", what: "Choose: the first result is the best match" },
    { keys: "Backspace", what: "Back to everything, in an empty search on a VM's or session's actions" },
  ],
};

const TERMINAL: ShortcutGroup = {
  title: "Terminal",
  shortcuts: [
    { keys: "Ctrl+Shift+K", what: "Command palette (Ctrl+K belongs to the shell)" },
    { keys: SHEET_KEYS_IN_TERMINAL, what: "This list of shortcuts (Ctrl+/ belongs to the shell)" },
    { keys: "Ctrl+Shift+F", what: "Search this terminal's scrollback" },
    { keys: "Enter / Shift+Enter", what: "Next or previous match, in a scrollback search" },
    { keys: "Ctrl+Shift+G", what: "Search every open terminal's scrollback" },
    { keys: "Ctrl+C", what: "Copy the selection; without one, Ctrl+C goes to the shell" },
    { keys: "Ctrl+Shift+C / Ctrl+Insert", what: "Copy the selection (secrets scrubbed)" },
    { keys: "Ctrl+V / Ctrl+Shift+V", what: "Paste (several lines ask first)" },
    { keys: "Right-click", what: "Paste; on a file name, download the file" },
    { keys: "Ctrl+click / Shift+click", what: "Pick tabs for Type in all tabs and Compare hosts" },
    { keys: "Ctrl+click", what: "Pick sessions in the session tree for Compare hosts" },
    { keys: "Middle-click", what: "Close a tab" },
    { keys: "Esc", what: "Turn off Type in all tabs, or clear the picked tabs, from their bar" },
  ],
};

const ELSEWHERE: ShortcutGroup = {
  title: "Dialogs and lists",
  shortcuts: [
    { keys: "Enter", what: "Approve, once every answer the approval asks for is right" },
    { keys: "Ctrl+Enter", what: "Run the command in Compare hosts" },
    { keys: "Up / Down, Enter", what: "Move between the dashboard's rows, and open one" },
    {
      keys: "Arrow keys",
      what: "Move a dashboard widget (its grip) or resize it (its corner) while editing the layout",
    },
    { keys: "Esc", what: "Clear the session tree's filter" },
  ],
};

/** The sheet's groups: anywhere, the pages in the order given (the sidebar's, UX-08), then each part of the app. */
export function shortcutGroups(pages: readonly { label: string; shortcut: string }[]): ShortcutGroup[] {
  const byPage: ShortcutGroup = {
    title: "Pages",
    shortcuts: pages.map((p) => ({ keys: p.shortcut, what: p.label })),
  };
  return [ANYWHERE, byPage, PALETTE, TERMINAL, ELSEWHERE];
}

/** Every shortcut, for the sheet's filter: those whose keys or words have the text. */
export function filterShortcuts(groups: readonly ShortcutGroup[], text: string): ShortcutGroup[] {
  const needle = text.trim().toLowerCase();
  if (!needle) return [...groups];
  return groups
    .map((g) => ({
      ...g,
      shortcuts: g.shortcuts.filter(
        (s) => s.keys.toLowerCase().includes(needle) || s.what.toLowerCase().includes(needle),
      ),
    }))
    .filter((g) => g.shortcuts.length > 0);
}
