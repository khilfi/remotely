// UX-03, UX-04: how the Terminal page lays itself out. Files here, Compare hosts and Commands share one panel on the
// right, which the toolbar switches (the one way into each); the session tree folds while terminals are open; the
// output actions have one set of labels wherever they show. Pure, so it is tested on its own (terminal-layout.test.ts).

/** The views of the right-hand panel. */
export type SidePanel = "files" | "compare" | "commands";

export const SIDE_PANELS: readonly { id: SidePanel; label: string }[] = [
  { id: "files", label: "Files here" },
  { id: "compare", label: "Compare hosts" },
  { id: "commands", label: "Commands" },
];

/** Which view is open ("none" for none), kept in the window's local storage. */
export const SIDE_PANEL_KEY = "remotely.terminal.sidePanel";
/** 0.5.0 kept the files drawer and the command panel apart, each shown or not. */
export const LEGACY_FILES_KEY = "remotely.terminal.filesShown";
export const LEGACY_COMMANDS_KEY = "remotely.terminal.commandsShown";
/** Below this window width the panel starts closed, so the terminals keep their room (as Commands did in 0.5.0). */
export const COMMANDS_SHOWN_FROM = 1440;

export function isSidePanel(value: unknown): value is SidePanel {
  return value === "files" || value === "compare" || value === "commands";
}

/** The view the page opens with: the one kept, else what 0.5.0 showed, else Commands on a wide window. */
export function initialSidePanel(read: (key: string) => string | null, windowWidth: number): SidePanel | null {
  const saved = read(SIDE_PANEL_KEY);
  if (saved === "none") return null;
  if (isSidePanel(saved)) return saved;
  if (read(LEGACY_FILES_KEY) === "true") return "files";
  const commands = read(LEGACY_COMMANDS_KEY);
  if (commands === "true") return "commands";
  if (commands === "false") return null;
  return windowWidth >= COMMANDS_SHOWN_FROM ? "commands" : null;
}

/** A toolbar switch clicked: its view, or none when it was the one open. */
export function toggleSidePanel(current: SidePanel | null, clicked: SidePanel): SidePanel | null {
  return current === clicked ? null : clicked;
}

/** What is kept for a view. */
export function storedSidePanel(panel: SidePanel | null): string {
  return panel ?? "none";
}

/** How wide each view opens, in % of the page: Compare hosts' grouped output needs the most room. */
export const SIDE_PANEL_SIZE: Record<SidePanel, number> = { commands: 24, files: 32, compare: 42 };

/**
 * The session tree shows while no terminal is open (it is how one opens), and folds once one is, unless the user
 * showed it again. Each choice is kept on its own.
 */
export function treeShown(input: { tabs: number; shownEmpty: boolean; shownWithTabs: boolean }): boolean {
  return input.tabs === 0 ? input.shownEmpty : input.shownWithTabs;
}

/** SS-11: the output actions' labels, the same in the "⋯" menu (this terminal) and the picked tabs' bar. */
export const OUTPUT_LABELS = {
  menu: "Output",
  copy: "Copy output",
  save: "Save to a file…",
  saveEach: "Save a file each…",
  print: "Print…",
  log: "Log to a file…",
  stopLog: "Stop logging",
} as const;

/** The picked tabs' bar: "2 tabs picked", with the terminals when a split tab holds more than one. */
export function pickedTabsText(tabs: number, terminals: number): string {
  const picked = `${tabs} ${tabs === 1 ? "tab" : "tabs"} picked`;
  return terminals > tabs ? `${picked} (${terminals} terminals)` : picked;
}
