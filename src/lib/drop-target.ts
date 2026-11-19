// UX-14, UX-15 (0.9.0 H1): which target gets files dropped from Explorer. The shell stages a drop and says where it
// fell (`files://dropped`, in CSS pixels); each page's listener reads what is under that point with `readDropSpot` (the
// markers its elements carry) and asks `dropTarget` what takes the files there, then does it through the paths it had.
// Each page keeps its own `active` check, and says itself what to do when nothing takes a drop.
//
// The owner's constraint (docs/plan-0.9.md, Decisions): a drop on a terminal pane uploads into that terminal's shell
// folder, or its home folder when the shell doesn't say, never as root, whatever the Files drawer beside it shows or
// browses as. A pane decides alone: nothing about the drawer is read for it. H6 extends the terminal target (a push to
// the picked hosts while typing in all tabs) and must leave this default as it is. Tested in drop-target.test.ts.

/** What is under a drop point, read from the pages' markers. */
export interface DropSpot {
  /** `data-pane-key`: a terminal pane on the Terminal page. */
  paneKey?: string;
  /** `data-files-drop`: a host pane (a Files page host tab, or the Terminal's drawer), This PC's pane, or Many hosts. */
  files?: "host" | "local" | "many";
  /** `data-files-tab`: which host pane. */
  filesTab?: string;
  /** `data-files-folder`: a folder row of that host pane. */
  filesFolder?: string;
  /** `data-vm-drop`: a VM's row or its details, by the VM's key. */
  vm?: string;
}

/** A terminal pane that takes drops. */
export interface DropPane {
  key: string;
  /** The shell's folder as its prompt hook reports it; null when it doesn't (the home folder is asked of the core). */
  folder: string | null;
}

/** A host pane that takes drops: a Files page host tab, or the Terminal's drawer. */
export interface DropHost {
  /** Its `data-files-tab`. */
  key: string;
  terminalId: string;
  /** The folder it shows; null while none has opened. */
  folder: string | null;
  /** It browses as root (its uploads go one tier higher). */
  asRoot: boolean;
}

/** What a page has on screen that takes drops. */
export interface DropPlaces {
  /** The Terminal page's panes. */
  panes?: readonly DropPane[];
  /** Host panes: the Files page's tabs, or the Terminal page's drawer. */
  hosts?: readonly DropHost[];
  /** The Files page's Many hosts tab is on screen. */
  many?: boolean;
  /** The Virtual machines page: a VM's row or details takes an ISO. */
  vms?: boolean;
}

export type DropTarget =
  /** An upload into the pane's shell folder (`null`: its home folder), never as root. */
  | { kind: "terminal"; paneKey: string; folder: string | null; asRoot: false }
  /** An upload into the folder a host pane shows, or the folder row it fell on, as root when the pane browses so. */
  | { kind: "host"; key: string; terminalId: string; folder: string; asRoot: boolean }
  /** The files fill Many hosts' push. */
  | { kind: "many" }
  /** An ISO for a VM's CD/DVD drive. */
  | { kind: "vm"; vm: string }
  /** Nothing takes it there: the page unstages it and says where to drop. */
  | { kind: "none" };

/** Where a drop goes, from what is under it and what the page has on screen. Pure. */
export function dropTarget(spot: DropSpot, places: DropPlaces): DropTarget {
  // A terminal pane decides alone, before anything else is looked at.
  if (places.panes && spot.paneKey !== undefined) {
    const pane = places.panes.find((p) => p.key === spot.paneKey);
    return pane ? { kind: "terminal", paneKey: pane.key, folder: pane.folder, asRoot: false } : { kind: "none" };
  }
  if (places.hosts && spot.files === "host") {
    const host = places.hosts.find((h) => h.key === spot.filesTab);
    if (!host?.folder) return { kind: "none" };
    return {
      kind: "host",
      key: host.key,
      terminalId: host.terminalId,
      folder: spot.filesFolder ?? host.folder,
      asRoot: host.asRoot,
    };
  }
  if (places.many && spot.files === "many") return { kind: "many" };
  if (places.vms && spot.vm) return { kind: "vm", vm: spot.vm };
  return { kind: "none" };
}

/** What a host pane says while files are dragged over it. */
export function hostDropLabel(target: Extract<DropTarget, { kind: "host" }>): string {
  return `Drop to upload into ${target.folder}${target.asRoot ? " as root" : ""}`;
}

/** The part of an element `readDropSpot` needs (a DOM element; a stand-in in tests). */
export interface SpotElement {
  closest(selector: string): { dataset: Record<string, string | undefined> } | null;
}

function filesKind(value: string | undefined): DropSpot["files"] {
  return value === "host" || value === "local" || value === "many" ? value : undefined;
}

/** What is under a point of the window (CSS pixels), from the markers the pages set. */
export function readDropSpot(
  x: number,
  y: number,
  // Every marked element is an HTMLElement, which has the `dataset` read here.
  at: (x: number, y: number) => SpotElement | null = (px, py) =>
    document.elementFromPoint(px, py) as HTMLElement | null,
): DropSpot {
  const under = at(x, y);
  if (!under) return {};
  const files = under.closest("[data-files-drop]");
  return {
    paneKey: under.closest("[data-pane-key]")?.dataset.paneKey,
    files: filesKind(files?.dataset.filesDrop),
    filesTab: files?.dataset.filesTab,
    filesFolder: under.closest("[data-files-folder]")?.dataset.filesFolder,
    vm: under.closest("[data-vm-drop]")?.dataset.vmDrop,
  };
}
