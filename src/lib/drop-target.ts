// UX-14, UX-15 (0.9.0 H1): which target gets files dropped from Explorer. The shell stages a drop and says where it
// fell (`files://dropped`, in CSS pixels); each page's listener reads what is under that point with `readDropSpot` (the
// markers its elements carry) and asks `dropTarget` what takes the files there, then does it through the paths it had.
// Each page keeps its own `active` check, and says itself what to do when nothing takes a drop.
//
// The owner's constraint (docs/plan-0.9.md, Decisions): a drop on a terminal pane uploads into that terminal's shell
// folder, or its home folder when the shell doesn't say, never as root, whatever the Files drawer beside it shows or
// browses as. A pane decides alone: nothing about the drawer is read for it. Tested in drop-target.test.ts.
//
// QL-30 (0.9.0 H6): while Type in all tabs is on with more than one tab picked, a terminal pane's target also offers a
// push to the picked hosts (`DropPlaces.typing`, `DropPush`), but only when the push would reach a host besides the
// dropped pane's own: the page asks, and its default is that same upload, unchanged. A push is one BX-10 job
// (`files_push` with the drop's staged id and the picked terminals as `TargetPicks.terminal_ids`): quick connections
// are left out (they have no saved session), and so are terminals a push can't take (not SSH, or not connected yet).
// Nothing changes without typing, or for the drawer.

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
  /** QL-30: its saved session (null or absent: a quick connection), so a push isn't offered to its own host alone. */
  sessionId?: string | null;
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
  /** Why it can't take uploads now (not connected, no folder open, the read-only lock); null: it can. */
  why?: string | null;
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
  /** QL-30: Type in all tabs is on (the Terminal page); absent while it is off. */
  typing?: DropTyping;
}

/** QL-30: a terminal of a tab picked for Type in all tabs. */
export interface TypingPane {
  /** Its core id; null until it has connected. */
  terminalId: string | null;
  /** Its saved session; null for a quick connection. */
  sessionId: string | null;
  /** An SSH terminal: a push goes over SSH, so a PowerShell, Telnet or serial tab can't take one. */
  ssh: boolean;
}

/** QL-30: Type in all tabs while it is on: how many tabs are picked, and their terminals. */
export interface DropTyping {
  tabs: number;
  panes: readonly TypingPane[];
}

/** QL-30: the push a drop on a terminal offers while typing in more than one tab. */
export interface DropPush {
  /** The terminals it goes to (`TargetPicks.terminal_ids`): connected SSH terminals of saved sessions. */
  terminalIds: string[];
  /** How many hosts that is: two tabs of one saved session are one host. */
  hosts: number;
  /** Of those, the hosts besides the dropped pane's own session's: with none, the drop doesn't ask. */
  others: number;
  /** Picked quick connections (terminals) left out: they have no saved session to push to. */
  quick: number;
  /** Other picked terminals left out: not SSH (Telnet, serial, PowerShell, editor), or not connected yet. */
  other: number;
  /** Why the push can't be chosen now; null when it can. */
  why: string | null;
}

export type DropTarget =
  /**
   * An upload into the pane's shell folder (`null`: its home folder), never as root. QL-30: `push` only while typing in
   * more than one tab, and only when it would reach a host besides the pane's own.
   */
  | { kind: "terminal"; paneKey: string; folder: string | null; asRoot: false; push?: DropPush }
  /** An upload into the folder a host pane shows, or the folder row it fell on, as root when the pane browses so. */
  | { kind: "host"; key: string; terminalId: string; folder: string; asRoot: boolean }
  /** A host pane that can't take uploads now, and why. */
  | { kind: "refused"; why: string }
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
    if (!pane) return { kind: "none" };
    const upload = { kind: "terminal", paneKey: pane.key, folder: pane.folder, asRoot: false } as const;
    // QL-30: the push is offered beside the upload while typing in more than one tab, when it would reach a host
    // besides the pane's own (else the drop is the upload alone, as without typing).
    if (!places.typing || places.typing.tabs < 2) return upload;
    const push = dropPush(places.typing, pane.sessionId ?? null);
    return push.others > 0 ? { ...upload, push } : upload;
  }
  if (places.hosts && spot.files === "host") {
    const host = places.hosts.find((h) => h.key === spot.filesTab);
    if (!host) return { kind: "none" };
    if (host.why) return { kind: "refused", why: host.why };
    if (!host.folder) return { kind: "refused", why: "Open a folder first" };
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

/** What a host pane says while files are dragged over it: where they would go, or why nothing would. */
export function hostDropLabel(target: { folder: string; asRoot: boolean } | { why: string }): string {
  if ("why" in target) return target.why;
  return `Drop to upload into ${target.folder}${target.asRoot ? " as root" : ""}`;
}

/** What the Terminal page needs of a pane to place a drop: its key, its core id and its shell's folder. */
export interface DropPaneSource {
  key: string;
  terminalId: string | null;
  /** QL-30: its saved session; null or absent for a quick connection. */
  sessionId?: string | null;
  getSnapshot(): { folder?: { path: string | null } | null };
}

/** QL-30: the core's cap on a push's files (bulk_files.rs MAX_PUSH_FILES). */
export const MAX_PUSH_FILES = 100;

/**
 * QL-30: the push a drop on a terminal offers, from the picked tabs' terminals; `dropSession` is the dropped pane's
 * saved session (null: a quick connection), which `others` leaves out. Pure.
 */
export function dropPush(typing: DropTyping, dropSession: string | null = null): DropPush {
  const terminalIds: string[] = [];
  const sessions = new Set<string>();
  let quick = 0;
  let other = 0;
  for (const pane of typing.panes) {
    if (!pane.ssh || pane.terminalId === null) other += 1;
    else if (pane.sessionId === null) quick += 1;
    else if (!terminalIds.includes(pane.terminalId)) {
      terminalIds.push(pane.terminalId);
      sessions.add(pane.sessionId);
    }
  }
  const why =
    terminalIds.length > 0
      ? null
      : quick > 0
        ? "Quick connections can't take a push: save them as sessions first"
        : "None of the picked tabs is a connected SSH session";
  const others = [...sessions].filter((s) => s !== dropSession).length;
  return { terminalIds, hosts: sessions.size, others, quick, other, why };
}

/** QL-30: the menu's push item, named for its hosts. */
export function pushLabel(push: DropPush): string {
  if (push.hosts === 0) return "Push to the picked hosts…";
  return push.hosts === 1 ? "Push to the picked host…" : `Push to the ${push.hosts} picked hosts…`;
}

/** QL-30: the menu's line on what the push leaves out; null when it leaves nothing out. */
export function pushLeftOut(push: DropPush): string | null {
  const parts: string[] = [];
  if (push.quick > 0) {
    parts.push(
      push.quick === 1
        ? "1 quick connection left out: it isn't a saved session"
        : `${push.quick} quick connections left out: they aren't saved sessions`,
    );
  }
  if (push.other > 0) {
    parts.push(
      push.other === 1
        ? "1 other terminal left out: it isn't SSH, or hasn't connected"
        : `${push.other} other terminals left out: they aren't SSH, or haven't connected`,
    );
  }
  return parts.length > 0 ? parts.join("; ") : null;
}

/**
 * QL-30: why the push can't take these files now: the read-only lock (`readOnly`, its reason, as Files › Many hosts
 * says it), no host, folders (a push sends files; the upload takes folders too), or more files than the core pushes.
 * Null: it can. Checked before the dialog, since `files_push` takes the drop's files whatever its answer. Pure.
 */
export function pushReason(
  push: DropPush,
  staged: { files: readonly { folder?: boolean }[] },
  readOnly: string | null = null,
): string | null {
  if (readOnly) return readOnly;
  if (push.why) return push.why;
  if (staged.files.some((f) => f.folder)) return "A push sends files: drop files, not folders";
  if (staged.files.length > MAX_PUSH_FILES) {
    return `A push sends at most ${MAX_PUSH_FILES} files; ${staged.files.length} were dropped`;
  }
  return null;
}

/** QL-30: the notice a push ends with (it leads to the job's results), from its hosts' statuses. */
export interface PushNotice {
  title: string;
  description: string;
  /** Every host that wasn't skipped got the files. */
  ok: boolean;
}

/**
 * QL-30: `what` was pushed into `folder`; the statuses are the job's targets' (`job_targets`), none when unread, and
 * `job` the job's own end (a cancelled or interrupted push says so, with the hosts that got it before). Pure.
 */
export function pushNotice(what: string, folder: string, statuses: readonly string[], job?: string): PushNotice {
  const skipped = statuses.filter((s) => s === "skipped").length;
  const ran = statuses.length - skipped;
  const got = statuses.filter((s) => s === "succeeded").length;
  const hosts = (n: number) => (n === 1 ? "1 host" : `${n} hosts`);
  const description = `Into ${folder}${skipped > 0 ? `; ${hosts(skipped)} skipped (protected)` : ""}`;
  if (job === "cancelled" || job === "interrupted") {
    const before = got > 0 ? `; ${got} of ${hosts(ran)} got it before` : "";
    return { title: `The push of ${what} was ${job}`, description: `${description}${before}`, ok: false };
  }
  if (statuses.length === 0) return { title: `The push of ${what} finished`, description, ok: true };
  if (ran > 0 && got === ran) return { title: `Pushed ${what} to ${hosts(got)}`, description, ok: true };
  if (got === 0) return { title: `The push of ${what} failed on ${hosts(ran)}`, description, ok: false };
  return { title: `Pushed ${what} to ${got} of ${hosts(ran)}`, description, ok: false };
}

/** An upload through `pane` into `folder` (null: its shell's folder or home, as the page has always found it). */
export interface TerminalPageUpload<P> {
  kind: "upload";
  pane: P;
  folder: string | null;
  asRoot: boolean;
}

/** What the Terminal page does with a drop. */
export type TerminalPageDrop<P> =
  | TerminalPageUpload<P>
  /**
   * QL-30: typing in more than one tab, a drop on a terminal asks when the push would reach another host. `upload` is
   * the default (Enter), exactly what the drop is without typing; `push` the other choice.
   */
  | { kind: "choose"; upload: TerminalPageUpload<P> & { asRoot: false }; push: DropPush }
  | { kind: "refused"; why: string }
  | { kind: "none" };

/** What the Terminal page needs of a pane while typing in all tabs: a `DropPaneSource` with its session and kind. */
export interface TypingPaneSource {
  terminalId: string | null;
  sessionId: string | null;
  kind: string;
}

/** QL-30: Type in all tabs as `terminalPageDrop` takes it: the picked tabs and their panes. */
export function dropTyping(pickedTabs: number, panes: readonly TypingPaneSource[]): DropTyping {
  return {
    tabs: pickedTabs,
    panes: panes.map((p) => ({ terminalId: p.terminalId, sessionId: p.sessionId, ssh: p.kind === "ssh" })),
  };
}

/**
 * The Terminal page's drop, from its panes and the drawer (null while it isn't shown). A pane takes a drop on it into
 * its own shell's folder (null: its home folder), never as root, through that pane; the drawer takes one into the folder
 * it shows, as root while it browses so, through its terminal's pane. The page then calls
 * `uploadStaged(pane, staged, folder, asRoot)` with exactly these. QL-30: with `typing` (Type in all tabs on), a drop on
 * a pane while more than one tab is picked is `choose`, whose `upload` is that same call. Pure.
 */
export function terminalPageDrop<P extends DropPaneSource>(
  spot: DropSpot,
  panes: readonly P[],
  drawer: DropHost | null,
  typing?: DropTyping,
): TerminalPageDrop<P> {
  const target = dropTarget(spot, {
    panes: panes.map((p) => ({ key: p.key, folder: p.getSnapshot().folder?.path ?? null, sessionId: p.sessionId })),
    hosts: drawer ? [drawer] : [],
    ...(typing ? { typing } : {}),
  });
  switch (target.kind) {
    case "terminal": {
      const pane = panes.find((p) => p.key === target.paneKey);
      if (!pane) return { kind: "none" };
      const upload = { kind: "upload", pane, folder: target.folder, asRoot: false } as const;
      return target.push ? { kind: "choose", upload, push: target.push } : upload;
    }
    case "host": {
      const pane = panes.find((p) => p.terminalId === target.terminalId);
      return pane ? { kind: "upload", pane, folder: target.folder, asRoot: target.asRoot } : { kind: "none" };
    }
    case "refused":
      return target;
    default:
      return { kind: "none" };
  }
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
