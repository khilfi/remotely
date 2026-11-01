// Terminal workspace (SS-03, QL-02 to QL-05, SS-11): a collapsible session tree on the left (QL-04), and
// tabs on the right, each splittable into panes (each pane its own SSH connection), with keep-alive and
// auto-reconnect shown on the pane and its tab. New terminal opens the quick-connect form (QL-02). A tab
// takes its session's colour and label, and shows the host's own name and the address it reached
// (QL-03). Search with Ctrl+Shift+F, copy and paste with Ctrl+Shift+C / Ctrl+Shift+V or right-click
// (QL-05). The Output menu copies, saves or prints a pane's whole scrollback or that of several tabs
// picked with Ctrl+click or Shift+click, and logs a pane to a file (SS-11). Host key questions (SS-05)
// come up as dialogs. Typing into one terminal skips the approval flow, as in any terminal; typing into several at
// once (MultiExec) and Compare output do not.
//
// P5: the command panel on the right (BX-08) pastes favourite and built-in commands into the current pane; the key
// button types a vault password at a sudo or su prompt (QL-06); a long command that finishes in a tab in the
// background (another tab, another page, or the window not in front) shows a Windows notification, unless turned off
// for that tab or in Settings (QL-07).
//
// P6: MultiExec (SS-10): the switch in the toolbar makes the picked tabs (all of them at first; Ctrl+click and
// Shift+click change it, or the bar picks by folder or label) receive what is typed into any of them, MobaXterm style,
// and can show them side by side. The core holds each line's Enter and rates it; above Low the approval dialog opens
// here, with the line and the terminals. The command panel's paste and Shift+click go through it too. Compare output
// (BX-03) runs one command on the picked tabs' hosts and on sessions Ctrl+clicked in the tree, as a one-shot job, and
// shows the grouped results in a panel under the terminals. QL-08: disabled buttons say why.
//
// P7: file transfer (SS-08) over each terminal's own SSH connection (SFTP, no second login). The "Files here" drawer
// follows the current terminal's folder (bash and zsh report it through an invisible prompt hook; other shells start
// in the home folder), downloads ticked files and uploads into the folder it shows. Files dropped on a terminal, or
// picked with the upload button, go into that terminal's folder; files already there are replaced only after asking.
// Right-clicking a file name in a terminal offers to download it. Uploads are commands on the bus (Low; Prod and
// replacing ask); the transfers panel shows progress, speed and time left, with cancel and retry. No path on this PC
// comes from here: the shell opens the dialogs and catches drops.
//
// 0.5.0: QL-18 searches every open terminal's scrollback from a panel under the terminals (Ctrl+Shift+G), results
// grouped by tab, a click showing the match in its pane. QL-19's saved groups open or select a saved group of sessions
// for MultiExec, save the picked tabs as one, and manage them.
//
// 0.6.0 (UX-02, UX-03, UX-04, UX-12): the toolbar sits in the page header with a few controls: Split, Type in all tabs,
// the switch of the one right-hand panel (Files here, Compare hosts, Commands: one view at a time, and the only way into
// each), and "⋯" for everything else, each in one place (search, Type a vault password, Tunnels, Output, Saved groups,
// notify, Reconnect, Close pane). The tabs have their own full-width row with + at its end; one slim bar under them
// serves Type in all tabs and the picked tabs (with their Output menu); the session tree folds while terminals are
// open. Shortcuts are in the shortcut sheet (Ctrl+/), not in a footer. A tab's environment is the one that applies (a
// Prod VM the session reaches makes it Prod), and its tooltip says where it comes from.

import { Fragment, useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { toast } from "sonner";
import {
  ArrowDownIcon,
  ArrowUpIcon,
  BellOffIcon,
  BellRingIcon,
  CableIcon,
  CaseSensitiveIcon,
  Columns2Icon,
  FileTextIcon,
  FolderOpenIcon,
  GitCompareArrowsIcon,
  LoaderCircleIcon,
  LockKeyholeIcon,
  MoreHorizontalIcon,
  PanelLeftCloseIcon,
  PanelLeftOpenIcon,
  PlusIcon,
  RadioTowerIcon,
  RefreshCwIcon,
  RegexIcon,
  Rows2Icon,
  SearchIcon,
  ShieldAlertIcon,
  SquareChevronRightIcon,
  SquareTerminalIcon,
  TextSearchIcon,
  XIcon,
} from "lucide-react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "@/components/ui/resizable";
import { Separator } from "@/components/ui/separator";
import { Toggle } from "@/components/ui/toggle";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ApprovalDialog } from "@/components/ApprovalDialog";
import { ColorDot } from "@/components/Badges";
import { CommandPanel } from "@/components/CommandPanel";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { Tip } from "@/components/Tip";
import { ComparePanel, type CompareView } from "@/components/ComparePanel";
import { FilesDrawer } from "@/components/FilesDrawer";
import { HostDetailsSheet } from "@/components/HostDetailsSheet";
import { HostKeyDialog } from "@/components/HostKeyDialog";
import { MultiExecBar, type MultiExecNote } from "@/components/MultiExecBar";
import { MultiExecGroupsDialog, type GroupsDialogStart } from "@/components/MultiExecGroupsDialog";
import { MultiExecGroupsSubmenu } from "@/components/MultiExecGroupsMenu";
import { NewTerminalDialog } from "@/components/NewTerminalDialog";
import { PasteConfirmDialog } from "@/components/PasteConfirmDialog";
import { usePresentation } from "@/components/Presentation";
import { ScrollbackSearchPanel, type SearchPane } from "@/components/ScrollbackSearchPanel";
import { SessionTree } from "@/components/SessionTree";
import { TunnelsDialog, tunnelsReason } from "@/components/TunnelsPanel";
import { useTypeSecret } from "@/components/TypeSecretMenu";
import { UploadConflictDialog } from "@/components/UploadConflictDialog";
import { ReasonLine, WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type ApprovalRequest,
  type EngineKind,
  type Environment,
  type LeftOut,
  type MultiExecEvent,
  type MultiExecGroup,
  type MultiExecOutcome,
  type MultiExecStatus,
  type QuickConnectRequest,
  type SessionColor,
  type SessionFolder,
  type DroppedFiles,
  type SessionRecord,
  type StagedFiles,
  type SubmitOutcome,
  type TerminalAlert,
  type TerminalRule,
  type TransferInfo,
  type UploadStart,
  type VaultInfo,
  type VmRecord,
} from "@/lib/api";
import { rulesForPane } from "@/lib/highlight-rules";
import { alertNotification, recordAlert } from "@/lib/terminal-alerts";
import { fromCommandFinished, fromTerminalAlert } from "@/lib/notifications";
import { notify as keepNotification } from "@/lib/notifications-store";
import { sendCommand } from "@/lib/command-send";
import { setNoteSendHandler } from "@/lib/note-send";
import { refreshRecents } from "@/lib/stars-store";
import { connectedReason, multiExecReason, READ_ONLY_REASON, splitReason, uploadReason } from "@/lib/disabled-reasons";
import {
  appliedEnvironment,
  environmentText,
  vmsById,
  type AppliedEnvironment,
  type EnvironmentOfVm,
} from "@/lib/session-environment";
import {
  initialSidePanel,
  OUTPUT_LABELS,
  SIDE_PANEL_KEY,
  SIDE_PANEL_SIZE,
  SIDE_PANELS,
  storedSidePanel,
  toggleSidePanel,
  treeShown as treeShownFor,
  type SidePanel,
} from "@/lib/terminal-layout";
import { formatDuration, plural } from "@/lib/format";
import { useThresholds } from "@/lib/metrics";
import { MultiExecSender } from "@/lib/multiexec";
import { groupTabs, memberNames, saveGroupReason, sessionsOfTabs, type GroupTab } from "@/lib/multiexec-groups";
import { lineNotification, shouldNotify, type NotifyChoice } from "@/lib/recordings";
import type { LineHit } from "@/lib/scrollback-search";
import type { PickableTab } from "@/lib/multiexec-picks";
import { clickTab, isMulti, NO_SELECTION, pruneSelection, type TabSelection } from "@/lib/tab-selection";
import { copyOutput, paneTitle, printOutput, saveOutput, type NamedPane } from "@/lib/terminal-output";
import {
  DEFAULT_PANE_OPTIONS,
  factsTitle,
  PaneSession,
  sessionAddress,
  TERMINAL_PALETTE,
  type CommandFinished,
  type PaneOpener,
  type PaneOptions,
  type PaneSnapshot,
  type PasteAsk,
} from "@/lib/terminal-session";
import { maskedOutside, readOnlyLocked } from "@/lib/presentation-state";
import type { ResolvedTheme } from "@/lib/theme";
import { formatSize } from "@/lib/transfers";
import { transferStore } from "@/lib/transfers-store";
import { liveTunnels, routeText, viaText } from "@/lib/tunnels";
import { cn } from "@/lib/utils";

/** A tab's panes: one pane, or a split of several side by side or stacked. */
type Layout =
  | { kind: "pane"; key: string; pane: PaneSession }
  | { kind: "split"; key: string; orientation: "horizontal" | "vertical"; children: Layout[] };

interface Tab {
  key: string;
  layout: Layout;
  /** The pane the toolbar acts on. */
  activePane: string;
  /** QL-07: notify when a long command finishes here while the tab is in the background. */
  notify: boolean;
}

/** More would make each pane too small to read. */
const MAX_PANES = 6;
/** UX-03: the session tree while no terminal is open (shown by default), and while some are (folded by default). */
const TREE_KEY = "remotely.terminal.treeShown";
const TREE_WITH_TABS_KEY = "remotely.terminal.treeWithTabs";

const SIDE_ICONS: Record<SidePanel, typeof FolderOpenIcon> = {
  files: FolderOpenIcon,
  compare: GitCompareArrowsIcon,
  commands: SquareChevronRightIcon,
};

function readKey(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function keep(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Not kept; the default shows next time.
  }
}

/** CT-01 "Open a shell" in a container on a session's host. */
interface ContainerShellOpen {
  sessionId: string;
  engine: EngineKind;
  containerId: string;
  title: string;
}

interface Props {
  /** The page stays mounted while hidden so its connections survive. */
  active: boolean;
  theme: ResolvedTheme;
  /** A session to open in a new tab; `n` changes for each request. */
  openRequest: {
    sessionId: string;
    n: number;
    /** CT-01: a shell in one of the session's containers. */
    container?: ContainerShellOpen;
  } | null;
  /** QL-02: opens the New terminal form when it changes (the command palette). */
  newRequest: number;
  /** BX-03: opens Compare output when it changes (the command palette). */
  compareRequest: number;
  /** SS-10: turns MultiExec on when it changes (the command palette). */
  multiExecRequest: number;
  /** QL-18: opens Search all terminals when it changes (the command palette). */
  searchRequest?: number;
  /** R10: shows the tab of this terminal (a notification, the map, the status bar), with its tunnels panel. */
  focusRequest?: { terminalId: string; tunnels?: boolean; n: number } | null;
  /** QL-20: opens the command panel on this command (the palette's search). */
  snippetRequest?: { command: string; n: number } | null;
  vault: VaultInfo | null;
  /** Compare runs go through the app, which opens the approval dialog; `onJob` gets the job once queued. */
  onSubmitted: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onOpenVault: () => void;
}

function newKey() {
  return crypto.randomUUID();
}

function allPanes(layout: Layout): PaneSession[] {
  return layout.kind === "pane" ? [layout.pane] : layout.children.flatMap(allPanes);
}

/**
 * The saved session a tab shows: its current pane's, or another pane's (a pane split "like" another doesn't know its
 * session, and every pane of a tab reaches the same one), so the tab keeps its name, colour and environment.
 */
function tabSessionId(tab: Tab, current: string | null): string | null {
  return current ?? allPanes(tab.layout).find((p) => p.sessionId)?.sessionId ?? null;
}

function findPane(layout: Layout, key: string): PaneSession | undefined {
  return allPanes(layout).find((p) => p.key === key);
}

/** Replaces the pane with a split holding it and a new pane (or adds to a split going the same way). */
function splitLayout(
  layout: Layout,
  target: string,
  added: PaneSession,
  orientation: "horizontal" | "vertical",
): Layout {
  const leaf: Layout = { kind: "pane", key: added.key, pane: added };
  if (layout.kind === "pane") {
    if (layout.key !== target) return layout;
    return { kind: "split", key: newKey(), orientation, children: [layout, leaf] };
  }
  const index = layout.children.findIndex((c) => c.kind === "pane" && c.key === target);
  if (index >= 0 && layout.orientation === orientation) {
    const children = [...layout.children];
    children.splice(index + 1, 0, leaf);
    return { ...layout, children };
  }
  return { ...layout, children: layout.children.map((c) => splitLayout(c, target, added, orientation)) };
}

/** Removes a pane; a split left with one child becomes that child. `null` when nothing is left. */
function removePane(layout: Layout, target: string): Layout | null {
  if (layout.kind === "pane") return layout.key === target ? null : layout;
  const children = layout.children.map((c) => removePane(c, target)).filter((c): c is Layout => c !== null);
  if (children.length === 0) return null;
  if (children.length === 1) return children[0];
  return { ...layout, children };
}

/** QL-04: a tab takes its session's colour along its top edge; Prod also tints it. */
const COLOR_TAB: Record<SessionColor, string> = {
  red: "border-t-red-500",
  orange: "border-t-orange-500",
  amber: "border-t-amber-500",
  green: "border-t-green-500",
  teal: "border-t-teal-500",
  blue: "border-t-blue-500",
  violet: "border-t-violet-500",
  pink: "border-t-pink-500",
  slate: "border-t-slate-500",
};

const ENV_TAB: Record<Environment, string> = {
  none: "border-t-transparent",
  lab: "border-t-env-lab",
  staging: "border-t-env-staging",
  prod: "border-t-env-prod",
};

const ENV_TEXT: Record<Environment, string> = {
  none: "",
  lab: "text-env-lab",
  staging: "text-env-staging",
  prod: "text-env-prod",
};

function readShown(key: string, byDefault: boolean) {
  try {
    const value = localStorage.getItem(key);
    return value === null ? byDefault : value !== "false";
  } catch {
    return byDefault;
  }
}

/** QL-07, QL-12: every terminal of a recorded MultiExec line is done. */
type LineFinished = Extract<MultiExecEvent, { event: "lineFinished" }>;

/** QL-07: the window is not in front, or the tab or page is not the one on screen. */
function inBackground(tabKey: string, activeTab: string | null, pageActive: boolean) {
  return tabKey !== activeTab || !pageActive || !document.hasFocus() || document.visibilityState !== "visible";
}

/** SS-10: "web03 (at a password prompt)", for the MultiExec bar. */
function leftOutText(leftOut: LeftOut[], nameOfTerminal: (id: string) => string) {
  return leftOut.map((l) => `${nameOfTerminal(l.terminalId)} (${l.reason})`).join(", ");
}

function finishedText(name: string, finished: CommandFinished) {
  const ran = formatDuration(finished.afterSecs);
  return {
    title: `Command finished in ${name}`,
    body:
      finished.how === "prompt"
        ? `It ran ${ran} and the prompt is back.`
        : `It ran ${ran}, then the output stopped: it finished, or it waits for an answer.`,
  };
}

export function TerminalPage({
  active,
  theme,
  openRequest,
  newRequest,
  compareRequest,
  multiExecRequest,
  searchRequest = 0,
  focusRequest = null,
  snippetRequest = null,
  vault,
  onSubmitted,
  onOpenVault,
}: Props) {
  // FD-03: the read-only lock turns MultiExec and uploads off (QL-08 says why); typing into one terminal stays.
  const presentation = usePresentation();
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const [selection, setSelection] = useState<TabSelection>(NO_SELECTION);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [options, setOptions] = useState<PaneOptions>(DEFAULT_PANE_OPTIONS);
  /** UX-03: the tree shows while no terminal is open, and folds while some are, unless the user shows it again. */
  const [treeEmpty, setTreeEmpty] = useState(() => readShown(TREE_KEY, true));
  const [treeWithTabs, setTreeWithTabs] = useState(() => readShown(TREE_WITH_TABS_KEY, false));
  /** UX-03: the one right-hand panel: Files here, Compare hosts or Commands, or none. */
  const [side, setSide] = useState<SidePanel | null>(() => initialSidePanel(readKey, window.innerWidth));
  /** UX-12: the VMs sessions reach, for the environment that applies to each. */
  const [vms, setVms] = useState<VmRecord[]>([]);
  /** QL-07: what Settings say about notifications (on, long commands or any while away, how long). */
  const [notify, setNotify] = useState<NotifyChoice>({ on: true, when: "long", afterSecs: 30 });
  const notifyOn = notify.on;
  /** QL-07: tabs where a long command finished (QL-17: or an alert rule matched) while they were in the background. */
  const [attention, setAttention] = useState<string[]>([]);
  /** QL-17: the highlight and alert rules; each pane highlights with those for its scope. */
  const [highlightRules, setHighlightRules] = useState<TerminalRule[]>([]);
  const [newOpen, setNewOpen] = useState(false);
  const [version, setVersion] = useState(0);
  /** SS-10: MultiExec is on; the picked tabs (`selection`) receive what is typed into any of them. */
  const [multiExec, setMultiExec] = useState(false);
  const [mxStatus, setMxStatus] = useState<MultiExecStatus | null>(null);
  const [mxNote, setMxNote] = useState<MultiExecNote | null>(null);
  /** SS-10: a held line that needs the approval dialog. */
  const [mxApproval, setMxApproval] = useState<{ lineId: string; request: ApprovalRequest } | null>(null);
  /** SS-07: tunnels waiting for the approval dialog, one at a time (several may start with a Prod terminal). */
  const [tunnelApprovals, setTunnelApprovals] = useState<
    { pane: PaneSession; forwardId: string; request: ApprovalRequest }[]
  >([]);
  /** SS-10: the picked tabs side by side while MultiExec is on. */
  const [tile, setTile] = useState(true);
  /** BX-03: Compare hosts is the side panel's view. */
  const compareOpen = side === "compare";
  /** MO-13, MO-14: a session's host details, from the session tree. */
  const [hostDetails, setHostDetails] = useState<{ id: string; name: string } | null>(null);
  const [thresholds] = useThresholds();
  /** QL-12: the panel's one-shot run, or the lines MultiExec recorded. */
  const [compareView, setCompareView] = useState<CompareView>("run");
  const [treePicks, setTreePicks] = useState<string[]>([]);
  const [folders, setFolders] = useState<SessionFolder[]>([]);
  /** Bumped when a pane's state changes, so what depends on terminal ids and statuses is recomputed. */
  const [paneTick, setPaneTick] = useState(0);
  /**
   * SS-08: "Files here" is the side panel's view. P6: the transfers themselves are in the transfers store
   * (src/lib/transfers-store.ts), which the panel reads, so a transfer's progress doesn't re-render this page.
   */
  const filesShown = side === "files";
  /** SS-07: the current terminal's tunnels, from the "⋯" menu (or a link to them). */
  const [tunnelsOpen, setTunnelsOpen] = useState(false);
  /** SS-08: files picked or dropped for upload that are in the folder already. */
  const [conflict, setConflict] = useState<{
    pane: PaneSession;
    staged: StagedFiles;
    folder: string;
    existing: string[];
  } | null>(null);
  /** SS-08: a file name right-clicked in a terminal, offered for download. */
  const [fileMenu, setFileMenu] = useState<{
    pane: PaneSession;
    path: string;
    name: string;
    size: number;
    x: number;
    y: number;
  } | null>(null);
  /** QL-19: saved MultiExec groups, and the dialog that manages them. */
  const [groups, setGroups] = useState<MultiExecGroup[]>([]);
  const [groupsDialog, setGroupsDialog] = useState<GroupsDialogStart | null>(null);
  const handled = useRef(0);
  // For closing every pane when the page goes away (the app closing).
  const tabsRef = useRef(tabs);

  const loadGroups = useCallback(() => {
    api.multiExecGroups().then(setGroups, () => undefined);
  }, []);

  const loadSessions = useCallback(() => {
    api.sessions().then(setSessions, (err) => toast.error(errorMessage(err)));
    api.sessionFolders().then(setFolders, () => undefined);
    // UX-12: a stored read (no hypervisor is asked), so the tabs and the tree say when a VM makes a session Prod.
    api.vmList().then(setVms, () => setVms([]));
    // QL-17: Settings edits the rules, so they are read again each time the page shows.
    api.terminalRules().then(setHighlightRules, () => undefined);
    api.terminalSettings().then(
      (s) => {
        setOptions({
          fontSize: s.fontSize,
          scrollback: s.scrollback,
          copyOnSelect: s.copyOnSelect,
          confirmMultilinePaste: s.confirmMultilinePaste,
        });
        setNotify({ on: s.notifyFinished, when: s.notifyWhen, afterSecs: s.notifyAfterSecs });
      },
      () => undefined,
    );
  }, []);

  useEffect(() => {
    if (active) loadSessions();
  }, [active, loadSessions, version]);
  useEffect(() => {
    if (active) loadGroups();
  }, [active, loadGroups]);

  useEffect(() => {
    tabsRef.current = tabs;
    for (const pane of tabs.flatMap((t) => allPanes(t.layout))) {
      pane.setOptions(options);
      pane.setTheme(theme);
    }
  }, [tabs, options, theme]);

  /** UX-03: the toolbar's tree switch; what it chose is kept for its own case (terminals open or not). */
  function toggleTree() {
    if (tabs.length === 0) {
      setTreeEmpty(!treeEmpty);
      keep(TREE_KEY, String(!treeEmpty));
    } else {
      setTreeWithTabs(!treeWithTabs);
      keep(TREE_WITH_TABS_KEY, String(!treeWithTabs));
    }
  }

  /** UX-03: the toolbar's panel switch. Only the user's own choice is kept; until then the window's width decides. */
  function chooseSide(next: SidePanel | null) {
    setSide(next);
    keep(SIDE_PANEL_KEY, storedSidePanel(next));
  }

  // Closing the app closes every connection; the core audits each close.
  useEffect(() => () => tabsRef.current.forEach((t) => allPanes(t.layout).forEach((p) => p.close())), []);

  const sessionById = useMemo(() => new Map(sessions.map((s) => [s.id, s])), [sessions]);
  const vmById = useMemo(() => vmsById(vms), [vms]);

  // QL-17: each pane highlights with the enabled rules for its scope: its saved session, and that session's label
  // (none for a quick connection that was not saved). The same rules again change nothing in a pane.
  useEffect(() => {
    for (const pane of tabs.flatMap((t) => allPanes(t.layout))) {
      const session = pane.sessionId ? sessionById.get(pane.sessionId) : undefined;
      pane.setHighlightRules(rulesForPane(highlightRules, pane.sessionId, session?.environment ?? "none"));
    }
  }, [tabs, highlightRules, sessionById]);

  /** SS-07: a tunnel needs the approval dialog (started here, or one that starts with the terminal). */
  const askTunnel = useCallback((pane: PaneSession, forwardId: string, request: ApprovalRequest) => {
    setTunnelApprovals((queue) =>
      queue.some((a) => a.request.id === request.id) ? queue : [...queue, { pane, forwardId, request }],
    );
  }, []);

  // QL-07: a pane's finished command is handled with the page's latest state.
  const finishedRef = useRef<(pane: PaneSession, finished: CommandFinished) => void>(() => undefined);
  // QL-17: so is an alert.
  const alertRef = useRef<(pane: PaneSession, alert: TerminalAlert) => void>(() => undefined);
  // SS-08: a file name right-clicked in a pane, too.
  const fileWordRef = useRef<(pane: PaneSession, word: string, x: number, y: number) => void>(() => undefined);
  // QL-05: a paste with a line break waits for the confirm (one at a time: a newer one cancels the one shown).
  const pasteAskRef = useRef<(pane: PaneSession, ask: PasteAsk) => Promise<boolean>>(() => Promise.resolve(false));
  const createPane = useCallback(
    (opener: PaneOpener, label: string, fixedTitle = false) => {
      const pane = new PaneSession(newKey(), opener, label, theme, options, fixedTitle);
      pane.onCommandFinished = (finished) => finishedRef.current(pane, finished);
      pane.onAlert = (alert) => alertRef.current(pane, alert);
      pane.onFileWord = (word, x, y) => fileWordRef.current(pane, word, x, y);
      pane.onPasteConfirm = (p, ask) => pasteAskRef.current(p, ask);
      // OSC 8 links from the host are never opened: the address shows, to copy.
      pane.onLink = (uri) =>
        toast.info("Links from a host don't open in Remotely", {
          description: uri.length > 300 ? `${uri.slice(0, 299)}…` : uri,
          action: { label: "Copy", onClick: () => void navigator.clipboard?.writeText(uri) },
        });
      // SS-07: a tunnel that starts with the terminal may ask first (a Prod host): show its approval.
      pane.onTunnelAsking = (p, forwardId) => {
        p.tunnelRequest(forwardId).then(
          (request) => request && askTunnel(p, forwardId, request),
          (err) => toast.error(errorMessage(err)),
        );
      };
      return pane;
    },
    [theme, options, askTunnel],
  );

  // SS-10: a new tab does not join MultiExec by itself (Ctrl+click adds it), and keeps the picked tabs picked.
  const multiExecOn = useRef(false);
  /** Returns the new tab's key (QL-19 picks the tabs a group opened). */
  const addTab = useCallback((pane: PaneSession): string => {
    const tab: Tab = {
      key: newKey(),
      layout: { kind: "pane", key: pane.key, pane },
      activePane: pane.key,
      notify: true,
    };
    setTabs((prev) => [...prev, tab]);
    setActiveTab(tab.key);
    setSelection((s) => (multiExecOn.current ? s : { keys: [], anchor: tab.key }));
    return tab.key;
  }, []);

  const openSession = useCallback(
    (session: Pick<SessionRecord, "id" | "name">, container?: ContainerShellOpen) => {
      if (container) {
        // CT-01 "Open a shell": a tab inside a container, named after it.
        const opener: PaneOpener = {
          kind: "container",
          sessionId: container.sessionId,
          engine: container.engine,
          containerId: container.containerId,
        };
        addTab(createPane(opener, container.title, true));
      } else {
        addTab(createPane({ kind: "session", sessionId: session.id }, session.name));
      }
      // Recent sessions moved (QL-26: Ctrl+K's Recent too).
      window.setTimeout(() => {
        setVersion((v) => v + 1);
        refreshRecents();
      }, 500);
    },
    [addTab, createPane],
  );

  /** QL-02: the pane opens before its tab exists, so the form can show why it could not. */
  async function openQuick(request: QuickConnectRequest, label: string) {
    const pane = createPane({ kind: "quick", request }, label);
    try {
      await pane.start();
    } catch (err) {
      pane.close();
      throw err;
    }
    addTab(pane);
    if (request.save) setVersion((v) => v + 1);
  }

  const newHandled = useRef(newRequest);
  useEffect(() => {
    if (newRequest === newHandled.current) return;
    newHandled.current = newRequest;
    setNewOpen(true);
  }, [newRequest]);

  useEffect(() => {
    if (!openRequest || openRequest.n === handled.current) return;
    handled.current = openRequest.n;
    loadSessions();
    openSession(
      { id: openRequest.sessionId, name: sessionById.get(openRequest.sessionId)?.name ?? "Session" },
      openRequest.container,
    );
  }, [openRequest, openSession, loadSessions, sessionById]);

  function closePane(tabKey: string, paneKey: string) {
    const tab = tabs.find((t) => t.key === tabKey);
    if (!tab) return;
    findPane(tab.layout, paneKey)?.close();
    const layout = removePane(tab.layout, paneKey);
    const next: Tab[] = [];
    for (const t of tabs) {
      if (t.key !== tabKey) next.push(t);
      else if (layout) {
        const left = allPanes(layout).map((p) => p.key);
        next.push({ ...t, layout, activePane: left.includes(t.activePane) ? t.activePane : left[0] });
      }
    }
    setTabs(next);
    setSelection((s) =>
      pruneSelection(
        s,
        next.map((t) => t.key),
      ),
    );
    if (!next.some((t) => t.key === activeTab)) setActiveTab(next[next.length - 1]?.key ?? null);
    if (next.length === 0) {
      stopMultiExec();
      setSearchAll(false);
    }
  }

  function closeTab(tab: Tab) {
    allPanes(tab.layout).forEach((p) => p.close());
    const next = tabs.filter((t) => t.key !== tab.key);
    setTabs(next);
    setSelection((s) =>
      pruneSelection(
        s,
        next.map((t) => t.key),
      ),
    );
    if (activeTab === tab.key) setActiveTab(next[next.length - 1]?.key ?? null);
    if (next.length === 0) {
      stopMultiExec();
      setSearchAll(false);
    }
  }

  function pickTab(key: string, modifiers: { ctrl: boolean; shift: boolean }) {
    const order = tabs.map((t) => t.key);
    // SS-10: with MultiExec on, a plain click only shows the tab; the picked ones stay picked.
    if (!multiExec || modifiers.ctrl || modifiers.shift) {
      setSelection((s) => clickTab(s.anchor ? s : { ...s, anchor: activeTab }, key, order, modifiers));
    }
    setActiveTab(key);
  }

  const current = tabs.find((t) => t.key === activeTab) ?? null;
  const currentPane = current ? findPane(current.layout, current.activePane) : undefined;
  const currentSnapshot = usePane(currentPane);
  // FD-06: a note's code block goes to the current terminal as a paste, which asks first when it has a line break
  // (QL-05) and never presses Enter.
  const notePane = useRef(currentPane);
  useEffect(() => {
    notePane.current = currentPane;
  }, [currentPane]);
  useEffect(() => {
    setNoteSendHandler((text) => {
      const pane = notePane.current;
      if (!pane || !pane.connected) return false;
      void pane.paste(text);
      return true;
    });
    return () => setNoteSendHandler(null);
  }, []);

  // QL-07: looking at a tab clears its "finished in the background" mark.
  const viewing = active ? activeTab : null;
  const [viewed, setViewed] = useState<string | null>(null);
  if (viewing !== viewed) {
    setViewed(viewing);
    if (viewing && attention.includes(viewing)) setAttention(attention.filter((k) => k !== viewing));
  }

  const splitBlocked = current
    ? splitReason({
        panes: allPanes(current.layout).length,
        maxPanes: MAX_PANES,
        connectedOnce: Boolean(currentPane?.terminalId || currentPane?.sessionId),
      })
    : null;

  function split(orientation: "horizontal" | "vertical") {
    if (!current || !currentPane) return;
    if (allPanes(current.layout).length >= MAX_PANES) {
      toast.info(`A tab holds at most ${MAX_PANES} panes. Open the session in another tab.`);
      return;
    }
    let opener: PaneOpener;
    if (currentPane.terminalId) opener = { kind: "like", terminalId: currentPane.terminalId };
    else if (currentPane.sessionId) opener = { kind: "session", sessionId: currentPane.sessionId };
    else {
      toast.info("This terminal never connected, so there is nothing to split. Try New terminal again.");
      return;
    }
    const pane = createPane(opener, currentPane.label, currentPane.fixedTitle);
    setTabs((prev) =>
      prev.map((t) =>
        t.key === current.key
          ? { ...t, layout: splitLayout(t.layout, t.activePane, pane, orientation), activePane: pane.key }
          : t,
      ),
    );
  }

  /** How a pane is named in titles and saved output. */
  const nameOf = useCallback(
    (pane: PaneSession) => {
      // CT-01: a container's shell keeps the container's name.
      if (pane.fixedTitle) return pane.label;
      const snap = pane.getSnapshot();
      const session = snap.sessionId ? sessionById.get(snap.sessionId) : undefined;
      return paneTitle(session?.name ?? pane.label, snap.facts);
    },
    [sessionById],
  );

  useEffect(() => {
    finishedRef.current = (pane, finished) => {
      const tab = tabs.find((t) => allPanes(t.layout).includes(pane));
      if (!tab || !tab.notify || !shouldNotify(notify, finished.afterSecs, inBackground(tab.key, activeTab, active)))
        return;
      const { title, body } = finishedText(nameOf(pane), finished);
      // FD-03: Windows shows it outside the window, so it is masked here while presenting.
      api
        .notifyCommandFinished(maskedOutside(title), maskedOutside(body))
        .catch((err) => console.warn("notification failed", err));
      // QL-25: kept in the notification centre (the core redacts it).
      keepNotification(fromCommandFinished(title, body, pane.terminalId));
      if (tab.key !== activeTab || !active)
        setAttention((prev) => (prev.includes(tab.key) ? prev : [...prev, tab.key]));
    };
  });

  // QL-17: an alert (the core sends one per burst of matching lines, never one per line) is kept for the list of
  // recent alerts, and notifies like a finished command when its tab is away, unless the tab's bell is off.
  useEffect(() => {
    alertRef.current = (pane, alert) => {
      const name = nameOf(pane);
      recordAlert(alert, name);
      // QL-25: every alert is kept in the notification centre, whether or not Windows is told.
      keepNotification(fromTerminalAlert(alert, name));
      const tab = tabs.find((t) => allPanes(t.layout).includes(pane));
      if (!tab || !tab.notify || !inBackground(tab.key, activeTab, active)) return;
      const { title, body } = alertNotification(alert, name);
      // FD-03: Windows shows it outside the window, so it is masked here while presenting.
      api
        .notifyTerminalAlert(maskedOutside(title), maskedOutside(body))
        .catch((err) => console.warn("notification failed", err));
      if (tab.key !== activeTab || !active)
        setAttention((prev) => (prev.includes(tab.key) ? prev : [...prev, tab.key]));
    };
  });

  function setTabNotify(tabKey: string, notify: boolean) {
    setTabs((prev) => prev.map((t) => (t.key === tabKey ? { ...t, notify } : t)));
  }

  // QL-07: a MultiExec line notifies once, when all its terminals are done; never one per terminal.
  const lineFinishedRef = useRef<(event: LineFinished) => void>(() => undefined);
  useEffect(() => {
    lineFinishedRef.current = (event) => {
      const ids = new Set(event.terminalIds);
      const lineTabs = tabs.filter((t) =>
        allPanes(t.layout).some((p) => p.terminalId !== null && ids.has(p.terminalId)),
      );
      // The bell turns a tab off; the line notifies unless every one of its tabs is off.
      if (!lineTabs.some((t) => t.notify)) return;
      const tiled = multiExec && tile && tabs.filter((t) => selection.keys.includes(t.key)).length > 1;
      const away = tiled
        ? inBackground(lineTabs[0].key, lineTabs[0].key, active)
        : lineTabs.every((t) => inBackground(t.key, activeTab, active));
      if (!shouldNotify(notify, event.afterSecs, away)) return;
      const { title, body } = lineNotification(
        event.line,
        event.terminals,
        event.afterSecs,
        event.how,
        event.unfinished,
      );
      // FD-03: Windows shows it outside the window, so it is masked here while presenting.
      api
        .notifyCommandFinished(maskedOutside(title), maskedOutside(body))
        .catch((err) => console.warn("notification failed", err));
      keepNotification(fromCommandFinished(title, body, event.terminalIds[0] ?? null));
      const behind = lineTabs.filter((t) => t.key !== activeTab || !active).map((t) => t.key);
      if (behind.length > 0) setAttention((prev) => [...new Set([...prev, ...behind])]);
    };
  });

  // ---- SS-10 MultiExec --------------------------------------------------------------------------------

  // Terminal ids and statuses arrive as panes connect: follow them while MultiExec or Compare needs them.
  const everyPane = useMemo(() => tabs.flatMap((t) => allPanes(t.layout)), [tabs]);
  useEffect(() => {
    if (!multiExec && !compareOpen) return;
    const stops = everyPane.map((pane) => pane.subscribe(() => setPaneTick((n) => n + 1)));
    return () => stops.forEach((stop) => stop());
  }, [everyPane, multiExec, compareOpen]);

  const pickedTabs = multiExec ? tabs.filter((t) => selection.keys.includes(t.key)) : [];
  const pickedPanes = pickedTabs.flatMap((t) => allPanes(t.layout));
  const pickedIds = pickedPanes.map((p) => p.terminalId).filter((id): id is string => id !== null);
  const pickedIdsKey = pickedIds.join(",");
  // `paneTick` is read so a pane that just got its id is picked up.
  void paneTick;

  const terminalName = useCallback(
    (terminalId: string) => {
      const pane = everyPane.find((p) => p.terminalId === terminalId);
      return pane ? nameOf(pane) : "a closed terminal";
    },
    [everyPane, nameOf],
  );

  const handleOutcome = useCallback(
    (outcome: MultiExecOutcome) => {
      switch (outcome.status) {
        case "typed": {
          const reached = plural(outcome.reached.length, "terminal");
          const leftOut = leftOutText(outcome.leftOut, terminalName);
          const left = outcome.leftOut.length > 0 ? `; left out: ${leftOut}` : "";
          if (outcome.mode === "password") {
            setMxNote({
              tone: "pass",
              text: `Password prompt: keys go straight to ${reached}, not rated and never logged${left}`,
            });
          } else if (outcome.mode === "fullScreen") {
            setMxNote({ tone: "pass", text: `Full-screen program: keys go straight to ${reached}, not rated${left}` });
          } else if (outcome.leftOut.length > 0) {
            setMxNote({ tone: "warn", text: `This line goes to ${reached}; left out: ${leftOut}` });
          } else {
            setMxNote((n) => (n?.tone === "wait" ? n : null));
          }
          break;
        }
        case "alone":
          setMxNote({ tone: "info", text: `Typed into one terminal only: ${outcome.reason}` });
          break;
        case "held":
          if (outcome.request) {
            setMxApproval({ lineId: outcome.lineId, request: outcome.request });
            setMxNote({
              tone: "wait",
              text: `The line waits for your approval; ${outcome.runKey} is held in every terminal`,
            });
          } else {
            setMxNote({
              tone: "info",
              text: `Read-only: ${outcome.runKey} sent to ${plural(outcome.reached.length, "terminal")}`,
            });
          }
          break;
        case "queued":
          if (outcome.dropped) toast.warning("Too much was typed while a line waited: the rest was dropped");
          break;
        case "refused":
          setMxNote({ tone: "warn", text: outcome.reason });
          toast.warning(outcome.reason);
          break;
      }
    },
    [terminalName],
  );
  const outcomeRef = useRef(handleOutcome);
  const senderRef = useRef<MultiExecSender | null>(null);
  useEffect(() => {
    outcomeRef.current = handleOutcome;
  });
  useEffect(() => {
    senderRef.current = new MultiExecSender(
      (outcome) => outcomeRef.current(outcome),
      (err) => toast.error(`Type in all tabs: ${errorMessage(err)}`),
    );
  }, []);

  // The core follows the picked terminals; each picked pane hands it its keys.
  const wasOn = useRef(false);
  useEffect(() => {
    if (multiExec) {
      wasOn.current = true;
      const ids = pickedIdsKey ? pickedIdsKey.split(",") : [];
      api.multiExecSetTargets(ids).then(setMxStatus, (err) => toast.error(errorMessage(err)));
    } else if (wasOn.current) {
      wasOn.current = false;
      api.multiExecStop().then(setMxStatus, () => undefined);
    }
  }, [multiExec, pickedIdsKey]);
  useEffect(() => {
    const picked = new Set(pickedPanes.map((p) => p.key));
    for (const pane of everyPane) {
      pane.setInputRouter(
        multiExec && picked.has(pane.key)
          ? (from, bytes) => {
              if (from.terminalId) senderRef.current?.send(from.terminalId, bytes);
            }
          : null,
      );
    }
  });

  // QL-05: a paste with a line break asks first; with MultiExec on for that pane, it says how many terminals get it.
  const [pasteAsk, setPasteAsk] = useState<(PasteAsk & { multiExecTerminals: number | null }) | null>(null);
  const pasteAnswer = useRef<((paste: boolean) => void) | null>(null);
  useEffect(() => {
    pasteAskRef.current = (pane, ask) => {
      const routed = multiExec && pickedPanes.some((p) => p.key === pane.key);
      const terminals = routed ? Math.max(1, pickedPanes.filter((p) => p.connected).length) : null;
      pasteAnswer.current?.(false);
      return new Promise<boolean>((resolve) => {
        pasteAnswer.current = resolve;
        setPasteAsk({ ...ask, multiExecTerminals: terminals });
      });
    };
  });
  function answerPaste(paste: boolean) {
    const answer = pasteAnswer.current;
    pasteAnswer.current = null;
    setPasteAsk(null);
    answer?.(paste);
  }
  // Which picked terminals receive keys now (a password prompt or a full-screen program changes it).
  useEffect(() => {
    if (!multiExec || !active) return;
    const timer = window.setInterval(() => {
      api.multiExecStatus().then(setMxStatus, () => undefined);
    }, 1500);
    return () => window.clearInterval(timer);
  }, [multiExec, active]);
  useEffect(() => {
    const unlisten = api.onMultiExecEvent((event) => {
      if (event.event === "outcome") outcomeRef.current(event.outcome);
      else if (event.event === "lineFinished") lineFinishedRef.current(event);
      else if (event.event !== "lineDone") return;
      else if (event.sent)
        setMxNote({ tone: "info", text: `${event.runKey} sent to ${plural(event.terminals, "terminal")}` });
      else
        setMxNote({
          tone: "warn",
          text: `Cancelled: Ctrl+C cleared the line in ${plural(event.terminals, "terminal")}`,
        });
    });
    return () => void unlisten.then((stop) => stop());
  }, []);
  // Leaving the page for good (the app closing) turns it off.
  useEffect(() => () => void api.multiExecStop().catch(() => undefined), []);

  /** Turns MultiExec on; Compare hosts then opens on the lines it records (one way into Compare hosts, UX-03). */
  function typingOn() {
    setMultiExec(true);
    setCompareView("multiExec");
  }

  function startMultiExec() {
    // The tabs picked already, or every tab.
    if (selection.keys.length < 2) setSelection({ keys: tabs.map((t) => t.key), anchor: activeTab });
    setMxNote(null);
    typingOn();
  }

  function stopMultiExec() {
    setMultiExec(false);
    setMxNote(null);
    setMxApproval(null);
  }
  useEffect(() => {
    multiExecOn.current = multiExec;
  }, [multiExec]);

  // The palette turned it on.
  const [mxHandled, setMxHandled] = useState(multiExecRequest);
  if (multiExecRequest !== mxHandled) {
    setMxHandled(multiExecRequest);
    startMultiExec();
  }

  const pickable: PickableTab[] = tabs.map((t) => {
    const pane = findPane(t.layout, t.activePane);
    const sessionId = tabSessionId(t, pane?.sessionId ?? null);
    const session = sessionId ? sessionById.get(sessionId) : undefined;
    return {
      key: t.key,
      folderId: session?.folderId ?? null,
      // UX-12: "By environment" picks by the environment that applies.
      environment: session ? appliedEnvironment(session, vmById).environment : null,
      unsaved: !sessionId,
    };
  });

  // ---- QL-19 saved MultiExec groups ------------------------------------------------------------------

  /** Each tab's saved session (its panes share one), for the groups. */
  const groupTabList: GroupTab[] = tabs.map((t) => ({
    key: t.key,
    sessionId: allPanes(t.layout).find((p) => p.sessionId)?.sessionId ?? null,
  }));
  const groupsBlocked = multiExecReason({
    tabs: Math.max(1, tabs.length),
    on: false,
    readOnly: readOnlyLocked(presentation),
  });

  /** A tab for each of the group's sessions (one already open is used, not opened again), then MultiExec on them. */
  function openGroup(group: MultiExecGroup) {
    const { keys, missing } = groupTabs(group, groupTabList);
    const opened = missing.map((m) => {
      const pane = createPane(
        { kind: "session", sessionId: m.sessionId },
        sessionById.get(m.sessionId)?.name ?? m.name,
      );
      // Connects now, shown or not, so it can take MultiExec's keys.
      pane.start().catch(() => undefined);
      return addTab(pane);
    });
    const picked = [...keys, ...opened];
    setSelection({ keys: picked, anchor: picked[0] ?? null });
    if (picked[0]) setActiveTab(picked[0]);
    setMxNote({
      tone: "info",
      text:
        missing.length > 0
          ? `Group '${group.name}': opened ${plural(missing.length, "tab")}${keys.length > 0 ? `, used ${keys.length} open already` : ""}`
          : `Group '${group.name}': its ${plural(keys.length, "tab")} picked`,
    });
    typingOn();
    if (opened.length > 0) window.setTimeout(() => setVersion((v) => v + 1), 500);
  }

  /** The group's open tabs picked for MultiExec; the ones not open are named. */
  function selectGroup(group: MultiExecGroup) {
    const { keys, missing } = groupTabs(group, groupTabList);
    if (keys.length === 0) {
      toast.info(`None of the sessions of '${group.name}' is open: use Open group`);
      return;
    }
    setSelection({ keys, anchor: keys[0] });
    setMxNote(
      missing.length > 0
        ? { tone: "warn", text: `Group '${group.name}': not open, so left out: ${memberNames(missing)}` }
        : { tone: "info", text: `Group '${group.name}': its ${plural(keys.length, "tab")} picked` },
    );
    typingOn();
  }

  /** "Save picked tabs as a group": MultiExec's tabs, or the Ctrl+clicked ones, or the current one. */
  const saveTabKeys = multiExec
    ? pickedTabs.map((t) => t.key)
    : isMulti(selection)
      ? selection.keys
      : current
        ? [current.key]
        : [];
  const saveTabs = groupTabList.filter((t) => saveTabKeys.includes(t.key));
  const toSave = sessionsOfTabs(saveTabs);
  const saveReason = saveGroupReason({
    tabs: saveTabs,
    readOnly: readOnlyLocked(presentation) ? READ_ONLY_REASON : null,
  });

  function saveAsGroup() {
    setGroupsDialog({
      kind: "new",
      sessionIds: toSave.sessionIds,
      note:
        toSave.quick > 0
          ? `${plural(toSave.quick, "quick connection")} left out: save ${toSave.quick === 1 ? "it" : "them"} as a session to add ${toSave.quick === 1 ? "it" : "them"}.`
          : null,
    });
  }

  // ---- BX-03 Compare ----------------------------------------------------------------------------------

  // The palette opened it.
  const [compareHandled, setCompareHandled] = useState(compareRequest);
  if (compareRequest !== compareHandled) {
    setCompareHandled(compareRequest);
    setSide("compare");
  }
  /** Sessions Ctrl+clicked in the tree are only for Compare hosts, so the first one opens it. */
  function pickInTree(ids: string[]) {
    if (treePicks.length === 0 && ids.length > 0) setSide("compare");
    setTreePicks(ids);
  }
  /** The tabs Compare runs on: MultiExec's, or the picked ones, or the current one. */
  const compareTabs = multiExec
    ? pickedTabs
    : isMulti(selection)
      ? tabs.filter((t) => selection.keys.includes(t.key))
      : current
        ? [current]
        : [];
  const comparePanes = compareTabs.map((t) => findPane(t.layout, t.activePane)).filter((p): p is PaneSession => !!p);
  const compareTerminals = comparePanes.map((p) => p.terminalId).filter((id): id is string => id !== null);
  const unsavedTabs = comparePanes.filter((p) => !p.sessionId).length;

  // ---- QL-18 search all terminals ---------------------------------------------------------------------

  const [searchAll, setSearchAll] = useState(false);
  /** Bumped to put the focus in the search panel's input. */
  const [searchFocus, setSearchFocus] = useState(0);
  /** A match to show once its tab and pane are on screen. */
  const [reveal, setReveal] = useState<{ pane: PaneSession; hit: LineHit } | null>(null);
  const openSearchAll = useCallback(() => {
    setSearchAll(true);
    setSearchFocus((n) => n + 1);
  }, []);
  function closeSearchAll() {
    setSearchAll(false);
    setReveal(null);
    for (const pane of everyPane) pane.endScrollbackSearch();
    currentPane?.focus();
  }
  // The palette opened it.
  const [searchHandled, setSearchHandled] = useState(searchRequest);
  if (searchRequest !== searchHandled) {
    setSearchHandled(searchRequest);
    openSearchAll();
  }
  // R10: a link to one terminal (a notification, the map, the status bar's tunnels): its tab and pane in front.
  const [focusHandled, setFocusHandled] = useState(focusRequest?.n ?? 0);
  if (focusRequest && focusRequest.n !== focusHandled) {
    setFocusHandled(focusRequest.n);
    const tab = tabs.find((t) => allPanes(t.layout).some((p) => p.terminalId === focusRequest.terminalId));
    const pane = tab && allPanes(tab.layout).find((p) => p.terminalId === focusRequest.terminalId);
    if (tab && pane) {
      setActiveTab(tab.key);
      setTabs((prev) => prev.map((t) => (t.key === tab.key ? { ...t, activePane: pane.key } : t)));
      if (focusRequest.tunnels) setTunnelsOpen(true);
    } else {
      toast.info("That terminal has closed");
    }
  }
  // QL-20: a command found in the palette: the command panel shows it.
  const [snippetHandled, setSnippetHandled] = useState(snippetRequest?.n ?? 0);
  const [panelQuery, setPanelQuery] = useState<{ text: string; n: number } | null>(null);
  if (snippetRequest && snippetRequest.n !== snippetHandled) {
    setSnippetHandled(snippetRequest.n);
    setPanelQuery({ text: snippetRequest.command, n: snippetRequest.n });
    // Shown for now; what the panel shows next time stays the user's own choice.
    setSide("commands");
  }
  // Ctrl+Shift+G, caught before a focused terminal sees it (Ctrl+Shift+F searches that terminal alone).
  const hasTabs = tabs.length > 0;
  // Asked for with no terminal open (the palette): nothing to search. Closing the last tab closes it quietly.
  useEffect(() => {
    if (!searchAll || hasTabs) return;
    setSearchAll(false);
    toast.info("No terminal is open: open one, then search");
  }, [searchAll, hasTabs]);
  useEffect(() => {
    if (!active || !hasTabs) return;
    function onKey(e: KeyboardEvent) {
      if (!e.ctrlKey || !e.shiftKey || e.altKey || e.metaKey || e.key.toLowerCase() !== "g") return;
      e.preventDefault();
      e.stopPropagation();
      openSearchAll();
    }
    window.addEventListener("keydown", onKey, { capture: true });
    return () => window.removeEventListener("keydown", onKey, { capture: true });
  }, [active, hasTabs, openSearchAll]);

  /** Every pane of every tab, in tab order, named as their tabs and titles show them. */
  const searchPanes: SearchPane[] = tabs.flatMap((t) => {
    const panes = allPanes(t.layout);
    const shown = findPane(t.layout, t.activePane) ?? panes[0];
    const title = shown ? nameOf(shown) : "Terminal";
    return panes.map((pane) => ({ tabKey: t.key, title, pane, name: nameOf(pane), split: panes.length > 1 }));
  });

  /** A result clicked: its tab and pane shown, then (once they are on screen) the match. */
  function revealMatch(target: SearchPane, hit: LineHit) {
    if (!tabs.some((t) => t.key === target.tabKey && findPane(t.layout, target.pane.key))) {
      toast.info("That terminal has closed: search again");
      return;
    }
    for (const pane of everyPane) if (pane !== target.pane) pane.clearReveal();
    setActiveTab(target.tabKey);
    setTabs((prev) => prev.map((t) => (t.key === target.tabKey ? { ...t, activePane: target.pane.key } : t)));
    setReveal({ pane: target.pane, hit });
  }
  useEffect(() => {
    if (!reveal) return;
    const frame = window.requestAnimationFrame(() => {
      const why = reveal.pane.revealMatch(reveal.hit);
      if (why) toast.info(why);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [reveal]);

  /** BX-08: the command panel pastes into the current pane; with MultiExec on, into a picked one, which sends it on. */
  function sendToCurrent(command: string, enter: boolean) {
    if (multiExec) {
      const picked = new Set(pickedPanes.map((p) => p.key));
      const source =
        currentPane && picked.has(currentPane.key) && currentPane.connected
          ? currentPane
          : pickedPanes.find((p) => p.connected);
      return source ? sendCommand([source], command, { enter }) > 0 : false;
    }
    return currentPane ? sendCommand([currentPane], command, { enter }) > 0 : false;
  }

  // ---- SS-08 file transfer --------------------------------------------------------------------------

  // Every transfer, then each change as it comes, into the transfers store (no state here). A transfer that ends
  // while the drawer is hidden says so.
  const endedRef = useRef<(transfer: TransferInfo) => void>(() => undefined);
  useEffect(() => {
    let gone = false;
    api.filesTransfers().then(
      (list) => {
        if (!gone) transferStore.load(list);
      },
      () => undefined,
    );
    const unlisten = api.onTransfer((changed) => {
      if (transferStore.apply(changed)) endedRef.current(changed);
    });
    return () => {
      gone = true;
      void unlisten.then((stop) => stop());
    };
  }, []);
  useEffect(() => {
    endedRef.current = (t) => {
      if (filesShown && active) return;
      const show = { label: "Show", onClick: () => setSide("files") };
      if (t.state === "failed") {
        const what = t.direction === "upload" ? "Upload" : "Download";
        toast.error(`${what} of ${t.name} failed: ${t.message ?? ""}`, { action: show });
      } else if (t.state === "done" && t.direction === "download") {
        toast.success(`Downloaded ${t.name}`, {
          action: { label: "Open folder", onClick: () => void api.filesOpenFolder(t.id).catch(() => undefined) },
        });
      } else if (t.state === "done") {
        toast.success(`Uploaded ${t.name} to ${t.remotePath}`);
      }
    };
  });

  /** The pane under a point of the window (CSS pixels), if any. */
  function paneAt(x: number, y: number) {
    const el = document.elementFromPoint(x, y)?.closest<HTMLElement>("[data-pane-key]");
    return el ? everyPane.find((p) => p.key === el.dataset.paneKey) : undefined;
  }

  /** The folder a terminal's uploads go to: its shell's, or the home folder when the shell does not say. */
  async function folderOf(pane: PaneSession, terminalId: string) {
    return pane.getSnapshot().folder?.path ?? (await api.filesList(terminalId, null)).path;
  }

  function handleStart(pane: PaneSession, staged: StagedFiles, start: UploadStart) {
    if (start.status === "conflicts") setConflict({ pane, staged, folder: start.folder, existing: start.existing });
    else if (start.status === "submitted") onSubmitted(start.outcome, () => undefined);
    else toast.info("Every file is in the folder already, so nothing was uploaded.");
  }

  /** Uploads staged files through a pane: into `folder`, or the terminal's own folder. */
  async function uploadStaged(pane: PaneSession, staged: StagedFiles, folder: string | null) {
    const id = pane.terminalId;
    const why = uploadReason({ open: true, connected: pane.connected, readOnly: readOnlyLocked() });
    if (!id || why) {
      void api.filesUnstage(staged.id).catch(() => undefined);
      toast.info(`Not uploaded: ${why ?? "this terminal has not connected yet"}`);
      return;
    }
    try {
      const into = folder ?? (await folderOf(pane, id));
      handleStart(pane, staged, await api.filesUpload(id, staged.id, into, "ask"));
    } catch (err) {
      void api.filesUnstage(staged.id).catch(() => undefined);
      toast.error(`Upload failed: ${errorMessage(err)}`);
    }
  }

  /** The upload buttons: files from a dialog the shell opens. */
  async function pickAndUpload(pane: PaneSession | undefined, folder: string | null) {
    if (!pane) return;
    try {
      const staged = await api.filesPickUpload();
      if (staged) await uploadStaged(pane, staged, folder);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function download(pane: PaneSession, paths: string[], to: "downloads" | "choose") {
    const id = pane.terminalId;
    if (!id) return;
    try {
      const queued = await api.filesDownload(id, paths, to);
      if (queued && !filesShown) {
        const what = queued.length === 1 ? queued[0].name : plural(queued.length, "file");
        toast.info(`Downloading ${what}…`, { action: { label: "Show", onClick: () => setSide("files") } });
      }
    } catch (err) {
      toast.error(`Download failed: ${errorMessage(err)}`);
    }
  }

  async function retryTransfer(t: TransferInfo) {
    try {
      const retried = await api.filesRetry(t.id);
      if (retried.kind === "upload" && retried.start.status === "submitted") {
        onSubmitted(retried.start.outcome, () => undefined);
      }
    } catch (err) {
      toast.error(`Retry failed: ${errorMessage(err)}`);
    }
  }

  // Files dropped on the window: the shell staged them and says where they fell.
  const dropRef = useRef<(dropped: DroppedFiles) => void>(() => undefined);
  useEffect(() => {
    const unlisten = api.onFilesDropped((dropped) => dropRef.current(dropped));
    return () => void unlisten.then((stop) => stop());
  }, []);
  useEffect(() => {
    dropRef.current = (dropped) => {
      if (dropped.error) {
        if (active) toast.error(`Not uploaded: ${dropped.error}`);
        return;
      }
      // VM-23: the page on screen owns a drop (an ISO dropped on the Virtual machines page is that page's).
      if (!dropped.staged || !active) return;
      const pane = paneAt(dropped.x, dropped.y);
      if (!pane) {
        void api.filesUnstage(dropped.staged.id).catch(() => undefined);
        toast.info("Drop files on a terminal to upload them into its folder.");
        return;
      }
      void uploadStaged(pane, dropped.staged, null);
    };
  });

  // While files are dragged over the window, the pane under them says where they would go.
  const dropLabelRef = useRef<(key: string | undefined) => string>(() => "");
  useEffect(() => {
    dropLabelRef.current = (key) => {
      const pane = everyPane.find((p) => p.key === key);
      if (!pane?.connected) return "Not connected: nothing can be uploaded here";
      return `Drop to upload into ${pane.getSnapshot().folder?.path ?? "the home folder"}`;
    };
  });
  useEffect(() => {
    let marked: HTMLElement | null = null;
    const clear = () => {
      marked?.removeAttribute("data-drop");
      marked = null;
    };
    const unlisten = getCurrentWebview().onDragDropEvent((event) => {
      const p = event.payload;
      if (p.type !== "enter" && p.type !== "over") {
        clear();
        return;
      }
      const scale = window.devicePixelRatio || 1;
      const under = document.elementFromPoint(p.position.x / scale, p.position.y / scale);
      const el = under?.closest<HTMLElement>("[data-pane-key]") ?? null;
      if (el === marked) return;
      clear();
      if (el) {
        el.setAttribute("data-drop", dropLabelRef.current(el.dataset.paneKey));
        marked = el;
      }
    });
    return () => {
      clear();
      void unlisten.then((stop) => stop());
    };
  }, []);

  // Right-click on a file name: offered for download when it is a file there; otherwise the usual paste.
  useEffect(() => {
    fileWordRef.current = (pane, word, x, y) => {
      const id = pane.terminalId;
      if (!id) {
        void pane.pasteFromClipboard();
        return;
      }
      api.filesLookUp(id, word).then(
        (found) => {
          if (found?.entry.kind === "file") {
            setFileMenu({ pane, path: found.path, name: found.entry.name, size: found.entry.size, x, y });
          } else void pane.pasteFromClipboard();
        },
        () => void pane.pasteFromClipboard(),
      );
    };
  });

  const drawer = (
    <FilesDrawer
      terminalId={currentPane?.terminalId ?? null}
      snapshot={currentSnapshot}
      name={currentPane ? nameOf(currentPane) : "No terminal"}
      multiExecTerminals={multiExec ? pickedPanes.length : 0}
      onUpload={(folder) => void pickAndUpload(currentPane, folder)}
      onDownload={(paths, to) => {
        if (currentPane) void download(currentPane, paths, to);
      }}
      onRetry={(t) => void retryTransfer(t)}
    />
  );

  const currentSession = currentPane?.sessionId ? sessionById.get(currentPane.sessionId) : undefined;
  const loginSecretId =
    currentSession?.auth.method === "password"
      ? currentSession.auth.passwordId
      : currentSession?.auth.method === "key"
        ? currentSession.auth.passphraseId
        : null;
  const currentName = currentPane ? nameOf(currentPane) : "the terminal";
  // QL-06: the "⋯" menu's submenu, and its confirm outside the menu.
  const typeSecret = useTypeSecret({ pane: currentPane, loginSecretId, terminalName: currentName, onOpenVault });

  const multi = isMulti(selection);
  const selectedTabs = tabs.filter((t) => selection.keys.includes(t.key));
  /** SS-11: the picked tabs' terminals, for the slim bar's Output menu. */
  const pickedOutput: NamedPane[] = selectedTabs
    .flatMap((t) => allPanes(t.layout))
    .map((pane) => ({ pane, title: nameOf(pane) }));
  /** SS-11: the current terminal, for the "⋯" menu's Output. */
  const currentOutput: NamedPane[] = currentPane ? [{ pane: currentPane, title: nameOf(currentPane) }] : [];

  async function run(what: string, action: () => Promise<unknown>) {
    try {
      await action();
    } catch (err) {
      toast.error(`${what} failed: ${errorMessage(err)}`);
    }
  }

  const openSessions = useMemo(() => {
    const ids = new Set<string>();
    for (const pane of tabs.flatMap((t) => allPanes(t.layout))) {
      if (pane.sessionId) ids.add(pane.sessionId);
    }
    return ids;
  }, [tabs]);

  /** The terminals (and Search all terminals under them), or the empty state. */
  const stack = current ? (
    <ResizablePanelGroup
      orientation="vertical"
      className="min-h-0 flex-1"
      id={`terminal-stack-${searchAll ? "search" : "plain"}`}
    >
      <ResizablePanel id="terminal-panes" defaultSize={searchAll ? "55%" : "100%"} minSize="20%">
        {multiExec && tile && pickedTabs.length > 1 ? (
          <TileView
            tabs={pickedTabs}
            activeTab={activeTab}
            theme={theme}
            pageActive={active}
            nameOf={nameOf}
            status={mxStatus}
            onActivate={setActiveTab}
            onFocusPane={(tabKey, key) =>
              setTabs((prev) => prev.map((t) => (t.key === tabKey ? { ...t, activePane: key } : t)))
            }
            onClosePane={closePane}
            onOpenVault={onOpenVault}
          />
        ) : (
          <div className="h-full min-h-0 overflow-hidden rounded-lg border" key={current.key}>
            <LayoutView
              layout={current.layout}
              tab={current}
              theme={theme}
              pageActive={active}
              nameOf={nameOf}
              onFocusPane={(key) =>
                setTabs((prev) => prev.map((t) => (t.key === current.key ? { ...t, activePane: key } : t)))
              }
              onClosePane={(key) => closePane(current.key, key)}
              onOpenVault={onOpenVault}
            />
          </div>
        )}
      </ResizablePanel>
      {searchAll && (
        <>
          <ResizableHandle withHandle className="my-1" />
          <ResizablePanel id="terminal-search" defaultSize="45%" minSize="15%">
            <ScrollbackSearchPanel
              panes={searchPanes}
              focus={searchFocus}
              onReveal={revealMatch}
              onClose={closeSearchAll}
            />
          </ResizablePanel>
        </>
      )}
    </ResizablePanelGroup>
  ) : (
    <EmptyState
      icon={SquareTerminalIcon}
      title="No terminal open"
      description="Double-click a session in the tree, or connect to any host."
      action={
        <Button onClick={() => setNewOpen(true)}>
          <PlusIcon data-icon="inline-start" />
          New terminal
        </Button>
      }
      className="min-h-0 flex-1"
    />
  );

  /** UX-03: Files here, Compare hosts or Commands, one at a time. */
  const sidePanel =
    side === "files" ? (
      drawer
    ) : side === "compare" ? (
      <ComparePanel
        active={active}
        vault={vault}
        view={compareView}
        onViewChange={setCompareView}
        multiExecOn={multiExec}
        terminalIds={compareTerminals}
        sessionIds={treePicks}
        unsavedTabs={unsavedTabs}
        savedSessions={sessions.length}
        onClearTree={() => setTreePicks([])}
        onSubmit={onSubmitted}
        onOpenVault={onOpenVault}
      />
    ) : side === "commands" ? (
      <CommandPanel
        active={active}
        targetName={
          multiExec ? `${plural(pickedPanes.length, "terminal")} (all tabs)` : currentPane ? currentName : null
        }
        onSend={sendToCurrent}
        query={panelQuery}
      />
    ) : null;

  const treeVisible = treeShownFor({ tabs: tabs.length, shownEmpty: treeEmpty, shownWithTabs: treeWithTabs });
  const readOnly = readOnlyLocked(presentation);
  const live = liveTunnels(currentSnapshot.tunnels);
  const tunnelsBlocked = tunnelsReason(currentPane, currentSnapshot);
  const isSplit = current?.layout.kind === "split";

  /** An action that moves the focus (a search box) runs once its menu has closed, which holds the focus till then. */
  const afterMenu = useRef<(() => void) | null>(null);
  /** A toolbar menu closed: the focus goes back to the terminal, not the button, unless the action moved it. */
  function backToTerminal(e: Event) {
    e.preventDefault();
    const then = afterMenu.current;
    afterMenu.current = null;
    if (then) {
      then();
      return;
    }
    const pane = currentPane;
    window.requestAnimationFrame(() => {
      if (!document.activeElement || document.activeElement === document.body) pane?.focus();
    });
  }

  /** UX-03: everything the toolbar doesn't show, each in one place. */
  const moreMenu = (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button type="button" variant="outline" size="icon" aria-label="More actions on Terminal">
              <MoreHorizontalIcon />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>More actions</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end" className="w-72" onCloseAutoFocus={backToTerminal}>
        {current && currentPane && (
          <>
            <DropdownMenuLabel className="truncate font-normal text-muted-foreground">{currentName}</DropdownMenuLabel>
            <DropdownMenuItem onSelect={() => (afterMenu.current = () => currentPane.openSearch())}>
              <SearchIcon />
              Search this terminal
              <DropdownMenuShortcut>Ctrl+Shift+F</DropdownMenuShortcut>
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => (afterMenu.current = openSearchAll)}>
              <TextSearchIcon />
              Search all terminals
              <DropdownMenuShortcut>Ctrl+Shift+G</DropdownMenuShortcut>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            {typeSecret.menu}
            <DropdownMenuItem disabled={tunnelsBlocked !== null} onSelect={() => setTunnelsOpen(true)}>
              <CableIcon />
              <span>
                {live > 0 ? `Tunnels (${live} open)…` : "Tunnels…"}
                <ReasonLine reason={tunnelsBlocked} />
              </span>
            </DropdownMenuItem>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>
                <FileTextIcon />
                {OUTPUT_LABELS.menu}
              </DropdownMenuSubTrigger>
              <DropdownMenuSubContent className="w-60">
                <OutputItems panes={currentOutput} current={currentPane} run={run} titleOf={nameOf} />
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSeparator />
            <DropdownMenuCheckboxItem
              checked={current.notify && notifyOn}
              disabled={!notifyOn}
              onCheckedChange={(on) => setTabNotify(current.key, on)}
            >
              <span>
                Notifications from this tab
                <ReasonLine reason={notifyOn ? null : "Turned off in Settings › Terminal"} />
              </span>
            </DropdownMenuCheckboxItem>
            <DropdownMenuItem onSelect={() => currentPane.reconnect()}>
              <RefreshCwIcon />
              Reconnect
            </DropdownMenuItem>
            {isSplit && (
              <DropdownMenuItem onSelect={() => closePane(current.key, current.activePane)}>
                <XIcon />
                Close this pane
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
          </>
        )}
        <MultiExecGroupsSubmenu
          groups={groups}
          tabs={groupTabList}
          multiExecBlocked={groupsBlocked}
          saveReason={saveReason}
          saveCount={toSave.sessionIds.length}
          onOpenGroup={openGroup}
          onSelectGroup={selectGroup}
          onSave={saveAsGroup}
          onManage={() => setGroupsDialog({ kind: "manage" })}
          onShow={loadGroups}
        />
      </DropdownMenuContent>
    </DropdownMenu>
  );

  /** UX-03: about five controls: Split, Type in all tabs, the side panel's switch, and "⋯". */
  const toolbar = (
    <div className="ml-auto flex items-center gap-1">
      {readOnly && (
        <span
          className="mr-1 inline-flex shrink-0 items-center gap-1 text-xs font-medium text-presenting"
          title="Read-only while presenting: Type in all tabs, Compare hosts, uploads, tunnels and saving sessions are blocked. Typing into one terminal still works."
        >
          <LockKeyholeIcon className="size-3.5" />
          Read-only
        </span>
      )}
      <SplitMenu reason={current ? splitBlocked : "Open a terminal first"} onSplit={split} onClosed={backToTerminal} />
      <IconButton
        size="icon"
        label={
          multiExec
            ? "Type in all tabs is on: typing goes to every picked tab (click to turn off)"
            : multi
              ? `Type in all tabs: send your typing to the ${selectedTabs.length} picked tabs`
              : "Type in all tabs: send your typing to several tabs at once"
        }
        onClick={() => (multiExec ? stopMultiExec() : startMultiExec())}
        className={cn(multiExec && "bg-primary/15 text-primary")}
        disabledReason={multiExecReason({ tabs: tabs.length, on: multiExec, readOnly })}
        pressed={multiExec}
      >
        <RadioTowerIcon />
      </IconButton>
      <Separator orientation="vertical" className="mx-1 data-[orientation=vertical]:h-5" />
      <div role="group" aria-label="Side panel" className="flex items-center gap-0.5">
        {SIDE_PANELS.map(({ id, label }) => {
          const Icon = SIDE_ICONS[id];
          return (
            <Tooltip key={id}>
              <TooltipTrigger asChild>
                <Toggle
                  aria-label={label}
                  className="w-8 px-0"
                  pressed={side === id}
                  onPressedChange={() => chooseSide(toggleSidePanel(side, id))}
                >
                  <Icon />
                </Toggle>
              </TooltipTrigger>
              <TooltipContent>{side === id ? `Hide ${label}` : label}</TooltipContent>
            </Tooltip>
          );
        })}
      </div>
      <Separator orientation="vertical" className="mx-1 data-[orientation=vertical]:h-5" />
      {moreMenu}
    </div>
  );

  /** UX-03: the tabs on a row of their own, never squeezed: past the width they scroll. */
  const tabRow = (
    <div className="flex items-end gap-1 border-b">
      <IconButton label={treeVisible ? "Hide the sessions" : "Show the sessions"} onClick={toggleTree} className="mb-1">
        {treeVisible ? <PanelLeftCloseIcon /> : <PanelLeftOpenIcon />}
      </IconButton>
      <div
        className="flex min-w-0 flex-1 items-end gap-1 overflow-x-auto [scrollbar-width:thin]"
        role="tablist"
        aria-label="Terminals"
      >
        {tabs.map((tab) => {
          const pane = findPane(tab.layout, tab.activePane);
          const target = mxStatus?.targets.find((t) => t.terminalId === pane?.terminalId);
          return (
            <TabButton
              key={tab.key}
              tab={tab}
              sessions={sessionById}
              vms={vmById}
              pane={pane}
              current={tab.key === activeTab}
              picked={(multi || multiExec) && selection.keys.includes(tab.key)}
              multiExec={
                multiExec
                  ? selection.keys.includes(tab.key)
                    ? (target?.reason ?? target?.note ?? "receives")
                    : "off"
                  : null
              }
              multiExecOk={target ? target.receives : true}
              attention={attention.includes(tab.key)}
              onSelect={(modifiers) => pickTab(tab.key, modifiers)}
              onClose={() => closeTab(tab)}
            />
          );
        })}
        <IconButton label="New terminal" onClick={() => setNewOpen(true)} className="mb-1 shrink-0">
          <PlusIcon />
        </IconButton>
      </div>
    </div>
  );

  /** UX-02: one slim bar for Type in all tabs and the picked tabs. */
  const bar = (multiExec || multi) && (
    <MultiExecBar
      on={multiExec}
      tabs={pickable}
      picked={multiExec ? pickedTabs.length : selectedTabs.length}
      terminals={pickedOutput.length}
      status={mxStatus}
      note={mxNote}
      folders={folders}
      tile={tile}
      onTile={setTile}
      onPick={(keys) => setSelection({ keys, anchor: activeTab })}
      onClose={multiExec ? stopMultiExec : () => setSelection({ keys: [], anchor: activeTab })}
      output={
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button size="sm" variant="ghost">
              <FileTextIcon data-icon="inline-start" />
              {OUTPUT_LABELS.menu}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-60">
            <DropdownMenuLabel className="font-normal text-muted-foreground">
              {plural(selectedTabs.length, "picked tab")}, {plural(pickedOutput.length, "terminal")}
            </DropdownMenuLabel>
            <OutputItems panes={pickedOutput} current={undefined} run={run} titleOf={nameOf} />
          </DropdownMenuContent>
        </DropdownMenu>
      }
    />
  );

  const workspace = (
    <div className="flex h-full min-h-0 flex-col gap-2">
      {tabRow}
      {bar}
      {stack}
    </div>
  );

  const sideSize = side ? SIDE_PANEL_SIZE[side] : 0;
  const treeSize = 20;
  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <PageHeader page="terminal">{toolbar}</PageHeader>
      {/* UX-09: shown once, when picking several tabs first makes sense. */}
      {tabs.length >= 2 && (
        <Tip id="terminal.pickTabs">
          Ctrl+click tabs to pick several; Type in all tabs and Compare hosts then use them.
        </Tip>
      )}
      <div className="min-h-0 flex-1">
        {treeVisible || side ? (
          <ResizablePanelGroup
            orientation="horizontal"
            id={`terminal-workspace-${treeVisible ? "tree" : "no-tree"}-${side ?? "no-side"}`}
          >
            {treeVisible && (
              <>
                <ResizablePanel id="terminal-tree" defaultSize={`${treeSize}%`} minSize="12%" maxSize="40%">
                  <div className="h-full pr-3">
                    <SessionTree
                      active={active}
                      version={version}
                      openSessions={openSessions}
                      onOpen={openSession}
                      picks={treePicks}
                      onPicksChange={pickInTree}
                      onHostDetails={(s) => setHostDetails({ id: s.id, name: s.name })}
                      vms={vmById}
                    />
                  </div>
                </ResizablePanel>
                <ResizableHandle />
              </>
            )}
            <ResizablePanel
              id="terminal-main"
              defaultSize={`${100 - (treeVisible ? treeSize : 0) - sideSize}%`}
              minSize="30%"
            >
              <div className={cn("h-full", treeVisible && "pl-3", side && "pr-3")}>{workspace}</div>
            </ResizablePanel>
            {side && (
              <>
                <ResizableHandle />
                <ResizablePanel id="terminal-side" defaultSize={`${sideSize}%`} minSize="16%" maxSize="60%">
                  <div className="h-full min-h-0 pl-3">{sidePanel}</div>
                </ResizablePanel>
              </>
            )}
          </ResizablePanelGroup>
        ) : (
          workspace
        )}
      </div>
      <NewTerminalDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        onConnect={openQuick}
        onOpenSession={(s) => openSession(s)}
      />
      <HostDetailsSheet session={hostDetails} thresholds={thresholds} onClose={() => setHostDetails(null)} />
      <TunnelsDialog
        open={tunnelsOpen}
        onOpenChange={setTunnelsOpen}
        pane={currentPane}
        snapshot={currentSnapshot}
        name={currentName}
        onApproval={(pane, forwardId, request) => {
          // The approval dialog takes over; the list opens again from the "⋯" menu.
          setTunnelsOpen(false);
          askTunnel(pane, forwardId, request);
        }}
      />
      {typeSecret.confirm}
      {groupsDialog && (
        <MultiExecGroupsDialog
          groups={groups}
          sessions={sessions}
          start={groupsDialog}
          onChanged={loadGroups}
          onClose={() => setGroupsDialog(null)}
        />
      )}
      {conflict && (
        <UploadConflictDialog
          folder={conflict.folder}
          existing={conflict.existing}
          total={conflict.staged.files.length}
          terminal={nameOf(conflict.pane)}
          onAnswer={async (answer) => {
            const { pane, staged, folder } = conflict;
            const id = pane.terminalId;
            if (!id) throw new Error("The terminal has closed.");
            const start = await api.filesUpload(id, staged.id, folder, answer);
            setConflict(null);
            handleStart(pane, staged, start);
          }}
          onCancel={() => {
            void api.filesUnstage(conflict.staged.id).catch(() => undefined);
            setConflict(null);
          }}
        />
      )}
      {fileMenu && (
        <DropdownMenu open onOpenChange={(open) => !open && setFileMenu(null)}>
          <DropdownMenuTrigger asChild>
            <span
              aria-hidden
              className="pointer-events-none fixed size-0"
              style={{ left: fileMenu.x, top: fileMenu.y }}
            />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-64">
            <DropdownMenuLabel className="truncate" title={fileMenu.path}>
              {fileMenu.name} · {formatSize(fileMenu.size)}
            </DropdownMenuLabel>
            <DropdownMenuItem onSelect={() => void download(fileMenu.pane, [fileMenu.path], "downloads")}>
              Download to Downloads
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => void download(fileMenu.pane, [fileMenu.path], "choose")}>
              Download to…
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => void fileMenu.pane.pasteFromClipboard()}>Paste</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      {pasteAsk && (
        <PasteConfirmDialog
          preview={pasteAsk.preview}
          bracketed={pasteAsk.bracketed}
          multiExecTerminals={pasteAsk.multiExecTerminals}
          onAnswer={answerPaste}
        />
      )}
      {tunnelApprovals.length > 0 && !mxApproval && (
        <ApprovalDialog
          key={tunnelApprovals[0].request.id}
          request={tunnelApprovals[0].request}
          vault={vault}
          approve={(answers) => tunnelApprovals[0].pane.approveTunnel(tunnelApprovals[0].forwardId, answers)}
          cancel={() => tunnelApprovals[0].pane.declineTunnel(tunnelApprovals[0].forwardId)}
          onOpenVault={() => {
            setTunnelApprovals((queue) => queue.slice(1));
            onOpenVault();
          }}
          onClose={() => setTunnelApprovals((queue) => queue.slice(1))}
        />
      )}
      {mxApproval && (
        <ApprovalDialog
          key={mxApproval.lineId}
          request={mxApproval.request}
          vault={vault}
          approve={(answers) => api.multiExecApprove(mxApproval.lineId, answers)}
          cancel={() => api.multiExecCancel(mxApproval.lineId)}
          onOpenVault={() => {
            setMxApproval(null);
            onOpenVault();
          }}
          onClose={() => {
            setMxApproval(null);
            // What the line's end said (sent, or cancelled) stays.
            setMxNote((n) => (n?.tone === "wait" ? null : n));
            currentPane?.focus();
          }}
        />
      )}
    </div>
  );
}

function IconButton({
  label,
  onClick,
  className,
  disabledReason,
  pressed,
  size = "icon-sm",
  children,
}: {
  label: string;
  onClick: () => void;
  className?: string;
  /** QL-08: why it is disabled; null or undefined when it is not. */
  disabledReason?: string | null;
  /** A switch that is on. */
  pressed?: boolean;
  /** "icon" in the page header's toolbar, "icon-sm" on the tab row. */
  size?: "icon" | "icon-sm";
  children: React.ReactNode;
}) {
  if (disabledReason) {
    return (
      <WhyDisabled reason={`${label}: ${disabledReason}`} className={className}>
        <Button variant="ghost" size={size} aria-label={label} disabled>
          {children}
        </Button>
      </WhyDisabled>
    );
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size={size}
          aria-label={label}
          aria-pressed={pressed}
          onClick={onClick}
          className={className}
        >
          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}

/** The toolbar's Split: right or down, for the current tab. */
function SplitMenu({
  reason,
  onSplit,
  onClosed,
}: {
  /** QL-08: why it can't split now, or null. */
  reason: string | null;
  onSplit: (orientation: "horizontal" | "vertical") => void;
  onClosed: (e: Event) => void;
}) {
  if (reason) {
    return (
      <WhyDisabled reason={`Split: ${reason}`}>
        <Button variant="ghost" size="icon" aria-label="Split" disabled>
          <Columns2Icon />
        </Button>
      </WhyDisabled>
    );
  }
  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label="Split">
              <Columns2Icon />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>Split this terminal</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end" className="w-44" onCloseAutoFocus={onClosed}>
        <DropdownMenuItem onSelect={() => onSplit("horizontal")}>
          <Columns2Icon />
          Split right
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onSplit("vertical")}>
          <Rows2Icon />
          Split down
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

const NO_SNAPSHOT: PaneSnapshot = {
  status: { state: "opening" },
  statusAt: 0,
  question: null,
  changedKey: null,
  facts: null,
  sessionId: null,
  logPath: null,
  logError: null,
  searching: false,
  searchResults: null,
  folder: null,
  tunnels: null,
};
const noSubscribe = () => () => undefined;

function usePane(pane: PaneSession | undefined): PaneSnapshot {
  return useSyncExternalStore(pane?.subscribe ?? noSubscribe, pane?.getSnapshot ?? (() => NO_SNAPSHOT));
}

function StatusDot({ snapshot }: { snapshot: PaneSnapshot }) {
  const { status, question } = snapshot;
  if (question) return <ShieldAlertIcon className="size-3.5 text-tier-high" aria-label="Needs an answer" />;
  switch (status.state) {
    case "opening":
    case "connecting":
    case "reconnecting":
      return <LoaderCircleIcon className="size-3.5 animate-spin text-muted-foreground" aria-label="Connecting" />;
    case "connected":
      return <span className="size-2 rounded-full bg-success" aria-label="Connected" />;
    case "disconnected":
      return <span className="size-2 rounded-full bg-destructive" aria-label="Not connected" />;
    default:
      return <span className="size-2 rounded-full bg-muted-foreground/50" aria-label="Ended" />;
  }
}

function TabButton({
  tab,
  sessions,
  vms,
  pane,
  current,
  picked,
  multiExec,
  multiExecOk,
  attention,
  onSelect,
  onClose,
}: {
  tab: Tab;
  sessions: Map<string, SessionRecord>;
  /** UX-12: a Prod VM the session reaches makes the tab Prod. */
  vms: ReadonlyMap<string, EnvironmentOfVm>;
  pane: PaneSession | undefined;
  current: boolean;
  picked: boolean;
  /**
   * SS-10, with MultiExec on: "receives", "off" (not picked), why a picked tab gets no keys now, or how it gets them
   * (straight through). null: MultiExec is off.
   */
  multiExec: string | null;
  /** SS-10: the picked tab gets what is typed now. */
  multiExecOk: boolean;
  /** QL-07: a long command finished here while the tab was in the background. */
  attention: boolean;
  onSelect: (modifiers: { ctrl: boolean; shift: boolean }) => void;
  onClose: () => void;
}) {
  const snapshot = usePane(pane);
  const sessionId = tabSessionId(tab, snapshot.sessionId);
  const session = sessionId ? sessions.get(sessionId) : undefined;
  const applied: AppliedEnvironment | null = session ? appliedEnvironment(session, vms) : null;
  const env = applied?.environment ?? "none";
  // CT-01: a container's shell is named after the container.
  const name = pane?.fixedTitle ? pane.label : (session?.name ?? pane?.label ?? "Terminal");
  const seen = factsTitle(snapshot.facts);
  // SS-07: the jump hosts on the way, as the core connected through them.
  const via = snapshot.facts?.via ?? [];
  const count = allPanes(tab.layout).length;
  const tooltip = [
    session
      ? `${pane?.fixedTitle ? `${name}: a shell in a container on ` : ""}${session.name} (${sessionAddress(session)})`
      : name,
    applied && env !== "none" && `Environment: ${environmentText(applied)}`,
    seen && `Host: ${seen}`,
    via.length > 0 && `Through ${routeText(via)}`,
    session ? null : "Not saved as a session",
    snapshot.logPath && `Logging to ${snapshot.logPath}`,
    attention && "A long command finished, or an alert rule matched, here",
    !tab.notify && "No notifications from this tab",
    multiExec === "receives" && "Type in all tabs: what you type goes here",
    multiExec === "off" && "Type in all tabs: not picked, so typing elsewhere does not reach it (Ctrl+click to add it)",
    multiExec &&
      multiExec !== "receives" &&
      multiExec !== "off" &&
      (multiExecOk ? `Type in all tabs: ${multiExec}` : `Type in all tabs: picked, but gets no keys now: ${multiExec}`),
    "Ctrl+click or Shift+click to pick several tabs",
  ]
    .filter(Boolean)
    .join("\n");
  return (
    <div
      role="tab"
      aria-selected={current}
      tabIndex={0}
      onClick={(e) => onSelect({ ctrl: e.ctrlKey || e.metaKey, shift: e.shiftKey })}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onSelect({ ctrl: false, shift: false })}
      onAuxClick={(e) => e.button === 1 && onClose()}
      title={tooltip}
      className={cn(
        "group flex h-10 max-w-64 min-w-40 shrink-0 cursor-pointer items-center gap-2 rounded-t-md border border-b-0 border-t-[3px] px-2.5 text-sm select-none",
        session?.color ? COLOR_TAB[session.color] : ENV_TAB[env],
        env === "prod" && "bg-env-prod/10",
        current ? "bg-background font-medium" : "text-muted-foreground hover:bg-muted/60",
        picked && "bg-primary/10 ring-2 ring-primary/50 ring-inset",
        multiExec === "off" && "border-dashed opacity-60",
      )}
    >
      {multiExec && multiExec !== "off" ? (
        <RadioTowerIcon
          className={cn("size-3.5 shrink-0", multiExecOk ? "text-primary" : "text-tier-medium")}
          aria-label={multiExec === "receives" ? "Type in all tabs: receives typing" : `Type in all tabs: ${multiExec}`}
        />
      ) : (
        <StatusDot snapshot={snapshot} />
      )}
      {session?.color && <ColorDot color={session.color} />}
      <span className="grid min-w-0 flex-1 leading-tight">
        <span className="truncate">{name}</span>
        {(env !== "none" || (seen && seen !== name) || via.length > 0) && (
          <span className="truncate text-[11px] font-normal text-muted-foreground">
            {env !== "none" && (
              <span
                className={cn(
                  "font-semibold uppercase",
                  ENV_TEXT[env],
                  applied?.from && "underline decoration-dotted underline-offset-2",
                )}
              >
                {env}{" "}
              </span>
            )}
            {seen !== name && seen}
            {via.length > 0 && <span className="text-muted-foreground/80"> {viaText(via)}</span>}
          </span>
        )}
      </span>
      {snapshot.logPath && <FileTextIcon className="size-3.5 shrink-0 text-tier-medium" aria-label="Logging" />}
      {attention && (
        <BellRingIcon className="size-3.5 shrink-0 text-primary" aria-label="A long command finished or an alert" />
      )}
      {!tab.notify && <BellOffIcon className="size-3.5 shrink-0 text-muted-foreground" aria-label="No notifications" />}
      {count > 1 && <span className="text-xs text-muted-foreground">{count}</span>}
      <button
        type="button"
        aria-label="Close tab"
        className="-mr-1 rounded p-0.5 opacity-60 hover:bg-muted hover:opacity-100"
        onClick={(e) => {
          e.stopPropagation();
          onClose();
        }}
      >
        <XIcon className="size-3.5" />
      </button>
    </div>
  );
}

/**
 * SS-11, UX-03: copy, save, print and log, with one set of labels (OUTPUT_LABELS) wherever they show: the "⋯" menu's
 * Output for the current terminal (`current`: logging too), and the slim bar's Output for the picked tabs.
 */
function OutputItems({
  panes,
  current,
  run,
  titleOf,
}: {
  panes: NamedPane[];
  /** The current terminal, for its log; none for the picked tabs. */
  current: PaneSession | undefined;
  run: (what: string, action: () => Promise<unknown>) => Promise<void>;
  titleOf: (pane: PaneSession) => string;
}) {
  const snapshot = usePane(current);
  const several = panes.length > 1;
  const noPanes = panes.length === 0 ? "No terminal is open" : null;
  return (
    <>
      <DropdownMenuItem disabled={noPanes !== null} onSelect={() => void run("Copying", () => copyOutput(panes))}>
        <span>
          {OUTPUT_LABELS.copy}
          <ReasonLine reason={noPanes} />
        </span>
      </DropdownMenuItem>
      <DropdownMenuItem
        disabled={noPanes !== null}
        onSelect={() =>
          void run("Saving", async () => {
            const saved = await saveOutput(panes, "oneFile");
            if (saved) toast.success(`Saved ${plural(saved.terminals, "terminal")} to ${saved.files[0]}`);
          })
        }
      >
        {OUTPUT_LABELS.save}
      </DropdownMenuItem>
      {several && (
        <DropdownMenuItem
          onSelect={() =>
            void run("Saving", async () => {
              const saved = await saveOutput(panes, "filePerTerminal");
              if (saved) toast.success(`Saved ${plural(saved.files.length, "file")}`);
            })
          }
        >
          {OUTPUT_LABELS.saveEach}
        </DropdownMenuItem>
      )}
      <DropdownMenuItem disabled={noPanes !== null} onSelect={() => void run("Printing", () => printOutput(panes))}>
        {OUTPUT_LABELS.print}
      </DropdownMenuItem>
      {current && (
        <>
          <DropdownMenuSeparator />
          {snapshot.logPath ? (
            <DropdownMenuItem onSelect={() => void run("Stopping the log", () => current.stopLog())}>
              {OUTPUT_LABELS.stopLog}
            </DropdownMenuItem>
          ) : (
            <DropdownMenuItem
              disabled={!current.terminalId}
              onSelect={() =>
                void run("Logging", async () => {
                  const path = await current.startLog(titleOf(current));
                  if (path) toast.success(`Logging this terminal to ${path}`);
                })
              }
            >
              <span>
                {OUTPUT_LABELS.log}
                <ReasonLine reason={connectedReason({ open: true, connected: Boolean(current.terminalId) })} />
              </span>
            </DropdownMenuItem>
          )}
        </>
      )}
    </>
  );
}

interface LayoutProps {
  layout: Layout;
  tab: Tab;
  theme: ResolvedTheme;
  pageActive: boolean;
  nameOf: (pane: PaneSession) => string;
  onFocusPane: (key: string) => void;
  onClosePane: (key: string) => void;
  onOpenVault: () => void;
}

function LayoutView(props: LayoutProps) {
  const { layout, tab } = props;
  if (layout.kind === "pane") {
    return (
      <PaneView
        {...props}
        pane={layout.pane}
        focused={tab.activePane === layout.key}
        split={tab.layout.kind === "split"}
      />
    );
  }
  const size = `${100 / layout.children.length}%`;
  return (
    <ResizablePanelGroup orientation={layout.orientation} id={layout.key}>
      {layout.children.map((child, i) => (
        <Fragment key={child.key}>
          {i > 0 && <ResizableHandle withHandle />}
          <ResizablePanel id={child.key} defaultSize={size} minSize="10%">
            <LayoutView {...props} layout={child} />
          </ResizablePanel>
        </Fragment>
      ))}
    </ResizablePanelGroup>
  );
}

/** SS-10: the tabs MultiExec types into, side by side, each showing its own output (a tab's current pane). */
function TileView({
  tabs,
  activeTab,
  theme,
  pageActive,
  nameOf,
  status,
  onActivate,
  onFocusPane,
  onClosePane,
  onOpenVault,
}: {
  tabs: Tab[];
  activeTab: string | null;
  theme: ResolvedTheme;
  pageActive: boolean;
  nameOf: (pane: PaneSession) => string;
  status: MultiExecStatus | null;
  onActivate: (tabKey: string) => void;
  onFocusPane: (tabKey: string, paneKey: string) => void;
  onClosePane: (tabKey: string, paneKey: string) => void;
  onOpenVault: () => void;
}) {
  const cols = Math.ceil(Math.sqrt(tabs.length));
  return (
    <div
      className="grid h-full min-h-0 gap-1.5"
      style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))`, gridAutoRows: "minmax(0, 1fr)" }}
    >
      {tabs.map((tab) => {
        const pane = findPane(tab.layout, tab.activePane);
        if (!pane) return null;
        const target = status?.targets.find((t) => t.terminalId === pane.terminalId);
        const current = tab.key === activeTab;
        const hidden = allPanes(tab.layout).length - 1;
        return (
          <div
            key={tab.key}
            className={cn(
              "flex min-h-0 min-w-0 flex-col overflow-hidden rounded-lg border",
              current && "ring-2 ring-primary/50",
            )}
            onMouseDownCapture={() => onActivate(tab.key)}
          >
            <div className="flex shrink-0 items-center gap-1.5 border-b bg-muted/40 px-2 py-0.5 text-xs">
              <RadioTowerIcon
                className={cn("size-3 shrink-0", target && !target.receives ? "text-tier-medium" : "text-primary")}
                aria-hidden
              />
              <span className="truncate font-medium">{nameOf(pane)}</span>
              {(target?.reason ?? target?.note) && (
                <span className={cn("truncate", target?.reason ? "text-tier-medium" : "text-muted-foreground")}>
                  {target?.reason ?? target?.note}
                </span>
              )}
              {hidden > 0 && (
                <span
                  className="ml-auto shrink-0 text-muted-foreground"
                  title="Every pane of a picked tab receives typing"
                >
                  +{plural(hidden, "pane")} not shown
                </span>
              )}
            </div>
            <div className="min-h-0 flex-1">
              <PaneView
                layout={tab.layout}
                tab={tab}
                theme={theme}
                pageActive={pageActive}
                nameOf={nameOf}
                onFocusPane={(key) => onFocusPane(tab.key, key)}
                onClosePane={(key) => onClosePane(tab.key, key)}
                onOpenVault={onOpenVault}
                pane={pane}
                focused={current}
                split={false}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function PaneView({
  pane,
  focused,
  split,
  theme,
  pageActive,
  nameOf,
  onFocusPane,
  onClosePane,
  onOpenVault,
}: LayoutProps & { pane: PaneSession; focused: boolean; split: boolean }) {
  const host = useRef<HTMLDivElement>(null);
  const snapshot = usePane(pane);

  // Attach the pane's terminal here; it survives this view (layout changes, tab switches).
  useEffect(() => {
    const el = host.current;
    if (!el) return;
    el.appendChild(pane.element);
    pane.fit();
    pane.start().catch(() => undefined);
    pane.refresh();
    const observer = new ResizeObserver(() => pane.fit());
    observer.observe(el);
    return () => {
      observer.disconnect();
      if (pane.element.parentElement === el) el.removeChild(pane.element);
    };
  }, [pane]);

  useEffect(() => {
    if (pageActive && focused && !snapshot.searching) {
      pane.fit();
      pane.focus();
    }
  }, [pageActive, focused, pane, snapshot.searching]);

  return (
    <div
      className={cn(
        "pane-drop relative flex h-full min-h-0 flex-col",
        split && focused && "ring-2 ring-primary/40 ring-inset",
      )}
      // SS-08: files dragged over the window find their pane by this, and it shows where they would go.
      data-pane-key={pane.key}
      onMouseDownCapture={() => onFocusPane(pane.key)}
    >
      <PaneStatusBar
        snapshot={snapshot}
        onReconnect={() => pane.reconnect()}
        onClose={() => onClosePane(pane.key)}
        onOpenVault={onOpenVault}
        onReviewKey={() => pane.reviewChangedKey()}
        onStopLog={() => void pane.stopLog().catch((err) => toast.error(errorMessage(err)))}
        onDismissLogError={() => pane.dismissLogError()}
      />
      {snapshot.searching && <SearchBar pane={pane} results={snapshot.searchResults} />}
      <div
        ref={host}
        className="terminal-host min-h-0 flex-1 overflow-hidden p-1.5"
        style={{ background: TERMINAL_PALETTE[theme].background }}
      />
      {snapshot.question && (
        <HostKeyDialog
          question={snapshot.question}
          sessionName={nameOf(pane)}
          onTrust={() => pane.answerHostKey(true)}
          onReject={() => pane.answerHostKey(false)}
          onReplace={() => pane.replaceHostKey()}
          onDismiss={() => pane.dismissQuestion()}
        />
      )}
    </div>
  );
}

/** QL-05: find in the scrollback. Enter finds the next match, Shift+Enter the previous, Esc closes. */
function SearchBar({ pane, results }: { pane: PaneSession; results: PaneSnapshot["searchResults"] }) {
  const [text, setText] = useState("");
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [regex, setRegex] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    input.current?.focus();
    input.current?.select();
  }, []);

  function find(backwards: boolean, value = text, opts = { caseSensitive, regex }) {
    try {
      pane.find(value, backwards, opts);
    } catch {
      // An unfinished regular expression: wait for more typing.
    }
  }

  const count =
    !text || !results
      ? null
      : results.count === 0
        ? "No matches"
        : results.index < 0
          ? `${results.count}+ matches`
          : `${results.index + 1} of ${results.count}`;

  return (
    <div className="absolute top-2 right-4 left-2 z-10 ml-auto flex max-w-max flex-wrap items-center justify-end gap-1 rounded-lg border bg-popover p-1 shadow-md">
      <Input
        ref={input}
        aria-label="Search the terminal"
        placeholder="Search"
        className="h-7 w-48 min-w-16 shrink text-sm"
        value={text}
        onChange={(e) => {
          setText(e.currentTarget.value);
          find(false, e.currentTarget.value);
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            find(e.shiftKey);
          } else if (e.key === "Escape") {
            e.preventDefault();
            pane.closeSearch();
          }
        }}
      />
      <span className="shrink-0 px-1 text-xs whitespace-nowrap text-muted-foreground tabular-nums" aria-live="polite">
        {count}
      </span>
      <Toggle
        size="sm"
        aria-label="Match case"
        title="Match case"
        pressed={caseSensitive}
        onPressedChange={(v) => {
          setCaseSensitive(v);
          find(false, text, { caseSensitive: v, regex });
        }}
      >
        <CaseSensitiveIcon />
      </Toggle>
      <Toggle
        size="sm"
        aria-label="Regular expression"
        title="Regular expression"
        pressed={regex}
        onPressedChange={(v) => {
          setRegex(v);
          find(false, text, { caseSensitive, regex: v });
        }}
      >
        <RegexIcon />
      </Toggle>
      <Button variant="ghost" size="icon-sm" aria-label="Previous match (Shift+Enter)" onClick={() => find(true)}>
        <ArrowUpIcon />
      </Button>
      <Button variant="ghost" size="icon-sm" aria-label="Next match (Enter)" onClick={() => find(false)}>
        <ArrowDownIcon />
      </Button>
      <Button variant="ghost" size="icon-sm" aria-label="Close the search (Esc)" onClick={() => pane.closeSearch()}>
        <XIcon />
      </Button>
    </div>
  );
}

function useSecondsLeft(snapshot: PaneSnapshot) {
  const { status, statusAt } = snapshot;
  const total = status.state === "reconnecting" ? status.seconds : 0;
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (total === 0) return;
    const timer = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, [total, statusAt]);
  return Math.max(0, Math.ceil(total - (now - statusAt) / 1000));
}

function PaneStatusBar({
  snapshot,
  onReconnect,
  onClose,
  onOpenVault,
  onReviewKey,
  onStopLog,
  onDismissLogError,
}: {
  snapshot: PaneSnapshot;
  onReconnect: () => void;
  onClose: () => void;
  onOpenVault: () => void;
  onReviewKey: () => void;
  onStopLog: () => void;
  onDismissLogError: () => void;
}) {
  const left = useSecondsLeft(snapshot);
  const { status } = snapshot;
  let tone = "border-border bg-muted/50";
  let text: React.ReactNode = null;
  const actions: React.ReactNode[] = [];
  switch (status.state) {
    case "opening":
    case "connected":
    case "closed":
      break;
    case "connecting":
      if (status.attempt === 0) break;
      tone = "border-tier-medium/40 bg-tier-medium/10";
      text = `Reconnecting (try ${status.attempt})…`;
      break;
    case "reconnecting":
      tone = "border-tier-medium/40 bg-tier-medium/10";
      text = `Connection lost: ${status.reason}. Reconnecting in ${left} s (try ${status.attempt} of ${status.maxAttempts}).`;
      actions.push(
        <Button key="now" size="xs" variant="outline" onClick={onReconnect}>
          Reconnect now
        </Button>,
      );
      break;
    case "ended":
      text =
        status.exitStatus === null ? "The session ended." : `The session ended (exit status ${status.exitStatus}).`;
      actions.push(
        <Button key="again" size="xs" variant="outline" onClick={onReconnect}>
          Reconnect
        </Button>,
        <Button key="close" size="xs" variant="ghost" onClick={onClose}>
          Close
        </Button>,
      );
      break;
    case "disconnected":
      tone = "border-destructive/40 bg-destructive/10";
      text = `Not connected: ${status.message}`;
      if (status.code === "vault_locked") {
        actions.push(
          <Button key="vault" size="xs" variant="outline" onClick={onOpenVault}>
            Open the vault
          </Button>,
        );
      }
      if (status.code === "host_key_changed" && snapshot.changedKey) {
        actions.push(
          <Button key="key" size="xs" variant="outline" onClick={onReviewKey}>
            Review the key…
          </Button>,
        );
      }
      actions.push(
        <Button key="again" size="xs" variant="outline" onClick={onReconnect}>
          Try again
        </Button>,
      );
      actions.push(
        <Button key="close" size="xs" variant="ghost" onClick={onClose}>
          Close
        </Button>,
      );
      break;
  }
  return (
    <>
      {snapshot.logError && (
        <div
          className="flex shrink-0 items-center gap-2 border-b border-destructive/40 bg-destructive/10 px-3 py-1 text-xs"
          role="alert"
        >
          <FileTextIcon className="size-3.5 text-destructive" aria-hidden />
          <span className="min-w-0 flex-1">{snapshot.logError}</span>
          <Button size="xs" variant="ghost" onClick={onDismissLogError}>
            Dismiss
          </Button>
        </div>
      )}
      {snapshot.logPath && (
        <div
          className="flex shrink-0 items-center gap-2 border-b border-tier-medium/30 bg-tier-medium/5 px-3 py-1 text-xs"
          role="status"
        >
          <FileTextIcon className="size-3.5 text-tier-medium" aria-hidden />
          <span className="min-w-0 flex-1 truncate" title={snapshot.logPath}>
            Logging to {snapshot.logPath}
          </span>
          <Button size="xs" variant="ghost" onClick={onStopLog}>
            Stop
          </Button>
        </div>
      )}
      {text && (
        <div className={cn("flex shrink-0 items-center gap-2 border-b px-3 py-1.5 text-sm", tone)} role="status">
          <span className="min-w-0 flex-1">{text}</span>
          {actions}
        </div>
      )}
    </>
  );
}
