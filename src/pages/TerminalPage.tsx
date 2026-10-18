// Terminal workspace (SS-03, QL-02 to QL-05, SS-11): a collapsible session tree on the left (QL-04), and
// tabs on the right, each splittable into panes (each pane its own SSH connection), with keep-alive and
// auto-reconnect shown on the pane and its tab. New terminal opens the quick-connect form (QL-02). A tab
// takes its session's colour and label, and shows the host's own name and the address it reached
// (QL-03). Search with Ctrl+Shift+F, copy and paste with Ctrl+Shift+C / Ctrl+Shift+V or right-click
// (QL-05). The Output menu copies, saves or prints a pane's whole scrollback or that of several tabs
// picked with Ctrl+click or Shift+click, and logs a pane to a file (SS-11). Host key questions (SS-05)
// come up as dialogs. Interactive shells skip the approval flow; remote commands get it with bulk runs.

import { Fragment, useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { toast } from "sonner";
import {
  ArrowDownIcon,
  ArrowUpIcon,
  CaseSensitiveIcon,
  Columns2Icon,
  FileTextIcon,
  LoaderCircleIcon,
  PanelLeftCloseIcon,
  PanelLeftOpenIcon,
  PlusIcon,
  RefreshCwIcon,
  RegexIcon,
  Rows2Icon,
  SearchIcon,
  ShieldAlertIcon,
  SquareTerminalIcon,
  XIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "@/components/ui/resizable";
import { Toggle } from "@/components/ui/toggle";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ColorDot } from "@/components/Badges";
import { HostKeyDialog } from "@/components/HostKeyDialog";
import { NewTerminalDialog } from "@/components/NewTerminalDialog";
import { SessionTree } from "@/components/SessionTree";
import {
  api,
  errorMessage,
  type Environment,
  type QuickConnectRequest,
  type SessionColor,
  type SessionRecord,
} from "@/lib/api";
import { plural } from "@/lib/format";
import { clickTab, isMulti, NO_SELECTION, pruneSelection, type TabSelection } from "@/lib/tab-selection";
import { copyOutput, paneTitle, printOutput, saveOutput, type NamedPane } from "@/lib/terminal-output";
import {
  DEFAULT_PANE_OPTIONS,
  factsTitle,
  PaneSession,
  sessionAddress,
  TERMINAL_PALETTE,
  type PaneOpener,
  type PaneOptions,
  type PaneSnapshot,
} from "@/lib/terminal-session";
import type { ResolvedTheme } from "@/lib/theme";
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
}

/** More would make each pane too small to read. */
const MAX_PANES = 6;
const TREE_KEY = "remotely.terminal.treeShown";

interface Props {
  /** The page stays mounted while hidden so its connections survive. */
  active: boolean;
  theme: ResolvedTheme;
  /** A session to open in a new tab; `n` changes for each request. */
  openRequest: { sessionId: string; n: number } | null;
  /** QL-02: opens the New terminal form when it changes (the command palette). */
  newRequest: number;
  onOpenVault: () => void;
}

function newKey() {
  return crypto.randomUUID();
}

function allPanes(layout: Layout): PaneSession[] {
  return layout.kind === "pane" ? [layout.pane] : layout.children.flatMap(allPanes);
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

function readTreeShown() {
  try {
    return localStorage.getItem(TREE_KEY) !== "false";
  } catch {
    return true;
  }
}

export function TerminalPage({ active, theme, openRequest, newRequest, onOpenVault }: Props) {
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const [selection, setSelection] = useState<TabSelection>(NO_SELECTION);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [options, setOptions] = useState<PaneOptions>(DEFAULT_PANE_OPTIONS);
  const [treeShown, setTreeShown] = useState(readTreeShown);
  const [newOpen, setNewOpen] = useState(false);
  const [version, setVersion] = useState(0);
  const handled = useRef(0);
  // For closing every pane when the page goes away (the app closing).
  const tabsRef = useRef(tabs);

  const loadSessions = useCallback(() => {
    api.sessions().then(setSessions, (err) => toast.error(errorMessage(err)));
    api.terminalSettings().then(
      (s) => setOptions({ fontSize: s.fontSize, scrollback: s.scrollback, copyOnSelect: s.copyOnSelect }),
      () => undefined,
    );
  }, []);

  useEffect(() => {
    if (active) loadSessions();
  }, [active, loadSessions, version]);

  useEffect(() => {
    tabsRef.current = tabs;
    for (const pane of tabs.flatMap((t) => allPanes(t.layout))) {
      pane.setOptions(options);
      pane.setTheme(theme);
    }
  }, [tabs, options, theme]);

  useEffect(() => {
    try {
      localStorage.setItem(TREE_KEY, String(treeShown));
    } catch {
      // Not kept; the tree shows next time.
    }
  }, [treeShown]);

  // Closing the app closes every connection; the core audits each close.
  useEffect(() => () => tabsRef.current.forEach((t) => allPanes(t.layout).forEach((p) => p.close())), []);

  const sessionById = useMemo(() => new Map(sessions.map((s) => [s.id, s])), [sessions]);

  const createPane = useCallback(
    (opener: PaneOpener, label: string) => new PaneSession(newKey(), opener, label, theme, options),
    [theme, options],
  );

  const addTab = useCallback((pane: PaneSession) => {
    const tab: Tab = { key: newKey(), layout: { kind: "pane", key: pane.key, pane }, activePane: pane.key };
    setTabs((prev) => [...prev, tab]);
    setActiveTab(tab.key);
    setSelection({ keys: [], anchor: tab.key });
  }, []);

  const openSession = useCallback(
    (session: Pick<SessionRecord, "id" | "name">) => {
      addTab(createPane({ kind: "session", sessionId: session.id }, session.name));
      // Recent sessions moved.
      window.setTimeout(() => setVersion((v) => v + 1), 500);
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
    openSession({ id: openRequest.sessionId, name: sessionById.get(openRequest.sessionId)?.name ?? "Session" });
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
  }

  function pickTab(key: string, modifiers: { ctrl: boolean; shift: boolean }) {
    const order = tabs.map((t) => t.key);
    setSelection((s) => clickTab(s.anchor ? s : { ...s, anchor: activeTab }, key, order, modifiers));
    setActiveTab(key);
  }

  const current = tabs.find((t) => t.key === activeTab) ?? null;
  const currentPane = current ? findPane(current.layout, current.activePane) : undefined;

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
    const pane = createPane(opener, currentPane.label);
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
      const snap = pane.getSnapshot();
      const session = snap.sessionId ? sessionById.get(snap.sessionId) : undefined;
      return paneTitle(session?.name ?? pane.label, snap.facts);
    },
    [sessionById],
  );

  const multi = isMulti(selection);
  const selectedTabs = tabs.filter((t) => selection.keys.includes(t.key));
  /** SS-11: what the Output menu acts on: the picked tabs' panes, or the current pane. */
  const outputPanes: NamedPane[] = (
    multi ? selectedTabs.flatMap((t) => allPanes(t.layout)) : currentPane ? [currentPane] : []
  ).map((pane) => ({ pane, title: nameOf(pane) }));

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

  const workspace = (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="flex items-end gap-1 border-b">
        <IconButton
          label={treeShown ? "Hide the sessions" : "Show the sessions"}
          onClick={() => setTreeShown((v) => !v)}
          className="mb-1"
        >
          {treeShown ? <PanelLeftCloseIcon /> : <PanelLeftOpenIcon />}
        </IconButton>
        <div
          className="flex min-w-0 flex-1 items-end gap-1 overflow-x-auto [scrollbar-width:thin]"
          role="tablist"
          aria-label="Terminals"
        >
          {tabs.map((tab) => (
            <TabButton
              key={tab.key}
              tab={tab}
              sessions={sessionById}
              pane={findPane(tab.layout, tab.activePane)}
              current={tab.key === activeTab}
              picked={multi && selection.keys.includes(tab.key)}
              onSelect={(modifiers) => pickTab(tab.key, modifiers)}
              onClose={() => closeTab(tab)}
            />
          ))}
          <IconButton label="New terminal" onClick={() => setNewOpen(true)} className="mb-1">
            <PlusIcon />
          </IconButton>
        </div>
        {current && (
          <div className="flex shrink-0 items-center gap-0.5 pb-1">
            <IconButton label="Search (Ctrl+Shift+F)" onClick={() => currentPane?.openSearch()}>
              <SearchIcon />
            </IconButton>
            <IconButton label="Split right" onClick={() => split("horizontal")}>
              <Columns2Icon />
            </IconButton>
            <IconButton label="Split down" onClick={() => split("vertical")}>
              <Rows2Icon />
            </IconButton>
            <IconButton label="Reconnect this pane" onClick={() => currentPane?.reconnect()}>
              <RefreshCwIcon />
            </IconButton>
            <OutputMenu
              panes={outputPanes}
              multi={multi}
              tabCount={selectedTabs.length}
              current={currentPane}
              onSelectAll={() => setSelection({ keys: tabs.map((t) => t.key), anchor: activeTab })}
              onClearSelection={() => setSelection({ keys: [], anchor: activeTab })}
              allTabs={tabs.length}
              run={run}
              titleOf={nameOf}
            />
            <IconButton label="Close this pane" onClick={() => closePane(current.key, current.activePane)}>
              <XIcon />
            </IconButton>
          </div>
        )}
      </div>
      {multi && (
        <div
          className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/50 px-3 py-1.5 text-sm"
          role="status"
        >
          <span className="font-medium">
            {plural(selectedTabs.length, "tab")} picked ({plural(outputPanes.length, "terminal")})
          </span>
          <Button size="xs" variant="outline" onClick={() => void run("Copying", () => copyOutput(outputPanes))}>
            Copy output
          </Button>
          <Button
            size="xs"
            variant="outline"
            onClick={() =>
              void run("Saving", async () => {
                const saved = await saveOutput(outputPanes, "oneFile");
                if (saved) toast.success(`Saved ${plural(saved.terminals, "terminal")} to ${saved.files[0]}`);
              })
            }
          >
            Save to one file…
          </Button>
          <Button
            size="xs"
            variant="outline"
            onClick={() =>
              void run("Saving", async () => {
                const saved = await saveOutput(outputPanes, "filePerTerminal");
                if (saved) toast.success(`Saved ${plural(saved.files.length, "file")}`);
              })
            }
          >
            A file each…
          </Button>
          <Button size="xs" variant="outline" onClick={() => void run("Printing", () => printOutput(outputPanes))}>
            Print…
          </Button>
          <Button
            size="xs"
            variant="ghost"
            className="ml-auto"
            onClick={() => setSelection({ keys: [], anchor: activeTab })}
          >
            Clear
          </Button>
        </div>
      )}
      {current ? (
        <div className="min-h-0 flex-1 overflow-hidden rounded-lg border" key={current.key}>
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
      ) : (
        <Empty className="min-h-0 flex-1 border">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <SquareTerminalIcon />
            </EmptyMedia>
            <EmptyTitle>No terminal open</EmptyTitle>
            <EmptyDescription>
              Double-click a session in the tree, or connect to any host with New terminal. Each tab can be split into
              panes, and a dropped connection reconnects by itself.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button onClick={() => setNewOpen(true)}>
              <PlusIcon />
              New terminal
            </Button>
          </EmptyContent>
        </Empty>
      )}
      <p className="text-xs text-muted-foreground">
        {options.copyOnSelect ? "Selecting text copies it. " : "Ctrl+Shift+C copies a selection. "}
        Ctrl+Shift+V or right-click pastes, Ctrl+Shift+F searches. Ctrl+click tabs to pick several for Output. Typing
        into a terminal is not audited; opening and closing it, and saving its output, are.
      </p>
    </div>
  );

  return (
    <>
      {treeShown ? (
        <ResizablePanelGroup orientation="horizontal" id="terminal-workspace">
          <ResizablePanel id="terminal-tree" defaultSize="20%" minSize="12%" maxSize="40%">
            <div className="h-full pr-3">
              <SessionTree active={active} version={version} openSessions={openSessions} onOpen={openSession} />
            </div>
          </ResizablePanel>
          <ResizableHandle />
          <ResizablePanel id="terminal-main" defaultSize="80%">
            <div className="h-full pl-3">{workspace}</div>
          </ResizablePanel>
        </ResizablePanelGroup>
      ) : (
        workspace
      )}
      <NewTerminalDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        onConnect={openQuick}
        onOpenSession={(s) => openSession(s)}
      />
    </>
  );
}

function IconButton({
  label,
  onClick,
  className,
  children,
}: {
  label: string;
  onClick: () => void;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label={label} onClick={onClick} className={className}>
          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
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
  searching: false,
  searchResults: null,
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
  pane,
  current,
  picked,
  onSelect,
  onClose,
}: {
  tab: Tab;
  sessions: Map<string, SessionRecord>;
  pane: PaneSession | undefined;
  current: boolean;
  picked: boolean;
  onSelect: (modifiers: { ctrl: boolean; shift: boolean }) => void;
  onClose: () => void;
}) {
  const snapshot = usePane(pane);
  const session = snapshot.sessionId ? sessions.get(snapshot.sessionId) : undefined;
  const env = session?.environment ?? "none";
  const name = session?.name ?? pane?.label ?? "Terminal";
  const seen = factsTitle(snapshot.facts);
  const count = allPanes(tab.layout).length;
  const tooltip = [
    session ? `${session.name} (${sessionAddress(session)})` : name,
    seen && `Host: ${seen}`,
    session ? null : "Not saved as a session",
    snapshot.logPath && `Logging to ${snapshot.logPath}`,
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
        "group flex h-10 max-w-64 min-w-36 shrink cursor-pointer items-center gap-2 rounded-t-md border border-b-0 border-t-[3px] px-2.5 text-sm select-none",
        session?.color ? COLOR_TAB[session.color] : ENV_TAB[env],
        env === "prod" && "bg-env-prod/10",
        current ? "bg-background font-medium" : "text-muted-foreground hover:bg-muted/60",
        picked && "bg-primary/10 ring-2 ring-primary/50 ring-inset",
      )}
    >
      <StatusDot snapshot={snapshot} />
      {session?.color && <ColorDot color={session.color} />}
      <span className="grid min-w-0 flex-1 leading-tight">
        <span className="truncate">{name}</span>
        {(env !== "none" || (seen && seen !== name)) && (
          <span className="truncate text-[11px] font-normal text-muted-foreground">
            {env !== "none" && <span className={cn("font-semibold uppercase", ENV_TEXT[env])}>{env} </span>}
            {seen !== name && seen}
          </span>
        )}
      </span>
      {snapshot.logPath && <FileTextIcon className="size-3.5 shrink-0 text-tier-medium" aria-label="Logging" />}
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

/** SS-11: copy, save, print and log, for the current pane or every picked tab. */
function OutputMenu({
  panes,
  multi,
  tabCount,
  current,
  allTabs,
  onSelectAll,
  onClearSelection,
  run,
  titleOf,
}: {
  panes: NamedPane[];
  multi: boolean;
  tabCount: number;
  current: PaneSession | undefined;
  allTabs: number;
  onSelectAll: () => void;
  onClearSelection: () => void;
  run: (what: string, action: () => Promise<unknown>) => Promise<void>;
  titleOf: (pane: PaneSession) => string;
}) {
  const snapshot = usePane(current);
  const terminals = plural(panes.length, "terminal");
  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" aria-label="Output: copy, save, print or log">
              <FileTextIcon />
              Output
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>Copy, save, print or log the output</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel>
          {multi ? `${plural(tabCount, "picked tab")}, ${terminals}` : "This pane's whole scrollback"}
        </DropdownMenuLabel>
        <DropdownMenuItem disabled={panes.length === 0} onSelect={() => void run("Copying", () => copyOutput(panes))}>
          {multi ? `Copy the output of ${terminals}` : "Copy all output"}
        </DropdownMenuItem>
        <DropdownMenuItem
          disabled={panes.length === 0}
          onSelect={() =>
            void run("Saving", async () => {
              const saved = await saveOutput(panes, "oneFile");
              if (saved) toast.success(`Saved to ${saved.files[0]}`);
            })
          }
        >
          {multi ? "Save to one file, a header each…" : "Save to a .txt file…"}
        </DropdownMenuItem>
        {multi && (
          <DropdownMenuItem
            onSelect={() =>
              void run("Saving", async () => {
                const saved = await saveOutput(panes, "filePerTerminal");
                if (saved) toast.success(`Saved ${plural(saved.files.length, "file")}`);
              })
            }
          >
            Save a file for each…
          </DropdownMenuItem>
        )}
        <DropdownMenuItem disabled={panes.length === 0} onSelect={() => void run("Printing", () => printOutput(panes))}>
          {multi ? `Print ${terminals}…` : "Print…"}
        </DropdownMenuItem>
        {!multi && current && (
          <>
            <DropdownMenuSeparator />
            {snapshot.logPath ? (
              <DropdownMenuItem onSelect={() => void run("Stopping the log", () => current.stopLog())}>
                Stop logging to a file
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
                Log this session to a file…
              </DropdownMenuItem>
            )}
          </>
        )}
        <DropdownMenuSeparator />
        {multi ? (
          <DropdownMenuItem onSelect={onClearSelection}>Clear the picked tabs</DropdownMenuItem>
        ) : (
          <DropdownMenuItem disabled={allTabs < 2} onSelect={onSelectAll}>
            Pick all {allTabs} tabs
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
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
    pane.term.refresh(0, pane.term.rows - 1);
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
      className={cn("relative flex h-full min-h-0 flex-col", split && focused && "ring-2 ring-primary/40 ring-inset")}
      onMouseDownCapture={() => onFocusPane(pane.key)}
    >
      <PaneStatusBar
        snapshot={snapshot}
        onReconnect={() => pane.reconnect()}
        onClose={() => onClosePane(pane.key)}
        onOpenVault={onOpenVault}
        onReviewKey={() => pane.reviewChangedKey()}
        onStopLog={() => void pane.stopLog().catch((err) => toast.error(errorMessage(err)))}
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
}: {
  snapshot: PaneSnapshot;
  onReconnect: () => void;
  onClose: () => void;
  onOpenVault: () => void;
  onReviewKey: () => void;
  onStopLog: () => void;
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
      if (status.code !== "jump_host_unsupported") {
        actions.push(
          <Button key="again" size="xs" variant="outline" onClick={onReconnect}>
            Try again
          </Button>,
        );
      }
      actions.push(
        <Button key="close" size="xs" variant="ghost" onClick={onClose}>
          Close
        </Button>,
      );
      break;
  }
  return (
    <>
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
