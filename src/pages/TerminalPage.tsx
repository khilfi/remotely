// Tabbed SSH terminal (SS-03): one tab per opened session, each splittable into panes (each pane its own
// SSH connection), copy-on-select, keep-alive and auto-reconnect with the state shown on the pane and its
// tab. The tab's colour is the session's environment label (SS-06). Host key questions (SS-05) come up
// as dialogs. Interactive shells skip the approval flow; remote commands get it with bulk run (BX-02).

import { Fragment, useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { toast } from "sonner";
import {
  Columns2Icon,
  LoaderCircleIcon,
  PlusIcon,
  RefreshCwIcon,
  Rows2Icon,
  ShieldAlertIcon,
  SquareTerminalIcon,
  XIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "@/components/ui/resizable";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ColorDot, EnvBadge } from "@/components/Badges";
import { HostKeyDialog } from "@/components/HostKeyDialog";
import { api, errorMessage, type Environment, type SessionRecord } from "@/lib/api";
import { PaneSession, TERMINAL_PALETTE, type PaneSnapshot } from "@/lib/terminal-session";
import type { ResolvedTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

/** A tab's panes: one pane, or a split of several side by side or stacked. */
type Layout =
  | { kind: "pane"; key: string; pane: PaneSession }
  | { kind: "split"; key: string; orientation: "horizontal" | "vertical"; children: Layout[] };

interface Tab {
  key: string;
  sessionId: string;
  layout: Layout;
  /** The pane the toolbar acts on. */
  activePane: string;
}

/** More would make each pane too small to read. */
const MAX_PANES = 6;

interface Props {
  /** The page stays mounted while hidden so its connections survive. */
  active: boolean;
  theme: ResolvedTheme;
  /** A session to open in a new tab; `n` changes for each request. */
  openRequest: { sessionId: string; n: number } | null;
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

const ENV_TAB: Record<Environment, string> = {
  none: "border-t-transparent",
  lab: "border-t-env-lab",
  staging: "border-t-env-staging",
  prod: "border-t-env-prod bg-env-prod/10",
};

function address(s: SessionRecord) {
  return `${s.username ? `${s.username}@` : ""}${s.host}${s.port === 22 ? "" : `:${s.port}`}`;
}

export function TerminalPage({ active, theme, openRequest, onOpenVault }: Props) {
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [copyOnSelect, setCopyOnSelect] = useState(true);
  const handled = useRef(0);
  // For closing every pane when the page goes away (the app closing).
  const tabsRef = useRef(tabs);

  const loadSessions = useCallback(() => {
    api.sessions().then(setSessions, (err) => toast.error(errorMessage(err)));
    api.terminalSettings().then(
      (s) => setCopyOnSelect(s.copyOnSelect),
      () => undefined,
    );
  }, []);

  useEffect(() => {
    if (active) loadSessions();
  }, [active, loadSessions]);

  useEffect(() => {
    tabsRef.current = tabs;
    for (const pane of tabs.flatMap((t) => allPanes(t.layout))) {
      pane.copyOnSelect = copyOnSelect;
      pane.setTheme(theme);
    }
  }, [tabs, copyOnSelect, theme]);

  // Closing the app closes every connection; the core audits each close.
  useEffect(() => () => tabsRef.current.forEach((t) => allPanes(t.layout).forEach((p) => p.close())), []);

  const createPane = useCallback(
    (sessionId: string) => {
      const pane = new PaneSession(newKey(), sessionId, theme);
      pane.copyOnSelect = copyOnSelect;
      return pane;
    },
    [theme, copyOnSelect],
  );

  const openSession = useCallback(
    (sessionId: string) => {
      const pane = createPane(sessionId);
      const tab: Tab = {
        key: newKey(),
        sessionId,
        layout: { kind: "pane", key: pane.key, pane },
        activePane: pane.key,
      };
      setTabs((prev) => [...prev, tab]);
      setActiveTab(tab.key);
    },
    [createPane],
  );

  useEffect(() => {
    if (!openRequest || openRequest.n === handled.current) return;
    handled.current = openRequest.n;
    loadSessions();
    openSession(openRequest.sessionId);
  }, [openRequest, openSession, loadSessions]);

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
    if (!next.some((t) => t.key === activeTab)) setActiveTab(next[next.length - 1]?.key ?? null);
  }

  function closeTab(tab: Tab) {
    allPanes(tab.layout).forEach((p) => p.close());
    const next = tabs.filter((t) => t.key !== tab.key);
    setTabs(next);
    if (activeTab === tab.key) setActiveTab(next[next.length - 1]?.key ?? null);
  }

  const current = tabs.find((t) => t.key === activeTab) ?? null;
  const currentPane = current ? findPane(current.layout, current.activePane) : undefined;

  function split(orientation: "horizontal" | "vertical") {
    if (!current) return;
    if (allPanes(current.layout).length >= MAX_PANES) {
      toast.info(`A tab holds at most ${MAX_PANES} panes. Open the session in another tab.`);
      return;
    }
    const pane = createPane(currentPane?.sessionId ?? current.sessionId);
    setTabs((prev) =>
      prev.map((t) =>
        t.key === current.key
          ? { ...t, layout: splitLayout(t.layout, t.activePane, pane, orientation), activePane: pane.key }
          : t,
      ),
    );
  }

  const sessionById = useMemo(() => new Map(sessions.map((s) => [s.id, s])), [sessions]);

  if (tabs.length === 0) {
    return (
      <Empty className="h-full border">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <SquareTerminalIcon />
          </EmptyMedia>
          <EmptyTitle>No terminal open</EmptyTitle>
          <EmptyDescription>
            Open a saved session here, or with Connect on the Sessions page. Each tab can be split into panes, and a
            dropped connection reconnects by itself.
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <SessionPicker sessions={sessions} onPick={openSession} label="Open a session" />
        </EmptyContent>
      </Empty>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="flex items-end gap-1 border-b">
        <div className="flex min-w-0 flex-1 items-end gap-1 overflow-x-auto" role="tablist" aria-label="Terminals">
          {tabs.map((tab) => (
            <TabButton
              key={tab.key}
              tab={tab}
              session={sessionById.get(tab.sessionId)}
              pane={findPane(tab.layout, tab.activePane)}
              selected={tab.key === activeTab}
              onSelect={() => setActiveTab(tab.key)}
              onClose={() => closeTab(tab)}
            />
          ))}
          <SessionPicker sessions={sessions} onPick={openSession} />
        </div>
        <div className="flex shrink-0 items-center gap-0.5 pb-1">
          <IconButton label="Split right" onClick={() => split("horizontal")}>
            <Columns2Icon />
          </IconButton>
          <IconButton label="Split down" onClick={() => split("vertical")}>
            <Rows2Icon />
          </IconButton>
          <IconButton label="Reconnect this pane" onClick={() => currentPane?.reconnect()}>
            <RefreshCwIcon />
          </IconButton>
          <IconButton label="Close this pane" onClick={() => current && closePane(current.key, current.activePane)}>
            <XIcon />
          </IconButton>
        </div>
      </div>
      {current && (
        <div className="min-h-0 flex-1 overflow-hidden rounded-lg border" key={current.key}>
          <LayoutView
            layout={current.layout}
            tab={current}
            theme={theme}
            pageActive={active}
            sessionName={sessionById.get(current.sessionId)?.name ?? "this session"}
            onFocusPane={(key) =>
              setTabs((prev) => prev.map((t) => (t.key === current.key ? { ...t, activePane: key } : t)))
            }
            onClosePane={(key) => closePane(current.key, key)}
            onOpenVault={onOpenVault}
          />
        </div>
      )}
      <p className="text-xs text-muted-foreground">
        {copyOnSelect ? "Selecting text copies it. " : "Ctrl+C copies a selection. "}
        Ctrl+V or right-click pastes. Typing into a terminal is not audited; opening and closing it is.
      </p>
    </div>
  );
}

function IconButton({ label, onClick, children }: { label: string; onClick: () => void; children: React.ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label={label} onClick={onClick}>
          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}

const NO_SNAPSHOT: PaneSnapshot = { status: { state: "opening" }, statusAt: 0, question: null, changedKey: null };
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
  session,
  pane,
  selected,
  onSelect,
  onClose,
}: {
  tab: Tab;
  session: SessionRecord | undefined;
  pane: PaneSession | undefined;
  selected: boolean;
  onSelect: () => void;
  onClose: () => void;
}) {
  const snapshot = usePane(pane);
  const env = session?.environment ?? "none";
  const count = allPanes(tab.layout).length;
  return (
    <div
      role="tab"
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onSelect()}
      onAuxClick={(e) => e.button === 1 && onClose()}
      title={session ? `${session.name} (${address(session)})` : undefined}
      className={cn(
        "group flex h-9 max-w-56 shrink-0 cursor-pointer items-center gap-2 rounded-t-md border border-b-0 border-t-2 px-2.5 text-sm",
        ENV_TAB[env],
        selected ? "bg-background font-medium" : "text-muted-foreground hover:bg-muted/60",
      )}
    >
      <StatusDot snapshot={snapshot} />
      {session?.color && <ColorDot color={session.color} />}
      <span className="truncate">{session?.name ?? "Session"}</span>
      {count > 1 && <span className="text-xs text-muted-foreground">{count}</span>}
      {env !== "none" && <span className="sr-only">{env}</span>}
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

function SessionPicker({
  sessions,
  onPick,
  label,
}: {
  sessions: SessionRecord[];
  onPick: (id: string) => void;
  label?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        {label ? (
          <Button>
            <PlusIcon />
            {label}
          </Button>
        ) : (
          <Button variant="ghost" size="icon-sm" aria-label="Open a session" className="mb-1">
            <PlusIcon />
          </Button>
        )}
      </PopoverTrigger>
      <PopoverContent className="w-80 p-0" align="start">
        <Command>
          <CommandInput placeholder="Search sessions…" />
          <CommandList>
            <CommandEmpty>No session found. Add one on the Sessions page.</CommandEmpty>
            <CommandGroup>
              {sessions.map((s) => (
                <CommandItem
                  key={s.id}
                  value={`${s.name} ${address(s)} ${s.tags.join(" ")}`}
                  onSelect={() => {
                    setOpen(false);
                    onPick(s.id);
                  }}
                >
                  {s.color ? <ColorDot color={s.color} /> : <span className="size-2" />}
                  <div className="grid min-w-0 flex-1">
                    <span className="truncate">{s.name}</span>
                    <span className="truncate text-xs text-muted-foreground">{address(s)}</span>
                  </div>
                  {s.environment !== "none" && <EnvBadge env={s.environment} />}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

interface LayoutProps {
  layout: Layout;
  tab: Tab;
  theme: ResolvedTheme;
  pageActive: boolean;
  sessionName: string;
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
  sessionName,
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
    pane.start();
    pane.term.refresh(0, pane.term.rows - 1);
    const observer = new ResizeObserver(() => pane.fit());
    observer.observe(el);
    return () => {
      observer.disconnect();
      if (pane.element.parentElement === el) el.removeChild(pane.element);
    };
  }, [pane]);

  useEffect(() => {
    if (pageActive && focused) {
      pane.fit();
      pane.focus();
    }
  }, [pageActive, focused, pane]);

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
      />
      <div
        ref={host}
        className="terminal-host min-h-0 flex-1 overflow-hidden p-1.5"
        style={{ background: TERMINAL_PALETTE[theme].background }}
      />
      {snapshot.question && (
        <HostKeyDialog
          question={snapshot.question}
          sessionName={sessionName}
          onTrust={() => pane.answerHostKey(true)}
          onReject={() => pane.answerHostKey(false)}
          onReplace={() => pane.replaceHostKey()}
          onDismiss={() => pane.dismissQuestion()}
        />
      )}
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
}: {
  snapshot: PaneSnapshot;
  onReconnect: () => void;
  onClose: () => void;
  onOpenVault: () => void;
  onReviewKey: () => void;
}) {
  const left = useSecondsLeft(snapshot);
  const { status } = snapshot;
  let tone = "border-border bg-muted/50";
  let text: React.ReactNode;
  const actions: React.ReactNode[] = [];
  switch (status.state) {
    case "opening":
    case "connected":
    case "closed":
      return null;
    case "connecting":
      if (status.attempt === 0) return null;
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
    <div className={cn("flex shrink-0 items-center gap-2 border-b px-3 py-1.5 text-sm", tone)} role="status">
      <span className="min-w-0 flex-1">{text}</span>
      {actions}
    </div>
  );
}
