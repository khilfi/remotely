// QL-04: the session tree on the left of the Terminal page. The same library as the Sessions page,
// grouped by folder, tag or environment label (the core builds the tree), with a search box and the
// recently opened sessions on top. Double-click (or Enter) opens a session in a new tab.
//
// Reachability dots (MO-08 lite): the core checks the port of each session the tree shows, in the
// background; collapsed groups are not checked, which keeps large libraries light. A setting turns it off.
// Hosts with an open connection (a terminal, the dashboard, the Containers page) are not probed and say "connected";
// a host that is down is checked less often.
// SS-07: a session behind jump hosts says which one it goes through ("via inner"); its dot is a ring showing the
// first jump host's check (the one this PC dials), since the session itself is not reachable from here.
//
// BX-03 Compare (post-MVP P6): Ctrl+click picks sessions to run a command on without opening tabs (Ctrl+click a
// group picks every session in it, for large runs); the Compare hosts panel shows and runs on them (UX-03: the page
// opens it on the first pick, so the tree has no button of its own).
// UX-12: each row shows the environment that applies (a Prod VM it reaches makes it Prod), and its tooltip says
// where it comes from.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import {
  CheckIcon,
  ChevronRightIcon,
  ClockIcon,
  FolderIcon,
  FolderOpenIcon,
  ListTreeIcon,
  MonitorIcon,
  NetworkIcon,
  SearchIcon,
  TagIcon,
  UsbIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ColorDot } from "@/components/Badges";
import { RefreshButton } from "@/components/RefreshButton";
import { RowMenu } from "@/components/RowMenu";
import { Tip } from "@/components/Tip";
import { appliedEnvironment, environmentText, type EnvironmentOfVm } from "@/lib/session-environment";
import { jumpChain, routeText, viaText, type JumpLink } from "@/lib/tunnels";
import {
  api,
  errorMessage,
  type Environment,
  type Reachability,
  type SessionRecord,
  type SessionTree as Tree,
  type TreeGrouping,
  type TreeNode,
} from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { sessionAddress } from "@/lib/terminal-session";
import { kindLabel } from "@/lib/session-kinds";
import { cn } from "@/lib/utils";
import { ToolboxMenu } from "@/components/toolbox/ToolboxMenu";

const GROUPING_KEY = "remotely.terminal.treeGrouping";
const OPEN_KEY = "remotely.terminal.treeOpen";
/** Larger libraries start with their groups closed. */
const OPEN_BY_DEFAULT_UP_TO = 40;

const GROUPINGS: { value: TreeGrouping; label: string }[] = [
  { value: "folder", label: "Folder" },
  { value: "tag", label: "Tag" },
  { value: "label", label: "Environment" },
];

const ENV_TEXT: Record<Environment, string> = {
  none: "text-muted-foreground",
  lab: "text-env-lab",
  staging: "text-env-staging",
  prod: "text-env-prod",
};

function readJson<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

interface Props {
  /** The page is shown: checks run only then. */
  active: boolean;
  /** Bumped when sessions change (a quick connection was saved, a tab opened). */
  version: number;
  /** Sessions with a tab open, marked in the tree. */
  openSessions: Set<string>;
  onOpen: (session: SessionRecord) => void;
  /** BX-03: sessions picked for Compare hosts (Ctrl+click). */
  picks: string[];
  onPicksChange: (ids: string[]) => void;
  /** MO-13, MO-14: the session's host details. */
  onHostDetails?: (session: SessionRecord) => void;
  /** UX-12: the VMs, so a session that reaches a Prod VM shows as Prod. */
  vms: ReadonlyMap<string, EnvironmentOfVm>;
}

/** Every session in a group and the groups under it. */
function sessionsUnder(node: TreeNode): string[] {
  return [...node.sessions, ...node.children.flatMap(sessionsUnder)];
}

export function SessionTree({
  active,
  version,
  openSessions,
  onOpen,
  picks,
  onPicksChange,
  onHostDetails,
  vms,
}: Props) {
  const [grouping, setGrouping] = useState<TreeGrouping>(() => readJson(GROUPING_KEY, "folder"));
  const [text, setText] = useState("");
  const [tree, setTree] = useState<Tree | null>(null);
  const [recent, setRecent] = useState<SessionRecord[]>([]);
  /** SS-07: every session, for the names of jump hosts the search left out. */
  const [links, setLinks] = useState<Map<string, JumpLink>>(new Map());
  const [open, setOpen] = useState<Record<string, boolean>>(() => readJson(OPEN_KEY, {}));
  const [reach, setReach] = useState<{ enabled: boolean; states: Map<string, Reachability> }>({
    enabled: false,
    states: new Map(),
  });
  const [picked, setPicked] = useState<string | null>(null);
  const [reloads, setReloads] = useState(0);
  const searching = text.trim() !== "";

  useEffect(() => {
    if (!active) return;
    const timer = window.setTimeout(
      () => {
        Promise.all([api.sessionTree(grouping, { text }), api.recentSessions(8), api.sessions()]).then(
          ([t, r, all]) => {
            setTree(t);
            setRecent(r);
            setLinks(new Map(all.map((s) => [s.id, s])));
          },
          (err) => toast.error(errorMessage(err)),
        );
      },
      searching ? 150 : 0,
    );
    return () => window.clearTimeout(timer);
  }, [active, grouping, text, searching, version, reloads]);

  useEffect(() => {
    try {
      localStorage.setItem(GROUPING_KEY, JSON.stringify(grouping));
      localStorage.setItem(OPEN_KEY, JSON.stringify(open));
    } catch {
      // Private storage off: the tree just forgets.
    }
  }, [grouping, open]);

  const byId = useMemo(() => new Map((tree?.records ?? []).map((s) => [s.id, s])), [tree]);
  const total = tree?.records.length ?? 0;
  const isOpen = useCallback(
    (key: string) => searching || (open[key] ?? total <= OPEN_BY_DEFAULT_UP_TO),
    [open, searching, total],
  );

  // The sessions on screen: the recent ones and those in open groups. Only these are checked.
  const shown = useMemo(() => {
    const ids = new Set<string>(searching ? [] : recent.map((s) => s.id));
    const walk = (nodes: TreeNode[]) => {
      for (const node of nodes) {
        if (!isOpen(node.key)) continue;
        node.sessions.forEach((id) => ids.add(id));
        walk(node.children);
      }
    };
    if (tree) {
      walk(tree.nodes);
      tree.sessions.forEach((id) => ids.add(id));
    }
    return [...ids].sort();
  }, [tree, recent, isOpen, searching]);
  const shownKey = shown.join(",");

  useEffect(() => {
    const ids = active && shownKey ? shownKey.split(",") : [];
    const timer = window.setTimeout(() => {
      api.reachabilityWatch(ids).then(
        (update) => setReach({ enabled: update.enabled, states: new Map(update.states.map((s) => [s.sessionId, s])) }),
        () => undefined,
      );
    }, 250);
    return () => window.clearTimeout(timer);
  }, [active, shownKey]);

  useEffect(() => {
    const unlisten = api.onReachability((update) =>
      setReach({ enabled: update.enabled, states: new Map(update.states.map((s) => [s.sessionId, s])) }),
    );
    return () => void unlisten.then((stop) => stop());
  }, []);

  function toggle(key: string) {
    setOpen((prev) => ({ ...prev, [key]: !isOpen(key) }));
  }

  const pickSet = useMemo(() => new Set(picks), [picks]);

  /** BX-03: Ctrl+click adds or removes; for a group, all of its sessions (removed when all were picked). */
  function togglePicks(ids: string[]) {
    const all = ids.every((id) => pickSet.has(id));
    const next = all ? picks.filter((id) => !ids.includes(id)) : [...picks, ...ids.filter((id) => !pickSet.has(id))];
    onPicksChange(next);
  }

  const row = (id: string, depth: number, from: string) => {
    const s = byId.get(id);
    if (!s) return null;
    return (
      <SessionRow
        key={`${from}:${id}`}
        session={s}
        via={jumpChain(id, links).names}
        depth={depth}
        picked={picked === `${from}:${id}`}
        checked={pickSet.has(id)}
        open={openSessions.has(id)}
        reach={reach.enabled ? (reach.states.get(id) ?? null) : undefined}
        onPick={() => setPicked(`${from}:${id}`)}
        onToggleCheck={() => togglePicks([id])}
        onOpen={() => onOpen(s)}
        onHostDetails={onHostDetails && (() => onHostDetails(s))}
        vms={vms}
      />
    );
  };

  const group = (node: TreeNode, depth: number): React.ReactNode => {
    const expanded = isOpen(node.key);
    const Icon = node.kind === "folder" ? (expanded ? FolderOpenIcon : FolderIcon) : TagIcon;
    return (
      <div key={node.key} role="group" aria-label={node.name}>
        <button
          type="button"
          className="flex h-7 w-full min-w-0 items-center gap-1.5 rounded-md pr-2 text-left text-sm hover:bg-accent [&_svg]:size-3.5 [&_svg]:shrink-0"
          style={{ paddingLeft: `${0.25 + depth * 0.75}rem` }}
          aria-expanded={expanded}
          title="Ctrl+click picks all its sessions for Compare hosts"
          onClick={(e) => (e.ctrlKey || e.metaKey ? togglePicks(sessionsUnder(node)) : toggle(node.key))}
        >
          <ChevronRightIcon className={cn("text-muted-foreground transition-transform", expanded && "rotate-90")} />
          {node.kind === "label" || (node.kind === "other" && node.environment) ? (
            <span className={cn("size-2 shrink-0 rounded-full bg-current", ENV_TEXT[node.environment ?? "none"])} />
          ) : (
            <Icon className="text-muted-foreground" />
          )}
          <span className="truncate">{node.name}</span>
          <span className="ml-auto text-xs text-muted-foreground tabular-nums">{node.count}</span>
        </button>
        {expanded && (
          <>
            {node.children.map((child) => group(child, depth + 1))}
            {node.sessions.map((id) => row(id, depth + 1, node.key))}
          </>
        )}
      </div>
    );
  };

  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="flex items-center gap-1">
        <div className="relative min-w-0 flex-1">
          <SearchIcon className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            aria-label="Search sessions"
            placeholder="Search sessions"
            className="h-8 pl-7 text-sm"
            value={text}
            onChange={(e) => setText(e.currentTarget.value)}
            onKeyDown={(e) => e.key === "Escape" && setText("")}
          />
        </div>
        <DropdownMenu>
          <Tooltip>
            <TooltipTrigger asChild>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon-sm" aria-label="Group sessions by">
                  <ListTreeIcon />
                </Button>
              </DropdownMenuTrigger>
            </TooltipTrigger>
            <TooltipContent>Group by {GROUPINGS.find((g) => g.value === grouping)?.label.toLowerCase()}</TooltipContent>
          </Tooltip>
          <DropdownMenuContent align="end" className="w-44">
            <DropdownMenuLabel>Group by</DropdownMenuLabel>
            <DropdownMenuRadioGroup value={grouping} onValueChange={(v) => setGrouping(v as TreeGrouping)}>
              {GROUPINGS.map((g) => (
                <DropdownMenuRadioItem key={g.value} value={g.value}>
                  {g.label}
                </DropdownMenuRadioItem>
              ))}
            </DropdownMenuRadioGroup>
          </DropdownMenuContent>
        </DropdownMenu>
        <RefreshButton onClick={() => setReloads((n) => n + 1)} />
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="flex flex-col gap-0.5 pr-2 pb-2" role="tree" aria-label="Sessions">
          {!searching && recent.length > 0 && (
            <div role="group" aria-label="Recent sessions" className="mb-1 border-b pb-1">
              <button
                type="button"
                className="flex h-7 w-full items-center gap-1.5 rounded-md pr-2 pl-1 text-left text-xs font-medium text-muted-foreground hover:bg-accent [&_svg]:size-3.5"
                aria-expanded={isOpen("recent")}
                onClick={() => toggle("recent")}
              >
                <ChevronRightIcon className={cn("transition-transform", isOpen("recent") && "rotate-90")} />
                <ClockIcon />
                Recent
              </button>
              {isOpen("recent") &&
                recent.map((s) => (
                  <SessionRow
                    key={`recent:${s.id}`}
                    session={s}
                    via={jumpChain(s.id, links).names}
                    depth={1}
                    picked={picked === `recent:${s.id}`}
                    checked={pickSet.has(s.id)}
                    open={openSessions.has(s.id)}
                    reach={reach.enabled ? (reach.states.get(s.id) ?? null) : undefined}
                    onPick={() => setPicked(`recent:${s.id}`)}
                    onToggleCheck={() => togglePicks([s.id])}
                    onOpen={() => onOpen(s)}
                    onHostDetails={onHostDetails && (() => onHostDetails(s))}
                    vms={vms}
                  />
                ))}
            </div>
          )}
          {tree?.nodes.map((node) => group(node, 0))}
          {tree?.sessions.map((id) => row(id, 0, "top"))}
          {tree && tree.records.length === 0 && (
            <p className="px-2 py-4 text-sm text-muted-foreground">
              {searching ? "No session matches." : "No saved sessions yet. Use New terminal and tick Save as session."}
            </p>
          )}
        </div>
      </ScrollArea>
      {!reach.enabled && tree && tree.records.length > 0 && (
        <p className="text-xs text-muted-foreground">Reachability checks are off (Settings, Terminal).</p>
      )}
      {/* UX-09: shown once; the picks show in Compare hosts. */}
      {tree && tree.records.length > 1 && picks.length === 0 && (
        <Tip id="terminal.treePicks">Ctrl+click sessions or a folder to run one command on them.</Tip>
      )}
    </div>
  );
}

function ReachDot({ reach }: { reach: Reachability | null | undefined }) {
  if (reach === undefined) return null;
  if (reach === null)
    return <span className="size-1.5 shrink-0 rounded-full bg-muted-foreground/40" aria-label="Not checked yet" />;
  // SS-07: a ring is a jump host's state, not the session's own.
  if (reach.via)
    return reach.state === "up" ? (
      <span
        className="size-2 shrink-0 rounded-full border-[1.5px] border-success"
        aria-label={reach.connected ? `Connected through ${reach.via}` : `Through ${reach.via}, which is reachable`}
      />
    ) : (
      <span
        className="size-2 shrink-0 rounded-full border-[1.5px] border-destructive"
        aria-label={`Through ${reach.via}, which is not reachable`}
      />
    );
  return reach.state === "up" ? (
    <span
      className="size-1.5 shrink-0 rounded-full bg-success"
      aria-label={reach.connected ? "Connected" : "Port open"}
    />
  ) : (
    <span className="size-1.5 shrink-0 rounded-full bg-destructive" aria-label="Not reachable" />
  );
}

function reachText(reach: Reachability | null | undefined) {
  if (!reach) return null;
  const when = formatWhen(reach.checkedAt);
  if (reach.connected) {
    return reach.via
      ? `Connected through ${reach.via} (a terminal, the dashboard or the Containers page), so it is not probed.`
      : "Connected (a terminal, the dashboard or the Containers page), so it is not probed.";
  }
  // Up without a latency: no probe since a connection closed.
  const up =
    reach.latencyMs === null ? `connected until ${when}` : `port open (${reach.latencyMs} ms), checked ${when}`;
  const down = `${reach.reason ?? "no answer"}, checked ${when}. Checked less often while it stays down.`;
  if (reach.via) {
    return reach.state === "up"
      ? `Reached through ${reach.via}: ${up}. The session itself is not checked from this PC.`
      : `Reached through ${reach.via}, which is not reachable: ${down}`;
  }
  return reach.state === "up" ? `${up.charAt(0).toUpperCase()}${up.slice(1)}` : `Not reachable: ${down}`;
}

function SessionRow({
  session,
  via,
  depth,
  picked,
  checked,
  open,
  reach,
  onPick,
  onToggleCheck,
  onOpen,
  onHostDetails,
  vms,
}: {
  session: SessionRecord;
  /** SS-07: the jump hosts on the way, first one first. */
  via: string[];
  vms: ReadonlyMap<string, EnvironmentOfVm>;
  depth: number;
  picked: boolean;
  /** BX-03: picked for Compare output. */
  checked: boolean;
  open: boolean;
  /** `undefined`: checks are off; `null`: not checked yet. */
  reach: Reachability | null | undefined;
  onPick: () => void;
  onToggleCheck: () => void;
  onOpen: () => void;
  onHostDetails?: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const seen =
    session.lastHostname || session.lastIp ? [session.lastHostname, session.lastIp].filter(Boolean).join(" · ") : null;
  const applied = appliedEnvironment(session, vms);
  // SS-12: Compare hosts and host details are for SSH sessions.
  const ssh = (session.kind?.protocol ?? "ssh") === "ssh";
  const env = applied.environment;
  const tooltip = [
    `${session.name} (${sessionAddress(session)})`,
    env !== "none" && `Environment: ${environmentText(applied)}`,
    via.length > 0 && `Through ${routeText(via)}`,
    seen && `Last seen as ${seen}, ${formatWhen(session.lastSeenAt)}`,
    reachText(reach),
    checked && "Picked for Compare hosts",
    ssh ? "Double-click to open; Ctrl+click to pick for Compare hosts" : "Double-click to open",
  ]
    .filter(Boolean)
    .join("\n");
  return (
    <div
      ref={ref}
      role="treeitem"
      aria-selected={picked}
      tabIndex={0}
      title={tooltip}
      className={cn(
        "group/row flex h-7 min-w-0 cursor-default items-center gap-1.5 rounded-md pr-1 text-sm select-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
        picked && "bg-accent",
        checked && "bg-primary/10",
      )}
      style={{ paddingLeft: `${0.5 + depth * 0.75}rem` }}
      onClick={(e) => (ssh && (e.ctrlKey || e.metaKey) ? onToggleCheck() : onPick())}
      onDoubleClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === "Enter") onOpen();
      }}
    >
      {checked ? (
        <CheckIcon className="size-3 shrink-0 text-primary" aria-label="Picked for Compare hosts" />
      ) : (
        <ReachDot reach={reach} />
      )}
      {session.color ? <ColorDot color={session.color} className="size-2" /> : <span className="size-2 shrink-0" />}
      <KindIcon protocol={session.kind?.protocol ?? "ssh"} />
      <span className={cn("truncate", open && "font-medium")}>{session.name}</span>
      {via.length > 0 && (
        <span className="max-w-24 shrink truncate text-[11px] text-muted-foreground">{viaText(via)}</span>
      )}
      {env !== "none" && (
        <span
          className={cn(
            "shrink-0 text-[10px] font-semibold uppercase",
            ENV_TEXT[env],
            applied.from && "underline decoration-dotted underline-offset-2",
          )}
        >
          {env}
        </span>
      )}
      <RowMenu
        label={session.name}
        align="start"
        className="ml-auto size-6 opacity-0 group-hover/row:opacity-100 focus-visible:opacity-100 data-[state=open]:opacity-100"
      >
        <DropdownMenuItem onSelect={onOpen}>{openLabel(session)}</DropdownMenuItem>
        {ssh && (
          <DropdownMenuItem onSelect={onToggleCheck}>
            {checked ? "Unpick for Compare hosts" : "Pick for Compare hosts"}
          </DropdownMenuItem>
        )}
        <DropdownMenuItem
          onSelect={() => void navigator.clipboard?.writeText(sessionAddress(session)).catch(() => undefined)}
        >
          Copy the address
        </DropdownMenuItem>
        {onHostDetails && ssh && <DropdownMenuItem onSelect={onHostDetails}>Host details…</DropdownMenuItem>}
        {session.kind?.protocol !== "serial" && (
          <ToolboxMenu target={{ kind: "session", sessionId: session.id, label: session.name }} />
        )}
      </RowMenu>
    </div>
  );
}

/** SS-12: what opening a session does, for its row menu. */
function openLabel(session: SessionRecord): string {
  const kind = session.kind ?? { protocol: "ssh" };
  if (kind.protocol === "rdp")
    return session.jumpSessionId ? "Open the remote desktop (tunnel tab)" : "Open the remote desktop";
  if (kind.protocol === "vnc")
    return session.jumpSessionId ? "Open in the VNC viewer (tunnel tab)" : "Open in the VNC viewer";
  return "Open in a new tab";
}

/** SS-12: a small icon for a session that is not SSH. */
function KindIcon({ protocol }: { protocol: string }) {
  const Icon =
    protocol === "rdp" || protocol === "vnc"
      ? MonitorIcon
      : protocol === "serial"
        ? UsbIcon
        : protocol === "telnet"
          ? NetworkIcon
          : null;
  if (!Icon) return null;
  return <Icon className="size-3 shrink-0 text-muted-foreground" aria-label={kindLabel(protocol)} />;
}
