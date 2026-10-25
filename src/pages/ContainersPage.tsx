// The Containers page (CT-01, CT-02): Docker and Podman on saved sessions marked as container hosts, and Docker Desktop
// on this PC. The hosts are on the left with their engines; the right shows the chosen engine's containers (name,
// image, state, ports, uptime, CPU and memory), images, volumes and networks. A click on a container's name opens its
// details beside the list (ContainerDetailsPanel: overview, logs, stats).
//
// Reads go to the core, which runs the host's CLI over the session's SSH connection (kept a few minutes between reads)
// or docker.exe on this PC. Nothing is read in the background except the open host's stats every 10 s (one read for
// the list and the details panel's Stats tab) and a followed log, and those only while this page shows and the window
// is visible, each read timed from when the last one finished (src/hooks/use-poll.ts). Every change (start, stop,
// restart, pause, remove, pull, prune) is a command for the bus: the policy engine rates it and the approval dialog
// previews it (AP-02). Marking a host is the app's own data, audited.

import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import {
  BoxIcon,
  ChevronDownIcon,
  DownloadIcon,
  EllipsisIcon,
  PauseIcon,
  PlayIcon,
  PlusIcon,
  RefreshCwIcon,
  RotateCwIcon,
  ShieldIcon,
  SquareIcon,
  SquareTerminalIcon,
  Trash2Icon,
  TriangleAlertIcon,
} from "lucide-react";
import { usePanelRef } from "react-resizable-panels";
import { toast } from "sonner";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "@/components/ui/resizable";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ContainerStateBadge, EngineBadge, EnvBadge } from "@/components/Badges";
import { ContainerDetailsPanel, type ContainerView } from "@/components/ContainerDetailsPanel";
import { ContainerHostDialog } from "@/components/ContainerHostDialog";
import { ImagesTab, NetworksTab, VolumesTab } from "@/components/ContainerResources";
import { NameDialog } from "@/components/NameDialog";
import { useReadOnlyReason } from "@/components/Presentation";
import { ReasonLine, WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorCode,
  errorMessage,
  type Command,
  type ContainerHost,
  type ContainerHostInfo,
  type ContainerList,
  type ContainerOp,
  type ContainerSummary,
  type EngineKind,
  type ImageSummary,
  type NetworkSummary,
  type PruneWhat,
  type SubmitOutcome,
  type VolumeSummary,
} from "@/lib/api";
import {
  actionReason,
  ACTIONS,
  applicable,
  containerTarget,
  ENGINE_LABEL,
  engineKey,
  filterContainers,
  formatBytes,
  hostActionReason,
  hostKey,
  imageReferenceProblem,
  portTexts,
  PRUNE_LABEL,
  pruneReason,
  sameHost,
  sentence,
  shellReason,
  STATS_POLL_MS,
  statsFor,
  type ContainerAction,
  type StateFilter,
  type StatsRead,
} from "@/lib/containers";
import { plural } from "@/lib/format";
import { shouldPoll } from "@/lib/polling";
import { usePoll, useVisibility } from "@/hooks/use-poll";
import { cn } from "@/lib/utils";
import { keepContainerHosts, rememberContainers } from "@/lib/container-cache";

/** R10: a container to show (a search result): its host and engine chosen, its details open. */
export interface ContainerRequest {
  host: ContainerHost;
  engine: EngineKind;
  containerId: string;
  n: number;
}

/** "Open a shell": the terminal tab to open for a container. */
export interface ContainerShellRequest {
  sessionId: string;
  engine: EngineKind;
  containerId: string;
  /** The tab's title until the core's own arrives. */
  title: string;
}

interface Props {
  /** True while the page is shown: the open host's stats and a followed log are read only then. */
  active: boolean;
  /** Shows the approval dialog for commands the policy engine says need one. */
  onSubmitted: (outcome: SubmitOutcome) => void;
  onOpenShell: (request: ContainerShellRequest) => void;
  onOpenSettings: () => void;
  /** Changes when a container action finished or this PC's docker.exe changed (P2): the lists are read again. */
  refreshKey: number;
  /** R10: a container to show. */
  request?: ContainerRequest | null;
}

type Tab = "containers" | "images" | "volumes" | "networks";
type Current = { host: ContainerHost; engine: EngineKind };
type Loaded<T> = { key: string; value: T } | { key: string; error: { code?: string; message: string } };

const DETAILS_WIDTH = 40;
const DIVIDER_ID = "containers-details-divider";
const BUTTONS: { action: ContainerAction; icon: typeof PlayIcon }[] = [
  { action: "start", icon: PlayIcon },
  { action: "stop", icon: SquareIcon },
  { action: "restart", icon: RotateCwIcon },
  { action: "pause", icon: PauseIcon },
  { action: "unpause", icon: PlayIcon },
];

function hostLabel(host: ContainerHostInfo) {
  return host.host.kind === "thisPc" ? "This PC" : host.name;
}

export function ContainersPage({
  active,
  onSubmitted,
  onOpenShell,
  onOpenSettings,
  refreshKey,
  request = null,
}: Props) {
  const readOnlyReason = useReadOnlyReason();
  const readOnly = readOnlyReason !== null;
  const [hosts, setHosts] = useState<ContainerHostInfo[] | null>(null);
  const [hostsError, setHostsError] = useState<string | null>(null);
  const [current, setCurrent] = useState<Current | null>(null);
  const [tab, setTab] = useState<Tab>("containers");
  const [reads, setReads] = useState(0);
  const [hostsVersion, setHostsVersion] = useState(0);
  const [list, setList] = useState<Loaded<ContainerList> | null>(null);
  const [stats, setStats] = useState<StatsRead | null>(null);
  const [images, setImages] = useState<Loaded<ImageSummary[]> | null>(null);
  const [volumes, setVolumes] = useState<Loaded<VolumeSummary[]> | null>(null);
  const [networks, setNetworks] = useState<Loaded<NetworkSummary[]> | null>(null);
  const [text, setText] = useState("");
  const [state, setState] = useState<StateFilter>("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [anchor, setAnchor] = useState<number | null>(null);
  const [detail, setDetail] = useState<string | null>(null);
  const [view, setView] = useState<ContainerView>("overview");
  const [submitting, setSubmitting] = useState(false);
  const [dialog, setDialog] = useState<{ kind: "host"; sessionId: string | null } | { kind: "pull" } | null>(null);

  // R10: a container asked for (the palette's search): its host and engine, the containers tab, its details.
  const [requestHandled, setRequestHandled] = useState(request?.n ?? 0);
  if (request && request.n !== requestHandled) {
    setRequestHandled(request.n);
    setCurrent({ host: request.host, engine: request.engine });
    setTab("containers");
    setDetail(request.containerId);
  }

  // The hosts: the marked sessions, then this PC when Docker Desktop is there. No connection is made.
  useEffect(() => {
    if (!active) return;
    let stale = false;
    api.containerHosts().then(
      (found) => {
        if (stale) return;
        setHosts(found);
        setHostsError(null);
        // QL-20: search forgets the containers of hosts that are no longer marked.
        keepContainerHosts(found);
        setCurrent((cur) => {
          const still = cur && found.find((h) => sameHost(h.host, cur.host));
          if (still && still.engines.some((e) => e.engine === cur.engine)) return cur;
          const first = found[0];
          return first ? { host: first.host, engine: first.engines[0]?.engine ?? "docker" } : null;
        });
      },
      (err) => {
        if (!stale) setHostsError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [active, hostsVersion, refreshKey]);

  const info = current ? hosts?.find((h) => sameHost(h.host, current.host)) : undefined;
  const engineInfo = info?.engines.find((e) => e.engine === current?.engine);
  const key = current ? `${engineKey(current.host, current.engine)}:${reads}:${refreshKey}` : "";

  // The open host's containers: when it is chosen, on Refresh, after a job.
  useEffect(() => {
    if (!current || !active) return;
    let stale = false;
    api.containers(current.host, current.engine).then(
      (value) => {
        if (stale) return;
        setList({ key, value });
        const ids = new Set(value.containers.map((c) => c.id));
        setSelected((prev) => new Set([...prev].filter((id) => ids.has(id))));
        setDetail((open) => (open && ids.has(open) ? open : null));
      },
      (err) => {
        if (!stale) setList({ key, error: { code: errorCode(err), message: errorMessage(err) } });
      },
    );
    return () => {
      stale = true;
    };
  }, [current, key, active]);

  // QL-20: the list just read, for the palette to find without a login of its own.
  const hostName = info?.name;
  useEffect(() => {
    if (!current || !list || list.key !== key || !("value" in list)) return;
    rememberContainers({
      host: current.host,
      engine: current.engine,
      hostName: hostName ?? "a host",
      containers: list.value.containers,
      readAt: list.value.readAt,
    });
  }, [current, list, key, hostName]);

  // Their resource use, now and every 10 s while the page shows the containers and the window is visible: one read at a
  // time, for the list and the details panel's Stats tab alike. Refresh (or another host) reads at once.
  const visibility = useVisibility();
  const polling = shouldPoll(active, visibility);
  const readStats = useCallback(
    async (live: () => boolean) => {
      if (!current) return;
      const statsKey = engineKey(current.host, current.engine);
      try {
        const list = await api.containerStats(current.host, current.engine);
        if (live()) setStats({ key: statsKey, list, error: null, readAt: Date.now() });
      } catch (err) {
        if (live()) setStats({ key: statsKey, list: [], error: errorMessage(err), readAt: Date.now() });
        throw err;
      }
    },
    [current],
  );
  usePoll(readStats, {
    enabled: polling && current !== null && tab === "containers",
    intervalMs: STATS_POLL_MS,
    resetKey: key,
  });

  // Images, volumes and networks: when their tab opens (volumes also for the images tab's "used by").
  useEffect(() => {
    if (!current || !active || tab === "containers") return;
    let stale = false;
    const done =
      <T,>(set: (v: Loaded<T>) => void) =>
      (value: T) => {
        if (!stale) set({ key, value });
      };
    const failed =
      <T,>(set: (v: Loaded<T>) => void) =>
      (err: unknown) => {
        if (!stale) set({ key, error: { code: errorCode(err), message: errorMessage(err) } });
      };
    if (tab === "images") api.containerImages(current.host, current.engine).then(done(setImages), failed(setImages));
    if (tab === "volumes")
      api.containerVolumes(current.host, current.engine).then(done(setVolumes), failed(setVolumes));
    if (tab === "networks")
      api.containerNetworks(current.host, current.engine).then(done(setNetworks), failed(setNetworks));
    return () => {
      stale = true;
    };
  }, [current, active, tab, key]);

  const containers = useMemo(
    () => (list && list.key === key && "value" in list ? list.value.containers : []),
    [list, key],
  );
  const listError = list && list.key === key && "error" in list ? list.error : null;
  const loading = current !== null && (!list || list.key !== key);
  const shown = useMemo(() => filterContainers(containers, text, state), [containers, text, state]);
  const picked = useMemo(() => containers.filter((c) => selected.has(c.id)), [containers, selected]);
  const statsRead = stats && current && stats.key === engineKey(current.host, current.engine) ? stats : null;
  const currentStats = statsRead?.list ?? [];
  const detailContainer = detail ? containers.find((c) => c.id === detail) : undefined;
  const detailOpen = detailContainer !== undefined;
  const context = { readOnly, protectedHost: info?.protected ?? false, submitting };

  // The details panel folds away when no container is open (it stays mounted, so the list keeps its place).
  const detailsPanel = usePanelRef();
  const detailsWidth = useRef(DETAILS_WIDTH);
  useEffect(() => {
    const panel = detailsPanel.current;
    if (!panel) return;
    if (detailOpen && panel.isCollapsed()) panel.resize(`${detailsWidth.current}%`);
    if (!detailOpen && !panel.isCollapsed()) panel.collapse();
  }, [detailOpen, detailsPanel, tab]);

  const choose = useCallback((next: Current) => {
    setCurrent(next);
    setSelected(new Set());
    setAnchor(null);
    setDetail(null);
  }, []);

  async function submit(command: Command) {
    setSubmitting(true);
    try {
      onSubmitted(await api.submit(command));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  function act(action: ContainerAction) {
    if (!current) return;
    const targets = applicable(action, picked).map((c) =>
      containerTarget(current.host, current.engine, { kind: "container", id: c.id }),
    );
    const left = picked.length - targets.length;
    if (left > 0)
      toast.info(
        `${plural(left, "selected container")} left out: ${ACTIONS[action].label.toLowerCase()} doesn't fit them.`,
      );
    void submit({ type: "container", targets, op: ACTIONS[action].op });
  }

  function onEngine(op: ContainerOp) {
    if (!current) return;
    void submit({
      type: "container",
      targets: [containerTarget(current.host, current.engine, { kind: "engine" })],
      op,
    });
  }

  function toggle(index: number, e: MouseEvent) {
    const id = shown[index].id;
    setSelected((prev) => {
      const next = new Set(prev);
      if (e.shiftKey && anchor !== null) {
        const [from, to] = anchor < index ? [anchor, index] : [index, anchor];
        for (let i = from; i <= to; i++) next.add(shown[i].id);
      } else if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
    setAnchor(index);
  }

  function openShell(container: ContainerSummary) {
    if (!current || current.host.kind !== "session" || !info) return;
    onOpenShell({
      sessionId: current.host.sessionId,
      engine: current.engine,
      containerId: container.id,
      title: `${container.name} (${info.name})`,
    });
  }

  const allShownSelected = shown.length > 0 && shown.every((c) => selected.has(c.id));
  const hostReason = hostActionReason(info, { readOnly, submitting });
  const onePicked = picked.length === 1 ? picked[0] : undefined;
  const shellOff = shellReason(onePicked, current?.host ?? null);

  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-0 flex-1">
          <h2 className="text-lg font-semibold">Containers</h2>
          <p className="text-sm text-muted-foreground">
            Docker and Podman on the sessions you mark as container hosts, and Docker Desktop on this PC.
          </p>
        </div>
        <WhyDisabled reason={readOnlyReason}>
          <Button variant="outline" onClick={() => setDialog({ kind: "host", sessionId: null })} disabled={readOnly}>
            <PlusIcon data-icon="inline-start" />
            Add a host…
          </Button>
        </WhyDisabled>
      </div>

      {hostsError && (
        <Alert variant="destructive">
          <TriangleAlertIcon />
          <AlertTitle>Could not read the container hosts</AlertTitle>
          <AlertDescription>{sentence(hostsError)}</AlertDescription>
        </Alert>
      )}

      {hosts && hosts.length === 0 ? (
        <Empty className="border">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <BoxIcon />
            </EmptyMedia>
            <EmptyTitle>No container hosts yet</EmptyTitle>
            <EmptyDescription>
              Mark a saved session as a Docker or Podman host, or let Remotely detect what the host has. Docker Desktop
              on this PC shows here when it is installed (or its docker.exe is set in Settings).
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent className="flex-row justify-center">
            <WhyDisabled reason={readOnlyReason}>
              <Button onClick={() => setDialog({ kind: "host", sessionId: null })} disabled={readOnly}>
                <PlusIcon data-icon="inline-start" />
                Add a host…
              </Button>
            </WhyDisabled>
            <Button variant="outline" onClick={onOpenSettings}>
              Docker Desktop path…
            </Button>
          </EmptyContent>
        </Empty>
      ) : (
        <div className="flex min-h-0 flex-1 gap-4">
          <nav aria-label="Container hosts" className="flex w-60 shrink-0 flex-col gap-1 overflow-auto">
            {!hosts && Array.from({ length: 3 }, (_, i) => <Skeleton key={i} className="h-14" />)}
            {hosts?.map((h) => (
              <div
                key={hostKey(h.host)}
                className={cn(
                  "group rounded-lg border p-2",
                  current && sameHost(current.host, h.host) && "border-primary bg-accent/40",
                )}
              >
                <div className="flex items-start gap-1">
                  <button
                    type="button"
                    className="min-w-0 flex-1 text-left"
                    onClick={() => choose({ host: h.host, engine: h.engines[0]?.engine ?? "docker" })}
                    aria-current={current && sameHost(current.host, h.host) ? "true" : undefined}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="truncate font-medium">{hostLabel(h)}</span>
                      {h.protected && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <ShieldIcon className="size-3.5 shrink-0 text-tier-high" aria-label="Protected" />
                          </TooltipTrigger>
                          <TooltipContent>Protected: actions skip this host until its VM is unprotected</TooltipContent>
                        </Tooltip>
                      )}
                      {h.environment !== "none" && <EnvBadge env={h.environment} />}
                    </div>
                    {h.hostname && (
                      <div className="truncate text-xs text-muted-foreground" data-mask="host">
                        {h.hostname}
                      </div>
                    )}
                    {h.via.length > 0 && (
                      <div className="truncate text-xs text-muted-foreground">via {h.via.join(" → ")}</div>
                    )}
                    {h.host.kind === "thisPc" && <div className="text-xs text-muted-foreground">Docker Desktop</div>}
                  </button>
                  {h.host.kind === "session" && (
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button size="icon-xs" variant="ghost" aria-label={`${h.name}: more`}>
                          <EllipsisIcon />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem
                          disabled={readOnly}
                          onSelect={() =>
                            h.host.kind === "session" && setDialog({ kind: "host", sessionId: h.host.sessionId })
                          }
                        >
                          <div>
                            Engines and sudo…
                            <ReasonLine reason={readOnlyReason} />
                          </div>
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={readOnly}
                          onSelect={() => {
                            if (h.host.kind !== "session") return;
                            const id = h.host.sessionId;
                            void api.setContainerMarks(id, []).then(
                              () => setHostsVersion((v) => v + 1),
                              (err) => toast.error(errorMessage(err)),
                            );
                          }}
                        >
                          <div>
                            Remove from container hosts
                            <ReasonLine reason={readOnlyReason} />
                          </div>
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  )}
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {h.engines.map((e) => {
                    const on = current && sameHost(current.host, h.host) && current.engine === e.engine;
                    return (
                      <Tooltip key={e.engine}>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => choose({ host: h.host, engine: e.engine })}
                            className={cn("rounded-md", on && "ring-2 ring-primary")}
                            aria-pressed={on ? true : false}
                          >
                            <EngineBadge engine={e.engine} sudo={e.sudo.kind !== "off"} />
                          </button>
                        </TooltipTrigger>
                        <TooltipContent>
                          {ENGINE_LABEL[e.engine]}, {e.runs}
                        </TooltipContent>
                      </Tooltip>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>

          <section className="flex min-h-0 min-w-0 flex-1 flex-col gap-3" aria-label="What runs on the host">
            {!current || !info ? (
              <Empty className="border">
                <EmptyHeader>
                  <EmptyTitle>Choose a host</EmptyTitle>
                  <EmptyDescription>Its containers, images, volumes and networks show here.</EmptyDescription>
                </EmptyHeader>
              </Empty>
            ) : (
              <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)} className="flex min-h-0 flex-1 flex-col gap-3">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 font-medium">
                      {hostLabel(info)} <EngineBadge engine={current.engine} sudo={engineInfo?.sudo.kind !== "off"} />
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {ENGINE_LABEL[current.engine]} {engineInfo?.runs ?? ""}
                      {list && list.key === key && "value" in list && (
                        <> · read {new Date(list.value.readAt).toLocaleTimeString()}</>
                      )}
                    </div>
                  </div>
                  <TabsList className="ml-auto">
                    <TabsTrigger value="containers">
                      Containers
                      {containers.length > 0 && (
                        <Badge variant="secondary" className="h-4 min-w-4 px-1 tabular-nums">
                          {containers.length}
                        </Badge>
                      )}
                    </TabsTrigger>
                    <TabsTrigger value="images">Images</TabsTrigger>
                    <TabsTrigger value="volumes">Volumes</TabsTrigger>
                    <TabsTrigger value="networks">Networks</TabsTrigger>
                  </TabsList>
                  <Button
                    variant="outline"
                    size="icon"
                    aria-label="Read the host again"
                    onClick={() => setReads((r) => r + 1)}
                    disabled={loading}
                  >
                    <RefreshCwIcon className={cn(loading && "animate-spin")} />
                  </Button>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline">
                        Host
                        <ChevronDownIcon data-icon="inline-end" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-72">
                      <DropdownMenuLabel>{hostLabel(info)}</DropdownMenuLabel>
                      <DropdownMenuItem disabled={hostReason !== null} onSelect={() => setDialog({ kind: "pull" })}>
                        <DownloadIcon />
                        <div>
                          Pull an image…
                          <ReasonLine reason={hostReason} />
                        </div>
                      </DropdownMenuItem>
                      <DropdownMenuSub>
                        <DropdownMenuSubTrigger disabled={hostReason !== null}>
                          <Trash2Icon />
                          Prune
                        </DropdownMenuSubTrigger>
                        <DropdownMenuSubContent className="w-72">
                          {(["containers", "images", "buildCache", "volumes"] as PruneWhat[]).map((what) => {
                            const reason = hostReason ?? pruneReason(what, current.engine);
                            return (
                              <DropdownMenuItem
                                key={what}
                                disabled={reason !== null}
                                onSelect={() => onEngine({ kind: "prune", what })}
                                variant={what === "volumes" ? "destructive" : "default"}
                              >
                                <div>
                                  {PRUNE_LABEL[what]}…
                                  <ReasonLine reason={reason} />
                                </div>
                              </DropdownMenuItem>
                            );
                          })}
                        </DropdownMenuSubContent>
                      </DropdownMenuSub>
                      {hostReason && (
                        <>
                          <DropdownMenuSeparator />
                          <div className="px-2 py-1">
                            <ReasonLine reason={hostReason} />
                          </div>
                        </>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>

                {listError && (
                  <Alert variant="destructive">
                    <TriangleAlertIcon />
                    <AlertTitle>Could not read {hostLabel(info)}</AlertTitle>
                    <AlertDescription>{sentence(listError.message)}</AlertDescription>
                    {(listError.code === "container_needs_sudo" || listError.code === "no_sudo_password") &&
                      current.host.kind === "session" && (
                        <AlertAction>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={readOnly}
                            onClick={() =>
                              current.host.kind === "session" &&
                              setDialog({ kind: "host", sessionId: current.host.sessionId })
                            }
                          >
                            Use sudo…
                          </Button>
                        </AlertAction>
                      )}
                    {listError.code === "container_cli_missing" && current.host.kind === "thisPc" && (
                      <AlertAction>
                        <Button size="sm" variant="outline" onClick={onOpenSettings}>
                          Settings
                        </Button>
                      </AlertAction>
                    )}
                    {/* MO-02, CT-01: a refused login or sudo is not tried again until the user asks. */}
                    {(listError.code === "login_parked" || listError.code === "logins_capped") &&
                      current.host.kind === "session" && (
                        <AlertAction>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              if (current.host.kind !== "session") return;
                              api.backgroundLoginRetry(current.host.sessionId).then(
                                () => setReads((r) => r + 1),
                                (err) => toast.error(errorMessage(err)),
                              );
                            }}
                          >
                            Retry
                          </Button>
                        </AlertAction>
                      )}
                  </Alert>
                )}

                <TabsContent value="containers" className="flex min-h-0 flex-1 flex-col gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Input
                      value={text}
                      onChange={(e) => setText(e.target.value)}
                      placeholder="Find a container, image, project or port"
                      aria-label="Find containers"
                      className="w-72"
                    />
                    <ToggleGroup
                      type="single"
                      variant="outline"
                      size="sm"
                      value={state}
                      onValueChange={(v) => v && setState(v as StateFilter)}
                      aria-label="Show"
                    >
                      <ToggleGroupItem value="all">All</ToggleGroupItem>
                      <ToggleGroupItem value="running">Running</ToggleGroupItem>
                      <ToggleGroupItem value="paused">Paused</ToggleGroupItem>
                      <ToggleGroupItem value="stopped">Stopped</ToggleGroupItem>
                    </ToggleGroup>
                    <div className="ml-auto flex flex-wrap items-center gap-1.5">
                      {picked.length > 0 && (
                        <span className="text-sm text-muted-foreground">{plural(picked.length, "selected")}</span>
                      )}
                      {BUTTONS.map(({ action, icon: Icon }) => {
                        const reason = actionReason(action, picked, context);
                        return (
                          <WhyDisabled key={action} reason={reason}>
                            <Button size="sm" variant="outline" disabled={reason !== null} onClick={() => act(action)}>
                              <Icon data-icon="inline-start" />
                              {ACTIONS[action].label}
                            </Button>
                          </WhyDisabled>
                        );
                      })}
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button size="sm" variant="outline">
                            <Trash2Icon data-icon="inline-start" />
                            Remove
                            <ChevronDownIcon data-icon="inline-end" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-72">
                          {(["remove", "forceRemove"] as ContainerAction[]).map((action) => {
                            const reason = actionReason(action, picked, context);
                            return (
                              <DropdownMenuItem
                                key={action}
                                disabled={reason !== null}
                                variant="destructive"
                                onSelect={() => act(action)}
                              >
                                <div>
                                  {action === "remove"
                                    ? "Remove stopped containers…"
                                    : "Force remove (kills running ones)…"}
                                  <ReasonLine reason={reason} />
                                </div>
                              </DropdownMenuItem>
                            );
                          })}
                        </DropdownMenuContent>
                      </DropdownMenu>
                      <WhyDisabled reason={shellOff}>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={shellOff !== null}
                          onClick={() => onePicked && openShell(onePicked)}
                        >
                          <SquareTerminalIcon data-icon="inline-start" />
                          Open a shell
                        </Button>
                      </WhyDisabled>
                    </div>
                  </div>

                  <ResizablePanelGroup orientation="horizontal" id="containers-split" className="min-h-0 flex-1">
                    <ResizablePanel id="containers-list" minSize="30%">
                      <div className="h-full overflow-auto rounded-lg border">
                        {loading && containers.length === 0 ? (
                          <div className="grid gap-2 p-3">
                            {Array.from({ length: 5 }, (_, i) => (
                              <Skeleton key={i} className="h-6" />
                            ))}
                          </div>
                        ) : (
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead className="w-10">
                                  <Checkbox
                                    aria-label="Select all shown containers"
                                    checked={allShownSelected ? true : picked.length > 0 ? "indeterminate" : false}
                                    onCheckedChange={() =>
                                      setSelected(allShownSelected ? new Set() : new Set(shown.map((c) => c.id)))
                                    }
                                  />
                                </TableHead>
                                <TableHead>Name</TableHead>
                                {!detailOpen && <TableHead>Image</TableHead>}
                                <TableHead>State</TableHead>
                                {!detailOpen && <TableHead>Ports</TableHead>}
                                <TableHead>Up for</TableHead>
                                <TableHead className="text-right">CPU</TableHead>
                                <TableHead className="text-right">Memory</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {shown.map((c, i) => {
                                const s = statsFor(currentStats, c.id);
                                return (
                                  <TableRow
                                    key={c.id}
                                    data-state={selected.has(c.id) ? "selected" : undefined}
                                    onClick={(e) => toggle(i, e)}
                                    className={cn(
                                      "select-none",
                                      detail === c.id && "shadow-[inset_3px_0_0_var(--color-primary)]",
                                    )}
                                  >
                                    <TableCell>
                                      <Checkbox aria-label={`Select ${c.name}`} checked={selected.has(c.id)} />
                                    </TableCell>
                                    <TableCell className="whitespace-nowrap">
                                      <button
                                        type="button"
                                        className="text-left font-medium hover:underline"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          setDetail((open) => (open === c.id ? null : c.id));
                                        }}
                                        aria-expanded={detail === c.id}
                                      >
                                        {c.name}
                                      </button>
                                      {c.project && <div className="text-xs text-muted-foreground">{c.project}</div>}
                                    </TableCell>
                                    {!detailOpen && (
                                      <TableCell className="max-w-56 break-words whitespace-normal">
                                        {c.image}
                                      </TableCell>
                                    )}
                                    <TableCell>
                                      <ContainerStateBadge state={c.state} />
                                      {c.health === "unhealthy" && (
                                        <Badge
                                          variant="outline"
                                          className="ml-1 border-destructive/40 text-destructive"
                                        >
                                          unhealthy
                                        </Badge>
                                      )}
                                    </TableCell>
                                    {!detailOpen && (
                                      <TableCell className="font-mono text-xs whitespace-normal">
                                        {portTexts(c.ports).join(", ") || (
                                          <span className="text-muted-foreground">—</span>
                                        )}
                                      </TableCell>
                                    )}
                                    <TableCell className="text-sm whitespace-normal text-muted-foreground">
                                      {c.status}
                                    </TableCell>
                                    <TableCell className="text-right tabular-nums">
                                      {s?.cpuPct != null ? `${s.cpuPct.toFixed(1)} %` : "—"}
                                    </TableCell>
                                    <TableCell className="text-right tabular-nums">
                                      {formatBytes(s?.memBytes)}
                                    </TableCell>
                                  </TableRow>
                                );
                              })}
                              {shown.length === 0 && !loading && !listError && (
                                <TableRow>
                                  <TableCell colSpan={8} className="text-center text-muted-foreground">
                                    {containers.length === 0 ? "No containers on this host." : "No container matches."}
                                  </TableCell>
                                </TableRow>
                              )}
                            </TableBody>
                          </Table>
                        )}
                      </div>
                    </ResizablePanel>
                    <ResizableHandle
                      id={DIVIDER_ID}
                      withHandle
                      disabled={!detailOpen}
                      className={cn("mx-1", !detailOpen && "hidden")}
                    />
                    <ResizablePanel
                      id="containers-details"
                      panelRef={detailsPanel}
                      collapsible
                      collapsedSize="0%"
                      defaultSize="0%"
                      minSize="22rem"
                      maxSize="65%"
                      onResize={(size, _id, before) => {
                        if (size.asPercentage > 0) detailsWidth.current = size.asPercentage;
                        else if (before && before.asPercentage > 0 && document.activeElement?.id === DIVIDER_ID) {
                          setDetail(null);
                        }
                      }}
                    >
                      {detailContainer && (
                        <ContainerDetailsPanel
                          host={current.host}
                          hostName={hostLabel(info)}
                          engine={current.engine}
                          container={detailContainer}
                          view={view}
                          onViewChange={setView}
                          onClose={() => setDetail(null)}
                          refreshKey={reads + refreshKey}
                          stats={statsRead}
                          polling={polling}
                          onOpenShell={() => openShell(detailContainer)}
                        />
                      )}
                    </ResizablePanel>
                  </ResizablePanelGroup>
                  <p className="text-xs text-muted-foreground">
                    Click a row to select it, Shift+click to select a range; actions leave out containers they
                    don&apos;t fit. Click a name for its details, logs and stats.
                  </p>
                </TabsContent>

                <TabsContent value="images" className="min-h-0 overflow-auto">
                  <Resource loaded={images} key_={key}>
                    {(value) => (
                      <ImagesTab
                        images={value}
                        containers={containers}
                        removeReason={hostReason}
                        onRemove={(list) =>
                          void submit({
                            type: "container",
                            targets: list.map((i) =>
                              containerTarget(current.host, current.engine, { kind: "image", id: i.id }),
                            ),
                            op: { kind: "removeImage" },
                          })
                        }
                      />
                    )}
                  </Resource>
                </TabsContent>
                <TabsContent value="volumes" className="min-h-0 overflow-auto">
                  <Resource loaded={volumes} key_={key}>
                    {(value) => (
                      <VolumesTab
                        volumes={value}
                        containers={containers}
                        removeReason={hostReason}
                        onRemove={(list) =>
                          void submit({
                            type: "container",
                            targets: list.map((v) =>
                              containerTarget(current.host, current.engine, { kind: "volume", name: v.name }),
                            ),
                            op: { kind: "removeVolume" },
                          })
                        }
                      />
                    )}
                  </Resource>
                </TabsContent>
                <TabsContent value="networks" className="min-h-0 overflow-auto">
                  <Resource loaded={networks} key_={key}>
                    {(value) => <NetworksTab networks={value} />}
                  </Resource>
                </TabsContent>
              </Tabs>
            )}
          </section>
        </div>
      )}

      {dialog?.kind === "host" && (
        <ContainerHostDialog
          sessionId={dialog.sessionId}
          readOnly={readOnlyReason}
          onSaved={(sessionId, marks) => {
            setHostsVersion((v) => v + 1);
            setReads((r) => r + 1);
            if (marks.length > 0) choose({ host: { kind: "session", sessionId }, engine: marks[0].engine });
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "pull" && current && info && (
        <NameDialog
          title={`Pull an image on ${hostLabel(info)}`}
          description={`${ENGINE_LABEL[current.engine]} downloads it, or the newest version of its tag. Containers already made from an older version keep running it. Low tier; Prod hosts ask first.`}
          label="Image"
          submitLabel="Pull"
          maxLength={255}
          onSubmit={async (reference) => {
            const problem = imageReferenceProblem(reference);
            if (problem) throw new Error(problem);
            onSubmitted(
              await api.submit({
                type: "container",
                targets: [containerTarget(current.host, current.engine, { kind: "engine" })],
                op: { kind: "pull", reference },
              }),
            );
          }}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  );
}

/** A tab's list once read, its error, or a skeleton while it is read. */
function Resource<T>({
  loaded,
  key_,
  children,
}: {
  loaded: Loaded<T> | null;
  key_: string;
  children: (value: T) => React.ReactNode;
}) {
  if (!loaded || loaded.key !== key_) {
    return (
      <div className="grid gap-2">
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-6" />
        ))}
      </div>
    );
  }
  if ("error" in loaded) {
    return (
      <Alert variant="destructive">
        <TriangleAlertIcon />
        <AlertDescription>{sentence(loaded.error.message)}</AlertDescription>
      </Alert>
    );
  }
  return <>{children(loaded.value)}</>;
}
