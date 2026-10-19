// MO-03 dashboard: the host capacity panel (MO-04), then a grid of running VMs and watched hosts with
// host-side metrics (MO-01, no login, including each VM's share of this host's CPU and RAM) and Linux
// guest metrics over SSH (MO-02), sorting, filters and colour thresholds, and a drill-down with live
// charts. Everything here is a read: it goes straight
// to the core's metrics collector, never through the command bus. Actions open the command palette,
// which submits to the bus like every other page.

import { useCallback, useEffect, useMemo, useState, type KeyboardEvent } from "react";
import {
  CheckIcon,
  EllipsisIcon,
  EyeIcon,
  EyeOffIcon,
  GaugeIcon,
  MonitorIcon,
  PlusIcon,
  SearchIcon,
  ServerIcon,
  SlidersHorizontalIcon,
  SquareTerminalIcon,
  TriangleAlertIcon,
  ZapIcon,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Toggle } from "@/components/ui/toggle";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EnvBadge, StateBadge } from "@/components/Badges";
import { CapacityPanel } from "@/components/CapacityPanel";
import { GuestStatusBadge } from "@/components/GuestStatusBadge";
import { MetricCell } from "@/components/MetricBits";
import { MetricsDetail } from "@/components/MetricsDetail";
import { SortableHead } from "@/components/SortableHead";
import { AutoBadge } from "@/components/VmLinkControls";
import {
  api,
  errorMessage,
  type CollectorCost,
  type DashboardOverview,
  type DashboardRow,
  type Environment,
  type HostCapacity,
  type SessionRecord,
} from "@/lib/api";
import { plural } from "@/lib/format";
import {
  compareNullsLast as compare,
  DEFAULT_THRESHOLDS,
  formatBytes,
  formatPct,
  formatRate,
  HOST_SHARE_HINT,
  rowCpu,
  rowDiskIo,
  rowDiskUsed,
  rowHostCpu,
  rowHostMem,
  rowLevel,
  rowMemory,
  rowNetwork,
  SOURCE_LABEL,
  useThresholds,
  type Thresholds,
} from "@/lib/metrics";
import type { ResolvedTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

interface Props {
  active: boolean;
  theme: ResolvedTheme;
  /** From the command palette: open this row's drill-down. */
  focus: { key: string; n: number } | null;
  onConnect: (sessionId: string) => void;
  /** Opens the command palette on a VM's actions. */
  onActions: (vmxPath: string) => void;
  onOpenVms: () => void;
  onOpenSessions: () => void;
}

type SortKey =
  "name" | "state" | "cpu" | "memory" | "hostCpu" | "hostMem" | "diskIo" | "network" | "load" | "diskUsed" | "guest";
type Kind = "all" | "vm" | "session";

const COLUMNS: { key: SortKey; label: string; className?: string; hint?: string }[] = [
  { key: "name", label: "Name" },
  { key: "state", label: "State" },
  { key: "cpu", label: "CPU", className: "w-32" },
  { key: "memory", label: "Memory", className: "w-40" },
  { key: "hostCpu", label: "% of host CPU", className: "w-28", hint: HOST_SHARE_HINT.cpu },
  { key: "hostMem", label: "% of host RAM", className: "w-28", hint: HOST_SHARE_HINT.memory },
  { key: "diskIo", label: "Disk I/O" },
  { key: "network", label: "Network" },
  { key: "load", label: "Load" },
  { key: "diskUsed", label: "Disk used", className: "w-32" },
  { key: "guest", label: "Guest" },
];

const ENVIRONMENTS: { value: Environment | "all"; label: string }[] = [
  { value: "all", label: "All labels" },
  { value: "prod", label: "Prod" },
  { value: "staging", label: "Staging" },
  { value: "lab", label: "Lab" },
  { value: "none", label: "No label" },
];

function sum(a: number | null, b: number | null) {
  return a === null && b === null ? null : (a ?? 0) + (b ?? 0);
}

function sortValue(row: DashboardRow, key: SortKey): number | string | null {
  switch (key) {
    case "name":
      return row.name.toLowerCase();
    case "state":
      return row.powerState ?? "";
    case "cpu":
      return rowCpu(row).value;
    case "memory":
      return rowMemory(row).pct;
    case "hostCpu":
      return rowHostCpu(row);
    case "hostMem":
      return rowHostMem(row);
    case "diskIo": {
      const io = rowDiskIo(row);
      return sum(io.a, io.b);
    }
    case "network": {
      const net = rowNetwork(row);
      return sum(net.a, net.b);
    }
    case "load":
      return row.guest?.load1 ?? null;
    case "diskUsed":
      return rowDiskUsed(row).pct;
    case "guest":
      return row.guestStatus?.state ?? "";
  }
}

function CostLine({ cost }: { cost: CollectorCost | null }) {
  if (!cost || cost.rounds === 0) {
    return <span>Collecting the first round…</span>;
  }
  return (
    <span>
      Every {cost.intervalSecs} s · last round {Math.round(cost.roundMs)} ms (host side {Math.round(cost.hostMs)} ms
      {cost.guests > 0 || cost.guestMs > 1 ? `, guests ${Math.round(cost.guestMs)} ms` : ""}) ·{" "}
      <Tooltip>
        <TooltipTrigger asChild>
          <span tabIndex={0} className="underline decoration-dotted underline-offset-2">
            Remotely used {cost.appCpuPct === null ? "—" : formatPct(cost.appCpuPct)} of this host's CPU
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">
          The app's core process over the last round, collecting included, as a share of every CPU on this host (the way
          Task Manager shows processes). The target is under 5% with 50 VMs.
        </TooltipContent>
      </Tooltip>
    </span>
  );
}

function ThresholdsEditor({ value, onChange }: { value: Thresholds; onChange: (t: Thresholds) => void }) {
  const rows: { key: keyof Thresholds; label: string }[] = [
    { key: "cpu", label: "CPU" },
    { key: "memory", label: "Memory" },
    { key: "disk", label: "Disk used" },
  ];
  const set = (key: keyof Thresholds, i: 0 | 1, raw: string) => {
    const n = Math.round(Number(raw));
    if (!Number.isFinite(n) || n < 1 || n > 100) return;
    const pair: [number, number] = [...value[key]];
    pair[i] = n;
    if (pair[0] > pair[1]) return;
    onChange({ ...value, [key]: pair });
  };
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm">
          <SlidersHorizontalIcon /> Thresholds
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-72">
        <div className="grid grid-cols-[1fr_4rem_4rem] items-center gap-2 text-sm">
          <span />
          <span className="text-xs text-muted-foreground">Warning %</span>
          <span className="text-xs text-muted-foreground">Critical %</span>
          {rows.map((r) => (
            <div key={r.key} className="contents">
              <Label htmlFor={`th-${r.key}-0`}>{r.label}</Label>
              {([0, 1] as const).map((i) => (
                <Input
                  key={i}
                  id={`th-${r.key}-${i}`}
                  type="number"
                  min={1}
                  max={100}
                  aria-label={`${r.label} ${i === 0 ? "warning" : "critical"} threshold`}
                  defaultValue={value[r.key][i]}
                  onBlur={(e) => set(r.key, i, e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && set(r.key, i, e.currentTarget.value)}
                  className="h-8"
                />
              ))}
            </div>
          ))}
        </div>
        <div className="mt-3 flex justify-between gap-2">
          <p className="text-xs text-muted-foreground">Kept on this computer.</p>
          <Button variant="ghost" size="sm" onClick={() => onChange(DEFAULT_THRESHOLDS)}>
            Reset
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

function WatchPicker({ watched, onWatch }: { watched: Set<string>; onWatch: (id: string, watch: boolean) => void }) {
  const [open, setOpen] = useState(false);
  const [sessions, setSessions] = useState<SessionRecord[] | null>(null);
  useEffect(() => {
    if (!open) return;
    api.sessions().then(setSessions, (err) => toast.error(errorMessage(err)));
  }, [open]);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button size="sm">
          <PlusIcon /> Watch hosts
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-0">
        <Command>
          <CommandInput placeholder="Find a session…" />
          <CommandList>
            <CommandEmpty>{sessions === null ? "Loading…" : "No session matches."}</CommandEmpty>
            <CommandGroup heading="Guest metrics over SSH (Linux)">
              {(sessions ?? []).map((s) => {
                const on = watched.has(s.id);
                return (
                  <CommandItem
                    key={s.id}
                    value={`${s.name} ${s.host} ${s.tags.join(" ")}`}
                    onSelect={() => onWatch(s.id, !on)}
                  >
                    <CheckIcon className={cn("size-4", on ? "opacity-100" : "opacity-0")} />
                    <span className="truncate">{s.name}</span>
                    <span className="ml-auto truncate text-xs text-muted-foreground" data-mask="host">
                      {s.host}
                    </span>
                  </CommandItem>
                );
              })}
            </CommandGroup>
          </CommandList>
        </Command>
        <p className="border-t px-3 py-2 text-xs text-muted-foreground">
          Watching logs in with the session's saved login every 5 seconds and reads /proc. Nothing on the host changes.
        </p>
      </PopoverContent>
    </Popover>
  );
}

function RatePairCell({ a, b, labels }: { a: number | null; b: number | null; labels: [string, string] }) {
  if (a === null && b === null) return <span className="text-muted-foreground">—</span>;
  return (
    <div className="text-xs leading-5 tabular-nums">
      <div>
        <span className="text-muted-foreground">{labels[0]}</span> {formatRate(a)}
      </div>
      <div>
        <span className="text-muted-foreground">{labels[1]}</span> {formatRate(b)}
      </div>
    </div>
  );
}

export function DashboardPage({ active, theme, focus, onConnect, onActions, onOpenVms, onOpenSessions }: Props) {
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [capacity, setCapacity] = useState<HostCapacity | null>(null);
  const [round, setRound] = useState(0);
  const [cost, setCost] = useState<CollectorCost | null>(null);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "name", dir: 1 });
  const [text, setText] = useState("");
  const [kind, setKind] = useState<Kind>("all");
  const [env, setEnv] = useState<Environment | "all">("all");
  const [alertsOnly, setAlertsOnly] = useState(false);
  const [thresholds, setThresholds] = useThresholds();
  const [selected, setSelected] = useState<string | null>(null);

  // Each round the core finishes -> read what it collected (only while this page shows).
  useEffect(() => {
    const unlisten = api.onMetricsRound((c) => {
      setCost(c);
      setRound((n) => n + 1);
    });
    return () => void unlisten.then((stop) => stop());
  }, []);

  const load = useCallback(() => {
    api.metricsOverview().then(
      (o) => {
        setOverview(o);
        setCost(o.cost);
      },
      (err) => toast.error(errorMessage(err), { id: "dashboard-load" }),
    );
  }, []);

  useEffect(() => {
    if (active) load();
  }, [active, round, load]);

  // Capacity changes slowly: read when the page opens, then every third round (15 s).
  const capacityTick = Math.floor(round / 3);
  useEffect(() => {
    if (!active) return;
    api.metricsCapacity().then(setCapacity, () => setCapacity(null));
  }, [active, capacityTick]);

  // The palette asked to open a row: follow it once per request.
  const [seenFocus, setSeenFocus] = useState(focus);
  if (focus !== seenFocus) {
    setSeenFocus(focus);
    if (focus) setSelected(focus.key);
  }

  const watch = useCallback(
    async (sessionId: string, on: boolean) => {
      try {
        await api.metricsWatch(sessionId, on);
        toast.success(on ? "Watching the guest. The first reading arrives within a round." : "Stopped guest metrics");
        load();
      } catch (err) {
        toast.error(errorMessage(err));
      }
    },
    [load],
  );

  const rows = useMemo(() => overview?.rows ?? [], [overview]);
  const watched = useMemo(() => new Set(rows.flatMap((r) => (r.watchedSession ? [r.watchedSession] : []))), [rows]);

  const shown = useMemo(() => {
    const needle = text.trim().toLowerCase();
    const filtered = rows.filter(
      (r) =>
        (kind === "all" || r.kind === kind) &&
        (env === "all" || r.environment === env) &&
        (!alertsOnly || rowLevel(r, thresholds) !== "ok") &&
        (!needle ||
          r.name.toLowerCase().includes(needle) ||
          (r.address ?? "").toLowerCase().includes(needle) ||
          r.tags.some((t) => t.toLowerCase().includes(needle))),
    );
    return [...filtered].sort(
      (a, b) =>
        compare(sortValue(a, sort.key), sortValue(b, sort.key), sort.dir) ||
        compare(a.name.toLowerCase(), b.name.toLowerCase(), 1),
    );
  }, [rows, text, kind, env, alertsOnly, thresholds, sort]);

  const alerts = rows.filter((r) => rowLevel(r, thresholds) !== "ok").length;
  const selectedRow = rows.find((r) => r.key === selected) ?? null;

  function sortBy(key: SortKey) {
    setSort((s) => (s.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: key === "name" ? 1 : -1 }));
  }

  // Up and Down move between rows; Enter opens the drill-down.
  function rowKeys(e: KeyboardEvent<HTMLTableRowElement>, row: DashboardRow) {
    const el = e.currentTarget;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      setSelected(row.key);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      (el.nextElementSibling as HTMLElement | null)?.focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      (el.previousElementSibling as HTMLElement | null)?.focus();
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <CapacityPanel capacity={capacity} />

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-56">
          <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Filter by name or tag"
            aria-label="Filter the grid"
            className="pl-8"
          />
        </div>
        <ToggleGroup
          type="single"
          variant="outline"
          size="sm"
          value={kind}
          onValueChange={(v) => v && setKind(v as Kind)}
          aria-label="Show"
        >
          <ToggleGroupItem value="all">All</ToggleGroupItem>
          <ToggleGroupItem value="vm">
            <MonitorIcon /> VMs
          </ToggleGroupItem>
          <ToggleGroupItem value="session">
            <ServerIcon /> Hosts
          </ToggleGroupItem>
        </ToggleGroup>
        <Select value={env} onValueChange={(v) => setEnv(v as Environment | "all")}>
          <SelectTrigger size="sm" className="w-32" aria-label="Environment label">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ENVIRONMENTS.map((e) => (
              <SelectItem key={e.value} value={e.value}>
                {e.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Toggle variant="outline" size="sm" pressed={alertsOnly} onPressedChange={setAlertsOnly}>
          <TriangleAlertIcon /> Over threshold{alerts > 0 && ` (${alerts})`}
        </Toggle>
        <div className="ml-auto flex items-center gap-2">
          <ThresholdsEditor value={thresholds} onChange={setThresholds} />
          <WatchPicker watched={watched} onWatch={(id, on) => void watch(id, on)} />
        </div>
      </div>

      {overview && rows.length === 0 ? (
        <Empty className="border">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <GaugeIcon />
            </EmptyMedia>
            <EmptyTitle>Nothing to show yet</EmptyTitle>
            <EmptyDescription>
              Running VMs show here on their own, read from Windows with no login. Watch a Linux host to add its own
              CPU, memory, disks, network and load over SSH.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent className="flex-row justify-center">
            <Button variant="outline" onClick={onOpenVms}>
              Go to VMs
            </Button>
            <Button variant="outline" onClick={onOpenSessions}>
              Go to sessions
            </Button>
          </EmptyContent>
        </Empty>
      ) : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                {COLUMNS.map((c) => (
                  <SortableHead
                    key={c.key}
                    label={c.label}
                    hint={c.hint}
                    className={c.className}
                    active={sort.key === c.key}
                    dir={sort.dir}
                    onSort={() => sortBy(c.key)}
                  />
                ))}
                <TableHead className="w-10">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((row) => {
                const cpu = rowCpu(row);
                const memory = rowMemory(row);
                const hostCpu = rowHostCpu(row);
                const hostMem = rowHostMem(row);
                const io = rowDiskIo(row);
                const net = rowNetwork(row);
                const used = rowDiskUsed(row);
                const worst = rowLevel(row, thresholds);
                return (
                  <TableRow
                    key={row.key}
                    tabIndex={0}
                    aria-label={`${row.name}: open details`}
                    onClick={() => setSelected(row.key)}
                    onKeyDown={(e) => rowKeys(e, row)}
                    className={cn(
                      "cursor-pointer focus-visible:bg-muted/60 focus-visible:outline-none",
                      worst === "critical" && "bg-status-critical/5",
                    )}
                  >
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {row.kind === "vm" ? (
                          <MonitorIcon className="size-4 shrink-0 text-muted-foreground" aria-label="VM" />
                        ) : (
                          <ServerIcon className="size-4 shrink-0 text-muted-foreground" aria-label="Host" />
                        )}
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="truncate font-medium">{row.name}</span>
                            <EnvBadge env={row.environment} />
                          </div>
                          <div className="truncate text-xs text-muted-foreground">
                            {row.address ?? row.guestOs ?? ""}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      {row.powerState ? (
                        <StateBadge state={row.powerState} />
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <MetricCell
                        value={cpu.value}
                        text={formatPct(cpu.value)}
                        pct={cpu.value}
                        limits={thresholds.cpu}
                        label={`CPU of ${row.name}`}
                        title={cpu.source ? SOURCE_LABEL[cpu.source] : undefined}
                      />
                    </TableCell>
                    <TableCell>
                      <MetricCell
                        value={memory.used}
                        text={`${formatBytes(memory.used)}${memory.total ? ` / ${formatBytes(memory.total)}` : ""}`}
                        pct={memory.pct}
                        limits={thresholds.memory}
                        label={`Memory of ${row.name}`}
                        title={memory.source ? SOURCE_LABEL[memory.source] : undefined}
                      />
                    </TableCell>
                    <TableCell>
                      <MetricCell
                        value={hostCpu}
                        text={formatPct(hostCpu)}
                        pct={hostCpu}
                        limits={thresholds.cpu}
                        label={`${row.name}'s share of this host's CPU`}
                      />
                    </TableCell>
                    <TableCell>
                      <MetricCell
                        value={hostMem}
                        text={formatPct(hostMem)}
                        pct={hostMem}
                        limits={thresholds.memory}
                        label={`${row.name}'s share of this host's RAM`}
                      />
                    </TableCell>
                    <TableCell title={io.source ? SOURCE_LABEL[io.source] : undefined}>
                      <RatePairCell a={io.a} b={io.b} labels={["R", "W"]} />
                    </TableCell>
                    <TableCell>
                      <RatePairCell a={net.a} b={net.b} labels={["In", "Out"]} />
                    </TableCell>
                    <TableCell className="tabular-nums">
                      {row.guest?.load1 != null ? (
                        row.guest.load1.toFixed(2)
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <MetricCell
                        value={used.pct}
                        text={formatPct(used.pct)}
                        pct={used.pct}
                        limits={thresholds.disk}
                        label={`Fullest disk of ${row.name}`}
                        title={used.mount ? `Fullest: ${used.mount}` : undefined}
                      />
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      {row.guestStatus ? (
                        <GuestStatusBadge status={row.guestStatus} />
                      ) : row.sessions.length > 0 ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => void watch(row.sessions[0].id, true)}
                          title={`Watch the guest through ${row.sessions[0].name}`}
                        >
                          <EyeIcon /> Watch
                        </Button>
                      ) : (
                        <span className="text-xs text-muted-foreground">No session</span>
                      )}
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon-sm" aria-label={`More for ${row.name}`}>
                            <EllipsisIcon />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onSelect={() => setSelected(row.key)}>
                            <GaugeIcon /> Details and charts
                          </DropdownMenuItem>
                          {row.kind === "vm" && (
                            <DropdownMenuItem onSelect={() => onActions(row.key)}>
                              <ZapIcon /> Actions…
                            </DropdownMenuItem>
                          )}
                          {row.watchedSession && (
                            <DropdownMenuItem onSelect={() => onConnect(row.watchedSession!)}>
                              <SquareTerminalIcon /> Open terminal
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuSeparator />
                          {row.watchedSession ? (
                            <DropdownMenuItem onSelect={() => void watch(row.watchedSession!, false)}>
                              <EyeOffIcon /> Stop guest metrics
                            </DropdownMenuItem>
                          ) : row.sessions.length > 0 ? (
                            row.sessions.map((s) => (
                              <DropdownMenuItem key={s.id} onSelect={() => void watch(s.id, true)}>
                                <EyeIcon /> Watch guest via {s.name}
                                {s.auto && <AutoBadge />}
                              </DropdownMenuItem>
                            ))
                          ) : (
                            <DropdownMenuItem disabled>Link a session to watch the guest</DropdownMenuItem>
                          )}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                );
              })}
              {overview && shown.length === 0 && (
                <TableRow>
                  <TableCell colSpan={COLUMNS.length + 1} className="py-6 text-center text-muted-foreground">
                    No row matches the filters.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        {plural(rows.filter((r) => r.kind === "vm").length, "VM")} and{" "}
        {plural(rows.filter((r) => r.kind === "session").length, "host")} ·{" "}
        {cost?.collectedAt ? `updated at ${new Date(cost.collectedAt).toLocaleTimeString()} · ` : ""}
        <CostLine cost={cost} /> · history kept in memory for 30 minutes
      </p>

      <MetricsDetail
        row={selectedRow}
        round={round}
        thresholds={thresholds}
        theme={theme}
        onClose={() => setSelected(null)}
        onWatch={(id, on) => void watch(id, on)}
        onConnect={onConnect}
        onActions={onActions}
      />
    </div>
  );
}
