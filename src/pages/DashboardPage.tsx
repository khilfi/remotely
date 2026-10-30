// MO-03 dashboard: widgets on a grid (MO-16, saved per workspace; Customize adds, removes, moves and resizes them): the
// host capacity panel (MO-04), this PC's memory (MO-15), the alert list (MO-07), the overview grid of running VMs and
// watched hosts with host-side metrics (MO-01, no login, including each VM's share of this host's CPU and RAM) and Linux
// guest metrics over SSH (MO-02), sorting, filters and colour thresholds, services of a watched host (MO-14) and metric
// charts; and a drill-down with charts, live or over a range from the history on disk (MO-06). Everything here is a
// read: it goes straight to the core's metrics collector, never through the command bus. Actions open the command
// palette, which submits to the bus like every other page.
//
// UX-08: the Map (QL-21's page until 0.6.0) is the Dashboard's second tab.
//
// UX-03, UX-07 (0.6.0): one range for the page's charts (in the header, and in a drill-down, which changes the same
// one), the round's timing behind "Updated hh:mm", Watch hosts as the one place to watch or stop watching a host,
// a row's click as the one way to its details, and Customize in the header's "⋯".
//
// P8: the page follows the core's rounds only while it shows and the window is visible (shouldPoll): hidden, it reads
// nothing and renders nothing each round; shown again, it reads once at once and then follows the rounds. Each widget
// reads only while it is on the dashboard, and none while the layout is being customized.

import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import {
  CheckIcon,
  GaugeIcon,
  LayoutDashboardIcon,
  MonitorIcon,
  NetworkIcon,
  PlusIcon,
  RotateCcwIcon,
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
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Toggle } from "@/components/ui/toggle";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { AlertsWidget } from "@/components/AlertsWidget";
import { EnvBadge, StateBadge } from "@/components/Badges";
import { CapacityPanel } from "@/components/CapacityPanel";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DashboardGrid } from "@/components/DashboardGrid";
import { EmptyState } from "@/components/EmptyState";
import { HelpTip } from "@/components/HelpTip";
import { GuestStatusBadge } from "@/components/GuestStatusBadge";
import { HostDetailsSheet } from "@/components/HostDetailsSheet";
import { MetricCell } from "@/components/MetricBits";
import { MetricChartWidget } from "@/components/MetricChartWidget";
import { MetricsDetail } from "@/components/MetricsDetail";
import { PageHeader } from "@/components/PageHeader";
import { useReadOnlyReason } from "@/components/Presentation";
import { RangePicker } from "@/components/RangePicker";
import { RowMenu } from "@/components/RowMenu";
import { ServicesWidget } from "@/components/ServicesWidget";
import { SortableHead } from "@/components/SortableHead";
import { ThisPcMemoryChart } from "@/components/ThisPcMemoryChart";
import { Tip } from "@/components/Tip";
import { ReasonLine } from "@/components/WhyDisabled";
import { useVisibility } from "@/hooks/use-poll";
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
import { dashboardApi, type ChartRange, type DashboardLayout, type LayoutInfo, type Widget } from "@/lib/dashboard-api";
import { addWidget, cannotAdd, WIDGET_CHOICES, widgetTitle, type WidgetKindName } from "@/lib/dashboard-layout";
import { formatWhen, plural } from "@/lib/format";
import { specsSummary } from "@/lib/host-details";
import { hypervisorName } from "@/lib/hypervisors";
import type { AppLink } from "@/lib/links";
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
import type { DashboardTab } from "@/lib/navigation";
import { shouldPoll } from "@/lib/polling";
import type { ResolvedTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";
import { MapPage } from "@/pages/MapPage";

interface Props {
  active: boolean;
  /** UX-08: Metrics, or the Map (App keeps the tab, so links can open either). */
  tab: DashboardTab;
  onTabChange: (tab: DashboardTab) => void;
  /** The map's nodes open their items. */
  onOpenLink: (link: AppLink) => void;
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
  { value: "all", label: "All environments" },
  { value: "prod", label: "Prod" },
  { value: "staging", label: "Staging" },
  { value: "lab", label: "Lab" },
  { value: "none", label: "None" },
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

/** The round's timing, one line each, for the tooltip on "Updated hh:mm". */
function costLines(cost: CollectorCost | null, rows: DashboardRow[]): string[] {
  const counts = `${plural(rows.filter((r) => r.kind === "vm").length, "VM")} and ${plural(
    rows.filter((r) => r.kind === "session").length,
    "watched host",
  )}`;
  if (!cost || cost.rounds === 0) return [counts, "Collecting the first round…"];
  return [
    counts,
    `Read every ${cost.intervalSecs} s${
      cost.guestIntervalSecs > 0 && cost.guestIntervalSecs !== cost.intervalSecs
        ? ` (watched hosts every ${cost.guestIntervalSecs} s)`
        : ""
    }`,
    `Last round took ${Math.round(cost.roundMs)} ms (this PC ${Math.round(cost.hostMs)} ms${
      cost.guests > 0 || cost.guestMs > 1 ? `, watched hosts ${Math.round(cost.guestMs)} ms` : ""
    })`,
    `Remotely used ${cost.appCpuPct === null ? "—" : formatPct(cost.appCpuPct)} of this PC's CPU`,
  ];
}

/** "Updated 2:03 am", with the round's timing on hover. */
function UpdatedAt({ cost, rows }: { cost: CollectorCost | null; rows: DashboardRow[] }) {
  const at = cost?.collectedAt ? new Date(cost.collectedAt) : null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className="text-xs whitespace-nowrap text-muted-foreground underline decoration-dotted underline-offset-2 outline-none focus-visible:rounded-sm focus-visible:ring-3 focus-visible:ring-ring/50"
        >
          {at ? `Updated ${at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : "Collecting…"}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        <ul className="grid gap-0.5">
          {costLines(cost, rows).map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </TooltipContent>
    </Tooltip>
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

/**
 * UX-03: the one place to watch a host, or stop watching it (the palette aside): a session per line, ticked while
 * watched. A session linked to a running VM names the VM, so a VM's guest is found by the VM's name too.
 */
function WatchPicker({
  open,
  onOpenChange,
  watched,
  vmOf,
  onWatch,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  watched: Set<string>;
  /** Session id -> the running VM it is linked to. */
  vmOf: Map<string, string>;
  onWatch: (id: string, watch: boolean) => void;
}) {
  const setOpen = onOpenChange;
  const [sessions, setSessions] = useState<SessionRecord[] | null>(null);
  useEffect(() => {
    if (!open) return;
    api.sessions().then(setSessions, (err) => toast.error(errorMessage(err)));
  }, [open]);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button>
          <PlusIcon data-icon="inline-start" /> Watch hosts
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
                    value={`${s.name} ${s.host} ${s.tags.join(" ")} ${vmOf.get(s.id) ?? ""}`}
                    onSelect={() => onWatch(s.id, !on)}
                  >
                    <CheckIcon className={cn("size-4", on ? "opacity-100" : "opacity-0")} />
                    <span className="truncate">{s.name}</span>
                    {vmOf.has(s.id) && (
                      <span className="shrink-0 text-xs text-muted-foreground">VM {vmOf.get(s.id)}</span>
                    )}
                    <span className="ml-auto truncate text-xs text-muted-foreground" data-mask="host">
                      {s.host}
                    </span>
                  </CommandItem>
                );
              })}
            </CommandGroup>
          </CommandList>
        </Command>
        <p className="flex items-center gap-1 border-t px-3 py-1.5 text-xs text-muted-foreground">
          Linux hosts, over SSH with the saved login. Nothing on the host changes.
          <HelpTip topic="dashboardPolling" side="top" />
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

interface OverviewProps {
  overview: DashboardOverview | null;
  rows: DashboardRow[];
  thresholds: Thresholds;
  setThresholds: (t: Thresholds) => void;
  onSelect: (key: string) => void;
  onConnect: (sessionId: string) => void;
  onActions: (vmxPath: string) => void;
  /** Opens Watch hosts, for the empty grid. */
  onWatchHosts: () => void;
}

/** MO-03: the overview grid widget: filters and the table of running VMs and watched hosts. */
function OverviewWidget({
  overview,
  rows,
  thresholds,
  setThresholds,
  onSelect,
  onConnect,
  onActions,
  onWatchHosts,
}: OverviewProps) {
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "name", dir: 1 });
  const [text, setText] = useState("");
  const [kind, setKind] = useState<Kind>("all");
  const [env, setEnv] = useState<Environment | "all">("all");
  const [alertsOnly, setAlertsOnly] = useState(false);

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

  function sortBy(key: SortKey) {
    setSort((s) => (s.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: key === "name" ? 1 : -1 }));
  }

  // Up and Down move between rows; Enter opens the drill-down.
  function rowKeys(e: KeyboardEvent<HTMLTableRowElement>, row: DashboardRow) {
    const el = e.currentTarget;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onSelect(row.key);
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
          <SelectTrigger size="sm" className="w-40" aria-label="Environment">
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
        </div>
      </div>

      {overview && rows.length === 0 ? (
        <EmptyState
          icon={GaugeIcon}
          title="Nothing running or watched"
          description="Running VMs show here by themselves; watch a Linux host to add it."
          help="dashboardPolling"
          action={
            <Button onClick={onWatchHosts}>
              <PlusIcon data-icon="inline-start" /> Watch hosts
            </Button>
          }
        />
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
              {shown.map((row) => (
                <OverviewRow
                  key={row.key}
                  row={row}
                  thresholds={thresholds}
                  onSelect={onSelect}
                  onKeys={rowKeys}
                  onConnect={onConnect}
                  onActions={onActions}
                />
              ))}
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
    </div>
  );
}

function OverviewRow({
  row,
  thresholds,
  onSelect,
  onKeys,
  onConnect,
  onActions,
}: {
  row: DashboardRow;
  thresholds: Thresholds;
  onSelect: (key: string) => void;
  onKeys: (e: KeyboardEvent<HTMLTableRowElement>, row: DashboardRow) => void;
  onConnect: (sessionId: string) => void;
  onActions: (vmxPath: string) => void;
}) {
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
      tabIndex={0}
      aria-label={`${row.name}: open details`}
      onClick={() => onSelect(row.key)}
      onKeyDown={(e) => onKeys(e, row)}
      className={cn(
        "cursor-pointer focus-visible:bg-muted/60 focus-visible:outline-none",
        worst === "critical" && "bg-status-critical/5",
      )}
    >
      <TableCell>
        <div className="flex items-center gap-2">
          {row.kind === "vm" ? (
            <span title={row.hypervisor ? `${hypervisorName(row.hypervisor)} VM` : "VM"} className="flex">
              <MonitorIcon
                className="size-4 shrink-0 text-muted-foreground"
                aria-label={row.hypervisor ? `${hypervisorName(row.hypervisor)} VM` : "VM"}
              />
            </span>
          ) : (
            <ServerIcon className="size-4 shrink-0 text-muted-foreground" aria-label="Host" />
          )}
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="truncate font-medium">{row.name}</span>
              <EnvBadge env={row.environment} />
            </div>
            <div className="truncate text-xs text-muted-foreground">{row.address ?? ""}</div>
            {/* MO-13: "4 vCPU · 8 GB · Ubuntu 24.04" */}
            <div
              className="truncate text-xs text-muted-foreground"
              title={row.specsAt ? `The host's facts as of ${formatWhen(row.specsAt)}` : undefined}
            >
              {specsSummary(
                row.kind === "vm" ? "vm" : "host",
                row.vcpus,
                row.memsizeMb ? row.memsizeMb * 1024 * 1024 : null,
                row.guestOs,
              )}
            </div>
          </div>
        </div>
      </TableCell>
      <TableCell>
        {row.powerState ? <StateBadge state={row.powerState} /> : <span className="text-muted-foreground">—</span>}
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
        {row.guest?.load1 != null ? row.guest.load1.toFixed(2) : <span className="text-muted-foreground">—</span>}
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
      <TableCell>
        {row.guestStatus ? (
          <GuestStatusBadge status={row.guestStatus} onCheckKey={onConnect} />
        ) : (
          <span
            className="text-xs text-muted-foreground"
            title={
              row.sessions.length > 0
                ? `Watch ${row.sessions[0].name} with Watch hosts to read the guest`
                : "Link a session to this VM to read the guest"
            }
          >
            Not watched
          </span>
        )}
      </TableCell>
      <TableCell>
        {(row.kind === "vm" || row.watchedSession) && (
          <RowMenu label={row.name}>
            {row.kind === "vm" && (
              <DropdownMenuItem onSelect={() => onActions(row.key)}>
                <ZapIcon /> Actions…
              </DropdownMenuItem>
            )}
            {row.watchedSession && (
              <DropdownMenuItem onSelect={() => onConnect(row.watchedSession!)}>
                <SquareTerminalIcon /> Open a terminal
              </DropdownMenuItem>
            )}
          </RowMenu>
        )}
      </TableCell>
    </TableRow>
  );
}

/** MO-16: while customizing, Add widget, Reset, Cancel and Save (Customize itself is in the header's "⋯"). */
function LayoutBar({
  draft,
  saving,
  onAdd,
  onReset,
  onCancel,
  onSave,
}: {
  /** The layout being customized. */
  draft: DashboardLayout;
  saving: boolean;
  onAdd: (kind: WidgetKindName) => void;
  onReset: () => void;
  onCancel: () => void;
  onSave: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg border border-dashed bg-muted/40 px-3 py-2">
      <span className="mr-auto text-sm font-medium">Customizing the dashboard</span>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="sm" variant="outline">
            <PlusIcon /> Add widget
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-72">
          {WIDGET_CHOICES.map((choice) => {
            const why = cannotAdd(draft, choice.kind);
            return (
              <DropdownMenuItem key={choice.kind} disabled={why !== null} onSelect={() => onAdd(choice.kind)}>
                <div className="flex flex-col">
                  <span>{choice.label}</span>
                  <span className="text-xs text-muted-foreground">{choice.description}</span>
                  <ReasonLine reason={why} />
                </div>
              </DropdownMenuItem>
            );
          })}
        </DropdownMenuContent>
      </DropdownMenu>
      <Button size="sm" variant="ghost" disabled={saving} onClick={onReset}>
        <RotateCcwIcon /> Reset to default
      </Button>
      <Button size="sm" variant="ghost" disabled={saving} onClick={onCancel}>
        Cancel
      </Button>
      <Button size="sm" disabled={saving} onClick={onSave}>
        <CheckIcon /> Save layout
      </Button>
    </div>
  );
}

export function DashboardPage({ active, tab, onTabChange, onOpenLink, theme, focus, onConnect, onActions }: Props) {
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [capacity, setCapacity] = useState<HostCapacity | null>(null);
  const [round, setRound] = useState(0);
  const [cost, setCost] = useState<CollectorCost | null>(null);
  const [thresholds, setThresholds] = useThresholds();
  const [selected, setSelected] = useState<string | null>(null);
  /** MO-13, MO-14: a session's host details, opened from the drill-down. */
  const [hostDetails, setHostDetails] = useState<{ id: string; name: string } | null>(null);
  /** MO-16: the saved layout, and a copy being customized. */
  const [layoutInfo, setLayoutInfo] = useState<LayoutInfo | null>(null);
  const [draft, setDraft] = useState<DashboardLayout | null>(null);
  const [saving, setSaving] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);
  const [sessionNames, setSessionNames] = useState<Map<string, string>>(new Map());
  /** UX-07: one range for every chart on the page (and the drill-down's). */
  const [range, setRange] = useState<ChartRange>("live");
  /** UX-03: Watch hosts, the one place to watch a host (the empty grid opens it too). */
  const [watchOpen, setWatchOpen] = useState(false);
  const readOnly = useReadOnlyReason();

  // P8: rounds count only while the page shows and the window is visible; showing it again counts as a round, so
  // everything reads once at once.
  const visibility = useVisibility();
  const live = shouldPoll(active && tab === "metrics", visibility);
  const liveRef = useRef(live);
  useEffect(() => {
    liveRef.current = live;
  }, [live]);
  const [wasLive, setWasLive] = useState(live);
  if (live !== wasLive) {
    setWasLive(live);
    if (live) setRound((n) => n + 1);
  }

  // Each round the core finishes -> read what it collected (only while this page shows).
  useEffect(() => {
    const unlisten = api.onMetricsRound((c) => {
      if (!liveRef.current) return;
      setCost(c);
      setRound((n) => n + 1);
    });
    return () => void unlisten.then((stop) => stop());
  }, []);

  useEffect(() => {
    dashboardApi.layout().then(setLayoutInfo, (err) => toast.error(errorMessage(err), { id: "dashboard-layout" }));
  }, []);
  const layout = draft ?? layoutInfo?.layout ?? null;
  const editing = draft !== null;
  const kinds = useMemo(() => new Set(layout?.widgets.map((w) => w.kind) ?? []), [layout]);
  const servicesIds = useMemo(
    () =>
      (layout?.widgets ?? [])
        .flatMap((w) => (w.kind === "services" && w.sessionId ? [w.sessionId] : []))
        .sort()
        .join(","),
    [layout],
  );

  // Widgets read only while shown: the grid's rows when the overview (or a drill-down) is on the page, capacity when
  // its widget is, the services widgets' host names when there are some.
  const needOverview = kinds.has("overview") || kinds.has("chart") || selected !== null || watchOpen;
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
    if (live && needOverview) load();
  }, [live, round, load, needOverview]);

  // Capacity changes slowly: read when the page shows, then every third round (15 s).
  const capacityTick = Math.floor(round / 3);
  const needCapacity = kinds.has("capacity");
  useEffect(() => {
    if (!live || !needCapacity) return;
    api.metricsCapacity().then(setCapacity, () => setCapacity(null));
  }, [live, capacityTick, needCapacity]);

  useEffect(() => {
    if (!live || !servicesIds) return;
    api.sessions().then(
      (sessions) => setSessionNames(new Map(sessions.map((s) => [s.id, s.name]))),
      () => undefined,
    );
  }, [live, servicesIds]);

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
  /** Each session linked to a running VM, by the VM's name, for Watch hosts. */
  const vmOf = useMemo(
    () => new Map(rows.flatMap((r) => (r.kind === "vm" ? r.sessions.map((s) => [s.id, r.name] as const) : []))),
    [rows],
  );
  // A row by its key, or by the watched session a VM row shows (an alert on a VM's guest). Nothing selected, no row:
  // a VM row nobody watches has a null watched session too.
  const selectedRow =
    selected === null
      ? null
      : (rows.find((r) => r.key === selected) ?? rows.find((r) => r.watchedSession === selected) ?? null);
  const rowName = (key: string | null | undefined) =>
    key ? (rows.find((r) => r.key === key || r.watchedSession === key)?.name ?? null) : null;
  const titleOf = (w: Widget) =>
    widgetTitle(
      w,
      w.kind === "services"
        ? (sessionNames.get(w.sessionId ?? "") ?? null)
        : w.kind === "chart"
          ? rowName(w.key)
          : null,
    );

  async function saveLayout() {
    if (!draft) return;
    setSaving(true);
    try {
      setLayoutInfo(await dashboardApi.setLayout(draft));
      setDraft(null);
      toast.success("Dashboard layout saved");
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  function renderWidget(widget: Widget, height: number) {
    // Nothing reads while the layout is being customized.
    const reading = live && !editing;
    switch (widget.kind) {
      case "overview":
        return (
          <OverviewWidget
            overview={overview}
            rows={rows}
            thresholds={thresholds}
            setThresholds={setThresholds}
            onSelect={setSelected}
            onConnect={onConnect}
            onActions={onActions}
            onWatchHosts={() => setWatchOpen(true)}
          />
        );
      case "capacity":
        return <CapacityPanel capacity={capacity} />;
      case "thisPcMemory":
        return <ThisPcMemoryChart round={round} range={range} live={reading} theme={theme} height={height - 124} />;
      case "alerts":
        return <AlertsWidget live={reading} onOpenTarget={(target) => setSelected(target.key)} />;
      case "services":
        return (
          <ServicesWidget
            sessionId={widget.sessionId ?? null}
            name={widget.sessionId ? (sessionNames.get(widget.sessionId) ?? null) : null}
            live={reading}
          />
        );
      case "chart":
        return (
          <MetricChartWidget
            widget={widget}
            name={rowName(widget.key)}
            round={round}
            range={range}
            live={reading}
            theme={theme}
            height={height - 104}
          />
        );
    }
  }

  return (
    <Tabs
      value={tab}
      onValueChange={(v) => onTabChange(v as DashboardTab)}
      className="flex h-full min-h-0 flex-col gap-4"
    >
      <PageHeader
        page="dashboard"
        primary={
          tab === "metrics" && !editing ? (
            <WatchPicker
              open={watchOpen}
              onOpenChange={setWatchOpen}
              watched={watched}
              vmOf={vmOf}
              onWatch={(id, on) => void watch(id, on)}
            />
          ) : undefined
        }
        tools={
          tab === "metrics" && layout && !editing ? (
            <DropdownMenuItem disabled={readOnly !== null} onSelect={() => setDraft(structuredClone(layout))}>
              <LayoutDashboardIcon />
              <div>
                Customize the dashboard
                <ReasonLine reason={readOnly} />
              </div>
            </DropdownMenuItem>
          ) : undefined
        }
        tabs={
          <TabsList>
            <TabsTrigger value="metrics">
              <GaugeIcon />
              Metrics
            </TabsTrigger>
            {/* UX-08: the map, a page of its own until 0.6.0. */}
            <TabsTrigger value="map">
              <NetworkIcon />
              Map
            </TabsTrigger>
          </TabsList>
        }
      >
        {tab === "metrics" && (
          <>
            <RangePicker value={range} onChange={setRange} label="Charts' range" />
            <UpdatedAt cost={cost} rows={rows} />
          </>
        )}
      </PageHeader>
      {/* Mounted while hidden, as the page itself is: widgets read only while the tab shows (live). */}
      <TabsContent value="metrics" forceMount className="flex flex-none flex-col gap-4 data-[state=inactive]:hidden">
        {draft && (
          <>
            <LayoutBar
              draft={draft}
              saving={saving}
              onAdd={(kind) => setDraft((d) => (d ? addWidget(d, kind) : d))}
              onReset={() => setConfirmReset(true)}
              onCancel={() => setDraft(null)}
              onSave={() => void saveLayout()}
            />
            <Tip id="dashboard.customize">
              Drag a widget by its handle to move it, or by its corner to resize it; nothing is kept until you save.
            </Tip>
          </>
        )}
        {layout && layout.widgets.length === 0 && (
          <EmptyState
            icon={LayoutDashboardIcon}
            title="No widgets"
            description={editing ? "Add widgets above, then save." : "Customize the dashboard to add some."}
            action={
              editing ? undefined : (
                <Button disabled={readOnly !== null} onClick={() => setDraft(structuredClone(layout))}>
                  <LayoutDashboardIcon data-icon="inline-start" />
                  Customize
                </Button>
              )
            }
          />
        )}
        {layout && (
          <DashboardGrid
            layout={layout}
            editing={editing}
            onChange={setDraft}
            renderWidget={renderWidget}
            titleOf={titleOf}
          />
        )}

        <MetricsDetail
          row={selectedRow}
          round={round}
          live={live}
          guestIntervalSecs={cost?.guestIntervalSecs || 5}
          range={range}
          onRangeChange={setRange}
          thresholds={thresholds}
          theme={theme}
          onClose={() => setSelected(null)}
          onRetry={(id) => {
            api.backgroundLoginRetry(id).then(
              () => {
                toast.success("Logging in again on the next round");
                load();
              },
              (err) => toast.error(errorMessage(err)),
            );
          }}
          onConnect={onConnect}
          onActions={onActions}
          onHostDetails={(session) => {
            setSelected(null);
            setHostDetails(session);
          }}
        />
        <HostDetailsSheet session={hostDetails} thresholds={thresholds} onClose={() => setHostDetails(null)} />
        {confirmReset && (
          <ConfirmDialog
            title="Reset the dashboard?"
            description="Back to the default widgets: host capacity, this PC's memory, the alerts and the overview grid. Your arrangement and its charts go."
            confirmLabel="Reset"
            onConfirm={async () => {
              setLayoutInfo(await dashboardApi.resetLayout());
              setDraft(null);
              toast.success("Dashboard reset to the default");
            }}
            onClose={() => setConfirmReset(false)}
          />
        )}
      </TabsContent>
      <TabsContent value="map" forceMount className="min-h-0 data-[state=inactive]:hidden">
        <MapPage active={active && tab === "map"} onOpenLink={onOpenLink} />
      </TabsContent>
    </Tabs>
  );
}
