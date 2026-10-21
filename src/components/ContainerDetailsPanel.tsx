// CT-01, CT-02: one container's panel beside the list on the Containers page. Overview: what `inspect` says (the
// environment by variable name only: values often hold passwords, so the core never sends them), mounts, networks,
// restart policy and health. Logs: the last lines, followed by asking for the lines after the newest one every few
// seconds, searchable, with or without timestamps. Stats: its resource use, read every few seconds while the tab shows.
// All reads; "Open a shell" opens a terminal tab (audited like any terminal).

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { RefreshCwIcon, SquareTerminalIcon, TriangleAlertIcon, XIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ContainerStateBadge, EngineBadge } from "@/components/Badges";
import { WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type ContainerDetails,
  type ContainerHost,
  type ContainerStats,
  type ContainerSummary,
  type EngineKind,
  type LogLine,
} from "@/lib/api";
import {
  appendLogs,
  formatBytes,
  lastLogTime,
  logTime,
  portTexts,
  searchLogs,
  shellReason,
  statsFor,
} from "@/lib/containers";
import { formatWhen } from "@/lib/format";
import { cn } from "@/lib/utils";

export type ContainerView = "overview" | "logs" | "stats";

interface Props {
  host: ContainerHost;
  hostName: string;
  engine: EngineKind;
  container: ContainerSummary;
  view: ContainerView;
  onViewChange: (view: ContainerView) => void;
  onClose: () => void;
  /** Changes when the list was read again: the overview is read again too. */
  refreshKey: number;
  onOpenShell: () => void;
}

const TAILS = [100, 500, 1000, 5000];
/** How often a followed log, and the Stats tab, ask again. */
const FOLLOW_MS = 2000;
const STATS_MS = 5000;

const dash = <span className="text-muted-foreground">—</span>;

export function ContainerDetailsPanel(props: Props) {
  const { container, view, onViewChange, onClose, engine, hostName, onOpenShell, host } = props;
  const noShell = shellReason(container, host);
  return (
    <aside
      aria-label={`${container.name}: details, logs and stats`}
      className="flex h-full min-h-0 flex-col rounded-lg border"
    >
      <div className="flex items-start gap-2 border-b p-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <h2 className="font-semibold break-all">{container.name}</h2>
            <ContainerStateBadge state={container.state} />
            <EngineBadge engine={engine} />
          </div>
          <div className="text-xs text-muted-foreground">
            {container.image} · on {hostName}
          </div>
          <div className="font-mono text-xs text-muted-foreground">{container.id.slice(0, 12)}</div>
        </div>
        <Button size="icon-sm" variant="ghost" aria-label="Close the details" onClick={onClose}>
          <XIcon />
        </Button>
      </div>
      <Tabs
        value={view}
        onValueChange={(v) => onViewChange(v as ContainerView)}
        className="min-h-0 flex-1 gap-0"
        aria-label={`${container.name}'s details`}
      >
        <div className="flex items-center gap-2 border-b px-3 py-2">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="logs">Logs</TabsTrigger>
            <TabsTrigger value="stats">Stats</TabsTrigger>
          </TabsList>
          <WhyDisabled reason={noShell} className="ml-auto">
            <Button variant="outline" size="sm" className="ml-auto" onClick={onOpenShell} disabled={noShell !== null}>
              <SquareTerminalIcon data-icon="inline-start" />
              Open a shell
            </Button>
          </WhyDisabled>
        </div>
        <TabsContent value="overview" className="min-h-0 overflow-auto p-3">
          <Overview {...props} />
        </TabsContent>
        <TabsContent value="logs" className="flex min-h-0 flex-col p-3">
          {view === "logs" && <LogsTab {...props} />}
        </TabsContent>
        <TabsContent value="stats" className="min-h-0 overflow-auto p-3">
          {view === "stats" && <StatsTab {...props} />}
        </TabsContent>
      </Tabs>
    </aside>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </>
  );
}

function Overview({ host, engine, container, refreshKey }: Props) {
  const [details, setDetails] = useState<{ key: string; value: ContainerDetails } | null>(null);
  const [error, setError] = useState<{ key: string; message: string } | null>(null);
  const key = `${container.id}:${refreshKey}`;
  const shown = details?.key === key ? details.value : null;
  const failed = error?.key === key ? error.message : null;

  useEffect(() => {
    let stale = false;
    api.containerDetails(host, engine, container.id).then(
      (value) => {
        if (!stale) setDetails({ key, value });
      },
      (err) => {
        if (!stale) setError({ key, message: errorMessage(err) });
      },
    );
    return () => {
      stale = true;
    };
  }, [host, engine, container.id, key]);

  if (failed) {
    return (
      <Alert variant="destructive">
        <TriangleAlertIcon />
        <AlertTitle>Could not read the details</AlertTitle>
        <AlertDescription>{failed}</AlertDescription>
      </Alert>
    );
  }
  if (!shown) {
    return (
      <div className="grid gap-2" aria-busy>
        {Array.from({ length: 6 }, (_, i) => (
          <Skeleton key={i} className="h-5" />
        ))}
      </div>
    );
  }
  const d = shown;
  return (
    <div className="grid gap-4 text-sm">
      <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1.5">
        <Row label="State">
          <ContainerStateBadge state={d.state} /> <span className="text-muted-foreground">{container.status}</span>
        </Row>
        <Row label="Image">
          {d.image}
          {d.imageId && <div className="font-mono text-xs break-all text-muted-foreground">{d.imageId}</div>}
        </Row>
        <Row label="Created">{formatWhen(d.createdAt)}</Row>
        <Row label="Started">{formatWhen(d.startedAt)}</Row>
        {d.finishedAt && <Row label="Finished">{formatWhen(d.finishedAt)}</Row>}
        {d.state !== "running" && d.exitCode != null && <Row label="Exit code">{d.exitCode}</Row>}
        {d.error && <Row label="Error">{d.error}</Row>}
        {d.oomKilled && (
          <Row label="Memory">
            <span className="text-destructive">Killed: it ran out of memory</span>
          </Row>
        )}
        <Row label="Restart policy">
          {d.restartPolicy ?? dash}
          {d.restartCount ? <span className="text-muted-foreground"> · restarted {d.restartCount} times</span> : null}
        </Row>
        <Row label="Health">
          {d.health ? (
            <>
              <span className={cn(d.health.status === "unhealthy" && "text-destructive")}>{d.health.status}</span>
              {d.health.failingStreak ? (
                <span className="text-muted-foreground"> · {d.health.failingStreak} failed checks in a row</span>
              ) : null}
            </>
          ) : (
            <span className="text-muted-foreground">No health check</span>
          )}
        </Row>
        <Row label="Command">{d.command ? <code className="text-xs">{d.command}</code> : dash}</Row>
        {d.entrypoint && (
          <Row label="Entrypoint">
            <code className="text-xs">{d.entrypoint}</code>
          </Row>
        )}
        {d.workingDir && <Row label="Working folder">{d.workingDir}</Row>}
        {d.runsAs && <Row label="Runs as">{d.runsAs}</Row>}
        <Row label="Ports">{portTexts(d.ports).join(", ") || dash}</Row>
        {d.project && <Row label="Compose project">{d.project}</Row>}
        {d.platform && <Row label="Platform">{d.platform}</Row>}
        <Row label="Id">
          <span className="font-mono text-xs break-all">{d.id}</span>
        </Row>
      </dl>

      <section aria-label="Networks" className="grid gap-1">
        <h3 className="font-medium">Networks</h3>
        {d.networks.length === 0 ? (
          <p className="text-muted-foreground">None</p>
        ) : (
          <ul className="grid gap-0.5">
            {d.networks.map((n) => (
              <li key={n.name}>
                {n.name}
                {n.ipAddress && (
                  <>
                    {" "}
                    <span className="font-mono text-xs text-muted-foreground" data-mask="ip">
                      {n.ipAddress}
                    </span>
                  </>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-label="Mounts" className="grid gap-1">
        <h3 className="font-medium">Mounts</h3>
        {d.mounts.length === 0 ? (
          <p className="text-muted-foreground">None</p>
        ) : (
          <ul className="grid gap-1">
            {d.mounts.map((m) => (
              <li key={m.destination} className="break-all">
                <Badge variant="outline" className="mr-1.5 font-normal">
                  {m.kind}
                </Badge>
                {m.name ?? m.source ?? "?"} → <span className="font-mono text-xs">{m.destination}</span>
                {m.readOnly && <span className="text-muted-foreground"> (read only)</span>}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-label="Environment variables" className="grid gap-1">
        <h3 className="font-medium">Environment variables</h3>
        <p className="text-xs text-muted-foreground">
          Names only. Their values often hold passwords and tokens, so Remotely never reads them out.
        </p>
        <div className="flex flex-wrap gap-1">
          {d.envNames.length === 0 ? (
            <span className="text-muted-foreground">None</span>
          ) : (
            d.envNames.map((name) => (
              <Badge key={name} variant="secondary" className="font-mono font-normal">
                {name}
              </Badge>
            ))
          )}
        </div>
      </section>
    </div>
  );
}

function LogsTab({ host, engine, container }: Props) {
  const [tail, setTail] = useState(500);
  const [follow, setFollow] = useState(false);
  const [timestamps, setTimestamps] = useState(true);
  const [search, setSearch] = useState("");
  const [lines, setLines] = useState<{ key: string; list: LogLine[]; truncated: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reads, setReads] = useState(0);
  const key = `${container.id}:${tail}:${reads}`;
  const shown = lines?.key === key ? lines : null;
  const bottom = useRef<HTMLDivElement>(null);
  const latest = useRef<LogLine[]>([]);

  // The last `tail` lines, on open and on Refresh.
  useEffect(() => {
    let stale = false;
    api.containerLogs(host, engine, container.id, { tail }).then(
      (logs) => {
        if (stale) return;
        latest.current = logs.lines;
        setLines({ key, list: logs.lines, truncated: logs.truncated });
        setError(null);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [host, engine, container.id, tail, key]);

  // Following: the lines after the newest one, every few seconds.
  useEffect(() => {
    if (!follow || !shown) return;
    let stale = false;
    const timer = window.setInterval(() => {
      const since = lastLogTime(latest.current);
      api.containerLogs(host, engine, container.id, { tail: 1000, since }).then(
        (logs) => {
          if (stale || logs.lines.length === 0) return;
          latest.current = appendLogs(latest.current, logs.lines);
          setLines((prev) => (prev && prev.key === key ? { ...prev, list: latest.current } : prev));
        },
        (err) => {
          if (!stale) setError(errorMessage(err));
        },
      );
    }, FOLLOW_MS);
    return () => {
      stale = true;
      window.clearInterval(timer);
    };
  }, [follow, shown, host, engine, container.id, key]);

  const matches = useMemo(() => searchLogs(shown?.list ?? [], search), [shown, search]);
  useEffect(() => {
    if (follow) bottom.current?.scrollIntoView({ block: "end" });
  }, [follow, matches.length]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Label htmlFor="log-tail" className="text-xs text-muted-foreground">
          Last
        </Label>
        <Select value={String(tail)} onValueChange={(v) => setTail(Number(v))}>
          <SelectTrigger id="log-tail" size="sm" className="w-24">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TAILS.map((t) => (
              <SelectItem key={t} value={String(t)}>
                {t} lines
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <label className="flex items-center gap-1.5 text-sm">
          <Switch checked={follow} onCheckedChange={setFollow} aria-label="Follow the log" />
          Follow
        </label>
        <label className="flex items-center gap-1.5 text-sm">
          <Switch checked={timestamps} onCheckedChange={setTimestamps} aria-label="Show timestamps" />
          Timestamps
        </label>
        <Button size="icon-sm" variant="ghost" aria-label="Read the log again" onClick={() => setReads((r) => r + 1)}>
          <RefreshCwIcon />
        </Button>
      </div>
      <div className="flex items-center gap-2">
        <Input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search the log"
          aria-label="Search the log"
          className="h-8"
        />
        {search.trim() && (
          <span className="shrink-0 text-xs text-muted-foreground tabular-nums">
            {matches.length} of {shown?.list.length ?? 0}
          </span>
        )}
      </div>
      {error && (
        <Alert variant="destructive">
          <TriangleAlertIcon />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div
        className="min-h-0 flex-1 overflow-auto rounded-md border bg-muted/30 p-2 font-mono text-xs"
        role="log"
        aria-label={`${container.name}'s log`}
      >
        {!shown && !error && <Skeleton className="h-4 w-2/3" />}
        {shown?.truncated && (
          <div className="text-muted-foreground">Older lines left out; showing the last {shown.list.length}.</div>
        )}
        {shown && shown.list.length === 0 && <div className="text-muted-foreground">The log is empty.</div>}
        {matches.map(({ line, index }) => (
          <div
            key={index}
            className={cn("break-all whitespace-pre-wrap", line.stream === "stderr" && "text-tier-high")}
          >
            {timestamps && line.at && (
              <span className="mr-2 text-muted-foreground select-none">{logTime(line.at)}</span>
            )}
            {line.text}
          </div>
        ))}
        <div ref={bottom} />
      </div>
      <p className="text-xs text-muted-foreground">
        Lines the container wrote to stderr are tinted. Following asks for new lines every {FOLLOW_MS / 1000} s on the
        host&apos;s kept connection.
      </p>
    </div>
  );
}

function StatsTab({ host, engine, container }: Props) {
  const [stats, setStats] = useState<ContainerStats | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stale = false;
    const read = () =>
      api.containerStats(host, engine).then(
        (list) => {
          if (stale) return;
          setStats(statsFor(list, container.id) ?? null);
          setError(null);
        },
        (err) => {
          if (!stale) setError(errorMessage(err));
        },
      );
    void read();
    const timer = window.setInterval(() => void read(), STATS_MS);
    return () => {
      stale = true;
      window.clearInterval(timer);
    };
  }, [host, engine, container.id]);

  if (error) {
    return (
      <Alert variant="destructive">
        <TriangleAlertIcon />
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }
  if (stats === undefined) return <Skeleton className="h-24" />;
  if (stats === null) {
    return <p className="text-sm text-muted-foreground">No stats: the container is not running.</p>;
  }
  const pct = (v: number | null) => (v == null ? "—" : `${v.toFixed(1)} %`);
  return (
    <div className="grid gap-3 text-sm">
      <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1.5">
        <Row label="CPU">{pct(stats.cpuPct)}</Row>
        <Row label="Memory">
          {formatBytes(stats.memBytes)}
          {stats.memLimitBytes ? ` of ${formatBytes(stats.memLimitBytes)}` : ""} ({pct(stats.memPct)})
        </Row>
        <Row label="Network">
          {formatBytes(stats.netRxBytes)} in · {formatBytes(stats.netTxBytes)} out
        </Row>
        <Row label="Disk">
          {formatBytes(stats.blockReadBytes)} read · {formatBytes(stats.blockWriteBytes)} written
        </Row>
        <Row label="Processes">{stats.pids ?? "—"}</Row>
      </dl>
      <p className="text-xs text-muted-foreground">
        One sample every {STATS_MS / 1000} s while this tab shows (stats --no-stream). Network and disk are totals since
        the container started.
      </p>
    </div>
  );
}
