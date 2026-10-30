// MO-13, MO-14: one SSH host's details, in a side sheet opened from the Sessions page, the Terminal page's session
// tree, the dashboard's drill-down and a VM's System tab.
//
// System (MO-13): OS, kernel, CPU, memory and swap, disks and filesystems, virtualization, host name and uptime, as
// last read (a terminal that connected, the dashboard, or Refresh) and stored, so they show offline. Admin (MO-14):
// services, listening ports, logged-in users, boots and top processes, read when the tab is opened or refreshed, and
// pending updates on their own button (dnf may take a minute). Everything is a read: nothing polls, nothing is
// audited, and the read-only lock doesn't stop it. The fixes offered (restart a service, kill a process, install
// updates) are commands to copy, never run from here. Host names, IPs and users carry `data-mask` (FD-03).

import { useEffect, useState, type ReactNode } from "react";
import {
  CircleAlertIcon,
  CopyIcon,
  EllipsisIcon,
  HardDriveIcon,
  PackageIcon,
  ServerIcon,
  ShieldAlertIcon,
} from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { LevelIcon, Meter } from "@/components/MetricBits";
import {
  api,
  errorMessage,
  type AdminReport,
  type HostService,
  type ProcessInfo,
  type SessionSpecs,
  type UpdatesCheck,
} from "@/lib/api";
import { RefreshButton } from "@/components/RefreshButton";
import { formatDuration, formatWhen, plural } from "@/lib/format";
import {
  collectedByText,
  cpuLayout,
  daysSince,
  killCommand,
  listensOutside,
  logsCommand,
  portAddress,
  portIp,
  restartCommand,
  upgradeCommand,
  viaText,
  virtualizationName,
} from "@/lib/host-details";
import { formatBytes, formatPct, level, type Thresholds } from "@/lib/metrics";

export type HostDetailsTab = "system" | "admin";

interface Props {
  /** The session whose host is shown; null when closed. */
  session: { id: string; name: string } | null;
  tab?: HostDetailsTab;
  thresholds: Thresholds;
  onClose: () => void;
}

const dash = <span className="text-muted-foreground">—</span>;

function copy(text: string) {
  void navigator.clipboard?.writeText(text).then(
    () => toast.success("Copied", { description: text }),
    () => toast.error("Could not copy to the clipboard"),
  );
}

/** A labelled list of facts. */
export function FactList({ rows }: { rows: { label: string; value: ReactNode; hint?: string }[] }) {
  return (
    <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] items-baseline gap-x-4 gap-y-2 text-sm">
      {rows.map((row) => (
        <div key={row.label} className="contents">
          <dt className="text-muted-foreground" title={row.hint}>
            {row.label}
          </dt>
          <dd className="min-w-0 break-words">{row.value ?? dash}</dd>
        </div>
      ))}
    </dl>
  );
}

function Section({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <h3 className="text-sm font-medium">{title}</h3>
        {aside && <div className="ml-auto flex items-center gap-2">{aside}</div>}
      </div>
      {children}
    </section>
  );
}

/**
 * MO-13: a host's OS and hardware, as read. Shared with a VM's System tab ("From the guest"), which is narrow and lists
 * the VM's own disks already: `compact` keeps the filesystems' mount, use and size, and leaves the block devices out.
 */
export function SystemFacts({
  read,
  thresholds,
  compact = false,
}: {
  read: SessionSpecs;
  thresholds: Thresholds;
  compact?: boolean;
}) {
  const s = read.specs;
  const memory = s.memory;
  const swapUsed =
    memory.swapTotalBytes != null && memory.swapFreeBytes != null ? memory.swapTotalBytes - memory.swapFreeBytes : null;
  return (
    <div className="flex flex-col gap-5">
      <FactList
        rows={[
          { label: "OS", value: s.os.prettyName ?? s.os.name ?? s.system },
          {
            label: "Kernel",
            value: s.kernel ? (
              <span className="font-mono text-xs">
                {s.kernel}
                {s.architecture ? ` · ${s.architecture}` : ""}
              </span>
            ) : null,
          },
          {
            label: "Host name",
            value: s.hostname ? (
              <span className="font-mono text-xs" data-mask="host">
                {s.hostname}
              </span>
            ) : null,
          },
          { label: "Virtualization", value: virtualizationName(s.virtualization) },
          { label: "CPU", value: s.cpu.model },
          { label: "Cores", value: cpuLayout(s.cpu) },
          {
            label: "Memory",
            value:
              memory.totalBytes != null
                ? `${formatBytes(memory.totalBytes)}${
                    memory.availableBytes != null ? ` · ${formatBytes(memory.availableBytes)} available` : ""
                  }`
                : null,
          },
          {
            label: "Swap",
            value:
              memory.swapTotalBytes === 0
                ? "None"
                : memory.swapTotalBytes != null
                  ? `${formatBytes(swapUsed)} used of ${formatBytes(memory.swapTotalBytes)}${
                      s.swaps.length > 0 ? ` (${s.swaps.map((a) => `${a.path}, ${a.kind}`).join("; ")})` : ""
                    }`
                  : null,
          },
          {
            label: "Up since",
            value: read.bootedAt
              ? `${formatWhen(read.bootedAt)}${s.uptimeSecs != null ? ` (${formatDuration(s.uptimeSecs)})` : ""}`
              : null,
          },
        ]}
      />

      {s.filesystems.length > 0 && (
        <Section title="Filesystems" aside={<span className="text-xs text-muted-foreground">local only</span>}>
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Mounted on</TableHead>
                  {!compact && <TableHead>Device</TableHead>}
                  {!compact && <TableHead>Type</TableHead>}
                  <TableHead className="w-40">Used</TableHead>
                  <TableHead className="text-right">Size</TableHead>
                  {!compact && <TableHead className="text-right">Free</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {s.filesystems.map((f) => {
                  const fsLevel = level(f.usedPct, thresholds.disk);
                  return (
                    <TableRow key={`${f.source}|${f.mount}`}>
                      <TableCell className="font-mono text-xs">{f.mount}</TableCell>
                      {!compact && (
                        <TableCell
                          className="max-w-48 truncate font-mono text-xs text-muted-foreground"
                          title={f.source}
                        >
                          {f.source}
                        </TableCell>
                      )}
                      {!compact && <TableCell className="text-xs">{f.fstype ?? "—"}</TableCell>}
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Meter pct={f.usedPct} level={fsLevel} label={`Used on ${f.mount}`} />
                          <span className="flex w-12 shrink-0 items-center justify-end gap-1 text-xs tabular-nums">
                            <LevelIcon level={fsLevel} />
                            {formatPct(f.usedPct)}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="text-right text-xs tabular-nums">{formatBytes(f.sizeBytes)}</TableCell>
                      {!compact && (
                        <TableCell className="text-right text-xs tabular-nums">
                          {formatBytes(f.availableBytes)}
                        </TableCell>
                      )}
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </Section>
      )}

      {!compact && s.disks.length > 0 && (
        <Section title="Disks and partitions">
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead className="text-right">Size</TableHead>
                  <TableHead>Filesystem</TableHead>
                  <TableHead>Mounted on</TableHead>
                  <TableHead>Model</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {s.disks.map((d, i) => (
                  <TableRow key={`${d.name}-${i}`}>
                    <TableCell className="font-mono text-xs">
                      <span style={{ paddingLeft: `${d.depth * 1}rem` }}>{d.name}</span>
                    </TableCell>
                    <TableCell className="text-xs">
                      {d.kind}
                      {d.kind === "disk" && d.rotational === false ? " (SSD)" : ""}
                    </TableCell>
                    <TableCell className="text-right text-xs tabular-nums">{formatBytes(d.sizeBytes)}</TableCell>
                    <TableCell className="text-xs">{d.fstype ?? ""}</TableCell>
                    <TableCell className="font-mono text-xs">{d.mountpoint ?? ""}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {[d.model, d.transport].filter(Boolean).join(" · ")}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </Section>
      )}
    </div>
  );
}

function SystemTab({ sessionId, thresholds }: { sessionId: string; thresholds: Thresholds }) {
  const [read, setRead] = useState<{ for: string; value: SessionSpecs | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stale = false;
    api.hostSpecs(sessionId).then(
      (value) => !stale && setRead({ for: sessionId, value }),
      (err) => {
        if (stale) return;
        setRead({ for: sessionId, value: null });
        setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [sessionId]);

  const refresh = () => {
    setBusy(true);
    setError(null);
    api
      .hostSpecsRefresh(sessionId)
      .then(
        (value) => setRead({ for: sessionId, value }),
        (err) => setError(errorMessage(err)),
      )
      .finally(() => setBusy(false));
  };

  const current = read?.for === sessionId ? read.value : undefined;
  const refreshButton = <RefreshButton variant="outline" busy={busy} onClick={refresh} />;

  return (
    <div className="flex flex-col gap-4">
      {current && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <span>
            As of {formatWhen(current.collectedAt)}, read {collectedByText(current.collectedBy)}
          </span>
          <span className="ml-auto">{refreshButton}</span>
        </div>
      )}
      {error && (
        <Alert variant="destructive">
          <CircleAlertIcon />
          <AlertTitle>Could not read the host</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {current === undefined && (
        <div className="flex flex-col gap-2" aria-label="Loading">
          <Skeleton className="h-5 w-2/3" />
          <Skeleton className="h-5 w-1/2" />
          <Skeleton className="h-24 w-full" />
        </div>
      )}
      {current === null && (
        <Empty className="border py-8">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <ServerIcon />
            </EmptyMedia>
            <EmptyTitle>Not read yet</EmptyTitle>
            <EmptyDescription>
              Read when a terminal to it connects; Refresh reads them now, logging in once if no connection is open.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>{refreshButton}</EmptyContent>
        </Empty>
      )}
      {current && <SystemFacts read={current} thresholds={thresholds} />}
    </div>
  );
}

function ServiceMenu({
  manager,
  service,
}: {
  manager: AdminReport["details"]["serviceManager"];
  service: HostService;
}) {
  const logs = logsCommand(manager, service);
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-xs" aria-label={`Commands for ${service.name}`}>
          <EllipsisIcon />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onSelect={() => copy(restartCommand(manager, service))}>
          <CopyIcon /> Copy the restart command
        </DropdownMenuItem>
        {logs && (
          <DropdownMenuItem onSelect={() => copy(logs)}>
            <CopyIcon /> Copy the log command
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function ProcessTable({ title, rows }: { title: string; rows: ProcessInfo[] }) {
  return (
    <Section title={title}>
      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-16 text-right">PID</TableHead>
              <TableHead>User</TableHead>
              <TableHead className="text-right" title="CPU time over the process's life, as ps counts it">
                CPU
              </TableHead>
              <TableHead className="text-right">Memory</TableHead>
              <TableHead>Running for</TableHead>
              <TableHead>Program</TableHead>
              <TableHead className="w-8">
                <span className="sr-only">Commands</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((p) => (
              <TableRow key={p.pid}>
                <TableCell className="text-right font-mono text-xs tabular-nums">{p.pid}</TableCell>
                <TableCell className="text-xs" data-mask="user">
                  {p.user}
                </TableCell>
                <TableCell className="text-right text-xs tabular-nums">{formatPct(p.cpuPct)}</TableCell>
                <TableCell className="text-right text-xs tabular-nums">
                  {formatBytes(p.rssBytes)} ({formatPct(p.memPct)})
                </TableCell>
                <TableCell className="text-xs">{p.elapsedSecs != null ? formatDuration(p.elapsedSecs) : "—"}</TableCell>
                <TableCell className="max-w-48 truncate font-mono text-xs" title={p.command}>
                  {p.command}
                </TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon-xs" aria-label={`Commands for process ${p.pid}`}>
                        <EllipsisIcon />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onSelect={() => copy(killCommand(p.pid))}>
                        <CopyIcon /> Copy &quot;{killCommand(p.pid)}&quot;
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </Section>
  );
}

function UpdatesSection({ sessionId }: { sessionId: string }) {
  const [check, setCheck] = useState<UpdatesCheck | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = () => {
    setBusy(true);
    setError(null);
    api
      .hostUpdates(sessionId)
      .then(setCheck, (err) => setError(errorMessage(err)))
      .finally(() => setBusy(false));
  };
  const report = check?.report;
  const upgrade = report ? upgradeCommand(report) : null;
  return (
    <Section
      title="Pending updates"
      aside={
        <>
          {upgrade && report && report.packages.length > 0 && (
            <Button variant="ghost" size="sm" onClick={() => copy(upgrade)}>
              <CopyIcon data-icon="inline-start" /> Copy the upgrade command
            </Button>
          )}
          <Button variant="outline" size="sm" disabled={busy} onClick={run}>
            <PackageIcon data-icon="inline-start" className={busy ? "animate-pulse" : undefined} />
            {busy ? "Checking…" : check ? "Check again" : "Check for updates"}
          </Button>
        </>
      }
    >
      <p className="text-xs text-muted-foreground">
        apt&apos;s package lists are used as they are (refreshing them needs root); dnf refreshes its metadata first
        when it is old, which can take a minute or two. Remotely waits up to 2½ minutes.
      </p>
      {error && (
        <Alert variant="destructive">
          <CircleAlertIcon />
          <AlertTitle>Could not check for updates</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {report && (
        <div className="flex flex-col gap-2 text-sm">
          {report.manager === null ? (
            <p className="text-muted-foreground">Neither apt nor dnf is on this host.</p>
          ) : report.error ? (
            <p className="text-destructive">{report.error}</p>
          ) : (
            <p>
              {report.packages.length === 0
                ? "Nothing to update."
                : `${plural(report.packages.length, "package")} to update`}
              {report.securityCount > 0 && (
                <Badge variant="destructive" className="ml-2">
                  <ShieldAlertIcon /> {plural(report.securityCount, "security update")}
                </Badge>
              )}
              <span className="ml-2 text-xs text-muted-foreground">
                {report.manager}
                {report.listsRefreshedUnix != null &&
                  `, lists refreshed ${daysSince(report.listsRefreshedUnix) === 0 ? "today" : `${daysSince(report.listsRefreshedUnix)} days ago`}`}
                {check && `, checked in ${(check.tookMs / 1000).toFixed(1)} s ${viaText(check.via)}`}
              </span>
            </p>
          )}
          {report.packages.length > 0 && (
            <div className="max-h-72 overflow-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Package</TableHead>
                    <TableHead>Installed</TableHead>
                    <TableHead>New</TableHead>
                    <TableHead>From</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {report.packages.map((p) => (
                    <TableRow key={`${p.name}|${p.source}`}>
                      <TableCell className="font-mono text-xs">
                        {p.name}
                        {p.security && (
                          <Badge variant="destructive" className="ml-2">
                            security
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{p.current ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs">{p.version}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{p.source}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
      )}
    </Section>
  );
}

function AdminTab({ sessionId }: { sessionId: string }) {
  const [report, setReport] = useState<{ for: string; value: AdminReport } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ for: string; message: string } | null>(null);

  const read = (id: string) => {
    setBusy(true);
    setError(null);
    return api
      .hostAdmin(id)
      .then(
        (value) => setReport({ for: id, value }),
        (err) => setError({ for: id, message: errorMessage(err) }),
      )
      .finally(() => setBusy(false));
  };

  // Read once when the tab is opened: the user asked for it. Nothing polls.
  useEffect(() => {
    let stale = false;
    api.hostAdmin(sessionId).then(
      (value) => !stale && setReport({ for: sessionId, value }),
      (err) => !stale && setError({ for: sessionId, message: errorMessage(err) }),
    );
    return () => {
      stale = true;
    };
  }, [sessionId]);

  const current = report?.for === sessionId ? report.value : null;
  const failed = error?.for === sessionId ? error.message : null;
  const d = current?.details;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        {current ? (
          <span>
            Read {formatWhen(current.collectedAt)} {viaText(current.via)}
          </span>
        ) : (
          <span>{failed ? "" : "Reading services, ports, users and processes…"}</span>
        )}
        <RefreshButton className="ml-auto" variant="outline" busy={busy} onClick={() => void read(sessionId)} />
      </div>
      {failed && (
        <Alert variant="destructive">
          <CircleAlertIcon />
          <AlertTitle>Could not read the host</AlertTitle>
          <AlertDescription>{failed}</AlertDescription>
        </Alert>
      )}
      {!current && !failed && (
        <div className="flex flex-col gap-2" aria-label="Loading">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-32 w-full" />
        </div>
      )}
      {d && d.notLinux && (
        <p className="text-sm text-muted-foreground">
          The host answered, but not like Linux: admin details need Linux.
        </p>
      )}
      {d && !d.notLinux && (
        <>
          {d.failed.length > 0 && (
            <Alert variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>{plural(d.failed.length, "failed service")}</AlertTitle>
              <AlertDescription>
                <ul className="flex w-full flex-col gap-1">
                  {d.failed.map((s) => (
                    <li key={s.name} className="flex items-center gap-2">
                      <span className="font-mono text-xs">{s.name}</span>
                      <span className="truncate text-xs">{s.description}</span>
                      <span className="ml-auto">
                        <ServiceMenu manager={d.serviceManager} service={s} />
                      </span>
                    </li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          )}

          <Section
            title={`Running services (${d.running.length})`}
            aside={
              <span className="text-xs text-muted-foreground">
                {d.serviceManager === "systemd"
                  ? "systemd"
                  : d.serviceManager === "openRc"
                    ? "OpenRC"
                    : d.serviceManager === "sysV"
                      ? "SysV init"
                      : "no service manager found"}
              </span>
            }
          >
            <div className="max-h-64 overflow-auto rounded-lg border">
              <Table>
                <TableBody>
                  {[...d.running, ...d.otherServices].map((s) => (
                    <TableRow key={s.name}>
                      <TableCell className="font-mono text-xs">{s.name}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {s.state === "running" ? s.description : (s.sub ?? s.state)}
                      </TableCell>
                      <TableCell className="w-8">
                        <ServiceMenu manager={d.serviceManager} service={s} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Section>

          <Section title={`Listening ports (${d.ports.length})`}>
            {d.portsNeedRoot && (
              <p className="text-xs text-muted-foreground">
                Some ports show no program: it belongs to another user, and only root can see it. Remotely reads as the
                login user and doesn&apos;t use sudo here.
              </p>
            )}
            <div className="max-h-64 overflow-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-14">Proto</TableHead>
                    <TableHead>Address</TableHead>
                    <TableHead>Program</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {d.ports.map((p) => (
                    <TableRow key={`${p.protocol}|${p.ip}|${p.port}`}>
                      <TableCell className="text-xs uppercase">{p.protocol}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {/* FD-03: only the address is masked; "any" (0.0.0.0, ::, *) and loopback stay. */}
                        <span data-mask="ip">{portIp(p)}</span>
                        {portAddress(p).slice(portIp(p).length)}
                        {!listensOutside(p) && (
                          <span className="ml-2 font-sans text-muted-foreground">this host only</span>
                        )}
                      </TableCell>
                      <TableCell className="text-xs">
                        {p.processes.length > 0 ? (
                          <>
                            {p.processes.join(", ")}
                            {p.pids.length > 0 && (
                              <span className="text-muted-foreground"> (pid {p.pids.join(", ")})</span>
                            )}
                          </>
                        ) : (
                          dash
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Section>

          <Section title={`Logged in (${d.users.length})`}>
            {d.users.length === 0 ? (
              <p className="text-xs text-muted-foreground">Nobody is logged in.</p>
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableBody>
                    {d.users.map((u, i) => (
                      <TableRow key={`${u.user}|${u.terminal}|${i}`}>
                        <TableCell className="text-xs" data-mask="user">
                          {u.user}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{u.terminal}</TableCell>
                        <TableCell className="text-xs">{u.since}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {u.ip ? (
                            <span data-mask="ip">{u.ip}</span>
                          ) : u.host ? (
                            <span data-mask="host">{u.host}</span>
                          ) : (
                            ""
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </Section>

          <Section title="Boots">
            <FactList
              rows={[
                {
                  label: "Last boot",
                  value: d.bootText ?? (d.uptimeSecs != null ? `${formatDuration(d.uptimeSecs)} ago` : null),
                },
                { label: "Up for", value: d.uptimeSecs != null ? formatDuration(d.uptimeSecs) : null },
              ]}
            />
            {d.boots.length > 0 && (
              <ul className="flex flex-col gap-1 text-xs">
                {d.boots.map((b, i) => (
                  <li key={i} className="flex gap-2">
                    <Badge variant={b.kind === "reboot" ? "secondary" : "outline"} className="w-16 justify-center">
                      {b.kind === "reboot" ? "boot" : "shutdown"}
                    </Badge>
                    <span className="tabular-nums">{b.when}</span>
                    {b.kernel && <span className="font-mono text-muted-foreground">{b.kernel}</span>}
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <ProcessTable title={`Top processes by CPU (of ${d.processCount})`} rows={d.topCpu} />
          <ProcessTable title="Top processes by memory" rows={d.topMemory} />
        </>
      )}
      <UpdatesSection sessionId={sessionId} />
    </div>
  );
}

export function HostDetailsSheet({ session, tab, thresholds, onClose }: Props) {
  const [shown, setShown] = useState<HostDetailsTab>(tab ?? "system");
  const [openedFor, setOpenedFor] = useState<string | null>(null);
  /** The Admin tab reads when it is first opened, then keeps what it read until Refresh. */
  const [adminSeen, setAdminSeen] = useState(false);
  // A new session opens on the tab asked for (state adjusted while rendering, not in an effect).
  if (session && openedFor !== session.id) {
    setOpenedFor(session.id);
    setShown(tab ?? "system");
    setAdminSeen(tab === "admin");
  }
  if (shown === "admin" && !adminSeen) setAdminSeen(true);
  const sessionId = session?.id ?? null;

  // Remotely's own connection, if a read made one, closes with the panel.
  useEffect(() => {
    if (!sessionId) return;
    return () => {
      void api.hostDetailsRelease(sessionId).catch(() => undefined);
    };
  }, [sessionId]);

  return (
    <Sheet open={session !== null} onOpenChange={(open) => !open && onClose()}>
      {session && (
        <SheetContent className="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-3xl">
          <SheetHeader>
            <div className="flex items-center gap-2">
              <Badge variant="secondary">
                <HardDriveIcon /> Host details
              </Badge>
            </div>
            <SheetTitle>{session.name}</SheetTitle>
            <SheetDescription>
              Reads only: nothing here changes the host. Commands offered for fixes are copied, never run.
            </SheetDescription>
          </SheetHeader>
          <Tabs value={shown} onValueChange={(v) => setShown(v as HostDetailsTab)} className="min-h-0 flex-1 gap-0">
            <div className="border-b px-4 pb-2">
              <TabsList>
                <TabsTrigger value="system">System</TabsTrigger>
                <TabsTrigger value="admin">Admin</TabsTrigger>
              </TabsList>
            </div>
            <TabsContent value="system" className="min-h-0 overflow-auto p-4">
              <SystemTab key={session.id} sessionId={session.id} thresholds={thresholds} />
            </TabsContent>
            <TabsContent value="admin" className="min-h-0 overflow-auto p-4">
              {adminSeen && <AdminTab key={session.id} sessionId={session.id} />}
            </TabsContent>
          </Tabs>
        </SheetContent>
      )}
    </Sheet>
  );
}
