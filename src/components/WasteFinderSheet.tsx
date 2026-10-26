// VM-16, VM-14: the waste finder, a read-only report in a side sheet on the Virtual machines page: running VMs idle for
// days (the dashboard's history: their share of this PC's CPU, and their guest's CPU and network when a linked
// session is watched), suspended VMs and what their saved state takes, long or large snapshot chains, and folders
// with VM files no VM in the list uses (only in the scanned folders and the hypervisors' and templates' VM folders).
//
// Each row's action is the usual one through the bus and its approvals: Suspend, Delete VM (R3, Critical), the VM's
// Snapshots tab to delete some, and Open folder (Explorer, at a folder the core names). The report itself changes
// nothing, is not audited, and the read-only lock doesn't stop it. QL-08: disabled actions say why.

import { useEffect, useState, type ReactNode } from "react";
import {
  CameraIcon,
  FolderOpenIcon,
  MoonIcon,
  PauseIcon,
  RecycleIcon,
  RefreshCwIcon,
  Trash2Icon,
  TriangleAlertIcon,
} from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EnvBadge, HypervisorLabel, StateBadge } from "@/components/Badges";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type SubmitOutcome } from "@/lib/api";
import { formatWhen, plural } from "@/lib/format";
import { formatBytes } from "@/lib/retention";
import type { VmView } from "@/lib/vm-snapshots";
import { insightApi, type WasteOptions, type WasteReport, type WasteVm } from "@/lib/vm-insight-api";
import {
  CHAIN_DEPTH_CHOICES,
  CHAIN_GB_CHOICES,
  IDLE_DAY_CHOICES,
  WASTE_DEFAULTS,
  deleteVmReason,
  orphanKindLabel,
  suspendReason,
  wasteTotals,
} from "@/lib/vm-insight";

interface Props {
  open: boolean;
  onClose: () => void;
  readOnly: string | null;
  onSubmitted: (outcome: SubmitOutcome) => void;
  /** Opens a VM's details on a tab (the snapshots to delete some). */
  onOpenVm: (vmxPath: string, view: VmView) => void;
}

function formatMb(mb: number | null) {
  if (!mb) return "—";
  return mb >= 1024 ? `${(mb / 1024).toFixed(mb % 1024 ? 1 : 0)} GB RAM` : `${mb} MB RAM`;
}

export function WasteFinderSheet({ open, onClose, ...rest }: Props) {
  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      {/* Mounted while open, so each opening looks again. */}
      {open && <WasteBody {...rest} />}
    </Sheet>
  );
}

function WasteBody({ readOnly, onSubmitted, onOpenVm }: Omit<Props, "open" | "onClose">) {
  const [options, setOptions] = useState<WasteOptions>(WASTE_DEFAULTS);
  // The options apply when Find is pressed; `n` counts the runs.
  const [asked, setAsked] = useState<{ n: number; options: WasteOptions }>({ n: 0, options: WASTE_DEFAULTS });
  const [result, setResult] = useState<{ for: number; report?: WasteReport; error?: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const loading = result?.for !== asked.n;
  const report = result?.report ?? null;
  const error = result?.error ?? null;

  useEffect(() => {
    let stale = false;
    insightApi.wasteReport(asked.options).then(
      (found) => !stale && setResult({ for: asked.n, report: found }),
      (err: unknown) => !stale && setResult({ for: asked.n, error: errorMessage(err) }),
    );
    return () => {
      stale = true;
    };
  }, [asked]);

  async function submit(command: Parameters<typeof api.submit>[0]) {
    setBusy(true);
    try {
      onSubmitted(await api.submit(command));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  function openFolder(target: { folder: string } | { vmxPath: string }) {
    insightApi.wasteOpenFolder(target).catch((err: unknown) => toast.error(errorMessage(err)));
  }

  const suspend = (vm: WasteVm) =>
    void submit({ type: "vmPower", targets: [{ kind: "vm", vmxPath: vm.vmxPath }], op: { kind: "suspend" } });
  const remove = (vm: WasteVm) =>
    void submit({ type: "vmLifecycle", targets: [{ kind: "vm", vmxPath: vm.vmxPath }], op: { kind: "delete" } });
  const totals = report ? wasteTotals(report) : null;
  const busyReason = busy ? "Sending the last action…" : null;

  return (
    <SheetContent className="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-4xl">
      <SheetHeader>
        <SheetTitle className="flex items-center gap-2">
          <RecycleIcon className="size-4" /> Waste finder
        </SheetTitle>
        <SheetDescription>
          What takes this PC&apos;s memory and disk for little. A report only: each action asks for approval as anywhere
          else.
        </SheetDescription>
      </SheetHeader>
      <div className="flex flex-wrap items-end gap-3 border-b px-4 pb-3">
        <Choice
          id="waste-idle"
          label="Idle for"
          value={options.idleDays}
          choices={IDLE_DAY_CHOICES}
          text={(n) => plural(n, "day")}
          onChange={(idleDays) => setOptions((o) => ({ ...o, idleDays }))}
        />
        <Choice
          id="waste-depth"
          label="Chains from"
          value={options.chainDepth}
          choices={CHAIN_DEPTH_CHOICES}
          text={(n) => `${n} deep`}
          onChange={(chainDepth) => setOptions((o) => ({ ...o, chainDepth }))}
        />
        <Choice
          id="waste-gb"
          label="or"
          value={options.chainGb}
          choices={CHAIN_GB_CHOICES}
          text={(n) => `${n} GB`}
          onChange={(chainGb) => setOptions((o) => ({ ...o, chainGb }))}
        />
        <Button variant="outline" disabled={loading} onClick={() => setAsked((a) => ({ n: a.n + 1, options }))}>
          <RefreshCwIcon data-icon="inline-start" className={loading ? "animate-spin" : undefined} />
          Find waste
        </Button>
        {totals && (
          <span className="ml-auto text-sm text-muted-foreground">
            {plural(totals.rows, "finding")} · {formatBytes(totals.diskBytes)} on disk
            {totals.memoryMb > 0 && ` · ${formatMb(totals.memoryMb)} in idle VMs`}
          </span>
        )}
      </div>
      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-auto p-4">
        {error && (
          <Alert variant="destructive">
            <TriangleAlertIcon />
            <AlertTitle>Could not read everything</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {!report && !error && (
          <div className="flex flex-col gap-2" aria-label="Looking for waste">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
          </div>
        )}
        {report && (
          <>
            {report.notes.map((n) => (
              <p key={n} className="text-xs text-muted-foreground">
                {n}
              </p>
            ))}
            <Section
              icon={<PauseIcon />}
              title={`Idle for ${plural(report.idleDays, "day")}`}
              count={report.idle.length}
              empty="No running VM was idle that long (the dashboard's history must cover a third of the time)."
            >
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>VM</TableHead>
                    <TableHead>Busiest hour</TableHead>
                    <TableHead>History</TableHead>
                    <TableHead className="w-0" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {report.idle.map(({ vm, verdict, guestSession }) => (
                    <TableRow key={vm.vmxPath}>
                      <VmCell vm={vm} extra={formatMb(vm.memoryMb)} />
                      <TableCell className="text-xs">
                        {verdict.cpuPeakHour.toFixed(1)}% of this PC&apos;s CPU
                        {verdict.guestCpuPeakHour !== null && (
                          <div className="text-muted-foreground">
                            guest {verdict.guestCpuPeakHour.toFixed(1)}% CPU
                            {guestSession ? ` (${guestSession})` : ""}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-xs">{verdict.coveredHours} h</TableCell>
                      <TableCell>
                        <Actions>
                          <WhyDisabled reason={suspendReason(vm, readOnly) ?? busyReason}>
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={(suspendReason(vm, readOnly) ?? busyReason) !== null}
                              onClick={() => suspend(vm)}
                            >
                              <MoonIcon data-icon="inline-start" />
                              Suspend…
                            </Button>
                          </WhyDisabled>
                          <FolderButton onClick={() => openFolder({ vmxPath: vm.vmxPath })} />
                        </Actions>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Section>

            <Section icon={<MoonIcon />} title="Suspended" count={report.suspended.length} empty="No VM is suspended.">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>VM</TableHead>
                    <TableHead>Saved state</TableHead>
                    <TableHead>Folder</TableHead>
                    <TableHead className="w-0" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {report.suspended.map((s) => (
                    <TableRow key={s.vm.vmxPath}>
                      <VmCell vm={s.vm} extra={s.since ? `since ${formatWhen(s.since)}` : null} />
                      <TableCell className="text-xs">
                        {s.stateBytes !== null ? formatBytes(s.stateBytes) : "—"}
                      </TableCell>
                      <TableCell className="text-xs">
                        {s.folderBytes !== null ? formatBytes(s.folderBytes) : "—"}
                      </TableCell>
                      <TableCell>
                        <Actions>
                          <DeleteButton
                            reason={deleteVmReason(s.vm, readOnly) ?? busyReason}
                            onClick={() => remove(s.vm)}
                          />
                          <FolderButton onClick={() => openFolder({ vmxPath: s.vm.vmxPath })} />
                        </Actions>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Section>

            <Section
              icon={<CameraIcon />}
              title="Long or large snapshot chains"
              count={report.chains.length}
              empty={`No VM has a chain ${report.options.chainDepth} deep or ${report.options.chainGb} GB of snapshot files.`}
            >
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>VM</TableHead>
                    <TableHead>Snapshots</TableHead>
                    <TableHead>Snapshot files</TableHead>
                    <TableHead className="w-0" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {report.chains.map((c) => (
                    <TableRow key={c.vm.vmxPath}>
                      <VmCell vm={c.vm} extra={c.why.join(", ")} />
                      <TableCell className="text-xs">
                        {c.snapshots}, {c.depth} deep
                        {c.oldest && <div className="text-muted-foreground">oldest {formatWhen(c.oldest)}</div>}
                      </TableCell>
                      <TableCell className="text-xs">
                        {c.snapshotBytes !== null ? formatBytes(c.snapshotBytes) : "—"}
                      </TableCell>
                      <TableCell>
                        <Actions>
                          <Button size="sm" variant="outline" onClick={() => onOpenVm(c.vm.vmxPath, "snapshots")}>
                            <CameraIcon data-icon="inline-start" />
                            Snapshots…
                          </Button>
                          <FolderButton onClick={() => openFolder({ vmxPath: c.vm.vmxPath })} />
                        </Actions>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Section>

            <Section
              icon={<FolderOpenIcon />}
              title="Folders no VM in the list uses"
              count={report.orphans.length}
              empty={
                report.searched.length === 0
                  ? "No folder to search: choose VM folders to scan in Settings, General."
                  : "Every folder with VM files belongs to a VM in the list."
              }
            >
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Folder</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead className="w-0" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {report.orphans.map((o) => (
                    <TableRow key={o.path}>
                      <TableCell className="max-w-96 whitespace-normal">
                        <div className="font-mono text-xs break-all">{o.path}</div>
                        <div className="text-xs text-muted-foreground">
                          {orphanKindLabel(o.kind)}: {o.examples.join(", ")}
                          {o.newest && ` · last written ${formatWhen(o.newest)}`}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs">
                        {formatBytes(o.bytes)}
                        <div className="text-muted-foreground">{plural(o.files, "file")}</div>
                      </TableCell>
                      <TableCell>
                        <FolderButton onClick={() => openFolder({ folder: o.path })} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Section>

            <div className="text-xs text-muted-foreground">
              {report.searched.length > 0 && (
                <p>
                  Searched (and the folders in them, 4 levels down):{" "}
                  <span className="font-mono break-all">{report.searched.join("; ")}</span>
                </p>
              )}
              {report.skipped.map((s) => (
                <p key={s.path}>
                  Not searched: <span className="font-mono break-all">{s.path}</span>: {s.reason}
                </p>
              ))}
              {report.problems.map((p) => (
                <p key={p} className="text-destructive">
                  {p}
                </p>
              ))}
              <p>Read {formatWhen(report.readAt)}.</p>
            </div>
          </>
        )}
      </div>
    </SheetContent>
  );
}

function Choice({
  id,
  label,
  value,
  choices,
  text,
  onChange,
}: {
  id: string;
  label: string;
  value: number;
  choices: number[];
  text: (n: number) => string;
  onChange: (n: number) => void;
}) {
  return (
    <div className="grid gap-1">
      <Label htmlFor={id} className="text-xs font-normal text-muted-foreground">
        {label}
      </Label>
      <Select value={String(value)} onValueChange={(v) => onChange(Number(v))}>
        <SelectTrigger id={id} className="w-28">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {choices.map((c) => (
            <SelectItem key={c} value={String(c)}>
              {text(c)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function Section({
  icon,
  title,
  count,
  empty,
  children,
}: {
  icon: ReactNode;
  title: string;
  count: number;
  empty: string;
  children: ReactNode;
}) {
  return (
    <section>
      <h3 className="mb-1.5 flex items-center gap-2 font-medium [&_svg]:size-4">
        {icon}
        {title}
        <Badge variant="secondary" className="tabular-nums">
          {count}
        </Badge>
      </h3>
      {count === 0 ? <p className="text-xs text-muted-foreground">{empty}</p> : children}
    </section>
  );
}

function VmCell({ vm, extra }: { vm: WasteVm; extra: string | null }) {
  return (
    <TableCell className="max-w-72 whitespace-normal">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-medium">{vm.name}</span>
        <HypervisorLabel hypervisor={vm.hypervisor} />
        <StateBadge state={vm.powerState} />
        {vm.environment !== "none" && <EnvBadge env={vm.environment} />}
      </div>
      {extra && <div className="text-xs text-muted-foreground">{extra}</div>}
    </TableCell>
  );
}

function Actions({ children }: { children: ReactNode }) {
  return <div className="flex justify-end gap-1.5">{children}</div>;
}

function FolderButton({ onClick }: { onClick: () => void }) {
  return (
    <Button
      size="icon-sm"
      variant="ghost"
      aria-label="Open the folder in Explorer"
      title="Open the folder in Explorer"
      onClick={onClick}
    >
      <FolderOpenIcon />
    </Button>
  );
}

function DeleteButton({ reason, onClick }: { reason: string | null; onClick: () => void }) {
  return (
    <WhyDisabled reason={reason}>
      <Button size="sm" variant="outline" disabled={reason !== null} onClick={onClick}>
        <Trash2Icon data-icon="inline-start" />
        Delete VM…
      </Button>
    </WhyDisabled>
  );
}
