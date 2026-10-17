// VM list (VM-01) with selection and bulk power actions (VM-02, VM-03). Listing asks the core to read
// Workstation's library, the chosen folders and `vmrun list`; every action is a command submitted to
// the command bus, never a vmrun call.

import { useEffect, useState, type MouseEvent } from "react";
import { FolderPlusIcon, MonitorOffIcon, RefreshCwIcon, TriangleAlertIcon } from "lucide-react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EnvBadge, StateBadge, ToolsLabel } from "@/components/Badges";
import {
  api,
  errorCode,
  errorMessage,
  type InventoryWarning,
  type PowerOp,
  type PowerState,
  type SubmitOutcome,
  type VmRecord,
} from "@/lib/api";

interface Props {
  /** Shows the approval dialog for commands the policy engine says need one. */
  onSubmitted: (outcome: SubmitOutcome) => void;
  onOpenSettings: () => void;
  /** Changes when the list should be read again: a job finished or a setting changed. */
  refreshKey: number;
}

interface Action {
  label: string;
  op: PowerOp;
  /** States the action makes sense in. VMs in other states are left out of the command. */
  appliesTo: PowerState[];
  destructive?: boolean;
}

const ON: PowerState[] = ["running", "paused"];

const ACTIONS: Action[] = [
  { label: "Suspend", op: { kind: "suspend" }, appliesTo: ["running"] },
  { label: "Pause", op: { kind: "pause" }, appliesTo: ["running"] },
  { label: "Unpause", op: { kind: "unpause" }, appliesTo: ["paused"] },
  { label: "Restart", op: { kind: "reset", mode: "soft" }, appliesTo: ON },
  { label: "Shut down", op: { kind: "stop", mode: "soft" }, appliesTo: ["running"] },
  { label: "Power off", op: { kind: "stop", mode: "hard" }, appliesTo: ON, destructive: true },
];

type LoadError = { code?: string; message: string };

function formatRam(mb: number | null) {
  if (!mb) return "—";
  return mb % 1024 === 0 ? `${mb / 1024} GB` : `${(mb / 1024).toFixed(1)} GB`;
}

export function VmsPage({ onSubmitted, onOpenSettings, refreshKey }: Props) {
  const [vms, setVms] = useState<VmRecord[]>([]);
  const [warnings, setWarnings] = useState<InventoryWarning[]>([]);
  const [error, setError] = useState<LoadError | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [anchor, setAnchor] = useState<number | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [refreshes, setRefreshes] = useState(0);
  const [loadedKey, setLoadedKey] = useState<string | null>(null);
  const key = `${refreshes}:${refreshKey}`;
  const loading = loadedKey !== key;

  // Finds every VM on open, on Refresh, after a job finishes and after a setting changes.
  useEffect(() => {
    let stale = false;
    api.vmRefresh().then(
      (report) => {
        if (stale) return;
        setVms(report.vms);
        setWarnings(report.warnings);
        setError(null);
        // Keep only selections that are still listed.
        setSelected((prev) => new Set(report.vms.map((v) => v.vmxPath).filter((p) => prev.has(p))));
        setLoadedKey(key);
      },
      (err) => {
        if (stale) return;
        setError({ code: errorCode(err), message: errorMessage(err) });
        setLoadedKey(key);
      },
    );
    return () => {
      stale = true;
    };
  }, [key]);

  // Click toggles one VM; shift-click selects the range from the last click (VM-02).
  function toggle(index: number, e: MouseEvent) {
    const path = vms[index].vmxPath;
    setSelected((prev) => {
      const next = new Set(prev);
      if (e.shiftKey && anchor !== null) {
        const [from, to] = anchor < index ? [anchor, index] : [index, anchor];
        for (let i = from; i <= to; i++) next.add(vms[i].vmxPath);
      } else if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
    setAnchor(index);
  }

  const selectedVms = vms.filter((v) => selected.has(v.vmxPath));
  const allSelected = vms.length > 0 && selected.size === vms.length;
  const runningCount = vms.filter((v) => ON.includes(v.powerState)).length;

  /** Selected VMs the action applies to. Unknown state (vmrun missing) is sent as is. */
  function targetsFor(appliesTo: PowerState[]) {
    return selectedVms.filter((v) => v.powerState === "unknown" || appliesTo.includes(v.powerState));
  }

  async function run(op: PowerOp, targets: VmRecord[]) {
    setSubmitting(true);
    try {
      const refs = targets.map((v) => ({ kind: "vm" as const, vmxPath: v.vmxPath }));
      onSubmitted(await api.submit({ type: "vmPower", targets: refs, op }));
    } catch (err) {
      setError({ code: errorCode(err), message: errorMessage(err) });
    } finally {
      setSubmitting(false);
    }
  }

  const missingWorkstation = warnings.some((w) => w.code === "vmrun_not_found");

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" onClick={() => setRefreshes((n) => n + 1)} disabled={loading}>
          <RefreshCwIcon data-icon="inline-start" className={loading ? "animate-spin" : undefined} />
          Refresh
        </Button>
        <span className="mr-2 text-sm text-muted-foreground">
          {vms.length} VMs · {runningCount} running{selected.size > 0 && ` · ${selected.size} selected`}
        </span>
        {ACTIONS.map((a) => {
          const targets = targetsFor(a.appliesTo);
          return (
            <Button
              key={a.label}
              variant={a.destructive ? "destructive" : "outline"}
              disabled={targets.length === 0 || submitting}
              onClick={() => void run(a.op, targets)}
            >
              {a.label}
            </Button>
          );
        })}
      </div>

      {error && (
        <Alert variant="destructive">
          <TriangleAlertIcon />
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{error.message}</AlertDescription>
        </Alert>
      )}

      {warnings.length > 0 && (
        <Alert>
          <TriangleAlertIcon />
          <AlertTitle>
            {missingWorkstation ? "VMware Workstation was not found" : "Some VMs may be missing from the list"}
          </AlertTitle>
          <AlertDescription>
            <ul className="list-disc pl-5">
              {warnings.map((w) => (
                <li key={w.message}>{w.message}</li>
              ))}
            </ul>
          </AlertDescription>
          <AlertAction>
            <Button size="sm" variant="outline" onClick={onOpenSettings}>
              {missingWorkstation ? "Set the vmrun.exe path" : "Settings"}
            </Button>
          </AlertAction>
        </Alert>
      )}

      {!error && !loading && vms.length === 0 && (
        <Empty className="border">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <MonitorOffIcon />
            </EmptyMedia>
            <EmptyTitle>No VMs found</EmptyTitle>
            <EmptyDescription>
              Remotely lists the VMs in VMware Workstation&apos;s library and in folders you choose. Open a VM in
              Workstation once, or add the folder that holds your VMs.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button variant="outline" onClick={onOpenSettings}>
              <FolderPlusIcon data-icon="inline-start" />
              Add a VM folder
            </Button>
          </EmptyContent>
        </Empty>
      )}

      {vms.length > 0 && (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">
                  <Checkbox
                    aria-label="Select all VMs"
                    checked={allSelected ? true : selected.size > 0 ? "indeterminate" : false}
                    onCheckedChange={() => setSelected(allSelected ? new Set() : new Set(vms.map((v) => v.vmxPath)))}
                  />
                </TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Guest OS</TableHead>
                <TableHead className="text-right">vCPU</TableHead>
                <TableHead className="text-right">RAM</TableHead>
                <TableHead>IP address</TableHead>
                <TableHead>Tools</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Label</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vms.map((vm, i) => (
                <TableRow
                  key={vm.vmxPath}
                  data-state={selected.has(vm.vmxPath) ? "selected" : undefined}
                  onClick={(e) => toggle(i, e)}
                  className="select-none"
                >
                  <TableCell>
                    {/* The click (or Space) bubbles to the row, which does the selecting. */}
                    <Checkbox aria-label={`Select ${vm.displayName}`} checked={selected.has(vm.vmxPath)} />
                  </TableCell>
                  <TableCell>
                    <div className="font-medium">{vm.displayName}</div>
                    <div className="font-mono text-xs break-all whitespace-normal text-muted-foreground">
                      {vm.vmxPath}
                    </div>
                  </TableCell>
                  <TableCell>
                    {vm.guestOsName ?? vm.guestOs ?? <span className="text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{vm.numVcpus ?? "—"}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatRam(vm.memsizeMb)}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {vm.ipAddress ?? <span className="font-sans text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell>
                    <ToolsLabel state={vm.toolsState} />
                  </TableCell>
                  <TableCell>
                    <StateBadge state={vm.powerState} />
                  </TableCell>
                  <TableCell>
                    <EnvBadge env={vm.environment} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
