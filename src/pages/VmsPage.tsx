// VM list (VM-01) with selection and bulk power actions (VM-02, VM-03). Listing asks the core for
// `vmrun list`; every action is a command submitted to the command bus, never a vmrun call.

import { useEffect, useState, type MouseEvent } from "react";
import { MonitorOffIcon, RefreshCwIcon, TriangleAlertIcon } from "lucide-react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EnvBadge, StateBadge } from "@/components/Badges";
import { api, errorCode, errorMessage, type PowerOp, type SubmitOutcome, type VmRecord } from "@/lib/api";

interface Props {
  /** Shows the approval dialog for commands the policy engine says need one. */
  onSubmitted: (outcome: SubmitOutcome) => void;
  onOpenSettings: () => void;
}

const ACTIONS: { label: string; op: PowerOp; destructive?: boolean }[] = [
  { label: "Suspend", op: { kind: "suspend" } },
  { label: "Pause", op: { kind: "pause" } },
  { label: "Unpause", op: { kind: "unpause" } },
  { label: "Restart", op: { kind: "reset", mode: "soft" } },
  { label: "Shut down", op: { kind: "stop", mode: "soft" } },
  { label: "Power off", op: { kind: "stop", mode: "hard" }, destructive: true },
];

type LoadError = { code?: string; message: string };

export function VmsPage({ onSubmitted, onOpenSettings }: Props) {
  const [vms, setVms] = useState<VmRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<LoadError | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [anchor, setAnchor] = useState<number | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [refreshes, setRefreshes] = useState(0);

  // Asks Workstation for running VMs on open and on every Refresh.
  useEffect(() => {
    let stale = false;
    api.vmListRunning().then(
      (running) => {
        if (stale) return;
        setVms(running);
        setError(null);
        // Keep only selections that are still listed.
        setSelected((prev) => new Set(running.map((v) => v.vmxPath).filter((p) => prev.has(p))));
        setLoading(false);
      },
      (err) => {
        if (stale) return;
        setError({ code: errorCode(err), message: errorMessage(err) });
        setLoading(false);
      },
    );
    return () => {
      stale = true;
    };
  }, [refreshes]);

  function refresh() {
    setLoading(true);
    setRefreshes((n) => n + 1);
  }

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

  const allSelected = vms.length > 0 && selected.size === vms.length;

  async function run(op: PowerOp) {
    setSubmitting(true);
    try {
      const targets = [...selected].map((vmxPath) => ({ kind: "vm" as const, vmxPath }));
      onSubmitted(await api.submit({ type: "vmPower", targets, op }));
    } catch (err) {
      setError({ code: errorCode(err), message: errorMessage(err) });
    } finally {
      setSubmitting(false);
    }
  }

  const missingWorkstation = error?.code === "vmrun_not_found";

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" onClick={refresh} disabled={loading}>
          <RefreshCwIcon data-icon="inline-start" className={loading ? "animate-spin" : undefined} />
          Refresh
        </Button>
        <span className="mr-2 text-sm text-muted-foreground">
          {vms.length} running{selected.size > 0 && ` · ${selected.size} selected`}
        </span>
        {ACTIONS.map((a) => (
          <Button
            key={a.label}
            variant={a.destructive ? "destructive" : "outline"}
            disabled={selected.size === 0 || submitting}
            onClick={() => void run(a.op)}
          >
            {a.label}
          </Button>
        ))}
      </div>

      {error && (
        <Alert variant={missingWorkstation ? "default" : "destructive"}>
          <TriangleAlertIcon />
          <AlertTitle>{missingWorkstation ? "VMware Workstation was not found" : "Something went wrong"}</AlertTitle>
          <AlertDescription>{error.message}</AlertDescription>
          {missingWorkstation && (
            <AlertAction>
              <Button size="sm" variant="outline" onClick={onOpenSettings}>
                Set the vmrun.exe path
              </Button>
            </AlertAction>
          )}
        </Alert>
      )}

      {!error && !loading && vms.length === 0 && (
        <Empty className="border">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <MonitorOffIcon />
            </EmptyMedia>
            <EmptyTitle>No VMs are running</EmptyTitle>
            <EmptyDescription>
              Start a VM in VMware Workstation, then press Refresh. Only running VMs are listed for now.
            </EmptyDescription>
          </EmptyHeader>
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
                    <div className="font-medium">
                      {vm.displayName}
                      {vm.protected && <span className="text-muted-foreground"> · protected</span>}
                    </div>
                    <div className="font-mono text-xs break-all whitespace-normal text-muted-foreground">
                      {vm.vmxPath}
                    </div>
                  </TableCell>
                  <TableCell>{vm.guestOs ?? <span className="text-muted-foreground">—</span>}</TableCell>
                  <TableCell className="text-right tabular-nums">{vm.numVcpus ?? "—"}</TableCell>
                  <TableCell className="text-right tabular-nums">
                    {vm.memsizeMb ? `${(vm.memsizeMb / 1024).toFixed(1)} GB` : "—"}
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
