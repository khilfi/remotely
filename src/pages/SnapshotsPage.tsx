// Snapshot manager (VM-04, VM-05): every VM's snapshot tree with creation times, snapshots older than
// 30 days flagged, and Remotely's safety snapshots marked. The trees are read from each VM's .vmsd
// file by the core (no vmrun call). Taking, reverting and deleting, in bulk or on one VM, are
// commands submitted to the command bus; revert and delete always go through an approval.

import { useEffect, useState, type MouseEvent } from "react";
import {
  CameraIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  HistoryIcon,
  ListChecksIcon,
  MapPinIcon,
  RefreshCwIcon,
  ShieldIcon,
  Trash2Icon,
  TriangleAlertIcon,
  Undo2Icon,
} from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EnvBadge, StateBadge } from "@/components/Badges";
import { SnapshotActionDialog, type SnapshotAction } from "@/components/SnapshotActionDialog";
import {
  api,
  errorMessage,
  type Command,
  type SnapshotLimits,
  type SnapshotNode,
  type SubmitOutcome,
  type VmSnapshots,
} from "@/lib/api";
import { formatAge, plural } from "@/lib/format";

interface Props {
  /** The page is shown. The trees are read each time it opens, so they match the VM list. */
  active: boolean;
  /** Shows the approval dialog for commands the policy engine says need one. */
  onSubmitted: (outcome: SubmitOutcome) => void;
  /** Changes when the trees should be read again: a job finished or a setting changed. */
  refreshKey: number;
  /** VMs picked on the VMs page to work on here; `n` changes each time the user comes over. */
  preselect: { paths: string[]; n: number } | null;
}

const vmRef = (vmxPath: string) => ({ kind: "vm" as const, vmxPath });

/** The name to give vmrun: the plain name, or the path form when this VM has two with that name. */
function snapshotArg(vm: VmSnapshots, node: SnapshotNode) {
  const twins = vm.snapshots.filter((s) => s.name === node.name).length;
  return twins > 1 ? node.path : node.name;
}

export function SnapshotsPage({ active, onSubmitted, refreshKey, preselect }: Props) {
  const [vms, setVms] = useState<VmSnapshots[]>([]);
  const [limits, setLimits] = useState<SnapshotLimits | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshes, setRefreshes] = useState(0);
  const [text, setText] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [anchor, setAnchor] = useState<number | null>(null);
  // Collapsed rather than expanded, so a VM shows its tree until the user folds it.
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<SnapshotAction | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [usedPreselect, setUsedPreselect] = useState<number | null>(null);

  useEffect(() => {
    api.snapshotLimits().then(setLimits, () => setLimits(null));
  }, []);

  // VM-04: reads the trees when the page opens, on Refresh and after a job finishes. The VM list
  // comes from the last inventory refresh, so Refresh here also asks Workstation again.
  useEffect(() => {
    if (!active) return;
    let stale = false;
    const load = refreshes > 0 ? api.vmRefresh().then(() => api.snapshots()) : api.snapshots();
    load.then(
      (list) => {
        if (stale) return;
        setVms(list);
        setError(null);
        setLoading(false);
        setSelected((prev) => new Set(list.map((v) => v.vmxPath).filter((p) => prev.has(p))));
      },
      (err) => {
        if (stale) return;
        setError(errorMessage(err));
        setLoading(false);
      },
    );
    return () => {
      stale = true;
    };
  }, [active, refreshes, refreshKey]);

  // VMs picked on the VMs page become the selection here, once per visit.
  if (preselect && preselect.n !== usedPreselect && !loading) {
    setUsedPreselect(preselect.n);
    const wanted = new Set(preselect.paths.map((p) => p.toLowerCase()));
    setSelected(new Set(vms.filter((v) => wanted.has(v.vmxPath.toLowerCase())).map((v) => v.vmxPath)));
    setText("");
  }

  const needle = text.trim().toLowerCase();
  const shown = needle
    ? vms.filter(
        (v) =>
          v.displayName.toLowerCase().includes(needle) ||
          v.snapshots.some((s) => s.name.toLowerCase().includes(needle)),
      )
    : vms;
  const selectedVms = vms.filter((v) => selected.has(v.vmxPath));
  const withSnapshots = selectedVms.filter((v) => v.snapshots.length > 0);
  const total = vms.reduce((n, v) => n + v.snapshots.length, 0);
  const old = vms.reduce((n, v) => n + v.oldCount, 0);
  const allSelected = shown.length > 0 && shown.every((v) => selected.has(v.vmxPath));

  function toggle(index: number, e: MouseEvent) {
    const path = shown[index].vmxPath;
    setSelected((prev) => {
      const next = new Set(prev);
      if (e.shiftKey && anchor !== null) {
        const [from, to] = anchor < index ? [anchor, index] : [index, anchor];
        for (let i = from; i <= to; i++) next.add(shown[i].vmxPath);
      } else if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
    setAnchor(index);
  }

  async function submit(command: Command) {
    setSubmitting(true);
    try {
      onSubmitted(await api.submit(command));
      return true;
    } catch (err) {
      toast.error(errorMessage(err));
      return false;
    } finally {
      setSubmitting(false);
    }
  }

  function single(vm: VmSnapshots, node: SnapshotNode, kind: "revert" | "delete") {
    void submit({ type: "vmSnapshot", targets: [vmRef(vm.vmxPath)], op: { kind, name: snapshotArg(vm, node) } });
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" onClick={() => setRefreshes((n) => n + 1)} disabled={loading}>
          <RefreshCwIcon data-icon="inline-start" className={loading ? "animate-spin" : undefined} />
          Refresh
        </Button>
        <Input
          className="w-64"
          placeholder="Find a VM or snapshot"
          aria-label="Find a VM or snapshot"
          value={text}
          onChange={(e) => setText(e.currentTarget.value)}
        />
        <span className="ml-auto text-sm text-muted-foreground">
          {plural(total, "snapshot")} on {plural(vms.length, "VM")}
          {old > 0 && (
            <span className="text-tier-medium">
              {" "}
              · {old} older than {limits?.oldAfterDays ?? 30} days
            </span>
          )}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline">
              <ListChecksIcon data-icon="inline-start" />
              Select
              <ChevronDownIcon data-icon="inline-end" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-64">
            <DropdownMenuItem
              disabled={shown.length === 0}
              onSelect={() => setSelected(new Set(shown.map((v) => v.vmxPath)))}
            >
              All shown
              <DropdownMenuShortcut>{shown.length}</DropdownMenuShortcut>
            </DropdownMenuItem>
            <DropdownMenuItem disabled={selected.size === 0} onSelect={() => setSelected(new Set())}>
              None
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              disabled={old === 0}
              onSelect={() => setSelected(new Set(vms.filter((v) => v.oldCount > 0).map((v) => v.vmxPath)))}
            >
              With old snapshots
              <DropdownMenuShortcut>{vms.filter((v) => v.oldCount > 0).length || ""}</DropdownMenuShortcut>
            </DropdownMenuItem>
            <DropdownMenuItem
              disabled={!vms.some((v) => v.safetyCount > 0)}
              onSelect={() => setSelected(new Set(vms.filter((v) => v.safetyCount > 0).map((v) => v.vmxPath)))}
            >
              With safety snapshots
              <DropdownMenuShortcut>{vms.filter((v) => v.safetyCount > 0).length || ""}</DropdownMenuShortcut>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <span className="mr-2 text-sm text-muted-foreground">{selected.size} selected</span>
        <Button
          variant="outline"
          disabled={selectedVms.length === 0 || submitting}
          onClick={() => setDialog({ kind: "take", vms: selectedVms })}
        >
          <CameraIcon data-icon="inline-start" />
          Take snapshot…
        </Button>
        <Button
          variant="outline"
          disabled={withSnapshots.length === 0 || submitting}
          onClick={() => setDialog({ kind: "revert", vms: withSnapshots })}
        >
          <Undo2Icon data-icon="inline-start" />
          Revert…
        </Button>
        <Button
          variant="outline"
          disabled={withSnapshots.length === 0 || submitting}
          onClick={() => setDialog({ kind: "delete", vms: withSnapshots })}
        >
          <Trash2Icon data-icon="inline-start" />
          Delete…
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <TriangleAlertIcon />
          <AlertTitle>Could not read the snapshots</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {!loading && !error && vms.length === 0 && (
        <Empty className="border">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <HistoryIcon />
            </EmptyMedia>
            <EmptyTitle>No VMs yet</EmptyTitle>
            <EmptyDescription>
              Snapshots are listed for the VMs on the Virtual machines page. Open it, or add a VM folder in Settings.
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      )}

      {shown.length > 0 && (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">
                  <Checkbox
                    aria-label="Select all shown VMs"
                    checked={allSelected ? true : selected.size > 0 ? "indeterminate" : false}
                    onCheckedChange={() => setSelected(allSelected ? new Set() : new Set(shown.map((v) => v.vmxPath)))}
                  />
                </TableHead>
                <TableHead>VM and snapshots</TableHead>
                <TableHead>Taken</TableHead>
                <TableHead>State</TableHead>
                <TableHead className="w-48 text-right" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((vm, i) => {
                const open = !collapsed.has(vm.vmxPath);
                return (
                  <VmRows
                    key={vm.vmxPath}
                    vm={vm}
                    open={open}
                    selected={selected.has(vm.vmxPath)}
                    busy={submitting}
                    onToggleSelect={(e) => toggle(i, e)}
                    onToggleOpen={() =>
                      setCollapsed((prev) => {
                        const next = new Set(prev);
                        if (next.has(vm.vmxPath)) next.delete(vm.vmxPath);
                        else next.add(vm.vmxPath);
                        return next;
                      })
                    }
                    onRevert={(node) => single(vm, node, "revert")}
                    onDelete={(node) => single(vm, node, "delete")}
                  />
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}

      {dialog && limits && (
        <SnapshotActionDialog action={dialog} limits={limits} onSubmit={submit} onClose={() => setDialog(null)} />
      )}
    </div>
  );
}

interface VmRowsProps {
  vm: VmSnapshots;
  open: boolean;
  selected: boolean;
  busy: boolean;
  onToggleSelect: (e: MouseEvent) => void;
  onToggleOpen: () => void;
  onRevert: (node: SnapshotNode) => void;
  onDelete: (node: SnapshotNode) => void;
}

function VmRows({ vm, open, selected, busy, onToggleSelect, onToggleOpen, onRevert, onDelete }: VmRowsProps) {
  const Chevron = open ? ChevronDownIcon : ChevronRightIcon;
  return (
    <>
      <TableRow data-state={selected ? "selected" : undefined} onClick={onToggleSelect} className="select-none">
        <TableCell>
          {/* The click (or Space) bubbles to the row, which does the selecting. */}
          <Checkbox aria-label={`Select ${vm.displayName}`} checked={selected} />
        </TableCell>
        <TableCell className="whitespace-normal">
          <div className="flex flex-wrap items-center gap-1.5">
            <Button
              size="icon-xs"
              variant="ghost"
              aria-label={open ? `Fold ${vm.displayName}` : `Unfold ${vm.displayName}`}
              aria-expanded={open}
              disabled={vm.snapshots.length === 0}
              onClick={(e) => {
                e.stopPropagation();
                onToggleOpen();
              }}
            >
              <Chevron />
            </Button>
            <span className="font-medium">{vm.displayName}</span>
            {vm.protected && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <ShieldIcon className="size-3.5 text-tier-high" aria-label="Protected" />
                </TooltipTrigger>
                <TooltipContent>Protected: actions skip this VM until it is unprotected</TooltipContent>
              </Tooltip>
            )}
            {vm.environment !== "none" && <EnvBadge env={vm.environment} />}
            <span className="text-sm text-muted-foreground">{plural(vm.snapshots.length, "snapshot")}</span>
            {vm.oldCount > 0 && (
              <Badge variant="outline" className="border-tier-medium/40 text-tier-medium">
                {vm.oldCount} old
              </Badge>
            )}
          </div>
          <div className="pl-7 font-mono text-xs break-all text-muted-foreground">{vm.vmxPath}</div>
          {vm.error && <div className="pl-7 text-xs text-destructive">{vm.error}</div>}
        </TableCell>
        <TableCell />
        <TableCell>
          <StateBadge state={vm.powerState} />
        </TableCell>
        <TableCell />
      </TableRow>
      {open &&
        vm.snapshots.map((node) => (
          <TableRow key={node.uid} className="hover:bg-muted/30">
            <TableCell />
            <TableCell className="whitespace-normal">
              <div className="flex items-start gap-1.5" style={{ paddingLeft: `${1.75 + node.depth * 1.25}rem` }}>
                <span className="text-muted-foreground" aria-hidden>
                  {node.depth > 0 ? "└" : "•"}
                </span>
                <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                  <span className="break-words">{node.name || "(no name)"}</span>
                  {node.current && (
                    <Badge variant="secondary" className="font-normal">
                      <MapPinIcon />
                      You are here
                    </Badge>
                  )}
                  {node.safety && (
                    <Badge variant="outline" className="font-normal">
                      <CameraIcon />
                      Safety
                    </Badge>
                  )}
                  {node.old && (
                    <Badge variant="outline" className="border-tier-medium/40 text-tier-medium">
                      Older than 30 days
                    </Badge>
                  )}
                  {node.name.includes("/") && (
                    <span className="text-xs text-muted-foreground">
                      vmrun reads &apos;/&apos; as a path, so manage this one in Workstation
                    </span>
                  )}
                </div>
              </div>
              {node.description && (
                <div
                  className="text-xs text-muted-foreground"
                  style={{ paddingLeft: `${2.75 + node.depth * 1.25}rem` }}
                >
                  {node.description}
                </div>
              )}
            </TableCell>
            <TableCell className="text-sm whitespace-nowrap">
              {node.createdAt ? (
                <span title={new Date(node.createdAt).toLocaleString()}>
                  {new Date(node.createdAt).toLocaleDateString()}{" "}
                  <span className="text-muted-foreground">({formatAge(node.ageDays)})</span>
                </span>
              ) : (
                <span className="text-muted-foreground">unknown</span>
              )}
            </TableCell>
            <TableCell />
            <TableCell className="text-right">
              <div className="flex justify-end gap-1">
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={busy || node.name.includes("/")}
                  onClick={() => onRevert(node)}
                >
                  <Undo2Icon data-icon="inline-start" />
                  Revert
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="text-destructive"
                  disabled={busy || node.name.includes("/")}
                  onClick={() => onDelete(node)}
                >
                  <Trash2Icon data-icon="inline-start" />
                  Delete
                </Button>
              </div>
            </TableCell>
          </TableRow>
        ))}
    </>
  );
}
