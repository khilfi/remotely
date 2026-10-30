// FD-02: VMs on this PC that no workspace has. They belong to no engagement, so every workspace sees them here; none
// can act on them until one adds them. Adding is audited in this workspace and refused by the read-only lock. (While
// only one workspace is active, every VM joins it by itself and this list stays empty.)

import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { HypervisorLabel, StateBadge } from "@/components/Badges";
import { HelpTip } from "@/components/HelpTip";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage } from "@/lib/api";
import { claimReason } from "@/lib/workspaces";
import { workspacesApi, type UnassignedVm } from "@/lib/workspaces-api";

interface Props {
  open: boolean;
  vms: UnassignedVm[];
  readOnly: string | null;
  onOpenChange: (open: boolean) => void;
  /** After VMs joined this workspace: the page reads its list again. */
  onAdded: () => void;
}

export function UnassignedVmsSheet({ open, vms, readOnly, onOpenChange, onAdded }: Props) {
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const chosen = vms.filter((v) => picked.has(v.vmxPath));
  const reason = claimReason(chosen.length, readOnly);

  async function add() {
    setBusy(true);
    try {
      await workspacesApi.claimVms(chosen.map((v) => v.vmxPath));
      toast.success(
        chosen.length === 1 ? "The VM is in this workspace now" : `${chosen.length} VMs are in this workspace now`,
      );
      setPicked(new Set());
      onAdded();
      onOpenChange(false);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const toggle = (key: string, on: boolean) =>
    setPicked((prev) => {
      const next = new Set(prev);
      if (on) next.add(key);
      else next.delete(key);
      return next;
    });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full gap-4 sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle>Unassigned VMs</SheetTitle>
          <SheetDescription>
            VMs on this PC no workspace has yet: add the ones this workspace uses. <HelpTip topic="workspaces" />
          </SheetDescription>
        </SheetHeader>
        <div className="min-h-0 flex-1 overflow-auto px-4">
          {vms.length === 0 ? (
            <p className="text-sm text-muted-foreground">Every VM Remotely found belongs to a workspace.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8">
                    <Checkbox
                      aria-label="Select all"
                      checked={picked.size === vms.length}
                      onCheckedChange={(on) => setPicked(on === true ? new Set(vms.map((v) => v.vmxPath)) : new Set())}
                    />
                  </TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Hypervisor</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Guest OS</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vms.map((vm) => (
                  <TableRow key={vm.vmxPath} title={vm.configPath ?? vm.vmxPath}>
                    <TableCell>
                      <Checkbox
                        aria-label={`Select ${vm.displayName}`}
                        checked={picked.has(vm.vmxPath)}
                        onCheckedChange={(on) => toggle(vm.vmxPath, on === true)}
                      />
                    </TableCell>
                    <TableCell className="font-medium">{vm.displayName}</TableCell>
                    <TableCell>
                      <HypervisorLabel hypervisor={vm.hypervisor} />
                    </TableCell>
                    <TableCell>
                      <StateBadge state={vm.powerState} />
                    </TableCell>
                    <TableCell className="text-muted-foreground">{vm.guestOs ?? "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
        <div className="flex justify-end gap-2 px-4 pb-4">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
          <WhyDisabled reason={reason}>
            <Button disabled={!!reason || busy} onClick={() => void add()}>
              Add to this workspace
            </Button>
          </WhyDisabled>
        </div>
      </SheetContent>
    </Sheet>
  );
}
