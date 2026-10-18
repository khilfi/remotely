// Bulk snapshot actions (VM-04): take a snapshot of the selected VMs, or pick a snapshot name and
// revert or delete it on every selected VM that has it. The dialog only builds the command; the
// command bus decides the tier and asks for any approval (revert and delete are High).

import { useState } from "react";
import { CameraIcon, InfoIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import type { Command, SnapshotLimits, VmSnapshots } from "@/lib/api";
import { plural } from "@/lib/format";

export type SnapshotAction = { kind: "take" | "revert" | "delete"; vms: VmSnapshots[] };

interface Props {
  action: SnapshotAction;
  limits: SnapshotLimits;
  /** Submits the command; resolves true when the bus took it. */
  onSubmit: (command: Command) => Promise<boolean>;
  onClose: () => void;
}

const vmRef = (vmxPath: string) => ({ kind: "vm" as const, vmxPath });

function defaultName() {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `Snapshot ${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}`;
}

/** The same checks the core makes, so the user sees the problem before submitting. */
function nameProblem(name: string, limits: SnapshotLimits) {
  if (name.trim() === "") return "Give the snapshot a name.";
  if (name.trim() !== name) return "A snapshot name can't start or end with a space.";
  if (name.includes("/")) return "A snapshot name can't contain '/': vmrun reads it as the path to a child snapshot.";
  if (name.length > limits.maxNameLength) return `A snapshot name can be at most ${limits.maxNameLength} characters.`;
  if (name.startsWith(limits.safetyPrefix))
    return `Names starting with '${limits.safetyPrefix}' are kept for safety snapshots.`;
  return null;
}

export function SnapshotActionDialog(props: Props) {
  return props.action.kind === "take" ? <TakeDialog {...props} /> : <PickDialog {...props} />;
}

function TakeDialog({ action, limits, onSubmit, onClose }: Props) {
  const [name, setName] = useState(defaultName);
  const [busy, setBusy] = useState(false);
  const problem = nameProblem(name, limits);
  // vmrun refuses a name the VM already has; leave those VMs out rather than fail them.
  const clash = action.vms.filter((v) => v.snapshots.some((s) => s.name === name));
  const targets = action.vms.filter((v) => !clash.includes(v));

  async function submit() {
    setBusy(true);
    const ok = await onSubmit({
      type: "vmSnapshot",
      targets: targets.map((v) => vmRef(v.vmxPath)),
      op: { kind: "take", name },
    });
    setBusy(false);
    if (ok) onClose();
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-md">
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (!problem && targets.length > 0) void submit();
          }}
        >
          <DialogHeader>
            <DialogTitle>Take a snapshot of {plural(action.vms.length, "VM")}</DialogTitle>
            <DialogDescription>
              Each VM gets a snapshot with this name, taken from where it is now. A running VM&apos;s memory is saved
              too, which takes longer.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="snapshot-name">Name</Label>
            <Input
              id="snapshot-name"
              autoFocus
              maxLength={limits.maxNameLength + 1}
              value={name}
              onChange={(e) => setName(e.currentTarget.value)}
              aria-invalid={problem ? true : undefined}
            />
            {problem && <p className="text-sm text-destructive">{problem}</p>}
            {!problem && clash.length > 0 && (
              <p className="text-sm text-tier-medium">
                {clash.map((v) => v.displayName).join(", ")} already {clash.length === 1 ? "has" : "have"} a snapshot
                with this name and {clash.length === 1 ? "is" : "are"} left out.
              </p>
            )}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy || problem !== null || targets.length === 0}>
              <CameraIcon data-icon="inline-start" />
              Take {plural(targets.length, "snapshot")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

interface Choice {
  name: string;
  vms: VmSnapshots[];
  safety: boolean;
  old: boolean;
  newest: string | null;
}

function PickDialog({ action, onSubmit, onClose }: Props) {
  const revert = action.kind === "revert";
  const byName = new Map<string, Choice>();
  // vmrun reads '/' in a name as a path, so it cannot name those snapshots.
  let unreachable = 0;
  for (const vm of action.vms) {
    for (const s of vm.snapshots) {
      if (s.name.includes("/")) {
        unreachable += 1;
        continue;
      }
      const choice = byName.get(s.name) ?? { name: s.name, vms: [], safety: s.safety, old: false, newest: null };
      if (!choice.vms.includes(vm)) choice.vms.push(vm);
      choice.old ||= s.old;
      if (s.createdAt && (!choice.newest || s.createdAt > choice.newest)) choice.newest = s.createdAt;
      byName.set(s.name, choice);
    }
  }
  // Names on the most VMs first (a bulk revert usually wants the shared one), then the newest.
  const choices = [...byName.values()].sort(
    (a, b) => b.vms.length - a.vms.length || (b.newest ?? "").localeCompare(a.newest ?? ""),
  );
  const [picked, setPicked] = useState<string>(choices[0]?.name ?? "");
  const [busy, setBusy] = useState(false);
  const choice = byName.get(picked);

  async function submit() {
    if (!choice) return;
    setBusy(true);
    const ok = await onSubmit({
      type: "vmSnapshot",
      targets: choice.vms.map((v) => vmRef(v.vmxPath)),
      op: { kind: action.kind === "revert" ? "revert" : "delete", name: choice.name },
    });
    setBusy(false);
    if (ok) onClose();
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {revert ? "Revert" : "Delete a snapshot on"} {plural(action.vms.length, "VM")}
          </DialogTitle>
          <DialogDescription>
            Pick a snapshot by name. It runs on each selected VM that has it; the others are left alone.
          </DialogDescription>
        </DialogHeader>
        <RadioGroup value={picked} onValueChange={setPicked} className="max-h-72 gap-1 overflow-auto">
          {choices.map((c, i) => (
            <Label
              key={c.name}
              htmlFor={`snapshot-choice-${i}`}
              className="flex cursor-pointer items-center gap-3 rounded-md border px-3 py-2 font-normal has-data-[state=checked]:border-primary"
            >
              <RadioGroupItem id={`snapshot-choice-${i}`} value={c.name} />
              <span className="min-w-0 flex-1 break-words">{c.name || "(no name)"}</span>
              {c.safety && (
                <Badge variant="outline" className="font-normal">
                  <CameraIcon />
                  Safety
                </Badge>
              )}
              {c.old && (
                <Badge variant="outline" className="border-tier-medium/40 text-tier-medium">
                  Old
                </Badge>
              )}
              <span className="text-xs whitespace-nowrap text-muted-foreground">
                on {c.vms.length} of {action.vms.length}
              </span>
            </Label>
          ))}
        </RadioGroup>
        {unreachable > 0 && (
          <p className="text-sm text-muted-foreground">
            {plural(unreachable, "snapshot")} with &apos;/&apos; in the name {unreachable === 1 ? "is" : "are"} not
            listed: vmrun reads &apos;/&apos; as a path. Manage {unreachable === 1 ? "it" : "them"} in Workstation.
          </p>
        )}
        <p className="flex items-start gap-1.5 text-sm text-muted-foreground">
          <InfoIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          {revert
            ? "Reverting loses what changed since the snapshot. The next step asks for approval and offers a safety snapshot of each VM first."
            : "Deleting keeps the snapshot's children and the VM's current state. The next step asks for approval; no safety snapshot is taken, since it would not hold the deleted snapshot."}
        </p>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={() => void submit()} disabled={busy || !choice}>
            {revert ? "Revert" : "Delete"} on {plural(choice?.vms.length ?? 0, "VM")}…
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
