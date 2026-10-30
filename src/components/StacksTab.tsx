// VM-08: the Templates page's Stacks tab. Stacks (launch templates in boot order, with the waits between steps) with
// Deploy, Edit, Duplicate and Delete; and the instances on this PC with Start (boot order), Shut down and Suspend
// (the last step first), Tear down (Critical: the VMs its deploy made, and hand-added ones only when picked), Add a
// VM, and Forget. Edits are audited in the core; every change to a VM goes through the bus and its approval.

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  CopyIcon,
  LayersIcon,
  MoreHorizontalIcon,
  PauseIcon,
  PencilIcon,
  PlayIcon,
  PlusIcon,
  PowerIcon,
  RocketIcon,
  Trash2Icon,
  UnlinkIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StackDeployDialog } from "@/components/StackDeployDialog";
import { StackDialog } from "@/components/StackDialog";
import { WhyDisabled } from "@/components/WhyDisabled";
import { EmptyState } from "@/components/EmptyState";
import { api, errorMessage, type LaunchTemplate, type SubmitOutcome, type VmRecord } from "@/lib/api";
import { copyName } from "@/lib/catalog";
import { plural } from "@/lib/format";
import {
  betweenText,
  deployStackReason,
  handAdded,
  instancePowerReason,
  instanceStateText,
  stepsText,
  teardownReason,
} from "@/lib/stacks";
import { stacksApi, type Stack, type StackInput, type StackInstance } from "@/lib/stacks-api";

interface Props {
  /** True while the tab is shown: it reads again when the user comes back. */
  active: boolean;
  templates: LaunchTemplate[];
  readOnly: string | null;
  /** The approval dialog for a deploy, an instance's power or a teardown. */
  onSubmitted: (outcome: SubmitOutcome) => void;
  /** Changes when a VM job finished, so the instances' states are read again. */
  refreshKey?: number;
  /** The palette asked for a new stack. */
  createRequest?: number;
}

type Dialog =
  | { kind: "edit"; existing?: Stack; initial?: StackInput }
  | { kind: "deploy"; stack: Stack }
  | { kind: "delete"; stack: Stack }
  | { kind: "teardown"; instance: StackInstance }
  | { kind: "addVm"; instance: StackInstance }
  | { kind: "forget"; instance: StackInstance };

export function StacksTab({ active, templates, readOnly, onSubmitted, refreshKey = 0, createRequest = 0 }: Props) {
  const [stacks, setStacks] = useState<Stack[]>([]);
  const [instances, setInstances] = useState<StackInstance[]>([]);
  const [dialog, setDialog] = useState<Dialog | null>(null);

  const load = useCallback(() => {
    Promise.all([stacksApi.list(), stacksApi.instances()]).then(
      ([s, i]) => {
        setStacks(s);
        setInstances(i);
      },
      (err) => toast.error(errorMessage(err)),
    );
  }, []);

  useEffect(() => {
    if (active) load();
  }, [active, load, refreshKey]);

  const [handled, setHandled] = useState(createRequest);
  if (createRequest !== handled) {
    setHandled(createRequest);
    if (!readOnly && templates.length) setDialog({ kind: "edit" });
  }

  async function power(instance: StackInstance, op: "start" | "stop" | "suspend") {
    try {
      const outcome = await stacksApi.power(
        instance.id,
        op === "start" ? { kind: "start" } : op === "suspend" ? { kind: "suspend" } : { kind: "stop", mode: "soft" },
      );
      onSubmitted(outcome);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function teardown(instance: StackInstance, also: string[]) {
    onSubmitted(await stacksApi.teardown(instance.id, also));
  }

  const editReason = readOnly ?? (templates.length === 0 ? "Add a launch template first" : null);

  return (
    <div className="grid gap-6">
      <section className="grid gap-3" aria-label="Stacks">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm text-muted-foreground">
            Launch templates in boot order, deployed as one job and torn down as one.
          </p>
          <WhyDisabled reason={editReason}>
            <Button disabled={editReason !== null} onClick={() => setDialog({ kind: "edit" })}>
              <PlusIcon data-icon="inline-start" />
              New stack
            </Button>
          </WhyDisabled>
        </div>
        {stacks.length === 0 ? (
          <EmptyState
            icon={LayersIcon}
            title="No stacks yet"
            description="A stack deploys several launch templates in boot order, as one."
          />
        ) : (
          <div className="overflow-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Stack</TableHead>
                  <TableHead>Steps</TableHead>
                  <TableHead className="text-right">VMs</TableHead>
                  <TableHead className="text-right">Instances</TableHead>
                  <TableHead className="w-44" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {stacks.map((stack) => {
                  const reason = deployStackReason(stack, readOnly);
                  return (
                    <TableRow key={stack.id}>
                      <TableCell className="whitespace-normal">
                        <div className="font-medium">{stack.name}</div>
                        {stack.description && <div className="text-xs text-muted-foreground">{stack.description}</div>}
                        {stack.problems.length > 0 && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Badge variant="outline" className="mt-1 border-tier-medium/50 text-tier-medium">
                                Can't deploy
                              </Badge>
                            </TooltipTrigger>
                            <TooltipContent className="max-w-sm">{stack.problems.join(" ")}</TooltipContent>
                          </Tooltip>
                        )}
                      </TableCell>
                      <TableCell className="text-sm whitespace-normal">
                        <div>{stepsText(stack.steps)}</div>
                        <div className="text-xs text-muted-foreground">
                          {stack.steps
                            .slice(0, -1)
                            .map((s, i) => {
                              const between = betweenText(s);
                              return between ? `after ${i + 1}: ${between}` : null;
                            })
                            .filter(Boolean)
                            .join("; ")}
                        </div>
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{stack.vmCount}</TableCell>
                      <TableCell className="text-right tabular-nums">{stack.instances}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <WhyDisabled reason={reason}>
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={reason !== null}
                              onClick={() => setDialog({ kind: "deploy", stack })}
                            >
                              <RocketIcon data-icon="inline-start" />
                              Deploy
                            </Button>
                          </WhyDisabled>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button size="icon" variant="ghost" aria-label={`More for ${stack.name}`}>
                                <MoreHorizontalIcon />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem
                                disabled={readOnly !== null}
                                onSelect={() => setDialog({ kind: "edit", existing: stack })}
                              >
                                <PencilIcon />
                                Edit…
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                disabled={readOnly !== null}
                                onSelect={() =>
                                  setDialog({
                                    kind: "edit",
                                    initial: {
                                      name: copyName(
                                        stack.name,
                                        stacks.map((s) => s.name),
                                      ),
                                      description: stack.description,
                                      steps: stack.steps,
                                    },
                                  })
                                }
                              >
                                <CopyIcon />
                                Duplicate…
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                variant="destructive"
                                disabled={readOnly !== null}
                                onSelect={() => setDialog({ kind: "delete", stack })}
                              >
                                <Trash2Icon />
                                Delete…
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <section className="grid gap-3" aria-label="Stack instances">
        <h2 className="text-sm font-medium">Instances on this PC</h2>
        {instances.length === 0 ? (
          <p className="text-sm text-muted-foreground">None: deploy a stack to make one.</p>
        ) : (
          <div className="overflow-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Instance</TableHead>
                  <TableHead>VMs</TableHead>
                  <TableHead className="w-60" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {instances.map((instance) => (
                  <InstanceRow
                    key={instance.id}
                    instance={instance}
                    readOnly={readOnly}
                    onPower={(op) => void power(instance, op)}
                    onTeardown={() => setDialog({ kind: "teardown", instance })}
                    onAddVm={() => setDialog({ kind: "addVm", instance })}
                    onForget={() => setDialog({ kind: "forget", instance })}
                  />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      {dialog?.kind === "edit" && (
        <StackDialog
          existing={dialog.existing}
          initial={dialog.initial}
          templates={templates}
          onSaved={() => load()}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "deploy" && (
        <StackDeployDialog stack={dialog.stack} onSubmitted={onSubmitted} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "delete" && (
        <ConfirmDialog
          title={`Delete ${dialog.stack.name}?`}
          description={
            dialog.stack.instances > 0
              ? `Its ${plural(dialog.stack.instances, "instance")} stay${dialog.stack.instances === 1 ? "s" : ""}, with their VMs.`
              : "Only the stack goes; no VM is touched."
          }
          confirmLabel="Delete"
          onConfirm={async () => {
            await stacksApi.remove(dialog.stack.id);
            load();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "forget" && (
        <ConfirmDialog
          title={`Forget ${dialog.instance.name}?`}
          description="Its VMs stay as they are, in no instance: they no longer start, stop or tear down together."
          confirmLabel="Forget"
          onConfirm={async () => {
            await stacksApi.forgetInstance(dialog.instance.id);
            load();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "teardown" && (
        <TeardownDialog
          instance={dialog.instance}
          onTeardown={(also) => teardown(dialog.instance, also)}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "addVm" && (
        <AddVmDialog
          instance={dialog.instance}
          instances={instances}
          onAdded={() => load()}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  );
}

function InstanceRow({
  instance,
  readOnly,
  onPower,
  onTeardown,
  onAddVm,
  onForget,
}: {
  instance: StackInstance;
  readOnly: string | null;
  onPower: (op: "start" | "stop" | "suspend") => void;
  onTeardown: () => void;
  onAddVm: () => void;
  onForget: () => void;
}) {
  const start = instancePowerReason(instance, "start", readOnly);
  const stop = instancePowerReason(instance, "stop", readOnly);
  const suspend = instancePowerReason(instance, "suspend", readOnly);
  const tear = teardownReason(instance, readOnly);
  return (
    <TableRow>
      <TableCell className="whitespace-normal">
        <div className="font-medium">{instance.name}</div>
        <div className="text-xs text-muted-foreground">stack {instance.stackName}</div>
      </TableCell>
      <TableCell className="text-sm whitespace-normal">
        <div>{instanceStateText(instance)}</div>
        <div className="text-xs break-words text-muted-foreground">
          {instance.vms.map((v) => `${v.name}${v.origin === "hand" ? " (added by hand)" : ""}`).join(", ")}
        </div>
      </TableCell>
      <TableCell className="text-right">
        <div className="flex justify-end gap-1">
          <WhyDisabled reason={start}>
            <Button size="sm" variant="outline" disabled={start !== null} onClick={() => onPower("start")}>
              <PlayIcon data-icon="inline-start" />
              Start
            </Button>
          </WhyDisabled>
          <WhyDisabled reason={stop}>
            <Button size="sm" variant="outline" disabled={stop !== null} onClick={() => onPower("stop")}>
              <PowerIcon data-icon="inline-start" />
              Shut down
            </Button>
          </WhyDisabled>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="icon" variant="ghost" aria-label={`More for ${instance.name}`}>
                <MoreHorizontalIcon />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem disabled={suspend !== null} onSelect={() => onPower("suspend")}>
                <PauseIcon />
                Suspend
              </DropdownMenuItem>
              <DropdownMenuItem disabled={readOnly !== null} onSelect={onAddVm}>
                <PlusIcon />
                Add a VM…
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem disabled={readOnly !== null} onSelect={onForget}>
                <UnlinkIcon />
                Forget the instance…
              </DropdownMenuItem>
              <DropdownMenuItem variant="destructive" disabled={tear !== null} onSelect={onTeardown}>
                <Trash2Icon />
                {tear ? `Tear down (${tear})` : "Tear down…"}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </TableCell>
    </TableRow>
  );
}

/** Picks the VMs added by hand that the teardown deletes too (none by default), then asks for the approval. */
function TeardownDialog({
  instance,
  onTeardown,
  onClose,
}: {
  instance: StackInstance;
  onTeardown: (also: string[]) => Promise<void>;
  onClose: () => void;
}) {
  const hand = handAdded(instance);
  const going = instance.vms.filter((v) => v.origin === "deploy" && v.powerState !== null);
  const [also, setAlso] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function go() {
    setBusy(true);
    setError(null);
    try {
      await onTeardown(also);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Tear down {instance.name}?</DialogTitle>
          <DialogDescription>
            Deletes the VMs its deploy made, with their files. The approval that follows lists every file that goes and
            asks for the vault password. Protected VMs are left alone.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 text-sm">
          <p>
            Deleted: <span className="font-medium">{going.map((v) => v.name).join(", ") || "none"}</span>
          </p>
          {hand.length > 0 && (
            <fieldset className="grid gap-2">
              <legend className="mb-1">Added by hand, kept unless you tick them:</legend>
              {hand.map((v) => (
                <Label key={v.key} className="flex items-center gap-2 font-normal">
                  <Checkbox
                    checked={also.includes(v.key)}
                    onCheckedChange={(on) => setAlso((all) => (on ? [...all, v.key] : all.filter((k) => k !== v.key)))}
                  />
                  Delete {v.name} too
                </Label>
              ))}
            </fieldset>
          )}
          {error && (
            <p className="text-destructive" role="alert">
              {error}
            </p>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={() => void go()} disabled={busy}>
            {busy ? "Submitting…" : `Tear down ${plural(going.length + also.length, "VM")}`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Adds a VM of this PC (in no instance) to the instance by hand, at a step. */
function AddVmDialog({
  instance,
  instances,
  onAdded,
  onClose,
}: {
  instance: StackInstance;
  instances: StackInstance[];
  onAdded: () => void;
  onClose: () => void;
}) {
  const [vms, setVms] = useState<VmRecord[]>([]);
  const [key, setKey] = useState("");
  const [step, setStep] = useState("0");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const taken = new Set(instances.flatMap((i) => i.vms.map((v) => v.key.toLowerCase())));
    api.vmList().then(
      (all) => setVms(all.filter((v) => !taken.has(v.vmxPath.toLowerCase()))),
      (err) => setError(errorMessage(err)),
    );
  }, [instances]);

  async function add() {
    setBusy(true);
    setError(null);
    try {
      await stacksApi.addVm(instance.id, key, Number(step));
      onAdded();
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  const steps = Math.max(1, instance.steps.length);
  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add a VM to {instance.name}</DialogTitle>
          <DialogDescription>
            It starts and stops with the instance at its step. A teardown keeps it unless you pick it then.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid gap-2">
            <Label htmlFor="stack-add-vm">VM</Label>
            <Select value={key} onValueChange={setKey}>
              <SelectTrigger id="stack-add-vm">
                <SelectValue placeholder={vms.length ? "Pick a VM" : "No VM outside an instance"} />
              </SelectTrigger>
              <SelectContent>
                {vms.map((v) => (
                  <SelectItem key={v.vmxPath} value={v.vmxPath}>
                    {v.displayName}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="stack-add-step">At step</Label>
            <Select value={step} onValueChange={setStep}>
              <SelectTrigger id="stack-add-step">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Array.from({ length: steps }, (_, i) => (
                  <SelectItem key={i} value={String(i)}>
                    {i + 1}. {instance.steps[i]?.label ?? `step ${i + 1}`}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void add()} disabled={busy || !key}>
            {busy ? "Adding…" : "Add"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
