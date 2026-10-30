// VM-08: the Templates page's Stacks tab. Stacks (launch templates in boot order, with the waits between steps) with
// Deploy, Edit, Duplicate and Delete; and the instances on this PC with Tear down (Critical: the VMs its deploy made,
// and hand-added ones only when picked), Add a VM, and Forget. UX-03: an instance's Start (boot order), Shut down and
// Suspend (the last step first) are on the VMs page, on its group's row; New stack is the page header's primary. Edits
// are audited in the core; every change to a VM goes through the bus and its approval.

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  CopyIcon,
  LayersIcon,
  MonitorIcon,
  PencilIcon,
  PlusIcon,
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
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { RowMenu } from "@/components/RowMenu";
import { StackDeployDialog } from "@/components/StackDeployDialog";
import { StackDialog } from "@/components/StackDialog";
import { Term } from "@/components/Term";
import { WhyDisabled } from "@/components/WhyDisabled";
import { EmptyState } from "@/components/EmptyState";
import { api, errorMessage, type LaunchTemplate, type SubmitOutcome, type VmRecord } from "@/lib/api";
import { copyName } from "@/lib/catalog";
import { plural } from "@/lib/format";
import { requestLink } from "@/lib/links";
import { betweenText, deployStackReason, handAdded, instanceStateText, stepsText, teardownReason } from "@/lib/stacks";
import { stacksApi, type Stack, type StackInput, type StackInstance } from "@/lib/stacks-api";
import { newStackReason } from "@/lib/templates-page";

interface Props {
  /** True while the tab is shown: it reads again when the user comes back. */
  active: boolean;
  templates: LaunchTemplate[];
  readOnly: string | null;
  /** The approval dialog for a deploy, an instance's power or a teardown. */
  onSubmitted: (outcome: SubmitOutcome) => void;
  /** Changes when a VM job finished, so the instances' states are read again. */
  refreshKey?: number;
  /** The palette or the page header asked for a new stack. */
  createRequest?: number;
  /** UX-07: with no launch template, the empty state's way to make the first one (or the image it needs). */
  onNewTemplate?: () => void;
  newTemplateLabel?: string;
  /** How many stacks there are, once read: the page header shows New stack only when the empty state doesn't. */
  onCount?: (stacks: number) => void;
}

type Dialog =
  | { kind: "edit"; existing?: Stack; initial?: StackInput }
  | { kind: "deploy"; stack: Stack }
  | { kind: "delete"; stack: Stack }
  | { kind: "teardown"; instance: StackInstance }
  | { kind: "addVm"; instance: StackInstance }
  | { kind: "forget"; instance: StackInstance };

export function StacksTab({
  active,
  templates,
  readOnly,
  onSubmitted,
  refreshKey = 0,
  createRequest = 0,
  onNewTemplate,
  newTemplateLabel = "New launch template",
  onCount,
}: Props) {
  const [stacks, setStacks] = useState<Stack[]>([]);
  const [instances, setInstances] = useState<StackInstance[]>([]);
  const [dialog, setDialog] = useState<Dialog | null>(null);

  const load = useCallback(() => {
    Promise.all([stacksApi.list(), stacksApi.instances()]).then(
      ([s, i]) => {
        setStacks(s);
        setInstances(i);
        onCount?.(s.length);
      },
      (err) => toast.error(errorMessage(err)),
    );
  }, [onCount]);

  useEffect(() => {
    if (active) load();
  }, [active, load, refreshKey]);

  const [handled, setHandled] = useState(createRequest);
  if (createRequest !== handled) {
    setHandled(createRequest);
    if (!readOnly && templates.length) setDialog({ kind: "edit" });
  }

  async function teardown(instance: StackInstance, also: string[]) {
    onSubmitted(await stacksApi.teardown(instance.id, also));
  }

  const editReason = newStackReason(readOnly, templates.length);

  return (
    <div className="grid gap-6">
      <section className="grid gap-3" aria-label="Stacks">
        {stacks.length === 0 ? (
          <EmptyState
            icon={LayersIcon}
            title="No stacks yet"
            description={
              <>
                A <Term id="stack">stack</Term> deploys several launch templates in boot order, as one.
              </>
            }
            action={
              templates.length === 0 && onNewTemplate ? (
                <WhyDisabled reason={readOnly}>
                  <Button disabled={readOnly !== null} onClick={onNewTemplate}>
                    <PlusIcon data-icon="inline-start" />
                    {newTemplateLabel}
                  </Button>
                </WhyDisabled>
              ) : (
                <WhyDisabled reason={editReason}>
                  <Button disabled={editReason !== null} onClick={() => setDialog({ kind: "edit" })}>
                    <PlusIcon data-icon="inline-start" />
                    New stack
                  </Button>
                </WhyDisabled>
              )
            }
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
                          <RowMenu label={stack.name} disabled={readOnly !== null}>
                            <DropdownMenuItem onSelect={() => setDialog({ kind: "edit", existing: stack })}>
                              <PencilIcon />
                              Edit…
                            </DropdownMenuItem>
                            <DropdownMenuItem
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
                              onSelect={() => setDialog({ kind: "delete", stack })}
                            >
                              <Trash2Icon />
                              Delete…
                            </DropdownMenuItem>
                          </RowMenu>
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

      {/* UX-03: an instance's power is on the VMs page, on its group's row; its membership and teardown are here. */}
      {(stacks.length > 0 || instances.length > 0) && (
        <section className="grid gap-3" aria-label="Stack instances">
          <h2 className="flex items-center gap-1 text-sm font-medium">
            <Term id="instance">Instances</Term> on this PC
          </h2>
          {instances.length === 0 ? (
            <p className="text-sm text-muted-foreground">None yet: deploy a stack to make one.</p>
          ) : (
            <div className="overflow-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Instance</TableHead>
                    <TableHead>VMs</TableHead>
                    <TableHead className="w-12">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {instances.map((instance) => (
                    <InstanceRow
                      key={instance.id}
                      instance={instance}
                      readOnly={readOnly}
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
      )}

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
  onTeardown,
  onAddVm,
  onForget,
}: {
  instance: StackInstance;
  readOnly: string | null;
  onTeardown: () => void;
  onAddVm: () => void;
  onForget: () => void;
}) {
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
        <RowMenu label={instance.name}>
          {/* Its power is on the VMs page, on the group's row with its VMs. */}
          <DropdownMenuItem onSelect={() => requestLink({ kind: "page", page: "vms" })}>
            <MonitorIcon />
            Start or stop on the VMs page
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
          <WhyDisabled reason={tear} className="flex w-full">
            <DropdownMenuItem className="w-full" variant="destructive" disabled={tear !== null} onSelect={onTeardown}>
              <Trash2Icon />
              Tear down…
            </DropdownMenuItem>
          </WhyDisabled>
        </RowMenu>
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
            Deletes the VMs its deploy made, with their files; the approval lists every file. Protected VMs stay.
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
