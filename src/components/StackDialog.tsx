// VM-08: adds or edits a stack: launch templates with a count each, in boot order, and between steps what the next
// step waits for (nothing, the guest tools running, or a port open on the guest) and a delay. As it is filled in the
// core says why it couldn't deploy. Saved in the core and audited (no approval tier); refused by the read-only lock.

import { useEffect, useMemo, useState } from "react";
import { AlertTriangleIcon, ArrowDownIcon, ArrowUpIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useDebounced } from "@/hooks/use-debounced";
import { errorMessage, type LaunchTemplate } from "@/lib/api";
import { HYPERVISOR_LABEL } from "@/lib/catalog";
import { moveStep, newStep, stackInputReason, vmCount } from "@/lib/stacks";
import { stacksApi, type Readiness, type Stack, type StackCheck, type StackInput } from "@/lib/stacks-api";

interface Props {
  existing?: Stack;
  /** Duplicate: a new stack from these values. */
  initial?: StackInput;
  templates: LaunchTemplate[];
  onSaved: (stack: Stack) => void;
  onClose: () => void;
}

/** A step as the form holds it: numbers as typed. */
interface StepForm {
  templateId: string;
  count: string;
  readiness: Readiness["kind"];
  port: string;
  timeoutMin: string;
  delaySecs: string;
}

function formOf(step: StackInput["steps"][number]): StepForm {
  return {
    templateId: step.templateId,
    count: String(step.count),
    readiness: step.readiness.kind,
    port: step.readiness.kind === "sshPort" ? String(step.readiness.port) : "22",
    timeoutMin: String(Math.round(step.readyTimeoutSecs / 60) || 1),
    delaySecs: String(step.delaySecs),
  };
}

function whole(text: string): number {
  return /^\d+$/.test(text.trim()) ? Number(text.trim()) : NaN;
}

function inputOf(name: string, description: string, steps: StepForm[]): StackInput {
  return {
    name,
    description: description.trim() || null,
    steps: steps.map((s) => ({
      templateId: s.templateId,
      count: whole(s.count),
      readiness:
        s.readiness === "sshPort"
          ? { kind: "sshPort", port: whole(s.port) }
          : s.readiness === "tools"
            ? { kind: "tools" }
            : { kind: "none" },
      // Minutes in the form, seconds in the core; a half minute is the shortest wait.
      readyTimeoutSecs: Math.max(30, whole(s.timeoutMin) * 60),
      delaySecs: whole(s.delaySecs),
    })),
  };
}

export function StackDialog({ existing, initial, templates, onSaved, onClose }: Props) {
  const start: StackInput = existing
    ? { name: existing.name, description: existing.description, steps: existing.steps }
    : (initial ?? { name: "", description: null, steps: templates[0] ? [newStep(templates[0].id)] : [] });
  const [name, setName] = useState(start.name);
  const [description, setDescription] = useState(start.description ?? "");
  const [steps, setSteps] = useState<StepForm[]>(() => start.steps.map(formOf));
  const [check, setCheck] = useState<StackCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const input = useMemo(() => inputOf(name, description, steps), [name, description, steps]);
  const checked = useDebounced(input, 250);
  const ownReason = stackInputReason(input);

  useEffect(() => {
    if (stackInputReason(checked)) return;
    let stopped = false;
    stacksApi.check(checked).then(
      (c) => !stopped && setCheck(c),
      (err) => !stopped && setError(errorMessage(err)),
    );
    return () => {
      stopped = true;
    };
  }, [checked]);

  function change(index: number, patch: Partial<StepForm>) {
    setSteps((all) => all.map((s, i) => (i === index ? { ...s, ...patch } : s)));
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const saved = existing ? await stacksApi.update(existing.id, input) : await stacksApi.add(input);
      onSaved(saved);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const reason = busy ? "Saving…" : (ownReason ?? (templates.length === 0 ? "Add a launch template first" : null));
  const templateName = (id: string) => templates.find((t) => t.id === id)?.name;

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{existing ? `Edit ${existing.name}` : "New stack"}</DialogTitle>
          <DialogDescription>
            Launch templates in boot order. A deploy makes them as one job, step by step, waiting between steps for what
            you choose.
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (!reason) void save();
          }}
        >
          <div className="-mx-1 grid max-h-[60vh] gap-4 overflow-x-hidden overflow-y-auto px-1">
            <div className="grid gap-2">
              <Label htmlFor="stack-name">Name</Label>
              <Input id="stack-name" value={name} onChange={(e) => setName(e.currentTarget.value)} maxLength={60} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="stack-description">Description</Label>
              <Textarea
                id="stack-description"
                rows={2}
                value={description}
                onChange={(e) => setDescription(e.currentTarget.value)}
                maxLength={500}
              />
            </div>

            <ol className="grid gap-3">
              {steps.map((step, i) => {
                const last = i === steps.length - 1;
                const id = `stack-step-${i}`;
                return (
                  <li key={i} className="grid gap-3 rounded-md border p-3">
                    <div className="flex flex-wrap items-end gap-2">
                      <div className="grid min-w-48 flex-1 gap-1.5">
                        <Label htmlFor={`${id}-template`}>Step {i + 1}: launch template</Label>
                        <Select value={step.templateId} onValueChange={(v) => change(i, { templateId: v })}>
                          <SelectTrigger id={`${id}-template`}>
                            <SelectValue placeholder={templateName(step.templateId) ?? "(deleted)"} />
                          </SelectTrigger>
                          <SelectContent>
                            {templates.map((t) => (
                              <SelectItem key={t.id} value={t.id}>
                                {t.name} ({HYPERVISOR_LABEL[t.hypervisor]})
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid w-20 gap-1.5">
                        <Label htmlFor={`${id}-count`}>Count</Label>
                        <Input
                          id={`${id}-count`}
                          inputMode="numeric"
                          value={step.count}
                          onChange={(e) => change(i, { count: e.currentTarget.value })}
                        />
                      </div>
                      <div className="flex gap-1">
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          aria-label={`Move step ${i + 1} up`}
                          disabled={i === 0}
                          onClick={() => setSteps((all) => moveStep(all, i, -1))}
                        >
                          <ArrowUpIcon />
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          aria-label={`Move step ${i + 1} down`}
                          disabled={last}
                          onClick={() => setSteps((all) => moveStep(all, i, 1))}
                        >
                          <ArrowDownIcon />
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          aria-label={`Remove step ${i + 1}`}
                          disabled={steps.length === 1}
                          onClick={() => setSteps((all) => all.filter((_, j) => j !== i))}
                        >
                          <Trash2Icon />
                        </Button>
                      </div>
                    </div>
                    {!last && (
                      <div className="flex flex-wrap items-end gap-2 text-sm">
                        <div className="grid min-w-44 gap-1.5">
                          <Label htmlFor={`${id}-ready`}>Before step {i + 2}, wait for</Label>
                          <Select
                            value={step.readiness}
                            onValueChange={(v) => change(i, { readiness: v as Readiness["kind"] })}
                          >
                            <SelectTrigger id={`${id}-ready`}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="none">Nothing</SelectItem>
                              <SelectItem value="tools">The guest tools running</SelectItem>
                              <SelectItem value="sshPort">A port open on the guest</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        {step.readiness === "sshPort" && (
                          <div className="grid w-20 gap-1.5">
                            <Label htmlFor={`${id}-port`}>Port</Label>
                            <Input
                              id={`${id}-port`}
                              inputMode="numeric"
                              value={step.port}
                              onChange={(e) => change(i, { port: e.currentTarget.value })}
                            />
                          </div>
                        )}
                        {step.readiness !== "none" && (
                          <div className="grid w-28 gap-1.5">
                            <Label htmlFor={`${id}-timeout`}>Up to (min)</Label>
                            <Input
                              id={`${id}-timeout`}
                              inputMode="numeric"
                              value={step.timeoutMin}
                              onChange={(e) => change(i, { timeoutMin: e.currentTarget.value })}
                            />
                          </div>
                        )}
                        <div className="grid w-28 gap-1.5">
                          <Label htmlFor={`${id}-delay`}>Then delay (s)</Label>
                          <Input
                            id={`${id}-delay`}
                            inputMode="numeric"
                            value={step.delaySecs}
                            onChange={(e) => change(i, { delaySecs: e.currentTarget.value })}
                          />
                        </div>
                      </div>
                    )}
                  </li>
                );
              })}
            </ol>
            <Button
              type="button"
              variant="outline"
              className="justify-self-start"
              disabled={templates.length === 0}
              onClick={() =>
                setSteps((all) => [
                  ...all,
                  formOf(newStep(templates[templates.length > all.length ? all.length : 0].id)),
                ])
              }
            >
              <PlusIcon data-icon="inline-start" />
              Add a launch template
            </Button>
            <p className="text-sm text-muted-foreground">
              {Number.isFinite(vmCount(input)) ? `${vmCount(input)} VMs in all.` : null} If a step fails or isn't ready
              in time, the steps after it don't start; a teardown deletes exactly the VMs a deploy made.
            </p>

            {check?.invalid && !ownReason && (
              <p className="text-sm text-destructive" role="alert">
                {check.invalid}
              </p>
            )}
            {check && check.problems.length > 0 && (
              <Alert>
                <AlertTriangleIcon />
                <AlertTitle>It can't deploy yet</AlertTitle>
                <AlertDescription>
                  <ul className="grid gap-1">
                    {check.problems.map((p) => (
                      <li key={p}>{p}</li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <WhyDisabled reason={reason}>
              <Button type="submit" disabled={reason !== null}>
                {busy ? "Saving…" : existing ? "Save" : "Add stack"}
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
