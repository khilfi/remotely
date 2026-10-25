// VM-14, VM-27: adds or edits a schedule: what it does (a snapshot, keeping the last N it took; start, shut down,
// suspend or resume), on which VMs and tags, and when (every hour, every day, on chosen days, or when idle for
// auto-suspend). The preview beside it is the core's: the next three runs in local time (with what daylight saving does
// to one), the VMs it finds now, and warnings (snapshot chains, VM-27). Saving asks for the schedule's approval, which
// the page shows next; new content always asks again.

import { useEffect, useMemo, useState } from "react";
import { CalendarClockIcon, TriangleAlertIcon } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type Tag, type VmRecord } from "@/lib/api";
import {
  ACTION_CHOICES,
  DAYS,
  emptyForm,
  formatPlanned,
  formFromView,
  formProblem,
  formToInput,
  MAX_KEEP,
  TIMING_CHOICES,
  withAction,
  withTiming,
  type ActionKind,
  type ScheduleForm,
  type TimingKind,
} from "@/lib/schedules";
import { schedulesApi, type Day, type SaveOutcome, type SchedulePreview, type ScheduleView } from "@/lib/schedules-api";

interface Props {
  /** A schedule to edit; without it, a new one. */
  existing?: ScheduleView;
  /** A new schedule's VMs (from a VM's Schedules tab). */
  initialVms?: string[];
  vms: VmRecord[];
  tags: Tag[];
  onSaved: (outcome: SaveOutcome) => void;
  onClose: () => void;
}

export function ScheduleDialog({ existing, initialVms, vms, tags, onSaved, onClose }: Props) {
  const [form, setForm] = useState<ScheduleForm>(() => (existing ? formFromView(existing) : emptyForm(initialVms)));
  const [read, setPreview] = useState<SchedulePreview | null>(null);
  const [readError, setPreviewError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("");
  const problem = formProblem(form);
  const set = (change: Partial<ScheduleForm>) => setForm((f) => ({ ...f, ...change }));

  // The core's preview, once the form is complete, a moment after the last change.
  const input = useMemo(() => (problem === null ? formToInput(form) : null), [form, problem]);
  // An incomplete form shows why instead of the last preview.
  const preview = input ? read : null;
  const previewError = input ? readError : null;
  useEffect(() => {
    if (!input) return;
    let live = true;
    const timer = window.setTimeout(() => {
      schedulesApi.preview(input).then(
        (p) => {
          if (!live) return;
          setPreview(p);
          setPreviewError(null);
        },
        (err: unknown) => {
          if (!live) return;
          setPreview(null);
          setPreviewError(errorMessage(err));
        },
      );
    }, 300);
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [input]);

  const shownVms = vms.filter((vm) => vm.displayName.toLowerCase().includes(filter.trim().toLowerCase()));
  const action = ACTION_CHOICES.find((a) => a.value === form.action);

  async function save() {
    if (!input) return;
    setBusy(true);
    setError(null);
    try {
      onSaved(await schedulesApi.save(input));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const toggle = (list: string[], value: string, on: boolean) =>
    on ? [...list.filter((v) => v !== value), value] : list.filter((v) => v !== value);

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>{existing ? `Edit schedule '${existing.name}'` : "New schedule"}</DialogTitle>
          <DialogDescription>
            Saving asks for its approval, with the same steps as running it now. Each run then runs under that approval;
            a change to what it does, its VMs or its times asks again.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-6 md:grid-cols-[1fr_18rem]">
          <div className="grid content-start gap-4">
            <div className="grid gap-2">
              <Label htmlFor="schedule-name">Name</Label>
              <Input
                id="schedule-name"
                value={form.name}
                placeholder="Nightly lab snapshots"
                maxLength={80}
                autoFocus
                onChange={(e) => set({ name: e.currentTarget.value })}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="schedule-action">What it does</Label>
              <Select value={form.action} onValueChange={(v) => setForm((f) => withAction(f, v as ActionKind))}>
                <SelectTrigger id="schedule-action" className="w-64">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ACTION_CHOICES.map((a) => (
                    <SelectItem key={a.value} value={a.value}>
                      {a.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {action && <p className="text-xs text-muted-foreground">{action.hint}</p>}
              {form.action === "snapshot" && (
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <Checkbox
                    id="schedule-keep"
                    checked={form.keepOn}
                    onCheckedChange={(on) => set({ keepOn: on === true })}
                  />
                  <Label htmlFor="schedule-keep" className="font-normal">
                    Keep only the last
                  </Label>
                  <Input
                    aria-label="Snapshots to keep"
                    className="w-20"
                    inputMode="numeric"
                    disabled={!form.keepOn}
                    value={form.keep}
                    onChange={(e) => set({ keep: e.currentTarget.value })}
                  />
                  <span>snapshots it took (1 to {MAX_KEEP})</span>
                  <p className="w-full text-xs text-muted-foreground">
                    Retention deletes only snapshots this schedule took, oldest first. Deleting snapshots is High, so
                    the approval asks for a reason and the number of VMs.
                  </p>
                </div>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="schedule-timing">When</Label>
              <div className="flex flex-wrap items-center gap-2">
                <Select value={form.timing} onValueChange={(v) => setForm((f) => withTiming(f, v as TimingKind))}>
                  <SelectTrigger id="schedule-timing" className="w-56">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TIMING_CHOICES.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        {t.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {form.timing === "hourly" && (
                  <>
                    <span className="text-sm">at minute</span>
                    <Input
                      aria-label="Minute of the hour"
                      className="w-20"
                      inputMode="numeric"
                      value={form.minute}
                      onChange={(e) => set({ minute: e.currentTarget.value })}
                    />
                  </>
                )}
                {(form.timing === "daily" || form.timing === "weekly") && (
                  <>
                    <span className="text-sm">at</span>
                    <Input
                      aria-label="Time of day"
                      type="time"
                      className="w-32"
                      value={form.at}
                      onChange={(e) => set({ at: e.currentTarget.value })}
                    />
                  </>
                )}
              </div>
              {form.timing === "weekly" && (
                <ToggleGroup
                  type="multiple"
                  variant="outline"
                  size="sm"
                  value={form.days}
                  onValueChange={(days) => set({ days: days as Day[] })}
                  aria-label="Days of the week"
                >
                  {DAYS.map((d) => (
                    <ToggleGroupItem key={d.value} value={d.value} aria-label={d.label}>
                      {d.label}
                    </ToggleGroupItem>
                  ))}
                </ToggleGroup>
              )}
              {form.timing === "idle" && (
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span>Suspend a running VM after</span>
                  <Input
                    aria-label="Idle minutes"
                    className="w-20"
                    inputMode="numeric"
                    value={form.idleMinutes}
                    onChange={(e) => set({ idleMinutes: e.currentTarget.value })}
                  />
                  <span>minutes with its CPU under</span>
                  <Input
                    aria-label="CPU percent"
                    className="w-16"
                    inputMode="numeric"
                    value={form.cpuBelow}
                    onChange={(e) => set({ cpuBelow: e.currentTarget.value })}
                  />
                  <span>%</span>
                  <p className="w-full text-xs text-muted-foreground">
                    Measured from the dashboard&apos;s history and its live readings of the VM&apos;s own CPU. A VM
                    Remotely didn&apos;t watch for the whole time (closed, asleep, just started) waits until it has.
                  </p>
                </div>
              )}
              {form.timing !== "idle" && (
                <p className="text-xs text-muted-foreground">
                  Local time. A run missed while Remotely is closed or the PC sleeps is reported, not caught up.
                </p>
              )}
            </div>

            <div className="grid gap-2">
              <Label>On</Label>
              {tags.length > 0 && (
                <div className="flex flex-wrap gap-3">
                  {tags.map((tag) => (
                    <label key={tag.id} className="flex items-center gap-1.5 text-sm">
                      <Checkbox
                        checked={form.tags.includes(tag.name)}
                        onCheckedChange={(on) => set({ tags: toggle(form.tags, tag.name, on === true) })}
                      />
                      Tag &lsquo;{tag.name}&rsquo; ({tag.vmCount === 1 ? "1 VM" : `${tag.vmCount} VMs`})
                    </label>
                  ))}
                </div>
              )}
              <Input
                aria-label="Filter VMs"
                placeholder="Filter VMs…"
                value={filter}
                onChange={(e) => setFilter(e.currentTarget.value)}
              />
              <div className="grid max-h-48 gap-1 overflow-auto rounded-md border p-2">
                {shownVms.length === 0 && <p className="text-sm text-muted-foreground">No VM matches.</p>}
                {shownVms.map((vm) => (
                  <label key={vm.vmxPath} className="flex items-center gap-1.5 text-sm">
                    <Checkbox
                      checked={form.vms.includes(vm.vmxPath)}
                      onCheckedChange={(on) => set({ vms: toggle(form.vms, vm.vmxPath, on === true) })}
                    />
                    {vm.displayName}
                    {vm.environment === "prod" && <span className="text-xs text-tier-high">Prod</span>}
                    {vm.protected && <span className="text-xs text-muted-foreground">protected (skipped)</span>}
                  </label>
                ))}
              </div>
            </div>
          </div>

          <aside className="grid content-start gap-3 rounded-md border p-3 text-sm" aria-label="Preview">
            <div className="flex items-center gap-2 font-medium">
              <CalendarClockIcon className="size-4" /> Preview
            </div>
            {!preview && !previewError && (
              <p className="text-muted-foreground">{problem ?? "Reading what it would do…"}</p>
            )}
            {previewError && <p className="text-destructive">{previewError}</p>}
            {preview && (
              <>
                <p>{preview.summary}</p>
                {preview.nextRuns.length > 0 && (
                  <div>
                    <div className="text-xs font-medium text-muted-foreground">Next runs</div>
                    <ul className="grid gap-1">
                      {preview.nextRuns.map((run) => (
                        <li key={run.at}>
                          {formatPlanned(run.at)}
                          {run.note && <div className="text-xs text-tier-medium">{run.note}</div>}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div>
                  <div className="text-xs font-medium text-muted-foreground">VMs now</div>
                  <p>{preview.vms.length ? preview.vms.join(", ") : "None: no VM has those tags now"}</p>
                </div>
                {preview.warnings.length > 0 && (
                  <Alert>
                    <TriangleAlertIcon />
                    <AlertDescription>
                      <ul className="list-disc pl-4">
                        {preview.warnings.map((w) => (
                          <li key={w}>{w}</li>
                        ))}
                      </ul>
                    </AlertDescription>
                  </Alert>
                )}
              </>
            )}
          </aside>
        </div>

        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <WhyDisabled reason={busy ? "Saving…" : problem}>
            <Button onClick={() => void save()} disabled={busy || problem !== null}>
              Save and approve…
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
