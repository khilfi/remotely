// MO-07: the alert rules, beside the alert list. Built-in rules come first: each can be turned on or off, its
// threshold, duration, severity and notification changed, and reset to Remotely's defaults; their name, metric and
// scope stay. The owner's own rules can be added, edited and deleted. Every change is audited by the core and refused
// while presenting with the read-only lock. Desktop only: a rule notifies through Windows, never by email or chat.
// MO-08: rules on health checks (down, slow, a certificate expiring) have their own scopes and units.

import { useEffect, useMemo, useState } from "react";
import { BellIcon, BellOffIcon, EllipsisIcon, PencilIcon, PlusIcon, RotateCcwIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { HelpTip } from "@/components/HelpTip";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type SessionRecord, type Tag, type VmRecord } from "@/lib/api";
import { checksApi, type HealthCheck } from "@/lib/checks-api";
import {
  cleanRuleInput,
  conditionText,
  defaultThreshold,
  DURATIONS,
  durationText,
  hasThreshold,
  METRICS,
  newRuleInput,
  onChecks,
  ruleProblem,
  scopeAllows,
  scopeOfKind,
  SCOPES,
  scopeText,
  SEVERITIES,
  thresholdUnit,
} from "@/lib/alerts";
import {
  dashboardApi,
  type AlertMetric,
  type AlertRule,
  type AlertRuleInput,
  type AlertScopeKind,
  type Severity,
} from "@/lib/dashboard-api";

interface Directory {
  vms: VmRecord[];
  sessions: SessionRecord[];
  tags: Tag[];
  /** MO-08. */
  checks: HealthCheck[];
}

function RuleDialog({
  rule,
  directory,
  onClose,
  onSaved,
}: {
  /** The rule edited, or null for a new one. */
  rule: AlertRule | null;
  directory: Directory;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [input, setInput] = useState<AlertRuleInput>(() => (rule ? { ...rule } : newRuleInput()));
  const [threshold, setThreshold] = useState(rule?.threshold?.toString() ?? "90");
  const [busy, setBusy] = useState(false);
  const builtin = rule?.builtin != null;
  const candidate: AlertRuleInput = { ...input, threshold: threshold.trim() === "" ? null : Number(threshold) };
  const problem = ruleProblem(candidate);
  const set = (change: Partial<AlertRuleInput>) => setInput((old) => ({ ...old, ...change }));

  async function save() {
    setBusy(true);
    try {
      const clean = cleanRuleInput(candidate);
      if (rule) await dashboardApi.updateAlertRule(rule.id, clean);
      else await dashboardApi.createAlertRule(clean);
      toast.success(rule ? "Rule saved" : "Rule added");
      onSaved();
      onClose();
    } catch (err) {
      toast.error(errorMessage(err));
      setBusy(false);
    }
  }

  const scope = input.scope;
  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{rule ? "Edit alert rule" : "New alert rule"}</DialogTitle>
          <DialogDescription>
            {builtin
              ? "A built-in rule: its name, metric and scope stay. Reset brings back Remotely's defaults."
              : "Fires when the condition has held for the duration, on every target in its scope."}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="rule-name">Name</Label>
            <Input
              id="rule-name"
              value={input.name}
              maxLength={80}
              disabled={builtin}
              placeholder="Build VMs busy"
              onChange={(e) => set({ name: e.target.value })}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="rule-metric">Watch</Label>
              <Select
                value={input.metric}
                disabled={builtin}
                onValueChange={(v) => {
                  const metric = v as AlertMetric;
                  const fallback = onChecks(metric) ? ({ kind: "allChecks" } as const) : ({ kind: "allVms" } as const);
                  set({ metric, scope: scopeAllows(scope.kind, metric) ? scope : fallback });
                  // Another unit (percent, milliseconds, days): start from its usual threshold.
                  if (thresholdUnit(metric) !== thresholdUnit(input.metric)) {
                    setThreshold(String(defaultThreshold(metric) ?? ""));
                  }
                }}
              >
                <SelectTrigger id="rule-metric" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {METRICS.map((m) => (
                    <SelectItem key={m.value} value={m.value}>
                      {m.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="rule-scope">On</Label>
              <Select
                value={scope.kind}
                disabled={builtin}
                onValueChange={(v) => set({ scope: scopeOfKind(v as AlertScopeKind, scope) })}
              >
                <SelectTrigger id="rule-scope" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SCOPES.filter((s) => scopeAllows(s.value, input.metric)).map((s) => (
                    <SelectItem key={s.value} value={s.value}>
                      {s.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">{METRICS.find((m) => m.value === input.metric)?.hint}</p>
          {scope.kind === "vm" && (
            <div className="grid gap-1.5">
              <Label htmlFor="rule-vm">VM</Label>
              <Select
                value={scope.key || undefined}
                disabled={builtin}
                onValueChange={(key) => set({ scope: { kind: "vm", key } })}
              >
                <SelectTrigger id="rule-vm" className="w-full">
                  <SelectValue placeholder="Choose a VM" />
                </SelectTrigger>
                <SelectContent>
                  {directory.vms.map((vm) => (
                    <SelectItem key={vm.vmxPath} value={vm.vmxPath}>
                      {vm.displayName}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          {scope.kind === "tag" && (
            <div className="grid gap-1.5">
              <Label htmlFor="rule-tag">Tag</Label>
              <Select
                value={scope.tag || undefined}
                disabled={builtin}
                onValueChange={(tag) => set({ scope: { kind: "tag", tag } })}
              >
                <SelectTrigger id="rule-tag" className="w-full">
                  <SelectValue placeholder="Choose a tag" />
                </SelectTrigger>
                <SelectContent>
                  {directory.tags.map((t) => (
                    <SelectItem key={t.id} value={t.name}>
                      {t.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          {scope.kind === "host" && (
            <div className="grid gap-1.5">
              <Label htmlFor="rule-host">Watched host</Label>
              <Select
                value={scope.sessionId || undefined}
                disabled={builtin}
                onValueChange={(sessionId) => set({ scope: { kind: "host", sessionId } })}
              >
                <SelectTrigger id="rule-host" className="w-full">
                  <SelectValue placeholder="Choose a session" />
                </SelectTrigger>
                <SelectContent>
                  {directory.sessions.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                It fires only while the dashboard watches the host (its guest metrics, over SSH).
              </p>
            </div>
          )}
          {scope.kind === "check" && (
            <div className="grid gap-1.5">
              <Label htmlFor="rule-check">Health check</Label>
              <Select
                value={scope.checkId || undefined}
                disabled={builtin}
                onValueChange={(checkId) => set({ scope: { kind: "check", checkId } })}
              >
                <SelectTrigger id="rule-check" className="w-full">
                  <SelectValue placeholder="Choose a check" />
                </SelectTrigger>
                <SelectContent>
                  {directory.checks.map((c) => (
                    <SelectItem key={c.id} value={c.id}>
                      {c.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          <div className="grid grid-cols-3 gap-3">
            {hasThreshold(input.metric) && (
              <div className="grid gap-1.5">
                <Label htmlFor="rule-threshold">
                  {input.metric === "checkSlow"
                    ? "Slower than (ms)"
                    : input.metric === "certExpiring"
                      ? "Under (days left)"
                      : "Above (%)"}
                </Label>
                <Input
                  id="rule-threshold"
                  type="number"
                  min={1}
                  max={input.metric === "checkSlow" ? 600000 : input.metric === "certExpiring" ? 365 : 99}
                  step={onChecks(input.metric) ? 1 : "any"}
                  value={threshold}
                  onChange={(e) => setThreshold(e.target.value)}
                />
              </div>
            )}
            <div className="grid gap-1.5">
              <Label htmlFor="rule-for">{input.metric === "stopped" ? "Still off after" : "For"}</Label>
              <Select value={String(input.forSecs)} onValueChange={(v) => set({ forSecs: Number(v) })}>
                <SelectTrigger id="rule-for" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {[...new Set([...DURATIONS, input.forSecs])]
                    .sort((a, b) => a - b)
                    .map((secs) => (
                      <SelectItem key={secs} value={String(secs)}>
                        {durationText(secs)}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="rule-severity">Severity</Label>
              <Select value={input.severity} onValueChange={(v) => set({ severity: v as Severity })}>
                <SelectTrigger id="rule-severity" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITIES.map((s) => (
                    <SelectItem key={s.value} value={s.value}>
                      {s.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex items-center justify-between gap-2">
            <Label htmlFor="rule-notify" className="font-normal">
              Windows notification when it fires (at most one per target in half an hour)
            </Label>
            <Switch id="rule-notify" checked={input.notify} onCheckedChange={(notify) => set({ notify })} />
          </div>
          <div className="flex items-center justify-between gap-2">
            <Label htmlFor="rule-enabled" className="font-normal">
              On
            </Label>
            <Switch id="rule-enabled" checked={input.enabled} onCheckedChange={(enabled) => set({ enabled })} />
          </div>
          {problem && (
            <p className="text-xs text-muted-foreground" role="status">
              {problem}
            </p>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={busy || problem !== null} onClick={() => void save()}>
            {rule ? "Save" : "Add rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function AlertRulesSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [rules, setRules] = useState<AlertRule[] | null>(null);
  const [directory, setDirectory] = useState<Directory>({ vms: [], sessions: [], tags: [], checks: [] });
  const [editing, setEditing] = useState<AlertRule | "new" | null>(null);
  const [deleting, setDeleting] = useState<AlertRule | null>(null);
  const readOnly = useReadOnlyReason();

  const load = () => {
    dashboardApi.alertRules().then(setRules, (err) => toast.error(errorMessage(err)));
  };
  useEffect(() => {
    if (!open) return;
    load();
    Promise.all([api.vmList(), api.sessions(), api.tags(), checksApi.overview("1h")]).then(
      ([vms, sessions, tags, overview]) =>
        setDirectory({ vms, sessions, tags, checks: overview.rows.map((r) => r.check) }),
      () => undefined,
    );
  }, [open]);

  const names = useMemo(() => {
    const vms = new Map(directory.vms.map((v) => [v.vmxPath.toLowerCase(), v.displayName]));
    const sessions = new Map(directory.sessions.map((s) => [s.id, s.name]));
    const checks = new Map(directory.checks.map((c) => [c.id, c.name]));
    return {
      vm: (key: string) => vms.get(key.toLowerCase()),
      session: (id: string) => sessions.get(id),
      check: (id: string) => checks.get(id),
    };
  }, [directory]);

  async function toggle(rule: AlertRule, enabled: boolean) {
    try {
      await dashboardApi.updateAlertRule(rule.id, { ...rule, enabled });
      load();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function reset(rule: AlertRule) {
    try {
      await dashboardApi.resetAlertRule(rule.id);
      toast.success(`'${rule.name}' is back to its defaults`);
      load();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>Alert rules</SheetTitle>
          <SheetDescription className="flex items-center gap-1">
            Checked every round; Windows notifies you when one fires.
            <HelpTip topic="alertRules" />
          </SheetDescription>
          <div>
            <WhyDisabled reason={readOnly}>
              <Button size="sm" disabled={readOnly !== null} onClick={() => setEditing("new")}>
                <PlusIcon /> Add rule
              </Button>
            </WhyDisabled>
          </div>
        </SheetHeader>
        <ul className="flex flex-col gap-1 overflow-auto px-4 pb-4">
          {(rules ?? []).map((rule) => (
            <li key={rule.id} className="flex items-start gap-3 rounded-md border px-3 py-2">
              <WhyDisabled reason={readOnly}>
                <Switch
                  checked={rule.enabled}
                  disabled={readOnly !== null}
                  aria-label={`${rule.enabled ? "Turn off" : "Turn on"} '${rule.name}'`}
                  onCheckedChange={(on) => void toggle(rule, on)}
                  className="mt-0.5"
                />
              </WhyDisabled>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{rule.name}</span>
                  {rule.builtin && <Badge variant="secondary">Built-in</Badge>}
                  <Badge
                    variant="outline"
                    className={rule.severity === "critical" ? "text-status-critical" : "text-status-warning"}
                  >
                    {rule.severity === "critical" ? "Critical" : "Warning"}
                  </Badge>
                  {rule.notify ? (
                    <BellIcon className="size-3.5 text-muted-foreground" aria-label="Notifies" />
                  ) : (
                    <BellOffIcon className="size-3.5 text-muted-foreground" aria-label="No notification" />
                  )}
                </div>
                <div className="text-xs text-muted-foreground">
                  {conditionText(rule)} on {scopeText(rule.scope, names)}
                </div>
              </div>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon-sm" aria-label={`More for '${rule.name}'`}>
                    <EllipsisIcon />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem disabled={readOnly !== null} onSelect={() => setEditing(rule)}>
                    <PencilIcon /> Edit…
                  </DropdownMenuItem>
                  {rule.builtin ? (
                    <DropdownMenuItem disabled={readOnly !== null} onSelect={() => void reset(rule)}>
                      <RotateCcwIcon /> Reset to its defaults
                    </DropdownMenuItem>
                  ) : (
                    <DropdownMenuItem
                      variant="destructive"
                      disabled={readOnly !== null}
                      onSelect={() => setDeleting(rule)}
                    >
                      <Trash2Icon /> Delete…
                    </DropdownMenuItem>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            </li>
          ))}
          {rules === null && <li className="text-xs text-muted-foreground">Reading the rules…</li>}
        </ul>
      </SheetContent>
      {editing && (
        <RuleDialog
          rule={editing === "new" ? null : editing}
          directory={directory}
          onClose={() => setEditing(null)}
          onSaved={load}
        />
      )}
      {deleting && (
        <ConfirmDialog
          title={`Delete '${deleting.name}'?`}
          description="Its alerts stay in the list. A built-in rule can only be turned off."
          confirmLabel="Delete"
          onConfirm={async () => {
            await dashboardApi.deleteAlertRule(deleting.id);
            load();
          }}
          onClose={() => setDeleting(null)}
        />
      )}
    </Sheet>
  );
}
