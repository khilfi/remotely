// Editable approval rules (AP-01): the tier of every action for one target and in bulk, the bulk
// thresholds (one for commands on hosts, BX-06, one for the rest), the Prod bump, the countdown, the
// safety snapshot default, dangerous-command patterns (BX-06) and read-only commands. Saved through
// the command bus, which checks the rules (an invalid one is refused with the reason) and writes what
// changed to the audit log.
//
// UX-10: this is the Advanced part of Settings > Approvals (ApprovalRulesCard shows the summary above it). Unlike the
// rest of Settings it keeps an explicit Save, in a bar that sticks to the bottom while there are unsaved changes:
// these rules decide how much a risky action asks, so a change applies only as a whole set that the core checks
// together (thresholds, patterns), it is audited as one entry listing every change, and a change that loosens them
// asks for the vault password once per save rather than once per field. A half-typed pattern never applies.

import { useState, type ReactNode } from "react";
import { PlusIcon, RotateCcwIcon, XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { TierBadge } from "@/components/Badges";
import {
  api,
  errorMessage,
  type ActionKind,
  type DangerousPattern,
  type PolicyCatalog,
  type PolicyRules,
  type PolicySaved,
  type Tier,
  type TierRule,
} from "@/lib/api";
import { HelpTip } from "@/components/HelpTip";
import { withVaultPassword } from "@/lib/reauth-prompt";

const TIERS: Tier[] = ["low", "medium", "high", "critical"];

// `exec`: the bulk tier applies from the threshold for commands on hosts (Compare hosts and Type in all tabs, BX-06).
const GROUPS: { title: string; kinds: ActionKind[]; exec?: boolean; deploy?: boolean }[] = [
  {
    title: "VM power",
    kinds: ["vmStart", "vmUnpause", "vmPause", "vmSuspend", "vmResetSoft", "vmStopSoft", "vmResetHard", "vmStopHard"],
  },
  { title: "Snapshots", kinds: ["snapshotTake", "snapshotRevert", "snapshotDelete"] },
  { title: "Protected", kinds: ["vmProtect", "vmUnprotect"] },
  {
    title: "VM settings and lifecycle",
    kinds: [
      "vmIso",
      "vmNicConnect",
      "vmNicDisconnect",
      "vmToolsInstall",
      "vmConfigure",
      "vmUpgradeHardware",
      "vmDiskAdd",
      "vmDiskCompact",
      "vmDiskExpand",
      "vmDiskRemove",
      "vmRegister",
      "vmDelete",
    ],
  },
  { title: "Deploy", kinds: ["vmDeploy"], deploy: true },
  { title: "Stacks", kinds: ["stackTeardown"] },
  { title: "Commands on hosts", kinds: ["execReadOnly", "execOther", "execDangerous"], exec: true },
  { title: "SSH keys", kinds: ["sshKeyPush", "sshKeyRemove"] },
  { title: "Files", kinds: ["fileUpload", "fileReplace"] },
  { title: "Tunnels", kinds: ["tunnelLocal", "tunnelRemote", "tunnelShared"] },
  {
    title: "Containers",
    kinds: [
      "containerStart",
      "containerUnpause",
      "containerPause",
      "containerRestart",
      "containerStop",
      "containerRemove",
      "imagePull",
      "imageRemove",
      "volumeRemove",
      "pruneContainers",
      "pruneImages",
      "pruneBuildCache",
      "pruneVolumes",
    ],
  },
  { title: "This app", kinds: ["appUpdate"] },
];

type Message = { ok: boolean; title: string } | null;

function TierSelect({ value, onChange, label }: { value: Tier; onChange: (tier: Tier) => void; label: string }) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as Tier)}>
      <SelectTrigger size="sm" className="w-32" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {TIERS.map((t) => (
          <SelectItem key={t} value={t}>
            <TierBadge tier={t} />
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

const readOnlyText = (rules: PolicyRules) => rules.readOnlyCommands.join("\n");
const psReadOnlyText = (rules: PolicyRules) => rules.powershell.readOnlyCommands.join("\n");

/** One command per line, blank lines left out. */
function entries(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

/** BX-06, BX-13: an editable list of dangerous-command rules (the shell's or PowerShell's). */
function DangerousList({
  patterns,
  onChange,
}: {
  patterns: DangerousPattern[];
  onChange: (patterns: DangerousPattern[]) => void;
}) {
  return (
    <div className="grid gap-2">
      {patterns.map((p, i) => (
        <div key={i} className="flex gap-2">
          <Input
            aria-label="Name"
            className="w-48"
            placeholder="Name"
            value={p.name}
            onChange={(e) => {
              const name = e.currentTarget.value;
              onChange(patterns.map((d, j) => (j === i ? { ...d, name } : d)));
            }}
          />
          <Input
            aria-label={`Pattern for ${p.name || "this rule"}`}
            className="flex-1 font-mono text-xs"
            placeholder="Regular expression"
            spellCheck={false}
            value={p.pattern}
            onChange={(e) => {
              const pattern = e.currentTarget.value;
              onChange(patterns.map((d, j) => (j === i ? { ...d, pattern } : d)));
            }}
          />
          <Button
            size="icon"
            variant="ghost"
            aria-label={`Remove ${p.name || "this rule"}`}
            onClick={() => onChange(patterns.filter((_, j) => j !== i))}
          >
            <XIcon />
          </Button>
        </div>
      ))}
      <div>
        <Button variant="outline" size="sm" onClick={() => onChange([...patterns, { name: "", pattern: "" }])}>
          <PlusIcon data-icon="inline-start" />
          Add a pattern
        </Button>
      </div>
    </div>
  );
}

interface Props {
  catalog: PolicyCatalog;
  /** The rules saved now. */
  saved: PolicyRules;
  onSaved: (result: PolicySaved) => void;
}

export function PolicyRulesEditor({ catalog, saved, onSaved }: Props) {
  const [draft, setDraft] = useState<PolicyRules>(saved);
  // Edited as text, one command per line; split when saving.
  const [readOnly, setReadOnly] = useState(readOnlyText(saved));
  const [psReadOnly, setPsReadOnly] = useState(psReadOnlyText(saved));
  const [message, setMessage] = useState<Message>(null);
  const [busy, setBusy] = useState(false);
  // The saved rules changed (a save here): the editor starts from them.
  const [shown, setShown] = useState(saved);
  if (saved !== shown) {
    setShown(saved);
    setDraft(saved);
    setReadOnly(readOnlyText(saved));
    setPsReadOnly(psReadOnlyText(saved));
  }

  const labels = new Map(catalog.actions.map((a) => [a.kind, a.label]));
  const withReadOnly = (rules: PolicyRules): PolicyRules => ({
    ...rules,
    readOnlyCommands: entries(readOnly),
    powershell: { ...rules.powershell, readOnlyCommands: entries(psReadOnly) },
  });
  const dirty = JSON.stringify(withReadOnly(draft)) !== JSON.stringify(saved);

  function update(change: Partial<PolicyRules>) {
    setDraft((d) => ({ ...d, ...change }));
    setMessage(null);
  }

  function setTier(kind: ActionKind, which: keyof TierRule, tier: Tier) {
    update({ tiers: { ...draft.tiers, [kind]: { ...draft.tiers[kind], [which]: tier } } });
  }

  function load(rules: PolicyRules) {
    setDraft(rules);
    setReadOnly(readOnlyText(rules));
    setPsReadOnly(psReadOnlyText(rules));
  }

  async function save() {
    setBusy(true);
    try {
      // AP-06: a change that loosens the rules asks for the vault password first.
      const rules = withReadOnly(draft);
      const result = await withVaultPassword((password) => api.setPolicyRules(rules, password));
      setMessage(null);
      onSaved(result);
    } catch (err) {
      setMessage({ ok: false, title: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-6">
      <div className="flex items-center gap-2">
        <p className="text-sm text-muted-foreground">Changes here are saved together, from the bar at the bottom.</p>
        <Button
          variant="ghost"
          size="sm"
          className="ml-auto"
          disabled={busy}
          onClick={() => {
            load(catalog.defaults);
            setMessage({ ok: true, title: "The default rules are filled in. Save to use them." });
          }}
        >
          <RotateCcwIcon data-icon="inline-start" />
          Reset to defaults
        </Button>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Action</TableHead>
              <TableHead className="w-40">One target</TableHead>
              <TableHead className="w-40">
                <span className="flex items-center gap-1">
                  In bulk
                  <HelpTip topic="bulkTier" />
                </span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {GROUPS.map((group) => {
              const bulkFrom = group.exec
                ? `${draft.execBulkThreshold} or more hosts`
                : group.deploy
                  ? `${draft.deployBulkThreshold} or more VMs`
                  : `${draft.bulkThreshold} or more targets`;
              return (
                <GroupRows key={group.title} title={group.title} bulkFrom={bulkFrom}>
                  {group.kinds.map((kind) => {
                    const rule = draft.tiers[kind];
                    const label = labels.get(kind) ?? kind;
                    return (
                      <TableRow key={kind}>
                        <TableCell className="pl-6">{label}</TableCell>
                        <TableCell>
                          <TierSelect
                            label={`${label}, one target`}
                            value={rule.single}
                            onChange={(t) => setTier(kind, "single", t)}
                          />
                        </TableCell>
                        <TableCell>
                          <TierSelect
                            label={`${label}, ${bulkFrom}`}
                            value={rule.bulk}
                            onChange={(t) => setTier(kind, "bulk", t)}
                          />
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </GroupRows>
              );
            })}
          </TableBody>
        </Table>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <NumberField
          id="bulk-threshold"
          label="Bulk tier from"
          unit="targets"
          min={2}
          max={catalog.maxBulkThreshold}
          value={draft.bulkThreshold}
          onChange={(bulkThreshold) => update({ bulkThreshold })}
        />
        <NumberField
          id="exec-bulk-threshold"
          label="Bulk tier for commands on hosts from"
          unit="hosts"
          min={2}
          max={catalog.maxBulkThreshold}
          value={draft.execBulkThreshold}
          onChange={(execBulkThreshold) => update({ execBulkThreshold })}
        />
        <NumberField
          id="deploy-bulk-threshold"
          label="Bulk tier for deploys from"
          unit="new VMs"
          min={2}
          max={catalog.maxBulkThreshold}
          value={draft.deployBulkThreshold}
          onChange={(deployBulkThreshold) => update({ deployBulkThreshold })}
        />
        <NumberField
          id="countdown"
          label="Countdown before High and Critical"
          unit="seconds (0 for none)"
          min={0}
          max={catalog.maxCountdownSeconds}
          value={draft.countdownSeconds}
          onChange={(countdownSeconds) => update({ countdownSeconds })}
        />
        <div className="flex items-center gap-3">
          <Switch
            id="prod-bump"
            checked={draft.prodBump}
            onCheckedChange={(checked) => update({ prodBump: checked })}
          />
          <Label htmlFor="prod-bump">A Prod target raises the tier by one</Label>
          <HelpTip topic="prodTier" />
        </div>
        <div className="flex items-center gap-3">
          <Switch
            id="safety-default"
            checked={draft.safetySnapshotDefault}
            onCheckedChange={(checked) => update({ safetySnapshotDefault: checked })}
          />
          <Label htmlFor="safety-default">Safety snapshot on by default</Label>
        </div>
      </div>

      <Separator />

      {/* BX-13: the commands on hosts are rated by the shell's rules over SSH and PowerShell's over WinRM. */}
      <Tabs defaultValue="shell" className="grid gap-4">
        <TabsList>
          <TabsTrigger value="shell">Shell</TabsTrigger>
          <TabsTrigger value="powershell">PowerShell</TabsTrigger>
        </TabsList>
        <TabsContent value="shell" className="grid gap-6">
          <div className="grid gap-3">
            <div className="flex items-center gap-1">
              <h3 className="text-sm font-medium">Dangerous commands</h3>
              <HelpTip topic="dangerousCommands" />
            </div>
            <p className="text-sm text-muted-foreground">A command that matches one of these patterns is High.</p>
            <DangerousList
              patterns={draft.dangerousCommands}
              onChange={(dangerousCommands) => update({ dangerousCommands })}
            />
          </div>
          <div className="grid gap-2">
            <div className="flex items-center gap-1">
              <Label htmlFor="read-only">Read-only commands</Label>
              <HelpTip topic="readOnlyCommands" />
            </div>
            <p className="text-sm text-muted-foreground">One per line. A command made only of these is Low.</p>
            <Textarea
              id="read-only"
              className="h-40 font-mono text-xs"
              spellCheck={false}
              value={readOnly}
              onChange={(e) => {
                setReadOnly(e.currentTarget.value);
                setMessage(null);
              }}
            />
          </div>
        </TabsContent>
        <TabsContent value="powershell" className="grid gap-6">
          <div className="grid gap-3">
            <div className="flex items-center gap-1">
              <h3 className="text-sm font-medium">Dangerous PowerShell commands</h3>
              <HelpTip topic="powershellDangerous" />
            </div>
            <p className="text-sm text-muted-foreground">
              A PowerShell command that matches one of these patterns is High.
            </p>
            <DangerousList
              patterns={draft.powershell.dangerousCommands}
              onChange={(dangerousCommands) => update({ powershell: { ...draft.powershell, dangerousCommands } })}
            />
          </div>
          <div className="grid gap-2">
            <div className="flex items-center gap-1">
              <Label htmlFor="ps-read-only">Read-only PowerShell commands</Label>
              <HelpTip topic="powershellReadOnly" />
            </div>
            <p className="text-sm text-muted-foreground">
              One per line, by full name. A script made only of these is Low.
            </p>
            <Textarea
              id="ps-read-only"
              className="h-40 font-mono text-xs"
              spellCheck={false}
              value={psReadOnly}
              onChange={(e) => {
                setPsReadOnly(e.currentTarget.value);
                setMessage(null);
              }}
            />
          </div>
        </TabsContent>
      </Tabs>

      {(dirty || message) && (
        <div className="sticky bottom-3 z-10 flex flex-wrap items-center gap-2 rounded-lg border bg-card px-4 py-3 shadow-md">
          <p
            className={message && !message.ok ? "text-sm text-destructive" : "text-sm text-muted-foreground"}
            role="status"
          >
            {message ? message.title : "Unsaved changes to the approval rules."}
          </p>
          <div className="ml-auto flex gap-2">
            <Button
              variant="outline"
              disabled={busy || !dirty}
              onClick={() => {
                load(saved);
                setMessage(null);
              }}
            >
              Discard
            </Button>
            <Button onClick={() => void save()} disabled={busy || !dirty}>
              {busy ? "Saving…" : "Save rules"}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function NumberField({
  id,
  label,
  unit,
  min,
  max,
  value,
  onChange,
}: {
  id: string;
  label: string;
  unit: string;
  min: number;
  max: number;
  value: number;
  onChange: (value: number) => void;
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <div className="flex items-center gap-2">
        <Input
          id={id}
          type="number"
          min={min}
          max={max}
          className="w-24"
          value={value}
          onChange={(e) => onChange(Number(e.currentTarget.value))}
        />
        <span className="text-sm text-muted-foreground">{unit}</span>
      </div>
    </div>
  );
}

function GroupRows({ title, bulkFrom, children }: { title: string; bulkFrom: string; children: ReactNode }) {
  return (
    <>
      <TableRow className="hover:bg-transparent">
        <TableCell
          colSpan={2}
          className="bg-muted/40 text-xs font-medium tracking-wide text-muted-foreground uppercase"
        >
          {title}
        </TableCell>
        <TableCell className="bg-muted/40 text-xs text-muted-foreground">{bulkFrom}</TableCell>
      </TableRow>
      {children}
    </>
  );
}
