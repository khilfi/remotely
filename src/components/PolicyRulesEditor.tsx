// Editable approval rules (AP-01): the tier of every action for one target and in bulk, the bulk
// threshold, the Prod bump, the countdown, the safety snapshot default, dangerous-command patterns
// (BX-06) and read-only commands. Saved through the command bus, which checks the rules (an invalid
// one is refused with the reason) and writes what changed to the audit log.

import { useEffect, useState, type ReactNode } from "react";
import { PlusIcon, RotateCcwIcon, XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { TierBadge } from "@/components/Badges";
import {
  api,
  errorMessage,
  type ActionKind,
  type PolicyCatalog,
  type PolicyRules,
  type Tier,
  type TierRule,
} from "@/lib/api";

const TIERS: Tier[] = ["low", "medium", "high", "critical"];

const GROUPS: { title: string; kinds: ActionKind[] }[] = [
  {
    title: "VM power",
    kinds: ["vmStart", "vmUnpause", "vmPause", "vmSuspend", "vmResetSoft", "vmStopSoft", "vmResetHard", "vmStopHard"],
  },
  { title: "Snapshots", kinds: ["snapshotTake", "snapshotRevert", "snapshotDelete"] },
  { title: "Do not touch", kinds: ["vmProtect", "vmUnprotect"] },
  { title: "Commands on hosts", kinds: ["execReadOnly", "execOther", "execDangerous", "sshKeyPush"] },
  { title: "This app", kinds: ["appUpdate"] },
];

type Message = { ok: boolean; title: string; lines?: string[] } | null;

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

export function PolicyRulesEditor() {
  const [catalog, setCatalog] = useState<PolicyCatalog | null>(null);
  const [saved, setSaved] = useState<PolicyRules | null>(null);
  const [draft, setDraft] = useState<PolicyRules | null>(null);
  // Edited as text, one command per line; split when saving.
  const [readOnly, setReadOnly] = useState("");
  const [message, setMessage] = useState<Message>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    Promise.all([api.policyCatalog(), api.policyRules()]).then(
      ([c, rules]) => {
        setCatalog(c);
        setSaved(rules);
        setDraft(rules);
        setReadOnly(readOnlyText(rules));
      },
      (err) => setMessage({ ok: false, title: errorMessage(err) }),
    );
  }, []);

  if (!catalog || !saved || !draft) {
    return message ? <p className="text-sm text-destructive">{message.title}</p> : null;
  }

  const labels = new Map(catalog.actions.map((a) => [a.kind, a.label]));
  const withReadOnly = (rules: PolicyRules): PolicyRules => ({
    ...rules,
    readOnlyCommands: readOnly
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l !== ""),
  });
  const dirty = JSON.stringify(withReadOnly(draft)) !== JSON.stringify(saved);

  function update(change: Partial<PolicyRules>) {
    setDraft((d) => (d ? { ...d, ...change } : d));
    setMessage(null);
  }

  function setTier(kind: ActionKind, which: keyof TierRule, tier: Tier) {
    if (!draft) return;
    update({ tiers: { ...draft.tiers, [kind]: { ...draft.tiers[kind], [which]: tier } } });
  }

  function load(rules: PolicyRules) {
    setDraft(rules);
    setReadOnly(readOnlyText(rules));
  }

  async function save() {
    if (!draft) return;
    setBusy(true);
    try {
      const result = await api.setPolicyRules(withReadOnly(draft));
      setSaved(result.rules);
      load(result.rules);
      setMessage(
        result.changes.length > 0
          ? {
              ok: true,
              title: "Saved. Applies from the next action on, and the change is in the audit log:",
              lines: result.changes,
            }
          : { ok: true, title: "Nothing changed." },
      );
    } catch (err) {
      setMessage({ ok: false, title: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Approval rules</CardTitle>
        <CardDescription>
          Every action that changes something gets a risk tier, and the tier decides the steps before it runs. Low:
          none, only logged. Medium: one confirm. High: impact preview, safety snapshot, type the number of targets, a
          reason and a countdown. Critical: all of those, then the vault password again.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-6">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Action</TableHead>
                <TableHead className="w-40">One target</TableHead>
                <TableHead className="w-40">{draft.bulkThreshold} or more targets</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {GROUPS.map((group) => (
                <GroupRows key={group.title} title={group.title}>
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
                            label={`${label}, ${draft.bulkThreshold} or more targets`}
                            value={rule.bulk}
                            onChange={(t) => setTier(kind, "bulk", t)}
                          />
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </GroupRows>
              ))}
            </TableBody>
          </Table>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="bulk-threshold">Bulk tier applies from</Label>
            <div className="flex items-center gap-2">
              <Input
                id="bulk-threshold"
                type="number"
                min={2}
                max={catalog.maxBulkThreshold}
                className="w-24"
                value={draft.bulkThreshold}
                onChange={(e) => update({ bulkThreshold: Number(e.currentTarget.value) })}
              />
              <span className="text-sm text-muted-foreground">targets</span>
            </div>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="countdown">Countdown before a High or Critical action</Label>
            <div className="flex items-center gap-2">
              <Input
                id="countdown"
                type="number"
                min={0}
                max={catalog.maxCountdownSeconds}
                className="w-24"
                value={draft.countdownSeconds}
                onChange={(e) => update({ countdownSeconds: Number(e.currentTarget.value) })}
              />
              <span className="text-sm text-muted-foreground">seconds (0 turns it off)</span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Switch
              id="prod-bump"
              checked={draft.prodBump}
              onCheckedChange={(checked) => update({ prodBump: checked })}
            />
            <Label htmlFor="prod-bump">A target labelled Prod raises the tier by one</Label>
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

        <div className="grid gap-3">
          <div>
            <h3 className="text-sm font-medium">Dangerous commands</h3>
            <p className="text-sm text-muted-foreground">
              A command that matches any of these regular expressions is High. A pattern that matches every command is
              refused.
            </p>
          </div>
          <div className="grid gap-2">
            {draft.dangerousCommands.map((p, i) => (
              <div key={i} className="flex gap-2">
                <Input
                  aria-label="Name"
                  className="w-48"
                  placeholder="Name"
                  value={p.name}
                  onChange={(e) => {
                    const name = e.currentTarget.value;
                    update({
                      dangerousCommands: draft.dangerousCommands.map((d, j) => (j === i ? { ...d, name } : d)),
                    });
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
                    update({
                      dangerousCommands: draft.dangerousCommands.map((d, j) => (j === i ? { ...d, pattern } : d)),
                    });
                  }}
                />
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label={`Remove ${p.name || "this rule"}`}
                  onClick={() => update({ dangerousCommands: draft.dangerousCommands.filter((_, j) => j !== i) })}
                >
                  <XIcon />
                </Button>
              </div>
            ))}
            <div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => update({ dangerousCommands: [...draft.dangerousCommands, { name: "", pattern: "" }] })}
              >
                <PlusIcon data-icon="inline-start" />
                Add a pattern
              </Button>
            </div>
          </div>
        </div>

        <div className="grid gap-2">
          <Label htmlFor="read-only">Read-only commands</Label>
          <p className="text-sm text-muted-foreground">
            One per line. A command whose every part starts with one of these, and that writes no file, is Low. Entries
            can&apos;t hold shell operators such as ; | &gt; or $. Forms that change something, such as ip link set,
            date -s or journalctl --vacuum-size, are never read-only.
          </p>
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

        {message && (
          <div className={message.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
            <p>{message.title}</p>
            {message.lines && (
              <ul className="mt-1 list-disc pl-5">
                {message.lines.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </CardContent>
      <CardFooter className="gap-2">
        <Button onClick={() => void save()} disabled={busy || !dirty}>
          {busy ? "Saving…" : "Save rules"}
        </Button>
        <Button
          variant="outline"
          disabled={busy || !dirty}
          onClick={() => {
            load(saved);
            setMessage(null);
          }}
        >
          Discard changes
        </Button>
        <Button
          variant="ghost"
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
      </CardFooter>
    </Card>
  );
}

function GroupRows({ title, children }: { title: string; children: ReactNode }) {
  return (
    <>
      <TableRow className="hover:bg-transparent">
        <TableCell
          colSpan={3}
          className="bg-muted/40 text-xs font-medium tracking-wide text-muted-foreground uppercase"
        >
          {title}
        </TableCell>
      </TableRow>
      {children}
    </>
  );
}
