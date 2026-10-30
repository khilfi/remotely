// QL-17 highlight and alert rules, in Settings, Terminal: the built-in rules (on or off, alert on or off, Duplicate
// for an editable copy) and the user's own (add, edit, reorder, delete), each a regular expression with a colour
// (text or fill), a scope (every terminal, sessions with a label, or one session), case sensitivity and an alert.
// The editor checks a pattern as it is typed: in the core (what Rust and JavaScript both read alike, no nested
// repeats) and here (it compiles in JavaScript), and shows what it matches in a line typed to try it. Saved in the
// core, audited (name and scope, never the pattern) and refused by presentation mode's read-only lock (QL-08 says why).
// Open terminals pick the changes up: alerts at once, highlights when the Terminal page shows again.

import { useEffect, useMemo, useState } from "react";
import {
  ArrowDownIcon,
  ArrowUpIcon,
  BellIcon,
  CopyIcon,
  PencilIcon,
  PlusIcon,
  Trash2Icon,
  TriangleAlertIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { HelpTip } from "@/components/HelpTip";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Switch } from "@/components/ui/switch";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { ColorDot, SESSION_COLORS } from "@/components/Badges";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { RowMenu } from "@/components/RowMenu";
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type PatternCheck,
  type RuleScope,
  type RuleStyle,
  type SessionColor,
  type SessionRecord,
  type TerminalRule,
  type TerminalRuleInput,
} from "@/lib/api";
import { compileRules, localPatternProblem, lookOf, matchLine } from "@/lib/highlight-rules";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

const NONE = "none";
const ENVIRONMENTS = [
  { value: "lab", label: "Lab sessions" },
  { value: "staging", label: "Staging sessions" },
  { value: "prod", label: "Prod sessions" },
] as const;

/** "Every terminal", "Prod sessions", "the session web01". */
function scopeText(scope: RuleScope, sessions: Map<string, SessionRecord>): string {
  switch (scope.kind) {
    case "global":
      return "Every terminal";
    case "environment":
      return ENVIRONMENTS.find((e) => e.value === scope.environment)?.label ?? "Sessions in an environment";
    case "session":
      return `Session ${sessions.get(scope.sessionId)?.name ?? "(deleted)"}`;
  }
}

/** A rule's built-in key, from its id. */
function builtinKey(rule: TerminalRule) {
  return rule.id.replace(/^builtin:/, "");
}

export function TerminalRulesCard() {
  const [rules, setRules] = useState<TerminalRule[] | null>(null);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  /** The dialog: a rule to edit, or a new one (maybe a built-in's copy). */
  const [editing, setEditing] = useState<{ rule: TerminalRule | null; initial: TerminalRuleInput | null } | null>(null);
  const [deleting, setDeleting] = useState<TerminalRule | null>(null);
  const readOnly = useReadOnlyReason();

  useEffect(() => {
    api.terminalRules().then(setRules, (err) => setMessage({ ok: false, text: errorMessage(err) }));
    api.sessions().then(setSessions, () => undefined);
  }, []);

  const sessionById = useMemo(() => new Map(sessions.map((s) => [s.id, s])), [sessions]);
  const builtins = rules?.filter((r) => r.builtin) ?? [];
  const own = rules?.filter((r) => !r.builtin) ?? [];

  async function run(action: () => Promise<unknown>, done?: string) {
    try {
      await action();
      setRules(await api.terminalRules());
      setMessage(done ? { ok: true, text: done } : null);
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    }
  }

  function move(index: number, by: -1 | 1) {
    const ids = own.map((r) => r.id);
    const to = index + by;
    if (to < 0 || to >= ids.length) return;
    [ids[index], ids[to]] = [ids[to], ids[index]];
    void run(() => api.reorderTerminalRules(ids));
  }

  function duplicate(rule: TerminalRule) {
    const taken = new Set(rules?.map((r) => r.name.toLowerCase()));
    let name = `${rule.name} (copy)`;
    for (let n = 2; taken.has(name.toLowerCase()); n++) name = `${rule.name} (copy ${n})`;
    setEditing({
      rule: null,
      initial: {
        name,
        pattern: rule.pattern,
        caseSensitive: rule.caseSensitive,
        color: rule.color,
        style: rule.style,
        alert: rule.alert,
        scope: rule.scope,
        enabled: true,
      },
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Highlight and alert rules
          <HelpTip topic="terminalRules" />
        </CardTitle>
        <CardDescription>
          Colour what a pattern matches in terminals, and be told about it while you&apos;re away.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-2">
          <h3 className="text-sm font-medium">Built in</h3>
          <ul className="grid divide-y rounded-md border">
            {builtins.map((rule) => (
              <li key={rule.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
                <RuleSummary rule={rule} scope="Every terminal" />
                <div className="ml-auto flex items-center gap-3">
                  <WhyDisabled reason={readOnly}>
                    <Label className="flex items-center gap-1.5 text-xs font-normal">
                      <Switch
                        checked={rule.enabled}
                        disabled={readOnly !== null}
                        aria-label={`Highlight with ${rule.name}`}
                        onCheckedChange={(enabled) =>
                          void run(() => api.setBuiltinTerminalRule(builtinKey(rule), enabled, rule.alert))
                        }
                      />
                      On
                    </Label>
                  </WhyDisabled>
                  <WhyDisabled reason={readOnly ?? (rule.enabled ? null : "Turn the rule on first")}>
                    <Label className="flex items-center gap-1.5 text-xs font-normal">
                      <Switch
                        checked={rule.alert}
                        disabled={readOnly !== null || !rule.enabled}
                        aria-label={`Alert on ${rule.name}`}
                        onCheckedChange={(alert) =>
                          void run(() => api.setBuiltinTerminalRule(builtinKey(rule), rule.enabled, alert))
                        }
                      />
                      Alert
                    </Label>
                  </WhyDisabled>
                  <RowMenu label={rule.name} disabled={readOnly !== null}>
                    <DropdownMenuItem onSelect={() => duplicate(rule)}>
                      <CopyIcon />
                      Duplicate to change it…
                    </DropdownMenuItem>
                  </RowMenu>
                </div>
              </li>
            ))}
          </ul>
        </div>
        <div className="grid gap-2">
          <h3 className="text-sm font-medium">Yours</h3>
          {own.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              None yet. Add one, or duplicate a built-in rule to change it.
            </p>
          ) : (
            <ul className="grid divide-y rounded-md border">
              {own.map((rule, index) => (
                <li key={rule.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
                  <RuleSummary rule={rule} scope={scopeText(rule.scope, sessionById)} />
                  <div className="ml-auto">
                    <RowMenu label={rule.name} disabled={readOnly !== null}>
                      <DropdownMenuItem onSelect={() => setEditing({ rule, initial: null })}>
                        <PencilIcon />
                        Edit…
                      </DropdownMenuItem>
                      <DropdownMenuItem disabled={index === 0} onSelect={() => move(index, -1)}>
                        <ArrowUpIcon />
                        Move up
                      </DropdownMenuItem>
                      <DropdownMenuItem disabled={index === own.length - 1} onSelect={() => move(index, 1)}>
                        <ArrowDownIcon />
                        Move down
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem variant="destructive" onSelect={() => setDeleting(rule)}>
                        <Trash2Icon />
                        Delete…
                      </DropdownMenuItem>
                    </RowMenu>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
        {message && (
          <p className={message.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
            {message.text}
          </p>
        )}
      </CardContent>
      <CardFooter>
        <WhyDisabled reason={readOnly}>
          <Button
            variant="outline"
            disabled={readOnly !== null || rules === null}
            onClick={() => setEditing({ rule: null, initial: null })}
          >
            <PlusIcon data-icon="inline-start" />
            Add a rule
          </Button>
        </WhyDisabled>
      </CardFooter>
      {editing && (
        <RuleDialog
          rule={editing.rule}
          initial={editing.initial}
          sessions={sessions}
          onSaved={(saved) => void run(() => Promise.resolve(), `Saved the rule ${saved.name}.`)}
          onClose={() => setEditing(null)}
        />
      )}
      {deleting && (
        <ConfirmDialog
          title={`Delete the rule ${deleting.name}?`}
          description="Terminals stop colouring and alerting on what it matches."
          confirmLabel="Delete"
          onConfirm={async () => {
            await api.deleteTerminalRule(deleting.id);
            setRules(await api.terminalRules());
          }}
          onClose={() => setDeleting(null)}
        />
      )}
    </Card>
  );
}

/** A rule's colour, name, pattern and scope, and what is off about it. */
function RuleSummary({ rule, scope }: { rule: TerminalRule; scope: string }) {
  return (
    <div className="grid min-w-0 flex-1 gap-0.5">
      <div className="flex min-w-0 items-center gap-2">
        {rule.color ? (
          <ColorDot color={rule.color} className={cn("size-3", rule.style === "fill" && "rounded-sm")} />
        ) : (
          <BellIcon className="size-3 shrink-0 text-muted-foreground" aria-label="Alert only" />
        )}
        <span className={cn("truncate text-sm", !rule.enabled && "text-muted-foreground line-through")}>
          {rule.name}
        </span>
        {rule.alert && rule.enabled && (
          <Badge variant="outline" className="shrink-0 text-xs">
            Alert
          </Badge>
        )}
        {!rule.enabled && (
          <Badge variant="outline" className="shrink-0 text-xs text-muted-foreground">
            Off
          </Badge>
        )}
        {rule.problem && (
          <span title={rule.problem} className="flex shrink-0 items-center gap-1 text-xs text-destructive">
            <TriangleAlertIcon className="size-3.5" aria-hidden />
            Not used
          </span>
        )}
      </div>
      <div className="flex min-w-0 gap-2 text-xs text-muted-foreground">
        <code className="truncate font-mono" title={rule.pattern}>
          {rule.pattern}
        </code>
        <span className="shrink-0">
          · {scope}
          {rule.caseSensitive ? " · matches case" : ""}
        </span>
      </div>
    </div>
  );
}

/** The scope picker's value: "global", "env:prod", "session". */
function scopeValue(scope: RuleScope): string {
  if (scope.kind === "environment") return `env:${scope.environment}`;
  return scope.kind;
}

function RuleDialog({
  rule,
  initial,
  sessions,
  onSaved,
  onClose,
}: {
  /** Edit this one; without it, add a new rule (from `initial` when duplicating). */
  rule: TerminalRule | null;
  initial: TerminalRuleInput | null;
  sessions: SessionRecord[];
  onSaved: (rule: TerminalRule) => void;
  onClose: () => void;
}) {
  const start: TerminalRuleInput = rule
    ? {
        name: rule.name,
        pattern: rule.pattern,
        caseSensitive: rule.caseSensitive,
        color: rule.color,
        style: rule.style,
        alert: rule.alert,
        scope: rule.scope,
        enabled: rule.enabled,
      }
    : (initial ?? {
        name: "",
        pattern: "",
        caseSensitive: false,
        color: "red",
        style: "text",
        alert: false,
        scope: { kind: "global" },
        enabled: true,
      });
  const [draft, setDraft] = useState<TerminalRuleInput>(start);
  /** The core's answer, and for which pattern and case it was. */
  const [checked, setChecked] = useState<{ key: string; result: PatternCheck } | null>(null);
  const [sample, setSample] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { resolved: theme } = useTheme();
  const sorted = useMemo(() => [...sessions].sort((a, b) => a.name.localeCompare(b.name)), [sessions]);

  // The core's verdict as the pattern is typed (it decides; the local check only answers sooner).
  const local = draft.pattern ? localPatternProblem(draft.pattern) : null;
  const key = `${draft.caseSensitive}:${draft.pattern}`;
  useEffect(() => {
    if (!draft.pattern.trim()) return;
    const asked = `${draft.caseSensitive}:${draft.pattern}`;
    const timer = window.setTimeout(() => {
      api.terminalRuleValidate(draft.pattern, draft.caseSensitive).then(
        (result) => setChecked({ key: asked, result }),
        (err) => setChecked({ key: asked, result: { valid: false, message: errorMessage(err) } }),
      );
    }, 250);
    return () => window.clearTimeout(timer);
  }, [draft.pattern, draft.caseSensitive]);
  const check = checked?.key === key ? checked.result : null;
  const problem = !draft.pattern.trim() ? null : (local ?? (check && !check.valid ? check.message : null));
  const ready = Boolean(draft.pattern.trim()) && problem === null && check?.valid === true;

  // What the pattern matches in the line typed to try it, coloured as terminals will show it.
  const preview = useMemo(() => {
    if (!sample || !ready) return null;
    const compiled = compileRules([
      { ...draft, id: "draft", builtin: false, color: draft.color ?? "slate", problem: null, updatedAt: null },
    ]);
    const ranges = matchLine(sample, compiled);
    const parts: { text: string; hit: boolean }[] = [];
    let at = 0;
    for (const r of ranges) {
      if (r.start > at) parts.push({ text: sample.slice(at, r.start), hit: false });
      parts.push({ text: sample.slice(r.start, r.end), hit: true });
      at = r.end;
    }
    if (at < sample.length) parts.push({ text: sample.slice(at), hit: false });
    return { parts, count: ranges.length };
  }, [sample, ready, draft]);
  const look = lookOf(draft.color ?? "slate", draft.style, theme);

  const set = (change: Partial<TerminalRuleInput>) => setDraft((d) => ({ ...d, ...change }));
  const scopeChoice = scopeValue(draft.scope);
  const blocked = !draft.name.trim()
    ? "Give the rule a name first"
    : !ready
      ? (problem ?? "Checking the pattern…")
      : draft.color === null && !draft.alert
        ? "Pick a colour, or turn the alert on"
        : draft.scope.kind === "session" && !draft.scope.sessionId
          ? "Pick the session"
          : busy
            ? "Saving…"
            : null;

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const saved = rule ? await api.updateTerminalRule(rule.id, draft) : await api.addTerminalRule(draft);
      onSaved(saved);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{rule ? "Edit the rule" : "New highlight or alert rule"}</DialogTitle>
          <DialogDescription>
            A regular expression, as in JavaScript: <code className="font-mono text-xs">\b</code>,{" "}
            <code className="font-mono text-xs">\d</code>, <code className="font-mono text-xs">[a-z]</code>,{" "}
            <code className="font-mono text-xs">(?:a|b)</code>, <code className="font-mono text-xs">{"{2,5}"}</code>.
            Case is the switch below, never <code className="font-mono text-xs">(?i)</code>.
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (!blocked) void save();
          }}
        >
          <div className="grid gap-2">
            <Label htmlFor="rule-name">Name</Label>
            <Input
              id="rule-name"
              value={draft.name}
              maxLength={60}
              autoFocus
              onChange={(e) => set({ name: e.currentTarget.value })}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="rule-pattern">Pattern</Label>
            <Input
              id="rule-pattern"
              className="font-mono"
              spellCheck={false}
              autoComplete="off"
              maxLength={200}
              placeholder="\bOutOfMemoryError\b"
              value={draft.pattern}
              aria-invalid={problem !== null}
              onChange={(e) => set({ pattern: e.currentTarget.value })}
            />
            <p className={cn("text-xs", problem ? "text-destructive" : "text-muted-foreground")} role="status">
              {problem ??
                (ready ? "Looks good." : "Up to 200 characters. Matched on each line's first 2,000 characters.")}
            </p>
            <div className="flex items-center gap-3">
              <Switch
                id="rule-case"
                checked={draft.caseSensitive}
                onCheckedChange={(caseSensitive) => set({ caseSensitive })}
              />
              <Label htmlFor="rule-case" className="font-normal">
                Match case
              </Label>
            </div>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="rule-try">Try it on a line (optional)</Label>
            <Input
              id="rule-try"
              className="font-mono"
              spellCheck={false}
              autoComplete="off"
              placeholder="Paste a line of output"
              value={sample}
              onChange={(e) => setSample(e.currentTarget.value)}
            />
            {preview && (
              <p className="overflow-x-auto rounded-md border bg-muted/40 px-2 py-1 font-mono text-xs whitespace-pre">
                {preview.parts.map((part, i) =>
                  part.hit ? (
                    <span
                      key={i}
                      style={{ color: look.foreground, background: look.background ?? undefined }}
                      className="rounded-sm font-semibold"
                    >
                      {part.text}
                    </span>
                  ) : (
                    <span key={i}>{part.text}</span>
                  ),
                )}
                <span className="ml-2 font-sans text-muted-foreground">
                  {preview.count === 0 ? "no match" : preview.count === 1 ? "1 match" : `${preview.count} matches`}
                </span>
              </p>
            )}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label>Colour</Label>
              <ToggleGroup
                type="single"
                variant="outline"
                size="sm"
                className="flex-wrap justify-self-start"
                value={draft.color ?? NONE}
                onValueChange={(v) => v && set({ color: v === NONE ? null : (v as SessionColor) })}
              >
                <ToggleGroupItem value={NONE} aria-label="No colour: alert only" className="text-xs">
                  None
                </ToggleGroupItem>
                {SESSION_COLORS.map((c) => (
                  <ToggleGroupItem key={c} value={c} aria-label={c} title={c}>
                    <ColorDot color={c} className="size-3" />
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
            </div>
            <div className="grid gap-2">
              <Label>Style</Label>
              <ToggleGroup
                type="single"
                variant="outline"
                size="sm"
                className="justify-self-start"
                disabled={draft.color === null}
                value={draft.style}
                onValueChange={(v) => v && set({ style: v as RuleStyle })}
              >
                <ToggleGroupItem value="text" className="text-xs">
                  Text colour
                </ToggleGroupItem>
                <ToggleGroupItem value="fill" className="text-xs">
                  Fill
                </ToggleGroupItem>
              </ToggleGroup>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="rule-scope">Applies to</Label>
              <Select
                value={scopeChoice}
                onValueChange={(v) => {
                  if (v === "global") set({ scope: { kind: "global" } });
                  else if (v === "session") set({ scope: { kind: "session", sessionId: sorted[0]?.id ?? "" } });
                  else {
                    const environment = ENVIRONMENTS.find((e) => `env:${e.value}` === v)?.value;
                    if (environment) set({ scope: { kind: "environment", environment } });
                  }
                }}
              >
                <SelectTrigger id="rule-scope" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="global">Every terminal</SelectItem>
                  {ENVIRONMENTS.map((e) => (
                    <SelectItem key={e.value} value={`env:${e.value}`}>
                      {e.label}
                    </SelectItem>
                  ))}
                  <SelectItem value="session" disabled={sorted.length === 0}>
                    One session
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            {draft.scope.kind === "session" && (
              <div className="grid gap-2">
                <Label htmlFor="rule-session">Session</Label>
                <Select
                  value={draft.scope.sessionId}
                  onValueChange={(sessionId) => set({ scope: { kind: "session", sessionId } })}
                >
                  <SelectTrigger id="rule-session" className="w-full">
                    <SelectValue placeholder="Pick a session" />
                  </SelectTrigger>
                  <SelectContent>
                    {sorted.map((s) => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>
          <div className="grid gap-1">
            <div className="flex items-center gap-3">
              <Switch id="rule-alert" checked={draft.alert} onCheckedChange={(alert) => set({ alert })} />
              <Label htmlFor="rule-alert" className="font-normal">
                Alert: notify me when a line matches while its tab is in the background
              </Label>
            </div>
            <p className="pl-12 text-xs text-muted-foreground">
              Once for a burst of matching lines, with the first one; then this rule waits a minute in that terminal and
              counts what it misses. The bell in the terminal toolbar turns notifications off for one tab.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Switch id="rule-enabled" checked={draft.enabled} onCheckedChange={(enabled) => set({ enabled })} />
            <Label htmlFor="rule-enabled" className="font-normal">
              On
            </Label>
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              Cancel
            </Button>
            <WhyDisabled reason={blocked}>
              <Button type="submit" disabled={blocked !== null}>
                {rule ? "Save" : "Add the rule"}
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
