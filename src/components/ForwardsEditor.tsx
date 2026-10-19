// SS-07: a session's saved port forwards, in the session dialog. Each is local (a port on this PC to a host the
// session's host reaches), remote (a port on the host back to a host this PC reaches) or SOCKS, listens on loopback
// unless another address is typed (which the approval then calls out), and may start with the terminal. Nothing opens
// here: a terminal opens them through the approval flow.

import { PlusIcon, Trash2Icon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { WhyDisabled } from "@/components/WhyDisabled";
import type { ForwardInput, ForwardKind } from "@/lib/api";
import {
  clashes,
  defaultBind,
  exposureText,
  FORWARD_KINDS,
  forwardProblem,
  isLoopback,
  MAX_FORWARDS,
  newForward,
} from "@/lib/tunnels";
import { cn } from "@/lib/utils";

function portValue(text: string): number {
  const n = Number(text.trim() || "0");
  return Number.isFinite(n) ? n : -1;
}

export function ForwardsEditor({
  forwards,
  onChange,
  disabled,
}: {
  forwards: ForwardInput[];
  onChange: (forwards: ForwardInput[]) => void;
  disabled?: boolean;
}) {
  const clash = clashes(forwards);
  const set = (i: number, change: Partial<ForwardInput>) =>
    onChange(forwards.map((f, at) => (at === i ? { ...f, ...change } : f)));
  const full = forwards.length >= MAX_FORWARDS;
  return (
    <div className="grid gap-2">
      {forwards.length === 0 && (
        <p className="text-sm text-muted-foreground">
          None. A forward reaches a port through this session&apos;s connection, like ssh -L, -R or -D.
        </p>
      )}
      {forwards.map((f, i) => {
        const problem = forwardProblem(f);
        const bind = f.bindAddress.trim() || defaultBind(f.kind);
        const shared = !isLoopback(bind);
        const kind = FORWARD_KINDS.find((k) => k.kind === f.kind);
        return (
          <div key={f.id ?? `new-${i}`} className="grid gap-2 rounded-md border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Select
                value={f.kind}
                disabled={disabled}
                onValueChange={(v) => {
                  const next = v as ForwardKind;
                  set(i, next === "dynamic" ? { kind: next, destHost: "", destPort: 0 } : { kind: next });
                }}
              >
                <SelectTrigger size="sm" className="w-28" aria-label={`Port forward ${i + 1}: kind`} title={kind?.hint}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {FORWARD_KINDS.map((k) => (
                    <SelectItem key={k.kind} value={k.kind} title={k.hint}>
                      {k.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Input
                className="h-8 w-40"
                maxLength={60}
                placeholder="Name (optional)"
                aria-label={`Port forward ${i + 1}: name`}
                value={f.label ?? ""}
                disabled={disabled}
                onChange={(e) => set(i, { label: e.currentTarget.value || null })}
              />
              <Label className="ml-auto flex items-center gap-2 text-sm font-normal">
                <Switch
                  checked={f.autoStart}
                  disabled={disabled}
                  onCheckedChange={(on) => set(i, { autoStart: on })}
                  aria-label={`Port forward ${i + 1}: starts with the terminal`}
                />
                Starts with the terminal
              </Label>
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label={`Remove port forward ${i + 1}`}
                disabled={disabled}
                onClick={() => onChange(forwards.filter((_, at) => at !== i))}
              >
                <Trash2Icon />
              </Button>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="text-muted-foreground">{f.kind === "remote" ? "Host listens on" : "Listen on"}</span>
              <Input
                className="h-8 w-32 font-mono text-xs"
                spellCheck={false}
                placeholder={defaultBind(f.kind)}
                data-mask="host"
                aria-label={`Port forward ${i + 1}: listen address`}
                value={f.bindAddress}
                disabled={disabled}
                onChange={(e) => set(i, { bindAddress: e.currentTarget.value })}
              />
              <span>:</span>
              <Input
                className="h-8 w-16 font-mono text-xs"
                inputMode="numeric"
                aria-label={`Port forward ${i + 1}: listen port (0 for any)`}
                title="0: any free port, shown once it listens"
                value={String(f.bindPort)}
                disabled={disabled}
                aria-invalid={clash.has(i) || undefined}
                onChange={(e) => set(i, { bindPort: portValue(e.currentTarget.value) })}
              />
              {f.kind !== "dynamic" && (
                <>
                  <span className="text-muted-foreground">→</span>
                  <Input
                    className="h-8 min-w-28 flex-1 font-mono text-xs"
                    spellCheck={false}
                    placeholder={f.kind === "remote" ? "127.0.0.1 (from this PC)" : "db01.example.com (from the host)"}
                    data-mask="host"
                    aria-label={`Port forward ${i + 1}: where it leads`}
                    value={f.destHost}
                    disabled={disabled}
                    onChange={(e) => set(i, { destHost: e.currentTarget.value })}
                  />
                  <span>:</span>
                  <Input
                    className="h-8 w-16 font-mono text-xs"
                    inputMode="numeric"
                    aria-label={`Port forward ${i + 1}: port it leads to`}
                    value={f.destPort === 0 ? "" : String(f.destPort)}
                    disabled={disabled}
                    onChange={(e) => set(i, { destPort: portValue(e.currentTarget.value) })}
                  />
                </>
              )}
            </div>
            <p className={cn("text-xs", shared ? "text-tier-medium" : "text-muted-foreground")}>
              {kind?.hint}. {exposureText(f)}
            </p>
            {(problem || clash.has(i)) && (
              <p className="text-xs text-destructive" role="alert">
                {problem ?? "Another forward listens on this port too."}
              </p>
            )}
          </div>
        );
      })}
      <WhyDisabled reason={full ? `A session keeps at most ${MAX_FORWARDS} port forwards.` : null}>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="justify-self-start"
          disabled={disabled || full}
          onClick={() => onChange([...forwards, newForward()])}
        >
          <PlusIcon data-icon="inline-start" />
          Add a port forward
        </Button>
      </WhyDisabled>
    </div>
  );
}
