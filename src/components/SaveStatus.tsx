// UX-10: Settings' one save model. A change saves at once: a switch or a choice when it changes, a number or a path
// when you press Enter or leave the field. The card then says so quietly in its header ("Saved", with Undo where it
// matters for a few seconds), or says why the core refused it. No card has a Save button; only the approval rules'
// Advanced editor keeps one (PolicyRulesEditor says why).
//
//   const status = useSaveStatus();
//   <CardAction><SaveStatus status={status} /></CardAction>
//   <Switch onCheckedChange={(on) => void status.run(() => api.setX(on))} />
//   <NumberSetting value={n} onCommit={(next) => status.run(() => api.setN(next), () => api.setN(n))} />

import { useCallback, useEffect, useState } from "react";
import { CheckIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";

type State =
  | { kind: "idle" }
  | { kind: "saving" }
  | { kind: "saved"; undo?: () => Promise<unknown>; undone?: boolean }
  | { kind: "error"; text: string };

/** How long "Saved" shows, and with an Undo. */
const SAVED_MS = 3000;
const UNDO_MS = 8000;

export interface SaveStatusHandle {
  state: State;
  /** Saves; on success says "Saved" (with Undo when `undo` is given). Resolves false when the core refused it. */
  run: (work: () => Promise<unknown>, undo?: () => Promise<unknown>) => Promise<boolean>;
  /** Undoes the last save, when it offered Undo. */
  undo: () => void;
  /** Forgets the last result (a new edit starts). */
  clear: () => void;
}

export function useSaveStatus(): SaveStatusHandle {
  const [state, setState] = useState<State>({ kind: "idle" });

  useEffect(() => {
    if (state.kind !== "saved") return;
    const timer = window.setTimeout(() => setState({ kind: "idle" }), state.undo ? UNDO_MS : SAVED_MS);
    return () => window.clearTimeout(timer);
  }, [state]);

  const run = useCallback(async (work: () => Promise<unknown>, undo?: () => Promise<unknown>) => {
    setState({ kind: "saving" });
    try {
      await work();
      setState({ kind: "saved", undo });
      return true;
    } catch (err) {
      setState({ kind: "error", text: errorMessage(err) });
      return false;
    }
  }, []);

  const undo = useCallback(() => {
    if (state.kind !== "saved" || !state.undo) return;
    const work = state.undo;
    setState({ kind: "saving" });
    work().then(
      () => setState({ kind: "saved", undone: true }),
      (err: unknown) => setState({ kind: "error", text: errorMessage(err) }),
    );
  }, [state]);

  const clear = useCallback(() => setState({ kind: "idle" }), []);
  return { state, run, undo, clear };
}

/** The quiet line in a card's header: "Saving…", "Saved · Undo", or why it wasn't saved. */
export function SaveStatus({ status, className }: { status: SaveStatusHandle; className?: string }) {
  const { state } = status;
  return (
    <div role="status" aria-live="polite" className={cn("flex min-h-7 items-center gap-1 text-sm", className)}>
      {state.kind === "saving" && <span className="text-muted-foreground">Saving…</span>}
      {state.kind === "saved" && (
        <>
          <CheckIcon className="size-3.5 text-success" aria-hidden />
          <span className="text-muted-foreground">{state.undone ? "Undone" : "Saved"}</span>
          {state.undo && (
            <Button type="button" variant="ghost" size="sm" className="h-7 px-2" onClick={status.undo}>
              Undo
            </Button>
          )}
        </>
      )}
      {state.kind === "error" && <span className="max-w-md text-destructive">{state.text}</span>}
    </div>
  );
}

/**
 * A number setting that saves when you press Enter or leave the field, and only when it changed. While it is being
 * typed the field keeps the text; once the value changes from outside (a save, an undo) it shows that.
 */
export function NumberSetting({
  id,
  label,
  value,
  min,
  max,
  suffix,
  disabled,
  onCommit,
}: {
  id: string;
  label: string;
  value: number | undefined;
  min: number;
  max: number;
  /** A word after the field ("seconds", "VMs"). */
  suffix?: string;
  disabled?: boolean;
  onCommit: (next: number) => void;
}) {
  const [draft, setDraft] = useState(value === undefined ? "" : String(value));
  const [shown, setShown] = useState(value);
  if (value !== shown) {
    setShown(value);
    setDraft(value === undefined ? "" : String(value));
  }
  function commit() {
    const text = draft.trim();
    const next = Number(text);
    if (value === undefined || text === "" || !Number.isFinite(next)) {
      setDraft(value === undefined ? "" : String(value));
      return;
    }
    if (next !== value) onCommit(next);
  }
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <div className="flex items-center gap-2">
        <Input
          id={id}
          type="number"
          inputMode="numeric"
          min={min}
          max={max}
          className="w-28"
          value={draft}
          disabled={disabled || value === undefined}
          onChange={(e) => setDraft(e.currentTarget.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              commit();
            }
            if (e.key === "Escape" && value !== undefined) setDraft(String(value));
          }}
        />
        {suffix && <span className="text-sm text-muted-foreground">{suffix}</span>}
      </div>
    </div>
  );
}
