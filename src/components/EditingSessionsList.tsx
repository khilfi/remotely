// SS-08 (0.8.0 G4): the files being edited on this PC, in Files here: each with its host, where it stands and how many
// saves went up, and Stop editing. Many editors run as one window, so closing the editor never ends a session: Stop
// editing does (the last save goes up first, then this PC's copy is deleted), or 4 hours, the terminal closing or
// another workspace. When the host's copy changed since it was opened, a save waits here for an answer: overwrite it,
// save yours beside it, compare the two, or keep editing. A save that didn't go up is never deleted: Stop editing asks
// first (keep it on this PC, upload again, or discard it), and every other end keeps the copy, listed here as not
// uploaded until it is saved elsewhere or discarded. Shows nothing while no file is edited or kept.

import { useEffect, useState } from "react";
import { CircleAlertIcon, FilePenLineIcon, LoaderIcon, ShieldIcon } from "lucide-react";
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { HelpTip } from "@/components/HelpTip";
import { errorMessage } from "@/lib/api";
import { applyEdit, editStateText, endsInText, fileName, savesText, stopChoices } from "@/lib/editing";
import { editingApi, type EditAnswer, type EditInfo, type StopChoice } from "@/lib/editing-api";
import { cn } from "@/lib/utils";

// Compare is the one primary: overwriting loses what changed on the host.
const ANSWERS: { answer: EditAnswer; label: string; primary?: boolean }[] = [
  { answer: "compare", label: "Compare", primary: true },
  { answer: "saveBeside", label: "Save beside it" },
  { answer: "overwrite", label: "Overwrite" },
  { answer: "keepEditing", label: "Keep editing" },
];

/** Stop editing's question: the session, why its last save is still here, and whether the host's copy changed. */
interface Unsent {
  edit: EditInfo;
  message: string;
  conflict: boolean;
}

export function EditingSessionsList() {
  const [edits, setEdits] = useState<EditInfo[]>([]);
  const [now, setNow] = useState(() => Date.now());
  const [unsent, setUnsent] = useState<Unsent | null>(null);
  const [busy, setBusy] = useState(false);
  const [discarding, setDiscarding] = useState<EditInfo | null>(null);

  useEffect(() => {
    let live = true;
    const unlisten = editingApi.onEdit((edit) => setEdits((list) => applyEdit(list, edit)));
    editingApi.edits().then(
      (list) => live && setEdits(list),
      () => undefined,
    );
    const clock = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => {
      live = false;
      window.clearInterval(clock);
      void unlisten.then((stop) => stop());
    };
  }, []);

  if (edits.length === 0) return null;

  async function act(what: () => Promise<unknown>) {
    try {
      await what();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  /** Stop editing, or Stop's answer: a save that didn't go up asks (again) instead of stopping. */
  async function stop(edit: EditInfo, choice: StopChoice | null) {
    setBusy(true);
    try {
      const outcome = await editingApi.stop(edit.id, choice);
      setUnsent(outcome.outcome === "unsent" ? { edit, message: outcome.message, conflict: outcome.conflict } : null);
    } catch (err) {
      toast.error(errorMessage(err));
      setUnsent(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="flex min-h-0 flex-col gap-1" aria-label="Edited on this PC">
      <div className="flex items-center gap-1">
        <h3 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">Edited on this PC</h3>
        <HelpTip topic="filesEditing" />
      </div>
      <ul className="min-h-0 divide-y overflow-auto rounded-md border">
        {edits.map((e) => {
          const state = editStateText(e.state);
          const kept = e.state.state === "kept";
          return (
            <li key={e.id} className="grid gap-1 px-2 py-1.5 text-xs">
              <div className="flex min-w-0 items-center gap-1.5">
                <FilePenLineIcon className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                <span className="truncate font-medium" title={e.path}>
                  {fileName(e.path)}
                </span>
                {e.asRoot && (
                  <Badge variant="outline" className="shrink-0 border-tier-high/50 font-normal text-tier-high">
                    <ShieldIcon aria-hidden />
                    as root
                  </Badge>
                )}
                {kept && (
                  <Badge variant="outline" className="shrink-0 border-tier-medium/50 font-normal text-tier-medium">
                    Not uploaded
                  </Badge>
                )}
                <span className="truncate text-muted-foreground">on {e.name}</span>
                {!kept && (
                  <Button
                    size="xs"
                    variant="ghost"
                    className="ml-auto shrink-0"
                    disabled={busy}
                    onClick={() => void stop(e, null)}
                  >
                    Stop editing
                  </Button>
                )}
              </div>
              <p
                className={cn(
                  "flex items-center gap-1",
                  state.tone === "muted" && "text-muted-foreground",
                  state.tone === "warn" && "text-tier-medium",
                  state.tone === "error" && "text-destructive",
                )}
              >
                {state.tone === "busy" && <LoaderIcon className="size-3 animate-spin" aria-hidden />}
                {(state.tone === "warn" || state.tone === "error") && (
                  <CircleAlertIcon className="size-3 shrink-0" aria-hidden />
                )}
                <span className="min-w-0 break-words">{state.text}</span>
                {!kept && (
                  <span className="ml-auto shrink-0 text-muted-foreground">
                    {savesText(e.saves)} · in {e.editor} · {endsInText(e.endsAt, now)}
                  </span>
                )}
              </p>
              {e.note && <p className="text-muted-foreground">{e.note}</p>}
              {e.state.state === "conflict" && (
                <div role="alert" className="grid gap-1 rounded-md border border-tier-medium/40 p-1.5">
                  <p>{e.state.message}</p>
                  <div className="flex flex-wrap gap-1">
                    {ANSWERS.map((a) => (
                      <Button
                        key={a.answer}
                        size="xs"
                        variant={a.primary ? "default" : "outline"}
                        onClick={() => void act(() => editingApi.answer(e.id, a.answer))}
                      >
                        {a.label}
                      </Button>
                    ))}
                  </div>
                </div>
              )}
              {e.state.state === "failed" && (
                <div>
                  <Button size="xs" variant="outline" onClick={() => void act(() => editingApi.answer(e.id, null))}>
                    Try again
                  </Button>
                </div>
              )}
              {kept && (
                <div className="flex flex-wrap gap-1">
                  <Button
                    size="xs"
                    variant="outline"
                    onClick={() =>
                      void act(async () => {
                        if (await editingApi.keptSave(e.id)) toast.success(`Saved ${fileName(e.path)}`);
                      })
                    }
                  >
                    Save as…
                  </Button>
                  <Button size="xs" variant="ghost" onClick={() => void act(() => editingApi.keptOpen(e.id))}>
                    Open
                  </Button>
                  <Button size="xs" variant="ghost" onClick={() => setDiscarding(e)}>
                    Discard
                  </Button>
                </div>
              )}
            </li>
          );
        })}
      </ul>
      {unsent && (
        <AlertDialog open onOpenChange={(open) => !open && !busy && setUnsent(null)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>The last save of {fileName(unsent.edit.path)} didn't go up</AlertDialogTitle>
              <AlertDialogDescription>{unsent.message}</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel disabled={busy}>Go back</AlertDialogCancel>
              {stopChoices(unsent.conflict).map((c, i) => (
                <Button
                  key={c.choice}
                  variant={i === 0 ? "default" : c.choice === "discard" ? "destructive" : "outline"}
                  disabled={busy}
                  onClick={() => void stop(unsent.edit, c.choice)}
                >
                  {c.label}
                </Button>
              ))}
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      )}
      {discarding && (
        <ConfirmDialog
          title={`Discard the edited copy of ${fileName(discarding.path)}?`}
          description="Its last save never went up to the host, so what you changed is gone once it is discarded."
          confirmLabel="Discard"
          onConfirm={() => editingApi.keptDiscard(discarding.id)}
          onClose={() => setDiscarding(null)}
        />
      )}
    </section>
  );
}
