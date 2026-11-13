// SS-08 (0.8.0 G4): the files being edited on this PC, in Files here: each with its host, where it stands and how many
// saves went up, and Stop editing. Many editors run as one window, so closing the editor never ends a session: Stop
// editing does (the last save goes up first, then this PC's copy is deleted), or 4 hours, a vault lock, the terminal
// closing or another workspace. When the host's copy changed since it was opened, a save waits here for an answer:
// overwrite it, save yours beside it, compare the two, or keep editing. Shows nothing while no file is edited.

import { useEffect, useState } from "react";
import { CircleAlertIcon, FilePenLineIcon, LoaderIcon, ShieldIcon } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { HelpTip } from "@/components/HelpTip";
import { errorMessage } from "@/lib/api";
import { applyEdit, editStateText, endsInText, fileName, savesText } from "@/lib/editing";
import { editingApi, type EditAnswer, type EditInfo } from "@/lib/editing-api";
import { cn } from "@/lib/utils";

// Compare is the one primary: overwriting loses what changed on the host.
const ANSWERS: { answer: EditAnswer; label: string; primary?: boolean }[] = [
  { answer: "compare", label: "Compare", primary: true },
  { answer: "saveBeside", label: "Save beside it" },
  { answer: "overwrite", label: "Overwrite" },
  { answer: "keepEditing", label: "Keep editing" },
];

export function EditingSessionsList() {
  const [edits, setEdits] = useState<EditInfo[]>([]);
  const [now, setNow] = useState(() => Date.now());

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

  async function act(what: () => Promise<void>) {
    try {
      await what();
    } catch (err) {
      toast.error(errorMessage(err));
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
                <span className="truncate text-muted-foreground">on {e.name}</span>
                <Button
                  size="xs"
                  variant="ghost"
                  className="ml-auto shrink-0"
                  onClick={() => void act(() => editingApi.stop(e.id))}
                >
                  Stop editing
                </Button>
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
                <span className="ml-auto shrink-0 text-muted-foreground">
                  {savesText(e.saves)} · in {e.editor} · {endsInText(e.endsAt, now)}
                </span>
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
            </li>
          );
        })}
      </ul>
    </section>
  );
}
