// SS-08, SS-14: "ask before overwriting". Files picked or dropped for upload that are in the host folder already, or
// files downloaded that are in the folder on this PC: replace them (an upload then needs the approval dialog's confirm,
// at least), replace only those that are newer, keep both (the new ones get a number), skip them, or do nothing.

import { useState } from "react";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { errorMessage, type Existing } from "@/lib/api";
import { EXISTING_CHOICES, replaces } from "@/lib/file-ops";

interface Props {
  /** Where they are: the host folder, or the folder on this PC. */
  folder: string;
  /** The names already there. */
  existing: string[];
  /** How many files were picked in all. */
  total: number;
  terminal: string;
  /** SS-14: an upload (the host's files) or a download (this PC's). */
  direction?: "upload" | "download";
  /** Throws to keep the dialog open and show the error. */
  onAnswer: (answer: Exclude<Existing, "ask">) => Promise<void>;
  onCancel: () => void;
}

export function UploadConflictDialog({
  folder,
  existing,
  total,
  terminal,
  direction = "upload",
  onAnswer,
  onCancel,
}: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [choice, setChoice] = useState<Exclude<Existing, "ask">>("keepBoth");
  const others = total - existing.length;
  const upload = direction === "upload";

  async function answer() {
    setBusy(true);
    setError(null);
    try {
      await onAnswer(choice);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  const shown = existing.slice(0, 8);
  const where = upload ? (
    <>
      in <code className="font-mono text-xs">{folder}</code> on {terminal}
    </>
  ) : (
    <>
      in <code className="font-mono text-xs">{folder}</code> on this PC
    </>
  );
  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onCancel()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {existing.length === 1 ? `'${existing[0]}' is already there` : `${existing.length} files are already there`}
          </AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="grid gap-2">
              <p>
                {existing.length === 1 ? "A file with this name is" : "Files with these names are"} {where}.
                {upload && replaces(choice) && " Replacing loses what is there now, so it asks for your approval next."}
              </p>
              {existing.length > 1 && (
                <ul className="list-disc pl-5 font-mono text-xs">
                  {shown.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                  {existing.length > shown.length && <li>and {existing.length - shown.length} more</li>}
                </ul>
              )}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <RadioGroup
          value={choice}
          onValueChange={(v) => setChoice(v as Exclude<Existing, "ask">)}
          aria-label="What to do with them"
          className="gap-2"
        >
          {EXISTING_CHOICES.filter((c) => c.value !== "skip" || others > 0).map((c) => (
            <div key={c.value} className="flex items-start gap-2">
              <RadioGroupItem id={`existing-${c.value}`} value={c.value} className="mt-0.5" />
              <Label htmlFor={`existing-${c.value}`} className="grid gap-0.5 font-normal">
                <span>{existing.length === 1 ? c.label.replace("them", "it") : c.label}</span>
                <span className="text-xs text-muted-foreground">{c.hint}</span>
              </Label>
            </div>
          ))}
        </RadioGroup>
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button disabled={busy} onClick={() => void answer()}>
            {upload ? "Upload" : "Download"}
            {upload && replaces(choice) ? "…" : ""}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
