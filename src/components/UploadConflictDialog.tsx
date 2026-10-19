// SS-08: "ask before overwriting". Files picked or dropped for upload that are in the host folder already: replace
// them (the upload then needs the approval dialog's confirm, at least), skip them, or upload nothing.

import { useState } from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { errorMessage, type Existing } from "@/lib/api";
import { plural } from "@/lib/format";

interface Props {
  folder: string;
  /** The names already there. */
  existing: string[];
  /** How many files were picked in all. */
  total: number;
  terminal: string;
  /** Throws to keep the dialog open and show the error. */
  onAnswer: (answer: Exclude<Existing, "ask">) => Promise<void>;
  onCancel: () => void;
}

export function UploadConflictDialog({ folder, existing, total, terminal, onAnswer, onCancel }: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const others = total - existing.length;

  async function answer(choice: Exclude<Existing, "ask">) {
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
                {existing.length === 1 ? "A file with this name is" : "Files with these names are"} in{" "}
                <code className="font-mono text-xs">{folder}</code> on {terminal}. Replacing loses what is there now, so
                it asks for your approval next.
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
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          {others > 0 && (
            <Button variant="outline" disabled={busy} onClick={() => void answer("skip")}>
              Skip {existing.length === 1 ? "it" : "them"}, upload {plural(others, "other file")}
            </Button>
          )}
          <AlertDialogAction
            variant="destructive"
            disabled={busy}
            onClick={(e) => {
              e.preventDefault();
              void answer("replace");
            }}
          >
            Replace…
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
