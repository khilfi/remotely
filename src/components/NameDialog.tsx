// Asks for one name: a tag to add (VM-02), a name to save a filter under, a folder or vault label to
// create or rename (SS-01, SS-04). Existing names are offered as one-click choices.

import { useState } from "react";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorMessage } from "@/lib/api";

interface Props {
  title: string;
  description: string;
  label: string;
  submitLabel: string;
  suggestions?: string[];
  /** The name to start from, e.g. when renaming. */
  initial?: string;
  maxLength?: number;
  /** Throws to keep the dialog open and show the error. */
  onSubmit: (name: string) => Promise<void>;
  onClose: () => void;
}

export function NameDialog({
  title,
  description,
  label,
  submitLabel,
  suggestions = [],
  initial = "",
  maxLength = 60,
  onSubmit,
  onClose,
}: Props) {
  const [name, setName] = useState(initial);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(value: string) {
    setBusy(true);
    setError(null);
    try {
      await onSubmit(value.trim());
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-md">
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim()) void submit(name);
          }}
        >
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="name-dialog-input">{label}</Label>
            <Input
              id="name-dialog-input"
              autoFocus
              autoComplete="off"
              maxLength={maxLength}
              value={name}
              onChange={(e) => setName(e.currentTarget.value)}
            />
          </div>
          {suggestions.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {suggestions.map((s) => (
                <Badge key={s} asChild variant="outline">
                  <button type="button" disabled={busy} onClick={() => void submit(s)}>
                    {s}
                  </button>
                </Badge>
              ))}
            </div>
          )}
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" disabled={!name.trim() || busy}>
              {submitLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
