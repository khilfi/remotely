// BX-08: adds or edits a favourite command: its folder (one level, picked from the existing ones or typed), name,
// command and an optional description. `{{name}}` or `{{name:default}}` in the command is asked when it is pasted;
// what the policy engine makes of the command shows as it is typed. Saved in the core and audited (name and folder,
// never the command).

import { useEffect, useId, useState } from "react";
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
import { Textarea } from "@/components/ui/textarea";
import { RiskBadge } from "@/components/Badges";
import { api, errorMessage, type CommandInfo, type Favourite, type FavouriteInput } from "@/lib/api";

interface Props {
  /** Edit this one; without it, add a new favourite from `initial`. */
  existing?: Favourite;
  initial?: Partial<FavouriteInput>;
  /** Existing folder names, offered while typing. */
  folders: string[];
  onSaved: (favourite: Favourite) => void;
  onClose: () => void;
}

export function FavouriteDialog({ existing, initial, folders, onSaved, onClose }: Props) {
  const [folder, setFolder] = useState(existing?.folder ?? initial?.folder ?? "");
  const [name, setName] = useState(existing?.name ?? initial?.name ?? "");
  const [command, setCommand] = useState(existing?.command ?? initial?.command ?? "");
  const [description, setDescription] = useState(existing?.description ?? initial?.description ?? "");
  const [info, setInfo] = useState<CommandInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const listId = useId();

  // What the command asks for and how it classifies, as it is typed.
  useEffect(() => {
    if (!command.trim()) return;
    const timer = window.setTimeout(() => {
      api.commandInspect(command).then(setInfo, () => setInfo(null));
    }, 200);
    return () => window.clearTimeout(timer);
  }, [command]);
  const shown = command.trim() ? info : null;

  async function save() {
    setBusy(true);
    setError(null);
    const input: FavouriteInput = {
      folder: folder.trim() || null,
      name,
      command,
      description: description.trim() || null,
    };
    try {
      const saved = existing ? await api.updateFavourite(existing.id, input) : await api.addFavourite(input);
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
          <DialogTitle>{existing ? "Edit the favourite" : "New favourite command"}</DialogTitle>
          <DialogDescription>
            Click it in the command panel to paste it into the current terminal; Shift+click also presses Enter. Write{" "}
            <code className="font-mono text-xs">{"{{name}}"}</code> or{" "}
            <code className="font-mono text-xs">{"{{name:default}}"}</code> for a value to ask each time.
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="favourite-name">Name</Label>
              <Input
                id="favourite-name"
                value={name}
                maxLength={80}
                autoFocus
                onChange={(e) => setName(e.currentTarget.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="favourite-folder">Folder (optional)</Label>
              <Input
                id="favourite-folder"
                value={folder}
                maxLength={60}
                list={listId}
                placeholder="None"
                onChange={(e) => setFolder(e.currentTarget.value)}
              />
              <datalist id={listId}>
                {folders.map((f) => (
                  <option key={f} value={f} />
                ))}
              </datalist>
            </div>
          </div>
          <div className="grid gap-2">
            <div className="flex items-center justify-between gap-2">
              <Label htmlFor="favourite-command">Command</Label>
              {shown && <RiskBadge risk={shown.risk} />}
            </div>
            <Textarea
              id="favourite-command"
              className="max-h-64 min-h-20 font-mono text-sm"
              spellCheck={false}
              value={command}
              onChange={(e) => setCommand(e.currentTarget.value)}
            />
            <p className="text-xs text-muted-foreground">
              {shown && shown.variables.length > 0
                ? `Asks for ${shown.variables.map((v) => (v.default ? `${v.name} (default ${v.default})` : v.name)).join(", ")} when pasted.`
                : "Several lines are pasted together; most shells wait for Enter before running them."}
              {shown &&
                shown.risk.dangerous.length > 0 &&
                ` Matches the dangerous rule ${shown.risk.dangerous.join(", ")}.`}
            </p>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="favourite-description">Description (optional)</Label>
            <Input
              id="favourite-description"
              value={description}
              maxLength={500}
              onChange={(e) => setDescription(e.currentTarget.value)}
            />
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
            <Button type="submit" disabled={busy || !name.trim() || !command.trim()}>
              {existing ? "Save" : "Add to favourites"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
