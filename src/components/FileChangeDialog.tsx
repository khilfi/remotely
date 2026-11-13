// SS-14: the Files here drawer's questions before a file change: a name (new folder, new file, rename), a folder to
// move or copy into, permissions (octal, with what they mean), or an owner and group by number. The change itself goes
// through the command bus, which asks for approval at its tier (deleting needs no question here: its approval is the
// question). QL-08: the button says why it is off.

import { useState, type FormEvent } from "react";
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
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type FileChange } from "@/lib/api";
import { baseName, folderProblem, modeOctal, modeText, nameProblem, parseId, parseMode } from "@/lib/file-ops";
import { plural } from "@/lib/format";

/** What the dialog asks about. */
export type FileAsk =
  | { kind: "newFolder" | "newFile"; folder: string }
  | { kind: "rename"; path: string }
  | { kind: "move" | "copy"; paths: string[]; folder: string }
  | { kind: "mode"; paths: string[]; mode: number | null }
  | { kind: "owner"; paths: string[]; uid: number | null; gid: number | null };

interface Props {
  ask: FileAsk;
  /** Root browsing: what changes, changes as root. */
  asRoot: boolean;
  /** Throws to keep the dialog open and show the error. */
  onSubmit: (change: FileChange) => Promise<void>;
  onClose: () => void;
}

function what(paths: string[]) {
  return paths.length === 1 ? `'${baseName(paths[0])}'` : plural(paths.length, "item");
}

function initial(ask: FileAsk): string {
  switch (ask.kind) {
    case "rename":
      return baseName(ask.path);
    case "move":
    case "copy":
      return ask.folder;
    case "mode":
      return ask.mode === null ? "" : modeOctal(ask.mode).replace(/^0/, "");
    case "owner":
      return ask.uid === null ? "" : String(ask.uid);
    default:
      return "";
  }
}

export function FileChangeDialog({ ask, asRoot, onSubmit, onClose }: Props) {
  const [text, setText] = useState(initial(ask));
  const [group, setGroup] = useState(ask.kind === "owner" && ask.gid !== null ? String(ask.gid) : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  let title: string;
  let label: string;
  let action: string;
  let problem: string | null;
  let change: FileChange | null = null;
  switch (ask.kind) {
    case "newFolder":
    case "newFile":
      title = ask.kind === "newFolder" ? "New folder" : "New empty file";
      label = "Name";
      action = "Make";
      problem = nameProblem(text);
      if (!problem) change = { kind: ask.kind, folder: ask.folder, name: text };
      break;
    case "rename":
      title = `Rename '${baseName(ask.path)}'`;
      label = "New name";
      action = "Rename";
      problem = nameProblem(text) ?? (text === baseName(ask.path) ? "That is its name already" : null);
      if (!problem) change = { kind: "rename", path: ask.path, name: text };
      break;
    case "move":
    case "copy":
      title = `${ask.kind === "move" ? "Move" : "Copy"} ${what(ask.paths)}`;
      label = "Into the folder";
      action = ask.kind === "move" ? "Move" : "Copy";
      problem = folderProblem(text);
      if (!problem) change = { kind: ask.kind, paths: ask.paths, into: text };
      break;
    case "mode": {
      title = `Permissions of ${what(ask.paths)}`;
      label = "Mode (octal, as chmod takes it)";
      action = "Set";
      const mode = parseMode(text);
      problem = mode === null ? "Type 3 or 4 octal digits, such as 644 or 0755" : null;
      if (mode !== null) change = { kind: "mode", paths: ask.paths, mode };
      break;
    }
    case "owner": {
      title = `Owner of ${what(ask.paths)}`;
      label = "Owner (user number)";
      action = "Set";
      const uid = parseId(text);
      const gid = parseId(group);
      problem =
        uid === "bad" || gid === "bad"
          ? "Type numbers (the host's uid and gid)"
          : uid === null && gid === null
            ? "Type an owner, a group or both"
            : null;
      if (!problem && uid !== "bad" && gid !== "bad") change = { kind: "owner", paths: ask.paths, uid, gid };
      break;
    }
  }

  async function submit(ev: FormEvent) {
    ev.preventDefault();
    if (!change) return;
    setBusy(true);
    setError(null);
    try {
      await onSubmit(change);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  const parsed = ask.kind === "mode" ? parseMode(text) : null;
  const where =
    ask.kind === "newFolder" || ask.kind === "newFile" ? ask.folder : ask.kind === "rename" ? ask.path : null;
  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>
              {where && <code className="font-mono text-xs break-all">{where}</code>}
              {where && " · "}
              {asRoot ? <span className="text-tier-high">as root</span> : "as the logged-in user"}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5">
            <Label htmlFor="file-change-value">{label}</Label>
            <Input
              id="file-change-value"
              autoFocus
              value={text}
              onChange={(e) => setText(e.target.value)}
              spellCheck={false}
              className={ask.kind === "move" || ask.kind === "copy" || ask.kind === "mode" ? "font-mono" : undefined}
            />
            {parsed !== null && <p className="font-mono text-xs text-muted-foreground">{modeText(parsed)}</p>}
          </div>
          {ask.kind === "owner" && (
            <div className="grid gap-1.5">
              <Label htmlFor="file-change-group">Group (group number)</Label>
              <Input
                id="file-change-group"
                value={group}
                onChange={(e) => setGroup(e.target.value)}
                spellCheck={false}
              />
            </div>
          )}
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              Cancel
            </Button>
            <WhyDisabled reason={busy ? null : problem}>
              <Button type="submit" disabled={busy || change === null}>
                {action}
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
