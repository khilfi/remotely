// QL-30 (0.9.0 H6): files dropped on a terminal while Type in all tabs is on, with more than one tab picked. A small
// menu at the drop point asks: "Upload to <tab>'s folder" (the default, taken by Enter: the drop's upload as it is
// without typing, lib/drop-target.ts terminalPageDrop) or "Push to the N picked hosts…", which opens DropPushDialog.
// Esc or a click away uploads nothing (the page unstages the files).
//
// The push is one BX-10 job: `files_push` with the drop's staged id and the picked tabs' terminals as
// `TargetPicks.terminal_ids`, into one folder filled in with the tab's own folder. Its approval names every host and
// rates it as Many hosts' push (Medium, High from 5 hosts, a Prod host one higher, protected hosts skipped). Quick
// connections have no saved session, so the menu says how many it leaves out, and the push is off with the reason when
// no picked tab is a saved SSH session.

import { useEffect, useRef, useState, type FormEvent } from "react";
import { FolderUpIcon, UploadIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ReasonLine, WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type ResolvedTargets, type StagedFiles } from "@/lib/api";
import { pushLabel, pushLeftOut, pushReason, type DropPush, type PushNotice } from "@/lib/drop-target";
import { folderProblem } from "@/lib/file-ops";
import { filesPageApi, type BulkFilesStart } from "@/lib/files-page-api";
import { plural } from "@/lib/format";
import { requestLink } from "@/lib/links";
import { toast } from "sonner";

/** QL-30: the push's notice, in place of the app's own toast for its job (the same id), leading to its results. */
export function showPushNotice(jobId: string, notice: PushNotice) {
  const options = {
    id: jobId,
    description: notice.description,
    duration: 10000,
    action: { label: "Show results", onClick: () => requestLink({ kind: "job", jobId }) },
  };
  if (notice.ok) toast.success(notice.title, options);
  else toast.warning(notice.title, options);
}

/** A drop that asks, where it fell (CSS pixels), what it holds, the tab under it and the push it offers. */
export interface DropAsk {
  x: number;
  y: number;
  staged: StagedFiles;
  /** The tab under the drop, by name. */
  tabName: string;
  /** The folder its upload goes into; null: its home folder. */
  folder: string | null;
  push: DropPush;
}

/** "'app.conf'", or "3 items": what was dropped. */
export function droppedWhat(staged: StagedFiles): string {
  return staged.files.length === 1 ? `'${staged.files[0].name}'` : plural(staged.files.length, "item");
}

interface MenuProps {
  ask: DropAsk;
  /** The default: the drop's upload, unchanged. */
  onUpload: () => void;
  onPush: () => void;
  /** Esc or a click away: nothing is uploaded. */
  onDismiss: () => void;
  /** The menu closed other than for the push (whose dialog takes the focus): back to the terminal. */
  onRefocus: () => void;
}

export function DropChoiceMenu({ ask, onUpload, onPush, onDismiss, onRefocus }: MenuProps) {
  const chosen = useRef(false);
  const pushing = useRef(false);
  const uploadItem = useRef<HTMLDivElement>(null);
  const why = pushReason(ask.push, ask.staged);
  const leftOut = pushLeftOut(ask.push);
  // Enter takes the upload: it has the focus once the menu is open.
  useEffect(() => {
    const frame = window.requestAnimationFrame(() => uploadItem.current?.focus());
    return () => window.cancelAnimationFrame(frame);
  }, []);

  function choose(then: () => void) {
    chosen.current = true;
    then();
  }

  return (
    <DropdownMenu
      open
      onOpenChange={(open) => {
        if (!open && !chosen.current) {
          chosen.current = true;
          onDismiss();
        }
      }}
    >
      <DropdownMenuTrigger asChild>
        <span aria-hidden className="pointer-events-none fixed size-0" style={{ left: ask.x, top: ask.y }} />
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="start"
        className="w-80"
        aria-label={`Where ${droppedWhat(ask.staged)} goes`}
        onCloseAutoFocus={(e) => {
          e.preventDefault();
          if (!pushing.current) onRefocus();
        }}
        onKeyDown={(e) => {
          // Nothing focused yet (the frame above hasn't run): Enter is still the upload.
          if (e.key === "Enter" && e.target === e.currentTarget) {
            e.preventDefault();
            choose(onUpload);
          }
        }}
      >
        <DropdownMenuLabel className="truncate">{droppedWhat(ask.staged)} dropped</DropdownMenuLabel>
        <DropdownMenuItem ref={uploadItem} onSelect={() => choose(onUpload)}>
          <UploadIcon />
          <span className="min-w-0">
            <span className="block truncate">Upload to {ask.tabName}'s folder</span>
            <span className="block truncate font-mono text-xs text-muted-foreground">
              {ask.folder ?? "its home folder"}
            </span>
          </span>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <WhyDisabled reason={why} className="flex w-full">
          <DropdownMenuItem
            className="w-full"
            disabled={why !== null}
            onSelect={() => {
              pushing.current = true;
              choose(onPush);
            }}
          >
            <FolderUpIcon />
            <span className="min-w-0">
              <span className="block">{pushLabel(ask.push)}</span>
              <ReasonLine reason={why ?? leftOut} />
            </span>
          </DropdownMenuItem>
        </WhyDisabled>
        {/* How many it leaves out, said also while the push is off for another reason. */}
        {why !== null && leftOut && <p className="px-2 pb-1.5 text-xs text-muted-foreground">{leftOut}</p>}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

interface DialogProps {
  ask: DropAsk;
  /** The tab's folder, filled in (its home folder when its shell doesn't say). */
  folder: string;
  /** The push went to the bus: the page follows its approval and job. */
  onPushed: (started: BulkFilesStart, folder: string) => void;
  /** Cancelled, or the push was refused: nothing is pushed (the page unstages the files). */
  onClose: (error?: string) => void;
}

export function DropPushDialog({ ask, folder: initial, onPushed, onClose }: DialogProps) {
  const [folder, setFolder] = useState(initial);
  const [replace, setReplace] = useState(false);
  const [busy, setBusy] = useState(false);
  const [resolved, setResolved] = useState<ResolvedTargets | null>(null);
  const terminalIds = ask.push.terminalIds;

  // Who gets the files, as the core resolves the picked terminals (the approval names them again).
  useEffect(() => {
    let stale = false;
    api.bulkTargets({ terminalIds }).then(
      (r) => !stale && setResolved(r),
      () => undefined,
    );
    return () => {
      stale = true;
    };
  }, [terminalIds]);

  const into = folder.trim();
  const problem = folderProblem(into);
  const hosts = resolved?.hosts ?? [];
  const reached = hosts.filter((h) => !h.protected);
  const count = resolved ? reached.length : ask.push.hosts;
  // One line: who gets the files, who is skipped, who is left out.
  const line = [
    reached.length > 0 ? `To ${reached.map((h) => h.name).join(", ")}` : "To the picked hosts",
    hosts.length > reached.length ? `${plural(hosts.length - reached.length, "protected host")} skipped` : null,
    pushLeftOut(ask.push),
  ]
    .filter((part): part is string => part !== null)
    .join(". ");

  async function submit(ev: FormEvent) {
    ev.preventDefault();
    if (problem) return;
    setBusy(true);
    try {
      // The staged files are the core's from here, whatever the push's answer.
      const started = await filesPageApi.push(
        { terminalIds },
        { kind: "staged", id: ask.staged.id },
        into,
        replace,
        false,
      );
      onPushed(started, into);
    } catch (err) {
      onClose(errorMessage(err));
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>
              Push {droppedWhat(ask.staged)} to {plural(count, "host")}
            </DialogTitle>
            <DialogDescription>{line}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5">
            <Label htmlFor="drop-push-folder">Into this folder on each host</Label>
            <Input
              id="drop-push-folder"
              autoFocus
              className="font-mono"
              value={folder}
              onChange={(e) => setFolder(e.target.value)}
              spellCheck={false}
            />
          </div>
          <div className="flex items-center gap-2">
            <Checkbox id="drop-push-replace" checked={replace} onCheckedChange={(v) => setReplace(v === true)} />
            <Label htmlFor="drop-push-replace" className="font-normal">
              Replace files of the same name there
            </Label>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={() => onClose()}>
              Cancel
            </Button>
            <WhyDisabled reason={busy ? null : problem}>
              <Button type="submit" disabled={busy || problem !== null}>
                Push to {plural(count, "host")}…
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
