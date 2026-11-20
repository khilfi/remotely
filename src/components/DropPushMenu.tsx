// QL-30 (0.9.0 H6): files dropped on a terminal while Type in all tabs is on, with more than one tab picked and another
// host to push to. A small menu at the drop point asks: "Upload to <tab>'s folder" (the default: the drop's upload as it
// is without typing, lib/drop-target.ts terminalPageDrop) or "Push to the N picked hosts…", which opens
// DropPushDialog.
//
// The menu stays open while the window loses the focus (Radix would close it): it closes on a choice, Esc, or a click in
// Remotely away from it, and the page says when nothing was uploaded. Enter takes the upload, and the menu says so,
// only while Remotely has the keyboard: after a drop from Explorer the window may not have won the focus, and an Enter
// that reaches Explorer opens the files still selected there.
//
// The push is one BX-10 job: `files_push` with the drop's staged id and the picked tabs' terminals as
// `TargetPicks.terminal_ids`, into one folder filled in with the tab's own folder. Its approval names every host and
// rates it as Many hosts' push (Medium, High from 5 hosts, a Prod host one higher, protected hosts skipped). Quick
// connections have no saved session, so the menu says how many it leaves out. The push is off with its reason under
// the read-only lock, for dropped folders and past the core's 100 files, before its dialog takes the drop.

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
import { usePresentation } from "@/components/Presentation";
import { ReasonLine, WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type ResolvedTargets, type StagedFiles } from "@/lib/api";
import { READ_ONLY_REASON } from "@/lib/disabled-reasons";
import { pushLabel, pushLeftOut, pushReason, type DropPush, type PushNotice } from "@/lib/drop-target";
import { folderProblem } from "@/lib/file-ops";
import { filesPageApi, type BulkFilesStart } from "@/lib/files-page-api";
import { plural } from "@/lib/format";
import { requestLink } from "@/lib/links";
import { readOnlyLocked } from "@/lib/presentation-state";
import { toast } from "sonner";

/** Whether this window has the keyboard (`document.hasFocus()`), followed as it changes. */
function useWindowFocus(): boolean {
  const [focused, setFocused] = useState(() => document.hasFocus());
  useEffect(() => {
    const now = () => setFocused(document.hasFocus());
    window.addEventListener("focus", now);
    window.addEventListener("blur", now);
    // The focus the page asked for after a drop may arrive after the first render.
    const late = window.setTimeout(now, 300);
    return () => {
      window.removeEventListener("focus", now);
      window.removeEventListener("blur", now);
      window.clearTimeout(late);
    };
  }, []);
  return focused;
}

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
  /** Esc or a click in Remotely away from the menu: nothing is uploaded. */
  onDismiss: () => void;
  /** The menu closed other than for the push (whose dialog takes the focus): back to the terminal. */
  onRefocus: () => void;
}

export function DropChoiceMenu({ ask, onUpload, onPush, onDismiss, onRefocus }: MenuProps) {
  const presentation = usePresentation();
  const chosen = useRef(false);
  const pushing = useRef(false);
  /** Esc, or a click in the window away from the menu: the only ways it closes without a choice. */
  const leaving = useRef(false);
  const uploadItem = useRef<HTMLDivElement>(null);
  const focused = useWindowFocus();
  const why = pushReason(ask.push, ask.staged, readOnlyLocked(presentation) ? READ_ONLY_REASON : null);
  const leftOut = pushLeftOut(ask.push);
  // Enter takes the upload once Remotely has the keyboard: the upload item gets the focus then, once.
  const offered = useRef(false);
  useEffect(() => {
    if (!focused || offered.current) return;
    const frame = window.requestAnimationFrame(() => {
      offered.current = true;
      uploadItem.current?.focus();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [focused]);

  function choose(then: () => void) {
    chosen.current = true;
    then();
  }

  return (
    <DropdownMenu
      open
      onOpenChange={(open) => {
        // Radix also closes a menu when the window loses the focus (switching to Explorer, say): this one stays, so
        // the files wait for a choice.
        if (open || chosen.current || !leaving.current) return;
        chosen.current = true;
        onDismiss();
      }}
    >
      <DropdownMenuTrigger asChild>
        <span aria-hidden className="pointer-events-none fixed size-0" style={{ left: ask.x, top: ask.y }} />
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="start"
        className="w-80"
        aria-label={`Where ${droppedWhat(ask.staged)} goes`}
        onEscapeKeyDown={() => (leaving.current = true)}
        onPointerDownOutside={() => (leaving.current = true)}
        onCloseAutoFocus={(e) => {
          e.preventDefault();
          if (!pushing.current) onRefocus();
        }}
        onKeyDown={(e) => {
          // No item has the focus yet: Enter is still the upload, as long as it came to this window.
          if (e.key === "Enter" && e.target === e.currentTarget && document.hasFocus()) {
            e.preventDefault();
            choose(onUpload);
          }
        }}
      >
        <DropdownMenuLabel className="flex items-baseline justify-between gap-2">
          <span className="truncate">{droppedWhat(ask.staged)} dropped</span>
          <span className="shrink-0 text-xs font-normal text-muted-foreground">
            {focused ? "Enter uploads" : "Click a choice"}
          </span>
        </DropdownMenuLabel>
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
  /** The dialog closed: back to the terminal (an approval that follows takes the focus from there). */
  onRefocus: () => void;
}

export function DropPushDialog({ ask, folder: initial, onPushed, onClose, onRefocus }: DialogProps) {
  const presentation = usePresentation();
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
  // The read-only lock may have come on since the menu: refused here, before `files_push` takes the drop.
  const problem = readOnlyLocked(presentation) ? READ_ONLY_REASON : folderProblem(into);
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
      <DialogContent
        className="sm:max-w-md"
        onCloseAutoFocus={(e) => {
          e.preventDefault();
          onRefocus();
        }}
      >
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
